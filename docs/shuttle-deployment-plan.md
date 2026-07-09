# Déploiement physique NetWatch v2 sur Shuttle Proxmox

Démarche à suivre pour passer du test VirtualBox (`docs/test-local-proxmox.md`) au
déploiement réel sur le Shuttle. Objectif final : capture du trafic réel via port
SPAN, stack complète répartie sur 2 VMs, portail NetWatch piloté depuis le PC.

> Ce guide part du principe que le Shuttle est vierge (pas d'OS installé) ou
> disponible pour repartir sur Proxmox VE en bare-metal.

---

## 0. Prérequis matériels à vérifier avant de commencer

| Élément | Besoin | Pourquoi |
|---|---|---|
| CPU | Xeon avec VT-x/VT-d | Virtualisation + passthrough NIC dédiée |
| RAM | 16 Go mini (32-64 Go si extensible) | 2 VMs (6 Go + 10 Go) + marge Proxmox |
| Disque | ~120 Go dispo (SSD si possible) | ES a un ILM 30j, logs Zeek/Snort/Suricata |
| NIC capture | Intel i350-T2 (2 ports, pilote igb) | Un port dédié SPAN, isolé du management |
| Switch | Manageable, port mirroring (SPAN) | Copier le trafic à surveiller vers la NIC capture |
| Accès BIOS | Activer VT-x + VT-d + éventuellement SR-IOV | Sans VT-d, pas de passthrough NIC propre |

---

## 1. Installation Proxmox VE bare-metal

1. Flasher l'ISO Proxmox VE 8.x sur clé USB (`dd` ou Rufus).
2. BIOS Shuttle : activer **Intel VT-x** et **VT-d** (souvent désactivés par défaut).
3. Boot USB → installeur graphique Proxmox :
   - Disque cible : le SSD/NVMe principal
   - Filesystem : `ext4` (zfs seulement si tu as ≥ 2 disques, sinon inutile ici)
   - Country/Timezone : France / Europe/Paris
   - Réseau management : IP fixe sur le port NIC **1** (pas la i350-T2 de capture)
     - Hostname FQDN : `pve-netwatch.local` (cohérent avec le guide VirtualBox)
4. Reboot → accès `https://<IP_management>:8006`, login `root@pam`.
5. Retirer le repo enterprise (pas d'abonnement) :
   ```bash
   sed -i 's/^deb/#deb/' /etc/apt/sources.list.d/pve-enterprise.list
   echo "deb http://download.proxmox.com/debian/pve bookworm pve-no-subscription" \
     > /etc/apt/sources.list.d/pve-no-subscription.list
   apt update && apt full-upgrade -y
   ```

---

## 2. Réseau — le point critique (SPAN + promiscuous)

But : le trafic mirroré par le switch doit arriver, intact, jusqu'à l'interface
`IFACE` du conteneur Zeek/Snort/Suricata côté VM Sensors — sans que Proxmox ou
la VM ne le traite comme du trafic normal (pas d'IP, pas de routage dessus).

1. **Câblage** : port SPAN du switch → port 2 de la carte i350-T2 sur le Shuttle.
   Port 1 de la i350-T2 (ou une autre NIC) reste sur le LAN normal pour les VMs.
2. **Sur le switch manageable** : configurer le port mirroring
   (`monitor session` en syntaxe Cisco-like, ou équivalent constructeur) —
   source = port(s)/VLAN à surveiller, destination = port relié à la i350-T2.
3. **Dans Proxmox — deux options** :
   - **Option A (recommandée, plus simple) : bridge Linux dédié en mode promiscuous**
     - Créer `vmbr1` sur le port physique de capture (Datacenter → Node → Network)
     - Ne PAS lui assigner d'IP (bridge pur, pas de routage)
     - Sur la VM Sensors : ajouter une 2e carte réseau reliée à `vmbr1`, modèle
       `virtio`, **sans** configurer d'IP dessus côté VM — Zeek/Snort/Suricata
       l'ouvrent directement en mode promiscuous (AF_PACKET), déjà géré par
       `docker-compose.yml` (`network_mode: host` ou `cap_add: NET_ADMIN` selon
       le service — vérifier la conf actuelle avant transfert).
   - **Option B (perf max) : PCI passthrough du port i350-T2**
     - Nécessite VT-d actif + IOMMU (`intel_iommu=on` dans `/etc/kernel/cmdline`)
     - Le port physique est alors visible nativement dans la VM (meilleure perf,
       pas de couche bridge), mais plus rigide (la VM "possède" le port).
     - À réserver si l'option A montre des pertes de paquets en charge réelle.
4. Dans la VM Sensors, adapter `IFACE=` dans `.env` pour pointer vers l'interface
   de capture réelle (`ip a` pour vérifier le nom, ex. `ens19`).

---

## 3. Architecture 2 VMs — répartition des services

| VM | vCPU / RAM | Services docker-compose |
|---|---|---|
| **VM Sensors** | 4 vCPU / 6 Go | `zeek`, `snort`, `suricata`, `filebeat`, `goflow2`, `beacon-detect`, `autoblock` |
| **VM Data** | 4 vCPU / 10 Go | `elasticsearch`, `grafana`, `prometheus`, `node-exporter`, `crowdsec`, `ollama`, `n8n` |

- Créer les 2 VMs sous Proxmox : Ubuntu 22.04 LTS (cloud-init image, plus rapide
  à provisionner qu'un ISO manuel), Docker + Docker Compose installés.
- Réseau : VM Sensors a la carte de capture (`vmbr1`, cf. §2) **+** une carte LAN
  normale (`vmbr0`) pour parler à Filebeat → Elasticsearch sur VM Data.
- Découper `docker-compose.yml` en deux fichiers (`docker-compose.sensors.yml` /
  `docker-compose.data.yml`) — pas encore fait dans le repo, à créer avant le
  transfert. Pointer `filebeat.yml` (côté Sensors) vers l'IP LAN de VM Data pour
  Elasticsearch, et les datasources Grafana / Prometheus scrape targets côté
  Data vers l'IP LAN de VM Sensors.

---

## 4. Déploiement du code

1. Cloner le repo sur chaque VM : `git clone https://github.com/Ourslow/Netwatch.git`
2. Copier `.env.example` → `.env`, remplir (`IFACE` réel, mots de passe, IPs
   croisées Sensors/Data).
3. `docker compose -f docker-compose.sensors.yml up -d` sur VM Sensors.
4. `docker compose -f docker-compose.data.yml up -d` sur VM Data.
5. Portail Flask : soit sur VM Data, soit sur une 3e petite VM/le PC de gestion
   — pointer `portal/.env` (`PROXMOX_HOST`, `ES_HOST`, etc.) vers les IPs réelles.

---

## 5. Checklist de validation

| Test | Attendu |
|---|---|
| `docker ps` sur les 2 VMs | Tous les conteneurs `Up` |
| `curl <VM_Data_IP>:9200/_cat/indices?v` | Index `zeek-*`, `snort-*`, `suricata-*`, `netflow-*` apparaissent après trafic réel |
| Génération de trafic test (ping, DNS, HTTP) depuis un poste sur le VLAN mirroré | Logs Zeek/Snort/Suricata alimentés en quelques secondes |
| Grafana (`<VM_Data_IP>:3000`) | Dashboards affichent des données non vides |
| Portail (`:5050`) | `/status` vert sur tous les services, `/topology` détecte au moins la passerelle |
| Débit SPAN vs débit réel | Pas de perte de paquets visible (`zeek/stats.log` — `pkts_dropped` ≈ 0) |

---

## 6. Ordre de priorité conseillé

1. Bare-metal Proxmox + réseau management (§1) — bloquant pour tout le reste.
2. SPAN + bridge promiscuous (§2) — le point le plus susceptible de mal se
   passer du premier coup (câblage/config switch), à tester tôt avec un simple
   `tcpdump -i <iface_capture>` avant même de monter les VMs Docker.
3. VM Sensors + VM Data (§3-4).
4. Portail + validation (§5).

**Pourquoi cet ordre** : la capture réseau (SPAN) est la partie la plus proche
du matériel physique et la moins réversible à distance si mal câblée/configurée
— mieux vaut la valider avec un outil simple (`tcpdump`) avant d'empiler Docker
par-dessus, pour isoler "le trafic n'arrive pas" de "le stack ne le traite pas".
