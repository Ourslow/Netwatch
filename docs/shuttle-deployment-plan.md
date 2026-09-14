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
| RAM | 16 Go mini · **32 Go recommandé** avec l'édition IA | 2 VMs (6 Go + 10 Go) + marge Proxmox — voir le budget mémoire §3 |
| Disque | ~120 Go (SSD) **+ un volume dédié PCAP pour Arkime** (200 Go+ selon la rétention voulue) | ES a un ILM 30j, logs Zeek/Snort/Suricata ; Arkime garde les PCAP jusqu'à `ARKIME_FREE_SPACE_G` |
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

Les services se répartissent selon un seul critère : **a-t-il besoin du port SPAN ?**
Oui → VM Sensors. Non → VM Data. Les cinq services d'observabilité complémentaire
(commit `9189bcc` et suivants) suivent la même règle.

| VM | vCPU / RAM | Services docker-compose | RAM mesurée (labo 14/09/2026) |
|---|---|---|---|
| **VM Sensors** | 4 vCPU / 6 Go | `zeek`, `snort`, `suricata`, `filebeat`, `goflow2`, `beacon-detect`, `autoblock`, `crowdsec`, `node-exporter` **+ `arkime` (capture + viewer), `ntopng`** | ≈ 3,5-4,5 Go (suricata 0,3-1 Go selon les règles, arkime 0,5-1 Go, ntopng 0,2 Go) |
| **VM Data** | 4 vCPU / 10 Go | `elasticsearch`, `grafana`, `prometheus`, `node-exporter`, `n8n` **+ `kibana`, `blackbox`, `netbox` (+ postgres, 2 redis, worker)** | ≈ 6 Go hors IA (ES heap 2 Go ≈ 3 Go RSS, netbox 1,2 Go, kibana 0,5 Go, grafana/prometheus/n8n ≈ 0,8 Go) |
| **VM Data — édition IA** | idem | `ollama` + modèle chargé | **+ 4-5 Go** avec `mistral` (7B) — voir ci-dessous |

### Budget mémoire et édition IA

- **Sans IA** (`OLLAMA_URL=` vide dans `.env` : le portail masque les boutons ✨ et
  ne surveille pas Ollama) : 16 Go suffisent largement — Data ≈ 6 Go sur 10.
- **Avec IA** : `mistral` occupe 4-5 Go *quand il est chargé*. Ollama décharge le
  modèle après 5 min d'inactivité (`OLLAMA_KEEP_ALIVE`, défaut 5m) : au repos la
  VM Data retombe à ≈ 6 Go, mais pendant/juste après une explication d'alerte elle
  monte à ≈ 10-11 Go — c'est exactement la saturation observée sur la VM WSL de
  7,8 Go le 14/09. Trois options :
  1. **32 Go sur le Shuttle** (recommandé pour vendre « IA locale incluse » sans
     compromis) → VM Data à 16 Go, `ES_HEAP=-Xms4g -Xmx4g`.
  2. Rester à 16 Go et prendre un modèle plus petit pour la démo
     (`OLLAMA_MODEL=llama3.2:3b`, ≈ 2,5 Go chargé).
  3. Rester à 16 Go avec `mistral` et accepter 10-20 s de latence à la première
     explication (chargement du modèle), en gardant `OLLAMA_KEEP_ALIVE=5m`.
- Ne jamais dimensionner en dessous : Elasticsearch **et** Arkime ont été tués en
  OOM (exit 137) sur la VM 7,8 Go avec la stack complète. Sur une petite machine,
  `ES_HEAP=-Xms1g -Xmx1g` dans `.env` (documenté dans `.env.example`).

### Deux éditions d'un même dépôt

Il n'y a pas deux produits à maintenir : c'est le même `docker-compose.yml`, et
l'IA est un **module** activé par la configuration.

| | Édition Core | Édition IA |
|---|---|---|
| `.env` | `OLLAMA_URL=` (vide) | `OLLAMA_URL=http://<VM_Data_IP>:11434`, `OLLAMA_MODEL=mistral` |
| Conteneur `ollama` | non démarré | démarré + `make llm-pull` une fois |
| Portail | boutons ✨ masqués, `/status` sans la carte « Assistant IA », `/agents` et `/llmops` vides | explication d'alertes, narration PCAP, résumé exécutif, monitoring LLMOps |
| RAM VM Data | ≈ 6 Go | ≈ 6 Go au repos, 10-11 Go en génération |

Passage Core → IA sur un site déjà déployé : renseigner `OLLAMA_URL`, démarrer le
conteneur, `make llm-pull`, redémarrer le portail — aucune migration de données.
(À faire côté code : un `profiles: [ia]` sur le service `ollama` pour que
`docker compose up -d` de l'édition Core ne le lance pas du tout — voir §6.)

### Réseau entre les deux VMs

- VM Sensors a la carte de capture (`vmbr1`, cf. §2) **+** une carte LAN
  normale (`vmbr0`) pour parler à Elasticsearch sur VM Data (Filebeat, Arkime
  capture/viewer, beacon-detect) et à Prometheus (node-exporter, blackbox scrape).
- Les fichiers `docker-compose.sensors.yml` / `docker-compose.data.yml` existent
  dans le repo pour le cœur de la stack ; **les 10 services complémentaires n'y
  sont pas encore répartis** (ils ne sont que dans `docker-compose.yml`) — à faire
  avant le transfert (§6). Pointer `filebeat.yml` et `ARKIME__elasticsearch` (côté
  Sensors) vers l'IP LAN de VM Data ; côté Data, les datasources Grafana, les
  cibles Prometheus (`node-exporter` Sensors, `blackbox`) et `NETWATCH_*_URL` du
  portail vers les bonnes IPs.

---

## 4. Déploiement du code

1. Cloner le repo sur chaque VM : `git clone https://github.com/Ourslow/Netwatch.git`
2. Copier `.env.example` → `.env`, remplir (`IFACE` réel, mots de passe, IPs
   croisées Sensors/Data).
3. `docker compose -f docker-compose.sensors.yml up -d` sur VM Sensors.
4. `docker compose -f docker-compose.data.yml up -d` sur VM Data.
5. Portail Flask : soit sur VM Data, soit sur une 3e petite VM/le PC de gestion
   — pointer `portal/.env` (`PROXMOX_HOST`, `FLASK_SECRET_KEY`, `PORTAL_*`) et le
   `.env` racine (`NETWATCH_ES_URL`, `NETWATCH_*_URL`, `NETBOX_*`, `OLLAMA_URL`)
   vers les IPs réelles — le portail lit les deux fichiers.
6. Services complémentaires : `make arkime-init` (une fois, côté Sensors),
   `make kibana-setup` (côté Data), puis `make demo-netbox` si on veut des données
   d'inventaire de démonstration. Secrets à générer (jamais les valeurs de démo
   `netwatch`) : voir les commandes dans `.env.example`.
7. Arkime en production : `ARKIME_AUTH_MODE=form` derrière le reverse-proxy
   HTTPS (`authTrustProxy`), et changer le mot de passe `admin` dans *Users*.

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
| `make health` | Les 5 services complémentaires `UP` ; `/sla` → sondes Blackbox 100 % sur les cibles du site (`prometheus/blackbox-targets.yml` adapté : passerelle, DNS interne, serveurs critiques) |
| Arkime (`:8005`) | Sessions du VLAN mirroré visibles ; `arkime_sessions3-*` grossit dans ES ; espace disque PCAP surveillé (`ARKIME_FREE_SPACE_G`) |
| NetBox (`:8000`) | Préfixes du site saisis → `/ip/<ip>` affiche la carte « Contexte NetBox », import hostgroups OK |
| Mémoire (`free -m` sur chaque VM) | ≥ 1 Go disponible après 15 min de capture, y compris après une explication IA (édition IA) |

---

## 6. Ordre de priorité conseillé

1. Bare-metal Proxmox + réseau management (§1) — bloquant pour tout le reste.
2. SPAN + bridge promiscuous (§2) — le point le plus susceptible de mal se
   passer du premier coup (câblage/config switch), à tester tôt avec un simple
   `tcpdump -i <iface_capture>` avant même de monter les VMs Docker.
3. VM Sensors + VM Data (§3-4).
4. Portail + validation (§5).

**Fait dans le repo le 14/09/2026** (édition Core / IA + répartition 2-VMs) :

- ✅ Les 10 services complémentaires sont répartis : `docker-compose.sensors.yml`
  (`arkime`, `ntopng`, liés à 192.168.100.11) et `docker-compose.data.yml`
  (`blackbox`, `kibana`, `netbox` + postgres/redis/worker, liés à 192.168.100.12,
  jobs Prometheus dans `prometheus.data.yml`). Les IPs restent en dur comme pour
  le reste des fichiers 2-VMs — à adapter au plan d'adressage du site.
- ✅ `profiles: ["ia"]` sur `ollama` (les 3 compose) : `COMPOSE_PROFILES=ia` dans
  `.env` ou `docker compose --profile ia up -d` ; sinon jamais lancé.
- ✅ Portail : `OLLAMA_URL` vide → `AI_ENABLED=False` : boutons ✨, entrée
  « Agents IA », résumé exécutif du rapport masqués ; Ollama absent de `/status` ;
  `/api/explain`, `/api/summary`, `/api/pcap-analysis/explain` → 503 explicite.
- ✅ `.env.example` : bloc « ÉDITION » en tête (`COMPOSE_PROFILES`, `OLLAMA_URL`).

**Pourquoi cet ordre** : la capture réseau (SPAN) est la partie la plus proche
du matériel physique et la moins réversible à distance si mal câblée/configurée
— mieux vaut la valider avec un outil simple (`tcpdump`) avant d'empiler Docker
par-dessus, pour isoler "le trafic n'arrive pas" de "le stack ne le traite pas".
