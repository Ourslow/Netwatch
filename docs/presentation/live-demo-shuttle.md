# Démo live — déploiement Shuttle Proxmox (jury École 2600 + Axians)

Script de démo pas à pas sur l'infra réelle (2 VMs sur le Shuttle), utilisable
pour les deux publics — les points spécifiques à chaque audience sont marqués
**[Jury]** ou **[Axians]**.

> Accès rapides :
> - Proxmox : `https://192.168.100.2:8006` (root/pam)
> - Portail NetWatch : `http://localhost:5050` (admin/netwatch)
> - Grafana : `http://192.168.100.12:3000` (admin/mot de passe dans `.env` VM Data)

---

## 0. Avant de commencer (checklist rapide)

```bash
# Depuis ce PC — vérifie que tout répond avant de te lancer
ssh ubuntu@192.168.100.11 "docker compose -f /home/ubuntu/netwatch/docker-compose.sensors.yml ps"
ssh ubuntu@192.168.100.12 "docker compose -f /home/ubuntu/netwatch/docker-compose.data.yml ps"
curl -s http://localhost:5050/api/status | python3 -m json.tool
```
Tout doit être "Up"/"up" (sauf Ollama, en stand-by assumé).

---

## 1. Ouverture (2 min)

**[Jury]** Rappelle le contexte : alternance Axians, projet SideQuest, objectif
explorer l'open-source face au commercial (Netscout/Gigamon/Riverbed).
**[Axians]** Rappelle le positionnement : outil interne + potentiel de service
facturable (audit express / managé) pour des clients hors budget premium.

Transition : *"Je ne vais pas vous montrer des captures d'écran ou une VM de
test — ça tourne réellement sur un serveur physique, là, maintenant."*

---

## 2. Infrastructure réelle — Proxmox (3 min)

Ouvre `https://192.168.100.2:8006`.

- Montre le nœud `pve-netwatch` : CPU/RAM en direct (i7-7700, 8 threads, 15 Go)
- Clique sur `netwatch-sensors` (101) et `netwatch-data` (102) : uptime, conso
  réelle CPU/RAM de chaque VM
- **[Axians]** Insiste sur l'architecture 2-VMs (séparation capture / stockage,
  pattern standard NPM) — c'est la même logique qu'un déploiement Netscout
  probe + collector.
- **[Jury]** Mentionne le découpage `docker-compose.sensors.yml` /
  `docker-compose.data.yml` — méthodologie propre, pas un tas de conteneurs
  sur une seule machine.

---

## 3. Portail unifié (5 min)

Ouvre `http://localhost:5050`, login `admin`/`netwatch`.

- `/status` → tous les services au vert (Elasticsearch, Grafana, Prometheus,
  AutoBlock). Explique le choix assumé de mettre Ollama en stand-by (gestion
  de charge sur un Shuttle partagé, pas une limite technique).
- `/exec` → KPIs direction, score IOC composite
- **[Jury]** `/audit` → score de posture sécurité, transparence sur les limites
- **[Axians]** `/report` → rapport PDF auto-généré, argument différenciation
  avant-vente / service facturable

---

## 4. Grafana — données réelles (5 min)

Ouvre `http://192.168.100.12:3000`.

- Dashboard corrélation multi-moteurs : montre les logs Zeek/Snort/Suricata
  qui remontent réellement (trafic de gestion : SSH, DNS, NTP — sois honnête
  que le SPAN production n'est pas encore câblé, cf. section 6)
- Dashboard capacity planning : formule `netwatch:iface_days_to_saturation`
- **[Axians]** Dashboard NetFlow/GoFlow2 : le volet NPM, le plus pertinent
  pour l'équipe observabilité

---

## 5. Point technique fort — les vrais bugs résolus (optionnel, 2 min)

Si le public est technique (jury, ou ingénieurs Axians) :
- Bug CPU Proxmox : type générique sans SSE4.2/POPCNT → Suricata refusait de
  builder → diagnostic précis (`lscpu`, message glibc) → fix CPU `host`
- Bug chemin de logs Zeek (`WORKDIR` vs volume monté) → ES à 0 documents
  malgré des logs générés → diagnostic bout en bout jusqu'à Filebeat
- Ces deux bugs illustrent une vraie démarche de debug méthodique, pas
  juste "ça marche du premier coup"

---

## 6. Transparence — ce qui reste à faire (1 min)

- **SPAN physique pas encore câblé** : les moteurs tournent sur l'interface
  de management (trafic limité), pas encore sur un vrai flux mirroré
  → prochaine étape logique, pas un blocage du concept
- Ollama en stand-by (ressources)
- **[Axians]** Modèle de vente externe encore à l'étude (audit facturable /
  service managé) — licence AGPL v3, on vend le service pas le code

---

## 7. Clôture

**[Jury]** Reviens sur la méthodologie : itératif, phases testables, bugs
documentés et corrigés en transparence.
**[Axians]** Reviens sur les deux pistes : formation interne (déjà solide) et
potentiel commercial externe (à cadrer).

---

## Filet de sécurité — si quelque chose ne répond pas pendant la démo

```bash
# Redémarrer un service qui plante
ssh ubuntu@192.168.100.11 "cd /home/ubuntu/netwatch && docker compose -f docker-compose.sensors.yml restart <service>"
ssh ubuntu@192.168.100.12 "cd /home/ubuntu/netwatch && docker compose -f docker-compose.data.yml restart <service>"

# Vérifier vite fait que rien n'a crashé pendant que tu parlais
ssh ubuntu@192.168.100.11 "docker compose -f /home/ubuntu/netwatch/docker-compose.sensors.yml ps"
```

Si le Wi-Fi/NAT de ce PC tombe (il sert de passerelle Internet aux 2 VMs),
les VMs restent fonctionnelles entre elles et avec ce PC (réseau local direct
sur le switch) — seul l'accès Internet des VMs serait coupé, sans impact sur
la démo elle-même.
