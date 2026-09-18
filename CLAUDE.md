# NetWatch — Contexte Projet pour Claude Code

## IDENTITE
- Projet : NetWatch v2 — Stack d'observabilité réseau multi-moteurs open-source
- Auteur : Nicolas Malok, analyste observabilité NPM @ Axians / Vinci Energies — France
- École : École 2600 (cyber), promotion 2024-2027
- Origine : SideQuest MVP (S2 2025-2026) — **depuis le 2026-09-18, projet personnel visant un produit commercialisable**
- Repo : https://github.com/Ourslow/netwatch

## CAP PRODUIT (2026-09-18)
Référence : `docs/positionnement-produit.md`. Résumé :
- Sonde NPM + NDR self-hosted pour PME 50-500 postes et MSP francophones. Pas de SaaS hébergé en phase 1.
- Édition **Community** (AGPL v3, ce dépôt, complète pour une sonde utile) + édition **Pro** (abonnement, clé de licence, dépôt privé `netwatch-pro` chargé comme extension). Jamais payant : doc, moteurs, dashboards Grafana, install, health.
- Ordre : validation terrain (6 semaines) → tests/CI → reverse proxy/TLS/auth unifiée → install/upgrade/backup → licence → split Pro (en dernier).
- Aucune fonctionnalité retirée ni bridée avant la fin de la validation.
- **Prochaine étape (19/09)** : dérouler `docs/validation-vm.md` (proxy, install.sh, backup/restore, upgrade n'ont jamais tourné en réel) et corriger ce qui remonte, avant la licence hors ligne. Décidé le 18/09 au soir : commencer par le § 5 (installation à blanc) sur une **distribution WSL neuve** — `wsl --shutdown`, `.wslconfig memory=12GB`, `wsl --install -d Ubuntu-24.04` (ou `--name netwatch-test`), dans Ubuntu vérifier `systemctl is-system-running`, puis `git clone … && ./install.sh --public-url https://localhost` (WSL en NAT → localhost depuis le navigateur Windows). Le labo existant reste sur son WSL, arrêté pendant le test (RAM partagée). Rien n'a encore été exécuté.
- Prérequis avant le premier euro : clarification écrite de la PI vis-à-vis d'Axians (§ 9 du doc).
- **Nom du produit** : « NetWatch » n'est pas utilisable commercialement (société NETWATCH SAS à Paris en conseil informatique, netwatch.ai = supervision IT par IA, Netwatch Irlande = vidéosurveillance). Longue session de noms le 18/09 (~150 candidats sur deux soirées — mythologie, langues rares, composés gréco-latins, calques anglais façon Datadog/Netscout — presque tous tués par une marque, un produit ou un usage existant : Vartio par un jeu Steam, Skopia par une EUTM active, Teichos par une marque italienne EUTM active en classe 42 logiciel, Pallas par une startup cyber, Argoscope/Vigilux/Nethawk par des produits réseau/sécurité existants).
  - **Candidat actuel : Polias** (Πολιάς, épithète d'Athéna « gardienne de la cité/citadelle » — rempart + veille + les valeurs voulues : courage, force, sacrifice). Aucune société ou marque logicielle/cyber trouvée sous ce nom exact (seulement du bruit de fond sans rapport : immobilier à Athens GA, coquilles UK inactives/dissoutes). **Non encore vérifié à l'INPI/TMview** — c'est la seule vérification qui a fait tomber tous les candidats précédents après une première impression favorable, donc ne pas s'y fier avant ce contrôle. Si Polias tombe aussi, secours dans l'ordre : Promachos (« combat au premier rang », société homonyme LLP UK à activité inconnue à vérifier), Packhawk (net+hawk façon Netscout, vierge), Vedetta.
  - Prochaine étape pour Nicolas : data.inpi.fr → Marques → `polias`, classes 9 et 42 ; TMview pour l'UE ; domaines `polias.fr` / `.io` / `.com`.
  - Renommage (dépôt, préfixes `netwatch-` → nom retenu, index `netwatch-*`, docs) = chantier technique à part, après la validation VM et une fois un nom confirmé propre — ne pas commencer le renommage avant confirmation INPI/TMview.

## CONCEPT
Stack d'observabilité réseau open-source qui reproduit les fonctionnalités clés d'un outil NPM commercial (type Netscout nGeniusONE) avec des briques 100% open-source. Le projet intègre 3 moteurs d'analyse en parallèle sur le même trafic.

## STACK TECHNIQUE (v2)
- **Zeek 6.2** — Analyse protocolaire, logs JSON, plugins JA3/HASSH
- **Snort 3.3.5** — IDS par signatures, règles community + custom, sortie alert_json
- **Suricata 7** — IDS par signatures, règles ET Open, sortie EVE JSON, Community ID
- **Filebeat 8.13** — Collecte les logs des 3 moteurs
- **Elasticsearch 8.13** — Index séparés : zeek-*, snort-*, suricata-*
- **Grafana 10.4** — Dashboards + alertes, 3 datasources provisionnées
- **Docker Compose** — Orchestration des 6 services
- **OS** — Ubuntu 22.04 LTS sur VM (Proxmox ou ESXi)

## ARCHITECTURE / PIPELINE
```
Trafic réseau (SPAN / PCAP)
        ↓
   ┌────┼────┐
   ↓    ↓    ↓
  Zeek Snort Suricata   ← 3 moteurs en parallèle
   ↓    ↓    ↓
    Filebeat            ← collecte unifiée
        ↓
   Elasticsearch        ← zeek-* / snort-* / suricata-*
        ↓
     Grafana            ← dashboards + alertes
```

## INFRASTRUCTURE CIBLE
- Shuttle avec Proxmox VE, Xeon, 16 Go RAM (extensible 32-64 Go)
- 2 ports de capture physiques + switch manageable (port SPAN)
- vSwitch Proxmox en mode promiscuous pour distribuer le trafic aux VMs
- Architecture 2 VMs : VM Sensors (Zeek/Snort/Suricata, 6 Go) + VM Data (ES/Grafana, 8 Go)
- Vision long terme : lab multi-VMs avec portail web custom pour sélectionner les outils (open-source + commerciaux Axians : Netscout, Gigamon, Riverbed)

## ETAT D'AVANCEMENT
### v1 (DONE - Mars 2026)
- Stack Docker Compose 4 services (Zeek + Filebeat + ES + Grafana)
- 4 dashboards Grafana (Vue réseau, DNS, HTTP/TLS, Alertes sécurité)
- 2 scripts Zeek custom (port-scan-detect, dns-entropy Shannon)
- Simulateur de trafic Python (simulate-traffic.py)
- README complet, docs, MoSCoW/WBS/Gantt, pitch 5 min

### v2 (COMPLETE)
- [x] Docker Compose 10 services (Zeek, Snort, Suricata, Filebeat, ES, Grafana, Prometheus, node-exporter, beacon-detect, autoblock)
- [x] Dockerfile Snort 3 (build from source + libdaq + tcmalloc)
- [x] Config Snort 3 (snort.lua, alert_json, règles custom SID 1000001-1000017 + MITRE)
- [x] Dockerfile Suricata 7 (jasonish/suricata + ET Open + suricata-update auto)
- [x] Config Suricata (suricata.yaml, EVE JSON, Community ID, threading)
- [x] Filebeat multi-sources (3 inputs, index par engine, ssh.log + intel.log)
- [x] Datasources Grafana (6 datasources : Zeek, Snort, Suricata, Beacons, AutoBlock, Prometheus)
- [x] Script replay-pcap.sh (replay sur les 3 moteurs)
- [x] Dashboards Grafana pour alertes Snort (+ MITRE ATT&CK)
- [x] Dashboards Grafana pour alertes Suricata (+ MITRE ATT&CK)
- [x] Dashboard corrélation multi-moteurs
- [x] Dashboards : vm-health, top-talkers, ja3-hassh, beacon-detect (11 total)
- [x] beacon-detect RITA-lite (beaconing CV, longues connexions, DNS tunneling)
- [x] autoblock webhook Flask → iptables (DRY_RUN=true par défaut)
- [x] Zeek Intel Framework (ip_watchlist.dat + domain_watchlist.dat + update-intel.sh)
- [x] JA3/HASSH fingerprinting dans logs SSL/SSH Zeek
- [x] Prometheus + node-exporter + dashboard vm-health
- [x] GeoIP pipeline Elasticsearch (setup-geoip.sh)
- [x] Grafana alerting (CPU, RAM, disk, Suricata spike, volume anomaly)
- [x] Contact points Grafana (Slack + AutoBlock webhook)
- [x] Mettre à jour simulate-traffic.py (JA3/HASSH, MITRE, beaconing, Intel, DNS tunneling)
- [x] Mettre à jour README pour v2 (10 services, 11 dashboards, AGPL v3)
- [x] Mettre à jour docs/architecture.md
- [x] demo.sh — script de démonstration interactif
- [x] Makefile — make start/stop/demo/logs/build/health/clean
- [x] Licence MIT → AGPL v3
- [x] Suppression IP en clair de l'historique git
- [x] .env.example propre (SNORT_MONITORED_SERVER, DRY_RUN=true)
- [ ] Tester le build complet sur la VM physique

### v3 — produit (PLANIFIE, voir docs/positionnement-produit.md § 7)
- [ ] Validation terrain : landing page + 10 conversations MSP/DSI + 1 pilote
- [ ] Tests automatisés + CI (portail, health, replay PCAP)
- [x] Reverse proxy unique TLS + auth unifiée (Caddy, profil `proxy`, `caddy/Caddyfile`, `/auth/check`) — **à valider sur la VM** (sous-chemins Grafana/Kibana/Arkime/ntopng/NetBox jamais exécutés en réel)
- [x] Install une commande (`install.sh`), `scripts/upgrade.sh`, `scripts/backup.sh` / `restore.sh` (snapshot ES via `path.repo` + volume `es-snapshots`) — **à valider sur la VM** ; ILM ES restant à faire
- [x] `VERSION` + `CHANGELOG.md` — reste : tags `vX.Y.Z` (`upgrade.sh` cible le dernier tag), images publiées
- [ ] Mécanisme de licence hors ligne (clé signée)
- [ ] Split Community / Pro (dépôt privé `netwatch-pro`, extension du portail)
- [ ] Déploiement physique sur Shuttle Proxmox (Intel i350-T2 + SPAN)
- Héritage lab (gestion VMs Proxmox/ESXi, templates outils commerciaux, comparaison côte à côte) : à trancher, § 10 du doc

## CONVENTIONS
- Fichiers de config en français (commentaires)
- Code et scripts en anglais (variables, fonctions)
- Logs Zeek en JSON (LogAscii::use_json = T)
- Index ES : {engine}-{date} (zeek-2026.05.27, snort-2026.05.27, suricata-2026.05.27)
- Docker : tous les conteneurs préfixés netwatch-
- Règles custom Snort : SID 1000001-1000999
- Règles custom Suricata : SID 2000001-2000999

## FICHIERS CLES
- `docker-compose.yml` — Orchestration 6 services
- `caddy/Caddyfile` — Point d'entrée HTTPS unique (profil `proxy`) : sous-chemins + auth unifiée via `/auth/check`
- `install.sh`, `scripts/backup.sh`, `scripts/restore.sh`, `scripts/upgrade.sh` — Exploitation (installation, sauvegarde, mise à jour) ; `VERSION`, `CHANGELOG.md`
- `replay-pcap.sh` — Replay PCAP sur les 3 moteurs
- `simulate-traffic.py` — Simulateur de trafic (injecte directement dans ES)
- `snort/snort.lua` — Config Snort 3
- `suricata/suricata.yaml` — Config Suricata
- `filebeat/filebeat.yml` — Collecte multi-sources
- `zeek/scripts/*.zeek` — Scripts de détection custom

## COMMANDES UTILES
```bash
# Lancer le stack
docker compose up -d

# Replay un PCAP sur les 3 moteurs
./replay-pcap.sh pcap/sample.pcap

# Vérifier les index ES
curl "http://localhost:9200/_cat/indices?v&s=index"

# Simuler du trafic (24h, intensité moyenne, avec attaques)
python3 simulate-traffic.py --hours 24 --intensity medium --attack

# Rebuild un service
docker compose build snort --no-cache
docker compose up -d snort
```
