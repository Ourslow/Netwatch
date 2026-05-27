# NetWatch — Contexte Projet pour Claude Code

## IDENTITE
- Projet : NetWatch v2 — Stack d'observabilité réseau multi-moteurs open-source
- Auteur : Nicolas Malok, alternant cybersécurité @ Axians / Vinci Energies
- École : École 2600 (cyber), promotion 2024-2027
- Catégorie : SideQuest MVP (S2 2025-2026)
- Repo : https://github.com/Ourslow/netwatch

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

### v2 (EN COURS)
- [x] Docker Compose 6 services (+ Snort 3 + Suricata)
- [x] Dockerfile Snort 3 (build from source + libdaq + tcmalloc)
- [x] Config Snort 3 (snort.lua, alert_json, règles custom)
- [x] Dockerfile Suricata 7 (jasonish/suricata + ET Open)
- [x] Config Suricata (suricata.yaml, EVE JSON, Community ID)
- [x] Filebeat multi-sources (3 inputs, index par engine)
- [x] Datasources Grafana (Zeek-ES, Snort-ES, Suricata-ES)
- [x] Script replay-pcap.sh (replay sur les 3 moteurs)
- [ ] Tester le build complet sur la VM
- [ ] Dashboards Grafana pour alertes Snort
- [ ] Dashboards Grafana pour alertes Suricata
- [ ] Dashboard corrélation multi-moteurs
- [ ] Mettre à jour simulate-traffic.py pour Snort/Suricata
- [ ] Mettre à jour README pour v2
- [ ] Mettre à jour docs/architecture.md

### v3 (PLANIFIE)
- Migration ESXi → Proxmox VE
- Portail web custom (Flask/FastAPI + API Proxmox) pour gérer les VMs
- Templates VM pour outils commerciaux (Netscout, Gigamon, Riverbed)
- Mode comparaison côte à côte

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
