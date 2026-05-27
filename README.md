# NetWatch v2 — Stack NPM Open-Source Multi-Moteurs

> Observabilité réseau avec **Zeek + Snort 3 + Suricata 7 + Elasticsearch + Grafana + Prometheus**
> Trois moteurs d'analyse en parallèle · Pipeline unifié · 11 dashboards · Détection comportementale · Réponse automatique

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED.svg)](docker-compose.yml)
[![Zeek](https://img.shields.io/badge/Zeek-6.2-orange.svg)](https://zeek.org)
[![Snort](https://img.shields.io/badge/Snort-3.3.5-red.svg)](https://snort.org)
[![Suricata](https://img.shields.io/badge/Suricata-7.0-blue.svg)](https://suricata.io)
[![Elasticsearch](https://img.shields.io/badge/Elasticsearch-8.13-005571.svg)](https://www.elastic.co)
[![Grafana](https://img.shields.io/badge/Grafana-10.4-F46800.svg)](https://grafana.com)

---

## Présentation

**NetWatch** est un stack d'observabilité réseau open-source qui reproduit les fonctionnalités clés d'un outil NPM commercial (Netscout nGeniusONE, Corelight, Riverbed) avec des briques 100% libres.

La v2 passe de 4 à **10 services** et étend les capacités de détection :

| Moteur | Rôle | Format de sortie |
|--------|------|-----------------|
| **Zeek 6.2** | Analyse protocolaire, logs JSON, JA3/HASSH, Intel Framework | conn/dns/http/ssl/ssh/intel/notice.log |
| **Snort 3.3.5** | IDS par signatures, règles community + custom NETWATCH | alert_json.txt |
| **Suricata 7** | IDS/IPS, règles ET Open (auto-mise à jour), Community ID | EVE JSON (eve.json) |
| **beacon-detect** | Détection comportementale RITA-lite (beaconing C2, DNS tunneling, longues connexions) | netwatch-beacons-* |
| **autoblock** | Réponse automatique iptables via webhook Grafana (DRY_RUN=true par défaut) | netwatch-autoblock-* |
| **Prometheus + node-exporter** | Métriques système VM (CPU, RAM, disque, réseau) | — |

> **Nicolas Malok** — Alternant Cybersécurité @ Axians / Vinci Energies — École 2600
> SideQuest MVP (S2 2025-2026)

---

## Architecture

```
        Trafic réseau (SPAN / PCAP)
                    │
        ┌───────────┼───────────┐
        ▼           ▼           ▼
  ┌──────────┐ ┌─────────┐ ┌────────────┐
  │ Zeek 6.2 │ │ Snort 3 │ │ Suricata 7 │
  │ proto    │ │ sigs    │ │ EVE JSON   │
  │ JA3/HASSH│ │ MITRE   │ │ ET Open    │
  │ Intel    │ │ custom  │ │ MITRE      │
  └────┬─────┘ └────┬────┘ └─────┬──────┘
       └────────────┼────────────┘
                    ▼
          ┌──────────────────┐
          │  Filebeat 8.13   │
          │  collecte 3 logs │
          └────────┬─────────┘
                   ▼
          ┌──────────────────┐
          │ Elasticsearch    │    ◄── beacon-detect (netwatch-beacons-*)
          │  zeek-*          │    ◄── autoblock    (netwatch-autoblock-*)
          │  snort-*         │
          │  suricata-*      │
          └────────┬─────────┘
                   ▼
          ┌──────────────────┐        ┌────────────────┐
          │   Grafana 10.4   │        │   Prometheus   │
          │  11 dashboards   │◄───────│  node-exporter │
          │  alertes + webhook│        │  métriques VM  │
          └────────┬─────────┘        └────────────────┘
                   │ webhook
                   ▼
          ┌──────────────────┐
          │   autoblock      │
          │  iptables block  │
          │  DRY_RUN=true    │
          └──────────────────┘
```

---

## Quickstart

### Prérequis

- **VM Ubuntu 22.04 LTS** — recommandé : 6 vCPU, 8 Go RAM, 60 Go disque
- **Docker & Docker Compose v2**
- Hyperviseur : Proxmox VE (recommandé), VMware ESXi, ou VirtualBox

### 1. Préparer la VM

```bash
sudo apt update && sudo apt upgrade -y
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER
exit   # déconnexion nécessaire pour que le groupe docker prenne effet
```

Reconnectez-vous, puis :

```bash
docker --version
docker compose version
```

### 2. Cloner le dépôt

```bash
git clone https://github.com/Ourslow/netwatch.git
cd netwatch
```

### 3. Configurer l'environnement

```bash
# Copier le fichier d'exemple et l'éditer
cp .env.example .env
nano .env
```

Variables à renseigner dans `.env` :

```bash
# Interface réseau de capture (vérifier avec: ip a)
IFACE=ens18

# IP du serveur à surveiller (règles Snort custom)
SNORT_MONITORED_SERVER=192.168.1.10

# Mot de passe admin Grafana (ne pas laisser "changeme")
GRAFANA_ADMIN_PASSWORD=MonMotDePasse!

# Webhook Slack pour les alertes (optionnel)
SLACK_WEBHOOK_URL=

# AutoBlock — laisser DRY_RUN=true pour tester sans bloquer réellement
AUTOBLOCK_DRY_RUN=true
BLOCK_DURATION_MIN=60
AUTOBLOCK_ALLOWLIST=192.168.1.1,192.168.1.254
```

### 4. Fixer les permissions Filebeat

```bash
sudo chown root:root filebeat/filebeat.yml
sudo chmod 644 filebeat/filebeat.yml
```

### 5. Lancer le stack

```bash
docker compose up -d

# Vérifier les 10 conteneurs
docker compose ps
```

Les 10 conteneurs attendus :

| Conteneur | Démarrage |
|-----------|-----------|
| `netwatch-elasticsearch` | Healthy après ~30 secondes |
| `netwatch-filebeat` | — |
| `netwatch-zeek` | — |
| `netwatch-snort` | Build long ~10-15 min la première fois (compilation depuis les sources) |
| `netwatch-suricata` | Lance `suricata-update` au démarrage (télécharge les règles ET Open) |
| `netwatch-grafana` | — |
| `netwatch-prometheus` | — |
| `netwatch-node-exporter` | — |
| `netwatch-beacon-detect` | Analyse toutes les 15 minutes |
| `netwatch-autoblock` | Écoute le webhook Grafana sur :5001 |

### 6. Initialiser le pipeline GeoIP (optionnel)

```bash
# Crée le pipeline ingest ES + les index templates
bash setup-geoip.sh
```

### 7. Mettre à jour la threat intelligence Zeek

```bash
# Télécharge Feodo Tracker + URLhaus → formats Zeek Intel TSV
bash update-intel.sh
```

### 8. Vérifier le stack

```bash
# Elasticsearch
curl http://localhost:9200/_cluster/health?pretty

# Index créés (après capture ou simulation)
curl "http://localhost:9200/_cat/indices?v&s=index"
```

Grafana : `http://<IP_VM>:3000` — login `admin` / `<GRAFANA_ADMIN_PASSWORD>`
Les 11 dashboards sont auto-provisionnés, aucune manipulation nécessaire.

### 9. Rejouer un PCAP sur les 3 moteurs

```bash
# Copier un PCAP dans pcap/
cp /path/to/sample.pcap pcap/

# Replay sur Zeek, Snort et Suricata simultanément
./replay-pcap.sh pcap/sample.pcap

# Vérifier les données dans ES
sleep 20
curl "http://localhost:9200/_cat/indices?v&s=index"
```

### 10. Simuler du trafic (sans PCAP)

```bash
# 24h de trafic, intensité moyenne, avec scénarios d'attaque
python3 simulate-traffic.py --hours 24 --intensity medium --attack

# Vérifier les 3 index
curl 'http://localhost:9200/zeek-*/_count?pretty'
curl 'http://localhost:9200/snort-*/_count?pretty'
curl 'http://localhost:9200/suricata-*/_count?pretty'
```

---

## Structure du projet

```
netwatch/
├── docker-compose.yml              # Orchestration 10 services
├── .env.example                    # Template de configuration (copier en .env)
├── replay-pcap.sh                  # Replay PCAP sur les 3 moteurs
├── simulate-traffic.py             # Simulateur de trafic (injecte dans ES)
├── setup-geoip.sh                  # Initialise le pipeline GeoIP Elasticsearch
├── update-intel.sh                 # Met à jour les listes de menaces Zeek Intel
├── zeek/
│   ├── Dockerfile                  # Zeek 6.2 + JA3/HASSH (zkg) + Community ID
│   ├── local.zeek                  # Config Zeek (JSON, protocoles, scripts, Intel)
│   ├── scripts/
│   │   ├── port-scan-detect.zeek   # Détection scan de ports (entropie seuil)
│   │   └── dns-entropy.zeek        # Détection DGA par entropie de Shannon
│   └── intel/
│       ├── ip_watchlist.dat        # IPs malveillantes (Feodo Tracker)
│       └── domain_watchlist.dat    # Domaines malveillants (URLhaus)
├── snort/
│   ├── Dockerfile                  # Build Snort 3 depuis les sources + libdaq + tcmalloc
│   ├── snort.lua                   # Config Snort 3 (alert_json, SNORT_MONITORED_SERVER)
│   └── local.rules                 # Règles custom NETWATCH (SID 1000001-1000999) + MITRE
├── suricata/
│   ├── Dockerfile                  # jasonish/suricata:7.0 + entrypoint suricata-update
│   ├── entrypoint.sh               # Lance suricata-update puis recharge les règles quotidiennement
│   ├── suricata.yaml               # Config Suricata (EVE JSON, Community ID, threading)
│   └── local.rules                 # Règles custom NETWATCH (SID 2000001-2000999)
├── beacon-detect/
│   ├── Dockerfile                  # Python 3.12-slim
│   └── beacon_detect.py            # Détection RITA-lite : beaconing, longues connexions, DNS tunneling
├── autoblock/
│   ├── Dockerfile                  # Python 3.12-slim + iptables + iproute2
│   └── autoblock.py                # Webhook Flask → iptables (DRY_RUN=true par défaut)
├── filebeat/
│   └── filebeat.yml                # Collecte 3 sources → index zeek-*/snort-*/suricata-*
├── elasticsearch/
│   ├── elasticsearch.yml           # Config ES (single node, lab)
│   └── pipelines/
│       └── netwatch-geoip.json     # Pipeline ingest GeoIP
├── prometheus/
│   └── prometheus.yml              # Scrape node-exporter
└── grafana/
    ├── provisioning/
    │   ├── datasources/
    │   │   └── elasticsearch.yml   # 5 datasources (Zeek, Snort, Suricata, Beacons, AutoBlock, Prometheus)
    │   ├── dashboards/
    │   │   └── dashboards.yml
    │   └── alerting/
    │       ├── rules.yaml          # Règles d'alerte (CPU, RAM, Disk, spikes Suricata, anomalie volume)
    │       └── contact_points.yaml # Slack + AutoBlock webhook
    └── dashboards/
        ├── network-overview.json   # Vue générale réseau (Zeek)
        ├── dns-analysis.json       # Analyse DNS + DGA (Zeek)
        ├── http-tls-analysis.json  # HTTP/TLS + JA3/JA3S (Zeek)
        ├── security-alerts.json    # Alertes Zeek (port scans, DGA, Intel hits)
        ├── snort-alerts.json       # Alertes Snort 3 + MITRE ATT&CK
        ├── suricata-alerts.json    # Alertes Suricata 7 + MITRE ATT&CK
        ├── correlation.json        # Corrélation multi-moteurs
        ├── vm-health.json          # Santé VM (Prometheus : CPU, RAM, disque)
        ├── top-talkers.json        # Top IPs par volume, protocoles, ports
        ├── ja3-hassh.json          # Fingerprints TLS (JA3/JA3S) et SSH (HASSH)
        └── beacon-detect.json      # Détections comportementales RITA-lite
```

---

## Dashboards

| Dashboard | Datasource | Contenu |
|-----------|-----------|---------|
| Vue Réseau | Zeek-ES | Connexions, protocoles, top IPs, conn_state |
| Analyse DNS | Zeek-ES | Requêtes, NXDOMAIN, DGA, types, clients |
| HTTP / TLS | Zeek-ES | Méthodes, statuts, versions TLS, hôtes |
| Alertes Sécurité | Zeek-ES | Port scans, DGA, Intel hits, alertes SSL |
| **Alertes Snort 3** | Snort-ES | Signatures, priorités, classes, top sources, MITRE |
| **Alertes Suricata 7** | Suricata-ES | Signatures ET Open, sévérités, catégories, MITRE |
| **Corrélation Multi-Moteurs** | Mixed | Zeek + Snort + Suricata sur le même axe temporel |
| **Santé VM** | Prometheus | CPU, RAM, disque, charge système (node-exporter) |
| **Top Talkers** | Zeek-ES | Top IPs/ports par volume, protocoles, bytes transférés |
| **JA3 / HASSH** | Zeek-ES | Fingerprints TLS (JA3/JA3S) et SSH (HASSH) |
| **Beacon Detector** | Beacons-ES | Beaconing C2, longues connexions, DNS tunneling |

---

## Détection et alertes

### Scripts Zeek custom

| Script | Seuil par défaut | Description |
|--------|-----------------|-------------|
| `port-scan-detect.zeek` | > 50 ports / 60s | Détection reconnaissance réseau |
| `dns-entropy.zeek` | Entropie Shannon > 3.5 | Détection domaines DGA / C2 |

### Zeek Intel Framework

Zeek charge automatiquement deux listes de menaces mises à jour par `update-intel.sh` :

| Liste | Source | Contenu |
|-------|--------|---------|
| `ip_watchlist.dat` | Feodo Tracker | IPs de botnets (Emotet, QakBot, Dridex…) |
| `domain_watchlist.dat` | URLhaus | Domaines distribuant des malwares |

Les hits apparaissent dans `intel.log` et génèrent des notices Zeek visibles dans le dashboard Alertes Sécurité.

### Règles Snort 3 custom (SID 1000001–1000999)

| SID | Description | MITRE |
|-----|-------------|-------|
| 1000001 | ICMP Ping Sweep (10 pings / 60s) | T1595 |
| 1000002 | SSH Brute Force (5 tentatives / 60s) | T1110 |
| 1000003–06 | DNS vers TLD suspects (.xyz, .info, .top, .biz) | T1568 |
| 1000007 | Credentials en clair sur HTTP POST | T1552 |
| 1000008 | Exfiltration potentielle (gros upload) | T1048 |
| 1000009 | Connexion vers port non standard | T1571 |
| 1000010 | User-Agent curl suspect | T1059 |
| 1000011 | ICMP Reply volume (flood) | T1498 |
| 1000012 | SYN Flood HTTP (DoS) | T1498 |
| 1000013–14 | Accès serveur surveillé — HTTP/HTTPS | T1190 |
| 1000015–16 | Accès serveur surveillé — SSH/FTP | T1021 |
| 1000017 | Scan de ports vers serveur surveillé | T1046 |

### Règles Suricata custom (SID 2000001–2000999)

| SID | Description |
|-----|-------------|
| 2000001 | ICMP Ping Sweep |
| 2000002 | SSH Brute Force |
| 2000003 | DNS Tunneling (requête longue) |
| 2000004–05 | TLS obsolète (TLSv1.0, TLSv1.1) |
| 2000006 | Mot de passe en clair HTTP |
| 2000007 | Transfert sortant massif |

### Détection comportementale — RITA-lite (beacon-detect)

Le service `beacon-detect` tourne toutes les 15 minutes et analyse les logs Zeek pour détecter trois catégories de comportements suspects :

| Détection | Logique | Indicateur |
|-----------|---------|------------|
| **Beaconing C2** | Coefficient de variation des intervalles < 0.25 (connexions trop régulières) | `beacon_score` 0-1 |
| **Longues connexions** | Connexion ouverte > 1h (reverse shell, tunnel SSH, exfiltration lente) | `duration_h` |
| **DNS Tunneling** | Sous-domaine > 40 chars OU > 100 requêtes vers le même domaine | `subdomain_length`, `query_count` |

Les résultats sont écrits dans l'index `netwatch-beacons-YYYY.MM.DD` et visualisés dans le dashboard **Beacon Detector**.

### Réponse automatique — AutoBlock

Le service `autoblock` expose un webhook Flask sur le port 5001. Grafana lui envoie les alertes critiques et autoblock applique un blocage iptables temporaire.

```
Grafana Alert → POST /webhook/alert → autoblock → iptables -I INPUT -s {ip} -j DROP
```

| Paramètre | Défaut | Description |
|-----------|--------|-------------|
| `AUTOBLOCK_DRY_RUN` | `true` | Simule sans appliquer iptables — à passer en `false` après validation |
| `BLOCK_DURATION_MIN` | `60` | Durée du blocage en minutes (expiration automatique) |
| `MAX_BLOCKS_PER_HOUR` | `20` | Limite de taux pour éviter les blocages en masse |
| `AUTOBLOCK_ALLOWLIST` | `192.168.1.1,192.168.1.254` | IPs jamais bloquées (gateway, DNS, serveurs critiques) |

> **Important :** ne passer `DRY_RUN=false` qu'après avoir validé le comportement en mode simulation. Un faux positif en production peut couper un serveur critique.

---

## Stack technique

| Composant | Outil | Version | Rôle |
|-----------|-------|---------|------|
| Analyse protocolaire | Zeek | 6.2 | Logs JSON, JA3/HASSH, Intel Framework, scripts custom |
| IDS signatures | Snort | 3.3.5 | Règles community + NETWATCH + MITRE, alert_json |
| IDS/IPS | Suricata | 7.0 | Règles ET Open (auto-update) + NETWATCH, EVE JSON |
| Détection comportementale | beacon-detect (Python) | — | RITA-lite : beaconing, longues connexions, DNS tunneling |
| Réponse automatique | autoblock (Flask) | — | Webhook Grafana → iptables (DRY_RUN=true par défaut) |
| Transport | Filebeat | 8.13 | Collecte unifiée → 3 index ES |
| Indexation | Elasticsearch | 8.13 | Stockage, index zeek-*/snort-*/suricata-*/beacons-* |
| Visualisation | Grafana | 10.4 | 11 dashboards, alertes, 5 datasources auto-provisionnées |
| Métriques système | Prometheus + node-exporter | 2.51 / 1.7 | CPU, RAM, disque, charge VM |
| Orchestration | Docker Compose | v2 | 10 services |
| OS cible | Ubuntu | 22.04 LTS | VM sur Proxmox VE |

---

## Proxmox VE vs VMware ESXi — Comparatif pour un lab réseau

> **Contexte :** choisir un hyperviseur pour héberger NetWatch et des outils réseau / sécurité sur un serveur physique (Shuttle, mini-PC, rack 1U).

| Critère | **Proxmox VE** | **VMware ESXi (free)** |
|---------|---------------|----------------------|
| **Licence** | Open-source (AGPL), gratuit | Gratuit mais bridé — la version free a perdu la plupart des fonctionnalités en 2024 après le rachat par Broadcom |
| **Interface** | Web UI intégrée (Proxmox) | Web UI + vSphere Client (plus lourd) |
| **vSwitch promiscuous** | Activable en 2 clics dans l'UI | Possible mais nécessite SSH + commandes `esxcli` |
| **API** | API REST native complète (`pvesh`) | API REST limitée en version gratuite |
| **Snapshots** | Oui (LVM, ZFS, QEMU) — gratuit | Oui, mais requiert datastore compatible |
| **Clustering** | Proxmox Cluster (HA, migration live) — gratuit | vMotion / HA → réservé à vSphere payant |
| **NIC passthrough (PCI)** | Oui, natif | Oui, mais complexe à configurer |
| **Stockage** | ZFS natif, LVM, Ceph, NFS, iSCSI | VMFS, NFS, iSCSI — ZFS absent |
| **Containers LXC** | Oui (en plus des VMs) | Non |
| **Communauté FR** | Très active (forum, wiki détaillé) | Bonne mais surtout anglophone |
| **Mises à jour** | Dépôt Debian stable, prévisible | Cycle de releases Broadcom, moins prévisible |
| **Backup intégré** | `vzdump` natif, Proxmox Backup Server | Nécessite veeam ou solution tierce |
| **Usage pour NetWatch** | Recommandé — vSwitch promiscuous simple, API pour le portail v3 | Fonctionne, mais plus de friction pour la capture réseau |

**Verdict pour ce projet :** Proxmox est le meilleur choix pour un lab réseau. Le vSwitch en mode promiscuous est trivial à configurer (case à cocher dans l'UI), l'API REST permettra d'automatiser la création de VMs depuis le portail web prévu en v3, et ZFS apporte de la résilience sans surcoût.

ESXi reste pertinent si le matériel est déjà en production sur VMware ou si l'objectif est d'apprendre l'environnement Broadcom/VMware (compétence très demandée chez les clients Axians).

---

## Parallèle avec les outils commerciaux

| Fonctionnalité | NetWatch v2 (open-source) | Outils commerciaux |
|----------------|--------------------------|---------------------|
| Capture trafic | Zeek (analyse proto) + SPAN | InfiniStream / nGenius Probe, Corelight |
| IDS signatures | Snort 3 + Suricata 7 (ET Open) | Suricata OEM, Snort Enterprise |
| Fingerprinting TLS/SSH | JA3 / HASSH / JA3S (Zeek) | DPI natif (ExtraHop, Corelight) |
| Détection comportementale | RITA-lite (beacon-detect) | Darktrace AI, ExtraHop Reveal(x) |
| Réponse automatique | AutoBlock webhook → iptables | Cisco Stealthwatch + NAC, Palo Alto XSOAR |
| MITRE ATT&CK | Suricata EVE JSON + Snort metadata | Darktrace, Vectra AI |
| Threat Intel | Zeek Intel Framework (Feodo + URLhaus) | Anomali, ThreatConnect, MISP |
| Corrélation multi-sources | Dashboard multi-moteurs | nGeniusONE Service Triage |
| Visibilité réseau | Grafana 11 dashboards | nGeniusONE portail |
| Alertes | Grafana alerting → Slack / webhook | Service Triage + SIEM |
| Stockage | Elasticsearch | nGenius Collector, Splunk |
| Métriques système | Prometheus + node-exporter | Datadog, Zabbix |
| Transport | Filebeat | Gigamon / TAP, Corelight Sensor |

---

## Troubleshooting

### Les capteurs redémarrent en boucle

Interface réseau incorrecte. Vérifier dans `.env` :

```bash
# Lister les interfaces disponibles
ip link show

# Corriger dans .env
IFACE=ens18

docker compose up -d zeek snort suricata
```

### Le build Snort échoue

Snort 3 compile depuis les sources — connexion internet requise. En cas d'erreur réseau :

```bash
docker compose build snort --no-cache
```

### Filebeat ne démarre pas

```
error loading config file: config file must be owned by root
```

```bash
sudo chown root:root filebeat/filebeat.yml && sudo chmod 644 filebeat/filebeat.yml
docker compose restart filebeat
```

### Les dashboards affichent "No data"

1. Vérifier la plage horaire dans Grafana ("Last 6 hours" ou "Last 24 hours")
2. Vérifier les index ES :
```bash
curl "http://localhost:9200/_cat/indices?v&s=index"
# Attendu : zeek-*, snort-*, suricata-*, netwatch-beacons-*
```
3. Si les index sont vides, lancer la simulation :
```bash
python3 simulate-traffic.py --hours 6 --intensity medium --attack
```

### Filebeat n'ingère pas les nouveaux logs (après replay PCAP)

```bash
docker compose rm -sf filebeat
docker compose up -d filebeat
```

### Suricata ne démarre pas (af-packet / tpacket-v3)

Si Suricata logue une erreur liée à af-packet, tenter en mode pcap :

```bash
# Dans docker-compose.yml, ajouter à la CMD suricata :
# ... -i ${IFACE:-eth0} --pcap
```

### AutoBlock ne bloque rien (DRY_RUN)

C'est le comportement attendu par défaut. Pour activer les vrais blocages iptables :

```bash
# Dans .env
AUTOBLOCK_DRY_RUN=false

docker compose up -d autoblock
```

> **Attention :** tester d'abord en DRY_RUN. Un faux positif peut bloquer votre propre accès SSH.

### Le beacon-detect ne détecte rien

Le service a besoin d'au moins 8 connexions entre une même paire src/dst (paramètre `MIN_CONNECTIONS`). Lancer la simulation avec l'option `--attack` pour générer du trafic C2 synthétique.

---

## Commandes utiles

```bash
# Lancer le stack complet
docker compose up -d

# Vérifier les 10 conteneurs
docker compose ps

# Logs d'un service
docker compose logs -f beacon-detect
docker compose logs -f autoblock

# Rebuild un service
docker compose build snort --no-cache
docker compose up -d snort

# Replay PCAP sur les 3 moteurs
./replay-pcap.sh pcap/sample.pcap

# Mise à jour threat intel Zeek
bash update-intel.sh

# Simuler du trafic (24h, intensité moyenne, avec attaques)
python3 simulate-traffic.py --hours 24 --intensity medium --attack

# Vérifier les index ES
curl "http://localhost:9200/_cat/indices?v&s=index"

# Voir les détections beacon
curl "http://localhost:9200/netwatch-beacons-*/_search?pretty&size=5"

# Voir les blocages autoblock
curl "http://localhost:9200/netwatch-autoblock-*/_search?pretty&size=5"
```

---

## Auteur

**Nicolas Malok** — Alternant Cybersécurité @ Axians / Vinci Energies — École 2600

Projet réalisé dans le cadre de la SideQuest MVP (S2 2025-2026).

---

## Licence

[GNU Affero General Public License v3.0](LICENSE) — voir [LICENSE](LICENSE)

Toute modification déployée en production (y compris en SaaS) doit être rendue publique sous la même licence. Conçu pour rester ouvert.
