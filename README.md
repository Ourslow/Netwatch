# NetWatch v2 — Stack NPM Open-Source Multi-Moteurs

> Observabilité réseau avec **Zeek + Snort 3 + Suricata 7 + Elasticsearch + Grafana**
> Trois moteurs d'analyse en parallèle sur le même trafic, pipeline unifié, 7 dashboards.

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED.svg)](docker-compose.yml)
[![Zeek](https://img.shields.io/badge/Zeek-6.2-orange.svg)](https://zeek.org)
[![Snort](https://img.shields.io/badge/Snort-3.3.5-red.svg)](https://snort.org)
[![Suricata](https://img.shields.io/badge/Suricata-7.0-blue.svg)](https://suricata.io)
[![Elasticsearch](https://img.shields.io/badge/Elasticsearch-8.13-005571.svg)](https://www.elastic.co)
[![Grafana](https://img.shields.io/badge/Grafana-10.4-F46800.svg)](https://grafana.com)

---

## Présentation

**NetWatch** est un stack d'observabilité réseau open-source qui reproduit les fonctionnalités clés d'un outil commercial de type NPM (Netscout nGeniusONE, Riverbed) avec des briques 100% libres.

La v2 passe de 1 à 3 moteurs d'analyse en parallèle sur le même trafic :

| Moteur | Rôle | Format de sortie |
|--------|------|-----------------|
| **Zeek 6.2** | Analyse protocolaire, logs JSON, fingerprinting JA3/HASSH | conn/dns/http/ssl/notice.log |
| **Snort 3.3.5** | IDS par signatures, règles community + custom NETWATCH | alert_json.txt |
| **Suricata 7** | IDS/IPS, règles ET Open + custom NETWATCH, Community ID | EVE JSON (eve.json) |

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
  │ JA3/HASSH│ │community│ │ ET Open    │
  └────┬─────┘ └────┬────┘ └─────┬──────┘
       └────────────┼────────────┘
                    ▼
          ┌──────────────────┐
          │  Filebeat 8.13   │
          │  collecte 3 logs │
          └────────┬─────────┘
                   ▼
          ┌──────────────────┐
          │ Elasticsearch    │
          │  zeek-*          │
          │  snort-*         │
          │  suricata-*      │
          └────────┬─────────┘
                   ▼
          ┌──────────────────┐
          │   Grafana 10.4   │
          │  7 dashboards    │
          │  3 datasources   │
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

### 2. Cloner et configurer l'interface réseau

```bash
git clone https://github.com/Ourslow/netwatch.git
cd netwatch

# Identifier l'interface réseau de capture
ip link show
# Sur Ubuntu 22.04 / Proxmox : souvent ens18, enp6s18, eth0...
```

Éditer `docker-compose.yml` et changer `IFACE=eth0` en `IFACE=<votre_interface>` pour les 3 services `zeek`, `snort`, `suricata`.

```bash
# Exemple pour ens18
sed -i 's/IFACE=eth0/IFACE=ens18/g' docker-compose.yml
```

### 3. Fixer les permissions Filebeat

```bash
sudo chown root:root filebeat/filebeat.yml
sudo chmod 644 filebeat/filebeat.yml
```

### 4. Lancer le stack

```bash
docker compose up -d

# Vérifier les 6 conteneurs
docker compose ps
```

Les 6 conteneurs attendus :
- `netwatch-elasticsearch` — Healthy après ~30 secondes
- `netwatch-filebeat`
- `netwatch-zeek`
- `netwatch-snort` (build long ~10-15 min la première fois — compilation depuis les sources)
- `netwatch-suricata`
- `netwatch-grafana`

### 5. Vérifier le stack

```bash
# Elasticsearch
curl http://localhost:9200/_cluster/health?pretty

# Index créés (après capture ou simulation)
curl "http://localhost:9200/_cat/indices?v&s=index"
```

Grafana : `http://<IP_VM>:3000` — login `admin` / `admin`
Les 7 dashboards sont auto-provisionnés, aucune manipulation nécessaire.

### 6. Rejouer un PCAP sur les 3 moteurs

```bash
# Copier un PCAP dans pcap/
cp /path/to/sample.pcap pcap/

# Replay sur Zeek, Snort et Suricata simultanément
./replay-pcap.sh pcap/sample.pcap

# Vérifier les données dans ES
sleep 20
curl "http://localhost:9200/_cat/indices?v&s=index"
```

### 7. Simuler du trafic (sans PCAP)

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
├── docker-compose.yml              # Orchestration 6 services
├── replay-pcap.sh                  # Replay PCAP sur les 3 moteurs
├── simulate-traffic.py             # Simulateur de trafic (Zeek + Snort + Suricata)
├── zeek/
│   ├── Dockerfile                  # Zeek 6.2 + JA3/HASSH (zkg)
│   ├── local.zeek                  # Config Zeek (JSON, protocoles, scripts)
│   └── scripts/
│       ├── port-scan-detect.zeek   # Détection scan de ports (entropie seuil)
│       └── dns-entropy.zeek        # Détection DGA par entropie de Shannon
├── snort/
│   ├── Dockerfile                  # Build Snort 3 depuis les sources + libdaq + tcmalloc
│   ├── snort.lua                   # Config Snort 3 (alert_json, règles, inspectors)
│   └── local.rules                 # Règles custom NETWATCH (SID 1000001-1000999)
├── suricata/
│   ├── Dockerfile                  # jasonish/suricata:7.0 + règles ET Open
│   ├── suricata.yaml               # Config Suricata (EVE JSON, Community ID, af-packet)
│   └── local.rules                 # Règles custom NETWATCH (SID 2000001-2000999)
├── filebeat/
│   └── filebeat.yml                # Collecte 3 sources → index zeek-*/snort-*/suricata-*
├── elasticsearch/
│   └── elasticsearch.yml           # Config ES (single node, lab, no security)
├── grafana/
│   ├── provisioning/
│   │   ├── datasources/elasticsearch.yml  # 3 datasources auto-provisionnées
│   │   └── dashboards/dashboards.yml
│   └── dashboards/
│       ├── network-overview.json   # Vue générale réseau (Zeek)
│       ├── dns-analysis.json       # Analyse DNS (Zeek)
│       ├── http-tls-analysis.json  # Analyse HTTP/TLS (Zeek)
│       ├── security-alerts.json    # Alertes sécurité Zeek
│       ├── snort-alerts.json       # Alertes Snort 3  [v2]
│       ├── suricata-alerts.json    # Alertes Suricata 7  [v2]
│       └── correlation.json        # Corrélation multi-moteurs  [v2]
├── pcap/                           # Fichiers PCAP (non versionnés)
└── docs/
    ├── architecture.md             # Architecture détaillée v2
    ├── replay-pcap.md              # Guide replay PCAP
    └── alerts.md                   # Scénarios de test
```

---

## Dashboards

| Dashboard | Datasource | Contenu |
|-----------|-----------|---------|
| Vue Réseau | Zeek-ES | Connexions, protocoles, top IPs, conn_state |
| Analyse DNS | Zeek-ES | Requêtes, NXDOMAIN, DGA, types, clients |
| HTTP / TLS | Zeek-ES | Méthodes, statuts, versions TLS, hôtes |
| Alertes Sécurité | Zeek-ES | Port scans, DGA, alertes SSL (scripts custom) |
| **Alertes Snort 3** | Snort-ES | Signatures, priorités, classes, top sources |
| **Alertes Suricata 7** | Suricata-ES | Signatures ET Open, sévérités, catégories |
| **Corrélation Multi-Moteurs** | Mixed | Zeek + Snort + Suricata sur le même axe temporel |

---

## Alertes et détection

### Scripts Zeek custom

| Script | Seuil par défaut | Description |
|--------|-----------------|-------------|
| `port-scan-detect.zeek` | > 50 ports / 60s | Détection reconnaissance réseau |
| `dns-entropy.zeek` | Entropie Shannon > 3.5 | Détection domaines DGA / C2 |

### Règles Snort 3 custom (SID 1000001–1000999)

| SID | Description |
|-----|-------------|
| 1000001 | ICMP Ping Sweep (10 pings / 60s) |
| 1000002 | SSH Brute Force (5 tentatives / 60s) |
| 1000003-06 | DNS vers TLD suspects (.xyz, .info, .top, .biz) |
| 1000007 | Credentials en clair sur HTTP POST |
| 1000008 | Exfiltration potentielle (gros upload) |
| 1000009 | Connexion vers port non standard |
| 1000010 | User-Agent curl suspect |

### Règles Suricata custom (SID 2000001–2000999)

| SID | Description |
|-----|-------------|
| 2000001 | ICMP Ping Sweep |
| 2000002 | SSH Brute Force |
| 2000003 | DNS Tunneling (requête longue) |
| 2000004-05 | TLS obsolète (TLSv1.0, TLSv1.1) |
| 2000006 | Mot de passe en clair HTTP |
| 2000007 | Transfert sortant massif |

---

## Stack technique

| Composant | Outil | Version | Rôle |
|-----------|-------|---------|------|
| Analyse proto | Zeek | 6.2 | Logs JSON, JA3/HASSH, scripts custom |
| IDS signatures | Snort | 3.3.5 | Règles community + NETWATCH, alert_json |
| IDS/IPS | Suricata | 7.0 | Règles ET Open + NETWATCH, EVE JSON |
| Transport | Filebeat | 8.13 | Collecte unifiée → 3 index ES |
| Indexation | Elasticsearch | 8.13 | Stockage, index zeek-*/snort-*/suricata-* |
| Visualisation | Grafana | 10.4 | 7 dashboards, 3 datasources auto-provisionnées |
| Orchestration | Docker Compose | v2 | 6 services |
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

| Fonctionnalité | NetWatch v2 (open-source) | Netscout nGeniusONE |
|----------------|--------------------------|---------------------|
| Capture trafic | Zeek (analyse proto) + SPAN | InfiniStream / nGenius Probe |
| IDS signatures | Snort 3 + Suricata 7 | Intégré (modules additionnels) |
| Fingerprinting | JA3 / HASSH (Zeek) | nGenius DPI |
| Corrélation | Dashboard multi-moteurs | Service Triage + corrélation native |
| Visibilité réseau | Grafana 7 dashboards | nGeniusONE portail |
| Alertes | Zeek Notices + règles IDS + Grafana | Service Triage |
| Stockage | Elasticsearch | nGenius Collector |
| Transport | Filebeat | Gigamon / TAP |

---

## Troubleshooting

### Les 3 capteurs redémarrent en boucle

Interface réseau incorrecte. Vérifier avec `ip link show` et corriger dans `docker-compose.yml` :
```bash
# Adapter IFACE à votre interface réelle
sed -i 's/IFACE=eth0/IFACE=ens18/g' docker-compose.yml
docker compose up -d zeek snort suricata
```

### Le build Snort échoue

Snort 3 compile depuis les sources — il faut une connexion internet pour télécharger libdaq, gperftools et les règles community. En cas d'erreur réseau pendant le build :
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

1. Vérifier la plage horaire dans Grafana (mettre "Last 6 hours" ou "Last 24 hours")
2. Vérifier les index ES :
```bash
curl "http://localhost:9200/_cat/indices?v&s=index"
# Vous devez voir zeek-*, snort-*, suricata-*
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

---

## Auteur

**Nicolas Malok** — Alternant Cybersécurité @ Axians / Vinci Energies — École 2600

Projet réalisé dans le cadre de la SideQuest MVP (S2 2025-2026).

---

## License

MIT License — voir [LICENSE](LICENSE)
