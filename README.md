# 🛡️ NetWatch — Mini-NPM Open-Source

> Stack d'observabilité réseau open-source : **Zeek + Elasticsearch + Grafana**
> Analyse de trafic en temps réel, dashboards interactifs et alertes de sécurité.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED.svg)](docker-compose.yml)
[![Zeek](https://img.shields.io/badge/Zeek-6.2-orange.svg)](https://zeek.org)
[![Grafana](https://img.shields.io/badge/Grafana-10.4-F46800.svg)](https://grafana.com)

---

## 📋 Présentation

**NetWatch** est un stack d'observabilité réseau qui reproduit les fonctionnalités clés d'un outil commercial de Network Performance Monitoring (type Netscout nGeniusONE) à l'aide de briques 100% open-source.

| Fonctionnalité | NetWatch (open-source) | Netscout nGeniusONE |
|----------------|----------------------|---------------------|
| Capture trafic | Zeek (analyse proto) | InfiniStream / nGenius |
| Visibilité réseau | Grafana dashboards | nGeniusONE dashboards |
| Alertes | Grafana alerts | Service Triage |
| Stockage | Elasticsearch | nGenius Collector |
| Agrégation | Filebeat | Gigamon / TAP |

> 🎓 Projet réalisé dans le cadre de la **SideQuest** — École 2600

---

## 🏗️ Architecture

```
┌─────────────────────────────┐
│   Trafic Réseau / PCAP      │
└──────────────┬──────────────┘
               ▼
┌─────────────────────────────┐
│   Zeek                      │
│   Analyse protocolaire      │
│   → conn.log, dns.log,      │
│     http.log, ssl.log,      │
│     notice.log              │
└──────────────┬──────────────┘
               ▼
┌─────────────────────────────┐
│   Filebeat                  │
│   Collecte & transport      │
└──────────────┬──────────────┘
               ▼
┌─────────────────────────────┐
│   Elasticsearch             │
│   Indexation & stockage     │
└──────────────┬──────────────┘
               ▼
┌─────────────────────────────┐
│   Grafana                   │
│   Dashboards & Alertes      │
└─────────────────────────────┘
```

---

## ⚡ Quickstart

### Prérequis

- Docker & Docker Compose v2
- VM Ubuntu 22.04 LTS (4 vCPU, 8 Go RAM, 40 Go disque)
- Fichiers PCAP pour les tests (voir [Données de test](#-données-de-test))

### Installation

```bash
# 1. Cloner le repo
git clone https://github.com/Ourslow/netwatch.git
cd netwatch

# 2. Lancer le stack
docker-compose up -d

# 3. Vérifier que tout tourne
docker-compose ps

# 4. Accéder à Grafana
# → http://localhost:3000  (admin / admin)
```

### Replay d'un fichier PCAP

```bash
# Copier un PCAP dans le dossier pcap/
cp /path/to/sample.pcap ./pcap/

# Le rejouer dans Zeek
docker exec -it netwatch-zeek zeek -r /pcap/sample.pcap local

# Les logs sont automatiquement envoyés à Elasticsearch via Filebeat
```

---

## 📁 Structure du projet

```
netwatch/
├── docker-compose.yml
├── zeek/
│   ├── Dockerfile
│   ├── local.zeek
│   └── scripts/
│       ├── port-scan-detect.zeek
│       └── dns-entropy.zeek
├── filebeat/
│   └── filebeat.yml
├── elasticsearch/
│   └── elasticsearch.yml
├── grafana/
│   ├── provisioning/
│   │   ├── datasources/elasticsearch.yml
│   │   └── dashboards/dashboards.yml
│   └── dashboards/
│       ├── network-overview.json
│       ├── dns-analysis.json
│       ├── http-tls-analysis.json
│       └── security-alerts.json
├── pcap/                   # Fichiers PCAP de test (non versionnés)
├── docs/
│   ├── architecture.md
│   ├── replay-pcap.md
│   └── alerts.md
└── README.md
```

---

## 📊 Dashboards

| # | Dashboard | Métriques |
|---|-----------|-----------|
| 1 | **Vue générale réseau** | Connexions actives TCP/UDP, top talkers, répartition protocoles |
| 2 | **Analyse DNS** | Top domaines, détection DGA (entropie), temps de réponse |
| 3 | **Analyse HTTP/TLS** | URLs, codes réponse, certificats, trafic non chiffré |
| 4 | **Alertes sécurité** | Scans de ports, IP malveillantes, anomalies volume |

---

## 🔔 Alertes

| Alerte | Seuil | Description |
|--------|-------|-------------|
| Port scan | >50 ports/min / IP | Détection de reconnaissance réseau |
| Pic de trafic | >3x la moyenne / 5 min | Exfiltration potentielle ou DDoS |
| DNS suspect | Entropie domaine >3.5 | Communication C2 (DGA) |
| Cert TLS expiré | Expiration <7 jours | Certificat à renouveler |

Voir [`docs/alerts.md`](docs/alerts.md) pour les scénarios de test.

---

## 🧪 Données de test

- [Malware Traffic Analysis](https://www.malware-traffic-analysis.net/)
- [Wireshark Sample Captures](https://wiki.wireshark.org/SampleCaptures)
- [NETRESEC](https://www.netresec.com/?page=PcapFiles)
- Captures CTF : Root-Me, CyberDefenders

---

## 📝 Auteur

**Nicolas Malok** — Alternant Cybersécurité @ Axians / Vinci Energies — École 2600

---

## 📄 License

MIT — voir [LICENSE](LICENSE)
