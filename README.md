# 🛡️ NetWatch — Mini-NPM Open-Source

> Stack d'observabilité réseau open-source : **Zeek + Elasticsearch + Grafana**
> Analyse de trafic en temps réel, dashboards interactifs et alertes de sécurité.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED.svg)](docker-compose.yml)
[![Zeek](https://img.shields.io/badge/Zeek-6.2-orange.svg)](https://zeek.org)
[![Elasticsearch](https://img.shields.io/badge/Elasticsearch-8.13-005571.svg)](https://www.elastic.co)
[![Grafana](https://img.shields.io/badge/Grafana-10.4-F46800.svg)](https://grafana.com)

---

## 📋 Présentation

**NetWatch** est un stack d'observabilité réseau qui reproduit les fonctionnalités clés d'un outil commercial de Network Performance Monitoring (type Netscout nGeniusONE) à l'aide de briques 100% open-source.

Le stack repose sur trois piliers :

- **Zeek** (ex-Bro) — Analyse protocolaire du trafic réseau, génération de logs structurés JSON (conn.log, dns.log, http.log, ssl.log, notice.log)
- **Elasticsearch** — Indexation, stockage et recherche des données réseau
- **Grafana** — Dashboards interactifs et système d'alertes

Le pipeline inclut deux scripts de détection custom : scan de ports (seuil configurable) et détection de domaines DGA par entropie de Shannon.

> 🎓 Projet réalisé dans le cadre de la **SideQuest MVP** — École 2600
> 
> **Nicolas Malok** — Alternant Cybersécurité @ Axians / Vinci Energies

---

## 🏗️ Architecture

```
┌─────────────────────────────┐
│   Trafic Réseau / PCAP      │
└──────────────┬──────────────┘
               ▼
┌─────────────────────────────┐
│   Zeek 6.2                  │
│   Analyse protocolaire      │
│   → conn.log, dns.log,      │
│     http.log, ssl.log,      │
│     files.log, notice.log   │
│   + JA3 / HASSH fingerprint │
└──────────────┬──────────────┘
               ▼
┌─────────────────────────────┐
│   Filebeat 8.13             │
│   Collecte & transport      │
│   (JSON parsing natif)      │
└──────────────┬──────────────┘
               ▼
┌─────────────────────────────┐
│   Elasticsearch 8.13        │
│   Index : zeek-*            │
│   Single node, no security  │
└──────────────┬──────────────┘
               ▼
┌─────────────────────────────┐
│   Grafana 10.4              │
│   4 dashboards + alertes    │
│   Datasource auto-provisio. │
└─────────────────────────────┘
```

---

## ⚡ Quickstart

### Prérequis

- **VM** Ubuntu 22.04 LTS (recommandé : 4 vCPU, 8 Go RAM, 40 Go disque)
- **Docker & Docker Compose v2** (installé dans la procédure ci-dessous)
- Hyperviseur : VMware ESXi, VirtualBox, ou VMware Workstation
- Fichiers PCAP pour les tests (voir section [Données de test](#-données-de-test))

### 1. Préparer la VM

```bash
# Mise à jour
sudo apt update && sudo apt upgrade -y

# Installer Docker
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER

# IMPORTANT : déconnectez-vous et reconnectez-vous pour que le groupe docker prenne effet
exit
```

Reconnectez-vous en SSH, puis vérifiez :
```bash
docker --version
docker compose version
```

### 2. Configurer le DNS Docker (optionnel, si problème de résolution)

Si les images Docker ne se téléchargent pas (erreur `no such host`), configurez les DNS Google :
```bash
sudo mkdir -p /etc/docker
echo '{"dns": ["8.8.8.8", "8.8.4.4"]}' | sudo tee /etc/docker/daemon.json
sudo systemctl restart docker
```

### 3. Cloner et lancer le stack

```bash
git clone https://github.com/Ourslow/netwatch.git
cd netwatch

# Fixer les permissions Filebeat (obligatoire)
sudo chown root:root filebeat/filebeat.yml
sudo chmod 644 filebeat/filebeat.yml

# Lancer le stack
docker compose up -d

# Vérifier que tout tourne
docker compose ps
```

Vous devez voir 4 conteneurs : `netwatch-elasticsearch` (Healthy), `netwatch-filebeat`, `netwatch-grafana`, et `netwatch-zeek`.

> **Note :** Le conteneur Zeek peut redémarrer en boucle si l'interface `eth0` n'est pas disponible. C'est normal — Zeek est principalement utilisé en mode replay PCAP (voir ci-dessous).

### 4. Vérifier le stack

```bash
# Elasticsearch répond ?
curl http://localhost:9200/_cluster/health?pretty

# Grafana accessible ?
# → http://<IP_DE_LA_VM>:3000
# Login : admin / admin
```

### 5. Rejouer un fichier PCAP

```bash
# Capturer du trafic réseau (200 paquets)
sudo tcpdump -c 200 -w pcap/sample.pcap

# OU utiliser un PCAP existant (copier dans le dossier pcap/)

# Rejouer dans Zeek (génère les logs dans le volume partagé)
docker compose run --rm --entrypoint "" zeek bash -c \
  "mkdir -p /zeek/logs/current && cd /zeek/logs/current && \
   zeek -C -r /pcap/sample.pcap /usr/local/zeek/share/zeek/site/local.zeek"

# Relancer Filebeat pour ingérer les logs
docker compose restart filebeat

# Vérifier que les données arrivent dans Elasticsearch (~20 secondes)
sleep 20
curl "http://localhost:9200/zeek-*/_count?pretty"
```

Si le `count` est supérieur à 0, le pipeline fonctionne de bout en bout.

### 6. Importer les dashboards Grafana

Les 4 fichiers JSON sont dans `grafana/dashboards/`. Pour les importer :

1. Ouvrir Grafana : `http://<IP_DE_LA_VM>:3000`
2. Menu gauche → **Dashboards** → **New** → **Import**
3. Cliquer **"Upload dashboard JSON file"**
4. Importer chaque fichier depuis `grafana/dashboards/`
5. Si un conflit d'UID apparaît, cliquer **"Change uid"** puis **Import**

---

## 📁 Structure du projet

```
netwatch/
├── docker-compose.yml              # Orchestration du stack complet
├── zeek/
│   ├── Dockerfile                  # Image Zeek 6.2 + JA3/HASSH (zkg)
│   ├── local.zeek                  # Config Zeek (JSON, protocoles, scripts)
│   └── scripts/
│       ├── port-scan-detect.zeek   # Détection scan de ports (seuil configurable)
│       └── dns-entropy.zeek        # Détection DGA par entropie de Shannon
├── filebeat/
│   └── filebeat.yml                # Config Filebeat → Elasticsearch
├── elasticsearch/
│   └── elasticsearch.yml           # Config ES (single node, lab)
├── grafana/
│   ├── provisioning/
│   │   ├── datasources/elasticsearch.yml  # Datasource Zeek-ES auto-provisionnée
│   │   └── dashboards/dashboards.yml      # Provider de dashboards
│   └── dashboards/
│       ├── network-overview.json   # Dashboard 1 — Vue générale réseau
│       ├── dns-analysis.json       # Dashboard 2 — Analyse DNS
│       ├── http-tls-analysis.json  # Dashboard 3 — Analyse HTTP/TLS
│       └── security-alerts.json    # Dashboard 4 — Alertes sécurité
├── pcap/                           # Fichiers PCAP de test (non versionnés)
├── docs/
│   ├── architecture.md             # Schéma détaillé du pipeline
│   ├── replay-pcap.md              # Guide de replay PCAP
│   └── alerts.md                   # Scénarios de test des alertes
├── LICENSE                         # MIT License
└── README.md
```

---

## 📊 Dashboards

### 1. Vue générale réseau
Connexions totales, volume de trafic entrant/sortant (bytes), protocoles uniques, connexions dans le temps, top 10 IP sources et destinations, répartition par protocole et état de connexion, top ports destination, tableau des dernières connexions.

### 2. Analyse DNS
Requêtes DNS totales, domaines uniques, réponses NXDOMAIN, alertes DGA, requêtes dans le temps, top 20 domaines, répartition par type de requête (A, AAAA, MX…), codes réponse DNS, top serveurs DNS, clients DNS les plus actifs.

### 3. Analyse HTTP/TLS
Requêtes HTTP totales, connexions TLS, hosts uniques, certificats TLS uniques, trafic HTTP/TLS dans le temps, top hosts HTTP, codes de réponse, méthodes HTTP, versions TLS, top user-agents, top server names (SNI), top émetteurs de certificats.

### 4. Alertes sécurité
Alertes totales (Zeek Notices), scans de ports détectés, DNS suspects (DGA), connexions rejetées, alertes dans le temps, répartition par type, top IP sources et ports ciblés des connexions rejetées, volume par IP source (détection exfiltration), connexions suspectes dans le temps, journal complet des alertes.

---

## 🔔 Alertes et détection

### Scripts Zeek custom

| Script | Fichier | Seuil par défaut | Description |
|--------|---------|------------------|-------------|
| Port Scan | `port-scan-detect.zeek` | > 50 ports/60s par IP | Détection de reconnaissance réseau via `new_connection` |
| DNS Entropy (DGA) | `dns-entropy.zeek` | Entropie Shannon > 3.5 | Détection de communications C2 via noms de domaine aléatoires |

Les seuils sont configurables via `&redef` dans les scripts Zeek.

### Alertes Grafana

| Alerte | Seuil | Description |
|--------|-------|-------------|
| Pic de trafic | > 3x la moyenne sur 5 min | Exfiltration potentielle ou DDoS |
| Cert TLS expiré | Expiration < 7 jours | Certificat à renouveler |

### Note sur les seuils en environnement lab

En environnement local (VM isolée, trafic capturé via `tcpdump`), les conditions de déclenchement des alertes sont différentes d'un réseau de production. Zeek analyse le PCAP en mode offline et les connexions sont "compressées" dans le temps, ce qui peut empêcher certains seuils temporels (ex: 50 ports en 60s) de se déclencher. Pour tester les alertes en lab, vous pouvez :

- Baisser les seuils dans les scripts (`scan_threshold`, `entropy_threshold`)
- Utiliser des PCAP publics contenant de vrais scénarios d'attaque (voir Données de test)
- Capturer du trafic live sur une interface réseau en mode promiscuous

---

## 🧪 Données de test

### Générer un PCAP sur la VM

```bash
# Terminal 1 : capturer le trafic
sudo timeout 60 tcpdump -w pcap/capture.pcap

# Terminal 2 : générer du trafic varié
# DNS
for domain in google.com github.com wikipedia.org cloudflare.com; do
  dig $domain; dig AAAA $domain; dig MX $domain
done

# HTTP / HTTPS
for url in http://example.com https://google.com https://github.com; do
  curl -s $url > /dev/null
done

# DGA simulé (domaines à haute entropie)
for domain in xkjhqpwmzr.com vjkqplxnbt.net rnmxqjzpvl.org; do
  dig $domain
done
```

### Tester un scan de ports

```bash
# Terminal 1 : capturer
sudo timeout 60 tcpdump -w pcap/capture-scan.pcap

# Terminal 2 : scanner
sudo nmap -sS -p 1-1000 <IP_CIBLE>
```

### PCAP publics recommandés

- [Malware Traffic Analysis](https://www.malware-traffic-analysis.net/) — PCAP d'infections réelles
- [Wireshark Sample Captures](https://wiki.wireshark.org/SampleCaptures) — Captures variées
- [NETRESEC](https://www.netresec.com/?page=PcapFiles) — Collection de PCAP publics
- Captures CTF : [CyberDefenders](https://cyberdefenders.org/), [Root-Me](https://www.root-me.org/)

---

## 🛠️ Stack technique détaillé

| Composant | Outil | Version | Rôle |
|-----------|-------|---------|------|
| Capture & Analyse | Zeek | 6.2 | Analyse protocolaire, logs JSON, JA3/HASSH |
| Transport | Filebeat | 8.13 | Collecte et envoi des logs vers ES |
| Indexation | Elasticsearch | 8.13 | Stockage, indexation (index `zeek-*`) |
| Visualisation | Grafana | 10.4 | 4 dashboards, alertes, exploration |
| Orchestration | Docker Compose | v2 | Déploiement conteneurisé |
| OS | Ubuntu | 22.04 LTS | VM locale (ESXi / VirtualBox / VMware) |

### Configuration Zeek

Zeek est configuré en mode JSON (`LogAscii::use_json = T`) avec les protocoles suivants activés : TCP/UDP (conn), DNS, HTTP, SSL/TLS. Les plugins JA3 (fingerprinting TLS) et HASSH (fingerprinting SSH) sont installés via `zkg`.

### Configuration Filebeat

Filebeat surveille les logs dans `/zeek/logs/current/` (conn.log, dns.log, http.log, ssl.log, notice.log) et les envoie à Elasticsearch avec un parsing JSON natif (`json.keys_under_root: true`).

### Configuration Elasticsearch

Single node, sécurité désactivée (environnement lab uniquement), performances optimisées pour l'ingestion (`index_buffer_size: 20%`, `write.queue_size: 1000`).

---

## 🔗 Parallèle avec les outils commerciaux

| Fonctionnalité | NetWatch (open-source) | Netscout nGeniusONE |
|----------------|----------------------|---------------------|
| Capture trafic | Zeek (analyse proto) | InfiniStream / nGenius |
| Fingerprinting | JA3 / HASSH | nGenius DPI |
| Visibilité réseau | Grafana dashboards | nGeniusONE dashboards |
| Alertes | Zeek Notices + Grafana | Service Triage |
| Stockage | Elasticsearch | nGenius Collector |
| Transport | Filebeat | Gigamon / TAP |

---

## 🐛 Troubleshooting

### Filebeat ne démarre pas
```
error loading config file: config file must be owned by root
```
**Solution :** `sudo chown root:root filebeat/filebeat.yml && sudo chmod 644 filebeat/filebeat.yml`

### Zeek crash-loop au démarrage
C'est normal si aucune interface réseau n'est disponible pour le sniffing live. Zeek est principalement utilisé en mode replay PCAP avec `docker compose run`.

### Les images Docker ne se téléchargent pas
Erreur `no such host` ou `dial tcp: lookup ... on 127.0.0.53:53` → voir la section DNS Docker dans le Quickstart.

### Les dashboards affichent "No data"
Vérifiez le time range en haut à droite de Grafana (mettre "Last 3 hours" ou "Last 24 hours"). Vérifiez aussi que des données existent dans ES : `curl "http://localhost:9200/zeek-*/_count?pretty"`.

### Filebeat n'ingère pas les nouveaux logs
Après un nouveau replay PCAP, recréez Filebeat pour réinitialiser son registre :
```bash
docker compose rm -sf filebeat
docker compose up -d filebeat
```

---

## 📝 Auteur

**Nicolas Malok** — Alternant Cybersécurité @ Axians / Vinci Energies — École 2600

Projet réalisé dans le cadre de la SideQuest MVP (S2 2025-2026).

---

## 📄 License

MIT License — voir [LICENSE](LICENSE)
