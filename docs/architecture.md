# Architecture NetWatch v2

## Vue d'ensemble

NetWatch v2 fait tourner **3 moteurs d'analyse en parallèle** sur le même trafic réseau, avec un pipeline de collecte unifié vers Elasticsearch, une couche de détection comportementale (RITA-lite), une réponse automatique par webhook, et 11 dashboards Grafana.

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
       │             │             │
       ▼             ▼             ▼
  conn/dns/http  alert_json.txt  eve.json
  ssl/ssh/intel
  notice.log
       └─────────────┼─────────────┘
                     ▼
           ┌──────────────────┐
           │  Filebeat 8.13   │
           │  3 inputs        │
           │  index par moteur│
           └────────┬─────────┘
                    ▼
           ┌──────────────────┐◄── beacon-detect  (netwatch-beacons-*)
           │ Elasticsearch    │◄── autoblock      (netwatch-autoblock-*)
           │  zeek-*          │
           │  snort-*         │
           │  suricata-*      │
           └────────┬─────────┘
                    ▼
           ┌──────────────────┐       ┌─────────────────────┐
           │   Grafana 10.4   │◄──────│ Prometheus 2.51     │
           │  11 dashboards   │       │ node-exporter 1.7   │
           │  alertes + webhook│       │ métriques VM        │
           └────────┬─────────┘       └─────────────────────┘
                    │ POST /webhook/alert
                    ▼
           ┌──────────────────┐
           │   autoblock      │
           │  Flask :5001     │
           │  iptables DROP   │
           │  DRY_RUN=true    │
           └──────────────────┘
```

---

## Moteurs d'analyse

### Zeek 6.2

**Rôle :** Analyse protocolaire complète, génération de logs JSON structurés, fingerprinting TLS/SSH, Intel Framework.

Logs générés dans `/zeek/logs/current/` :

| Log | Contenu |
|-----|---------|
| `conn.log` | Toutes les connexions (src/dst IP, port, proto, bytes, durée, conn_state) |
| `dns.log` | Requêtes DNS (query, qtype, rcode, answers, rtt) |
| `http.log` | Requêtes HTTP (method, host, uri, status, user-agent) |
| `ssl.log` | Sessions TLS (version, server_name, issuer, **ja3**, **ja3s**) |
| `ssh.log` | Sessions SSH (client, server, auth_success, **hassh**, **hassh_server**) |
| `intel.log` | Hits Intel Framework (seen.indicator, seen.indicator_type, sources) |
| `notice.log` | Alertes des scripts custom (port scans, DGA entropy) |

Plugins installés via `zkg` (dans le Dockerfile) :
- `corelight/zeek-community-id` — Community ID pour corréler avec Suricata
- JA3/JA3S — fingerprinting TLS (champs natifs Zeek 6.x)
- HASSH — fingerprinting SSH (champs natifs Zeek 6.x)

**Intel Framework** (chargé dans `zeek/local.zeek`) :
- `@load frameworks/intel/seen` + `@load frameworks/intel/do_notice`
- Lit `zeek/intel/ip_watchlist.dat` (Feodo Tracker) et `domain_watchlist.dat` (URLhaus)
- Mis à jour par `update-intel.sh` (téléchargement + conversion TSV)

Scripts de détection custom (`zeek/scripts/`) :
- `port-scan-detect.zeek` — seuil 50 ports distincts / 60 secondes par IP source
- `dns-entropy.zeek` — entropie de Shannon > 3.5 sur les noms de domaine (DGA/C2)

### Snort 3.3.5

**Rôle :** IDS par signatures, règles community + règles custom NETWATCH avec métadonnées MITRE ATT&CK.

**Build :** compilé depuis les sources dans `snort/Dockerfile` :
1. `libdaq` — Data Acquisition Library
2. `gperftools` (tcmalloc) — allocateur mémoire haute performance
3. Snort 3 (`cmake`, `ENABLE_TCMALLOC=ON`)
4. Règles community (`snort3-community-rules.tar.gz`)

**Variable d'environnement :** `SNORT_MONITORED_SERVER` (définie dans `.env`) — injectée dans `snort.lua` comme variable Lua `MONITORED_SERVER`, référencée dans les règles SID 1000013-1000017.

**Sortie :** `alert_json` → `/var/log/snort/alert_json.txt` (NDJSON)

Champs par alerte : `timestamp`, `msg`, `priority`, `class_desc`, `proto`, `src_addr`, `src_port`, `dst_addr`, `dst_port`, `service`, `rule`, `action`

Règles custom NETWATCH (`snort/local.rules`) :

| SID | Détection | MITRE |
|-----|-----------|-------|
| 1000001 | ICMP Ping Sweep (10 pings / 60s) | T1595 |
| 1000002 | SSH Brute Force (5 tentatives / 60s) | T1110 |
| 1000003–06 | DNS vers TLD suspects (.xyz, .info, .top, .biz) | T1568 |
| 1000007 | Credentials HTTP en clair | T1552 |
| 1000008 | Exfiltration (gros upload) | T1048 |
| 1000009 | Port non standard | T1571 |
| 1000010 | User-Agent curl suspect | T1059 |
| 1000011 | ICMP Reply volume (flood) | T1498 |
| 1000012 | SYN Flood HTTP | T1498 |
| 1000013–14 | Accès serveur surveillé HTTP/HTTPS | T1190 |
| 1000015–16 | Accès serveur surveillé SSH/FTP | T1021 |
| 1000017 | Port scan vers serveur surveillé | T1046 |

### Suricata 7.0

**Rôle :** IDS/IPS par signatures, règles ET Open avec mise à jour automatique, Community ID, MITRE ATT&CK natif dans EVE JSON.

**Image :** `jasonish/suricata:7.0` + `suricata/entrypoint.sh` :
1. Au démarrage : `suricata-update` télécharge/met à jour les règles ET Open
2. Suricata démarre en arrière-plan
3. Toutes les 24h : `suricata-update` + `kill -USR2 $PID` (reload sans redémarrage)

**Threading :** `detect-thread-ratio: 2.0`, `max-pending-packets: 65535`

**Sortie :** EVE JSON → `/var/log/suricata/eve.json`

Types d'événements EVE : `alert`, `dns`, `http`, `tls`, `flow`, `stats`

Chaque alerte contient :
```json
{
  "event_type": "alert",
  "src_ip": "...", "dest_ip": "...",
  "community_id": "1:xxxx==",
  "alert": {
    "signature": "...", "signature_id": 2000001,
    "category": "...", "severity": 1,
    "metadata": {
      "mitre_tactic_name": ["Reconnaissance"],
      "mitre_technique_id": ["T1595"]
    }
  }
}
```

Règles custom NETWATCH (`suricata/local.rules`, SID 2000001–2000999) :

| SID | Détection |
|-----|-----------|
| 2000001 | ICMP Ping Sweep |
| 2000002 | SSH Brute Force |
| 2000003 | DNS Tunneling (requête longue) |
| 2000004–05 | TLS obsolète (TLSv1.0/1.1) |
| 2000006 | Mot de passe en clair HTTP |
| 2000007 | Transfert sortant massif |

---

## Détection comportementale — beacon-detect (RITA-lite)

**Service :** `beacon-detect/beacon_detect.py` — Python 3.12, tourne toutes les 15 minutes.

**Source de données :** requête agrégée sur `zeek-*` (conn.log et dns.log).

**Trois détections :**

| Détection | Logique | Champs produits |
|-----------|---------|----------------|
| **Beaconing C2** | Pour chaque paire (src_ip, dst_ip, port) : récupère les timestamps des connexions, calcule les intervalles, CV = std/mean. Si CV < 0.25 et count ≥ 8 → beacon | `beacon_score`, `mean_interval_s`, `cv`, `connection_count` |
| **Longues connexions** | `duration > 3600s` dans conn.log | `duration_h`, `orig_bytes`, `resp_bytes` |
| **DNS Tunneling** | Sous-domaine > 40 chars OU > 100 requêtes vers même domaine | `subdomain_length`, `query_count` |

**Index de sortie :** `netwatch-beacons-YYYY.MM.DD`

Variables d'environnement :

| Variable | Défaut | Rôle |
|----------|--------|------|
| `ES_URL` | `http://elasticsearch:9200` | URL Elasticsearch |
| `SCAN_INTERVAL_MIN` | `15` | Fréquence d'analyse |
| `LOOKBACK_HOURS` | `2` | Fenêtre temporelle analysée |
| `MIN_CONNECTIONS` | `8` | Nombre minimum de connexions pour qualifier un beacon |
| `BEACON_CV_THRESHOLD` | `0.25` | Seuil CV en dessous duquel c'est un beacon |

---

## Réponse automatique — autoblock

**Service :** `autoblock/autoblock.py` — Flask sur port 5001, `network_mode: host` (accès iptables).

**Flux :**
```
Grafana (alerte critique) → POST /webhook/alert → autoblock → iptables -I INPUT -s {ip} -j DROP
```

**Routes API :**
- `POST /webhook/alert` — reçoit les alertes Grafana (JSON), extrait l'IP, bloque si non-allowlistée
- `POST /block` — blocage manuel `{"ip": "x.x.x.x"}`
- `POST /unblock` — déblocage manuel
- `GET /health` — état du service + liste des blocages actifs

**Mécanismes de sécurité :**
- `DRY_RUN=true` par défaut — simule sans appliquer iptables
- Allowlist configurable (`AUTOBLOCK_ALLOWLIST`) — IPs jamais bloquées
- Rate limiting : `MAX_BLOCKS_PER_HOUR=20`
- Expiration automatique : `BLOCK_DURATION_MIN=60`

**Index de sortie :** `netwatch-autoblock-YYYY.MM.DD`

---

## Métriques système — Prometheus + node-exporter

**Prometheus** (`prometheus/prometheus.yml`) scrape `node-exporter` toutes les 15 secondes. Rétention 15 jours.

**node-exporter** expose les métriques système de la VM hôte via `/host/proc`, `/host/sys`, `/rootfs`.

Métriques clés utilisées dans le dashboard `vm-health.json` :
- `node_cpu_seconds_total` — charge CPU par cœur
- `node_memory_MemAvailable_bytes` — RAM disponible
- `node_filesystem_avail_bytes` — espace disque libre
- `node_network_receive_bytes_total` / `transmit` — débit réseau
- `node_load1/5/15` — charge système

---

## Pipeline Filebeat

Filebeat (`filebeat/filebeat.yml`) collecte les 3 sources et crée un index par moteur :

| Input | Chemin | Index cible | Logs inclus |
|-------|--------|-------------|-------------|
| Zeek | `/zeek/logs/current/*.log` | `zeek-YYYY.MM.DD` | conn, dns, http, ssl, ssh, intel, notice |
| Snort | `/var/log/snort/alert_json.txt` | `snort-YYYY.MM.DD` | alert_json |
| Suricata | `/var/log/suricata/eve.json` | `suricata-YYYY.MM.DD` | EVE JSON (alert, dns, http, tls, flow) |

Le champ `engine` (zeek / snort / suricata) est ajouté à chaque document.
Deux processeurs timestamp couvrent les formats Zeek (`ts`) et Snort/Suricata (`timestamp`).

---

## Index Elasticsearch

| Index | Source | Champs clés |
|-------|--------|-------------|
| `zeek-YYYY.MM.DD` | Filebeat ← Zeek | `id.orig_h`, `id.resp_h`, `id.resp_p`, `proto`, `query`, `method`, `note`, `ja3`, `hassh` |
| `snort-YYYY.MM.DD` | Filebeat ← Snort | `msg`, `priority`, `class_desc`, `src_addr`, `dst_addr`, `proto` |
| `suricata-YYYY.MM.DD` | Filebeat ← Suricata | `event_type`, `alert.signature`, `alert.severity`, `src_ip`, `dest_ip`, `community_id`, `alert.metadata.mitre_tactic_name` |
| `netwatch-beacons-YYYY.MM.DD` | beacon-detect | `detection_type`, `src_ip`, `dst_ip`, `beacon_score`, `cv`, `mean_interval_s`, `duration_h` |
| `netwatch-autoblock-YYYY.MM.DD` | autoblock | `ip`, `action`, `dry_run`, `reason`, `duration_min` |

**Pipeline GeoIP** (optionnel, `setup-geoip.sh`) : enrichit `id.orig_h` → `source.geo.country_name` sur tous les index zeek-*, snort-*, suricata-*.

---

## Datasources Grafana

| Datasource | UID | Index / URL |
|-----------|-----|-------------|
| Zeek-ES | `zeek-es` | `zeek-*` |
| Snort-ES | `snort-es` | `snort-*` |
| Suricata-ES | `suricata-es` | `suricata-*` |
| Beacons-ES | `beacons-es` | `netwatch-beacons-*` |
| AutoBlock-ES | `autoblock-es` | `netwatch-autoblock-*` |
| Prometheus | `prometheus` | `http://prometheus:9090` |

Toutes provisionnées depuis `grafana/provisioning/datasources/elasticsearch.yml`.

---

## Alertes Grafana

Provisionnées depuis `grafana/provisioning/alerting/` :

| Règle | Condition | Sévérité |
|-------|-----------|----------|
| CPU critique | `node_cpu > 90%` pendant 5min | Critical |
| RAM critique | `node_memory_MemAvailable < 10%` | Critical |
| Disque critique | `node_filesystem_avail < 15%` | Warning |
| Spike Suricata | `count(suricata alerts) > 50/min` | High |
| Anomalie volume | `last_5min_bucket / mean_1h_buckets > 3` | Warning |

**Contact points :**
- `Slack NetWatch` — webhook Slack (`SLACK_WEBHOOK_URL` dans `.env`)
- `AutoBlock` — `POST http://netwatch-autoblock:5001/webhook/alert`

---

## Services Docker

| Conteneur | Image | RAM indicative | Volumes | Réseau |
|-----------|-------|----------------|---------|--------|
| `netwatch-zeek` | `zeek/zeek:6.2` (custom) | 512 Mo | `zeek-logs`, `pcap`, `intel` | host |
| `netwatch-snort` | `ubuntu:22.04` (build custom) | 512 Mo | `snort-logs`, `pcap` | host |
| `netwatch-suricata` | `jasonish/suricata:7.0` (custom) | 512 Mo | `suricata-logs`, `pcap` | host |
| `netwatch-filebeat` | `filebeat:8.13` | 256 Mo | `zeek-logs`, `snort-logs`, `suricata-logs` | bridge |
| `netwatch-elasticsearch` | `elasticsearch:8.13` | 2 Go (JVM -Xmx2g) | `es-data` | bridge |
| `netwatch-grafana` | `grafana:10.4` | 256 Mo | `grafana-data`, dashboards | bridge |
| `netwatch-prometheus` | `prom/prometheus:2.51` | 256 Mo | `prometheus-data` | bridge |
| `netwatch-node-exporter` | `prom/node-exporter:1.7` | 64 Mo | `/proc`, `/sys`, `/` (ro) | host (pid) |
| `netwatch-beacon-detect` | Python 3.12 (custom) | 128 Mo | — | bridge |
| `netwatch-autoblock` | Python 3.12 + iptables (custom) | 128 Mo | — | host |

**RAM totale recommandée : 8 Go minimum** (ES seul prend 2 Go).

**Capabilities :**
- `zeek`, `snort`, `suricata`, `autoblock` : `cap_drop: ALL` + `cap_add: [NET_ADMIN, NET_RAW]`
- `suricata` : `cap_add: [NET_ADMIN, NET_RAW, SYS_NICE]`
- `node-exporter` : `pid: host` (accès `/proc` host)

---

## Infrastructure cible

### Architecture 2 VMs (recommandée)

```
┌────────────────────────────────────────────────────────────────┐
│  Serveur physique — Shuttle / mini-rack                         │
│  Proxmox VE — Intel Xeon — 16 Go RAM                           │
│                                                                │
│  ┌───────────────────────────┐  ┌──────────────────────────┐   │
│  │  VM Sensors               │  │  VM Data                 │   │
│  │  Ubuntu 22.04             │  │  Ubuntu 22.04            │   │
│  │  4 vCPU / 6 Go RAM        │  │  4 vCPU / 10 Go RAM      │   │
│  │  vNIC1: vmbr0 (mgmt)      │  │  vNIC: vmbr0 (mgmt)      │   │
│  │  vNIC2: vmbr1 (capture)   │  │                          │   │
│  │                           │  │  netwatch-elasticsearch  │   │
│  │  netwatch-zeek            │  │  netwatch-grafana        │   │
│  │  netwatch-snort           │  │  netwatch-prometheus     │   │
│  │  netwatch-suricata        │  │  netwatch-node-exporter  │   │
│  │  netwatch-filebeat ──────────►  netwatch-beacon-detect  │   │
│  │                           │  │  netwatch-autoblock      │   │
│  └───────────────────────────┘  └──────────────────────────┘   │
│                                                                │
│  vmbr0 : LAN management (192.168.x.0/24)                       │
│  vmbr1 : SPAN capture — pas d'IP, mode promiscuous             │
└────────────────────────────────────────────────────────────────┘
          ▲
          │ Port SPAN
   ┌──────┴──────┐
   │   Switch    │
   │  manageable │
   └─────────────┘
          │
      Réseau LAN
```

**NIC de capture recommandé :** Intel i350-T2 (PCIe, dual port) — pilote `igb`, support af-packet natif.

**Configuration Proxmox vmbr1 :**
```
iface vmbr1 inet manual
    bridge-ports enp4s0
    bridge-stp off
    bridge-fd 0
    post-up ip link set vmbr1 promisc on
    post-up ip link set enp4s0 promisc on
```

### Architecture 1 VM (lab / démo)

Tous les 10 services sur une seule VM Ubuntu 22.04 avec **12 Go RAM minimum** (Elasticsearch + les 9 autres services).

---

## Ports exposés

| Service | Port | Accès |
|---------|------|-------|
| Grafana | `3000` | Interface web |
| Elasticsearch | `9200` | API REST |
| Prometheus | `9090` | Interface web + API |
| autoblock | `5001` | Webhook interne (Grafana → autoblock) |

---

## Commandes de diagnostic

```bash
# État des 10 conteneurs
docker compose ps

# Logs en temps réel
docker compose logs -f zeek
docker compose logs -f snort
docker compose logs -f suricata
docker compose logs -f beacon-detect
docker compose logs -f autoblock

# Index Elasticsearch
curl "http://localhost:9200/_cat/indices?v&s=index"

# Nombre de documents par index
curl "http://localhost:9200/zeek-*/_count?pretty"
curl "http://localhost:9200/snort-*/_count?pretty"
curl "http://localhost:9200/suricata-*/_count?pretty"
curl "http://localhost:9200/netwatch-beacons-*/_count?pretty"
curl "http://localhost:9200/netwatch-autoblock-*/_count?pretty"

# Dernières détections beacon
curl "http://localhost:9200/netwatch-beacons-*/_search?pretty&size=5&sort=@timestamp:desc"

# Santé autoblock
curl "http://localhost:5001/health"

# Blocages iptables actifs (si DRY_RUN=false)
iptables -L INPUT -n --line-numbers | grep DROP

# Rebuild un service après modification
docker compose build snort --no-cache
docker compose up -d snort

# Réinitialiser Filebeat (registre des fichiers lus)
docker compose rm -sf filebeat && docker compose up -d filebeat

# Mettre à jour la threat intel Zeek
bash update-intel.sh

# Simulation de trafic avec tous les scénarios d'attaque
python3 simulate-traffic.py --hours 6 --intensity high --attack
```
