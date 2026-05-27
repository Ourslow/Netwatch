# Architecture NetWatch v2

## Vue d'ensemble

NetWatch v2 fait tourner **3 moteurs d'analyse en parallèle** sur le même trafic réseau, avec un pipeline de collecte unifié vers Elasticsearch et 7 dashboards Grafana.

```
        Trafic réseau (SPAN / PCAP)
                    │
        ┌───────────┼───────────┐
        ▼           ▼           ▼
  ┌──────────┐ ┌─────────┐ ┌────────────┐
  │ Zeek 6.2 │ │ Snort 3 │ │ Suricata 7 │
  │          │ │ 3.3.5   │ │  (EVE JSON)│
  └────┬─────┘ └────┬────┘ └─────┬──────┘
       │             │             │
       ▼             ▼             ▼
  conn.log      alert_json.txt   eve.json
  dns.log
  http.log
  ssl.log
  notice.log
       └─────────────┼─────────────┘
                     ▼
           ┌──────────────────┐
           │  Filebeat 8.13   │
           │  3 inputs        │
           │  index par moteur│
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

## Moteurs d'analyse

### Zeek 6.2

**Rôle :** Analyse protocolaire complète, génération de logs JSON structurés.

Logs générés dans `/zeek/logs/current/` :

| Log | Contenu |
|-----|---------|
| `conn.log` | Toutes les connexions (src/dst IP, port, proto, bytes, durée, conn_state) |
| `dns.log` | Requêtes DNS (query, qtype, rcode, answers, rtt) |
| `http.log` | Requêtes HTTP (method, host, uri, status, user-agent) |
| `ssl.log` | Sessions TLS (version, server_name, issuer, cipher) |
| `notice.log` | Alertes des scripts custom (port scans, DGA) |

Plugins installés via `zkg` :
- `salesforce/ja3` — Fingerprinting TLS client
- `salesforce/hassh` — Fingerprinting SSH

Scripts de détection custom (`zeek/scripts/`) :
- `port-scan-detect.zeek` — Seuil 50 ports distincts / 60 secondes par IP source
- `dns-entropy.zeek` — Entropie de Shannon > 3.5 sur les noms de domaine (DGA/C2)

### Snort 3.3.5

**Rôle :** IDS par signatures, règles community + règles custom NETWATCH.

**Build :** compilé depuis les sources dans le Dockerfile (`snort/Dockerfile`) :
1. `libdaq` — Data Acquisition Library
2. `gperftools` (tcmalloc) — allocateur mémoire haute perf
3. Snort 3 (`cmake`, `ENABLE_TCMALLOC=ON`)
4. Règles community (`snort3-community-rules.tar.gz`)

**Sortie :** `alert_json` → `/var/log/snort/alert_json.txt` (NDJSON, un objet par ligne)

Champs dans chaque alerte : `timestamp`, `msg`, `priority`, `class_desc`, `proto`, `src_addr`, `src_port`, `dst_addr`, `dst_port`, `service`, `rule`, `action`

Règles custom NETWATCH (SID 1000001–1000999, fichier `snort/local.rules`) :
| SID | Détection |
|-----|-----------|
| 1000001 | ICMP Ping Sweep |
| 1000002 | SSH Brute Force |
| 1000003-06 | DNS vers TLD suspects |
| 1000007 | Credentials HTTP en clair |
| 1000008 | Exfiltration (gros upload) |
| 1000009 | Port non standard |
| 1000010 | User-Agent curl suspect |

### Suricata 7.0

**Rôle :** IDS/IPS par signatures, règles ET Open + règles custom NETWATCH.

**Image :** `jasonish/suricata:7.0` + `suricata-update` pour les règles Emerging Threats Open.

**Sortie :** EVE JSON → `/var/log/suricata/eve.json`

Types d'événements EVE générés : `alert`, `dns`, `http`, `tls`, `flow`, `stats`

Chaque alerte contient : `event_type`, `src_ip/port`, `dest_ip/port`, `proto`, `community_id`, `alert.signature`, `alert.signature_id`, `alert.category`, `alert.severity`

Le **Community ID** (`1:xxxx==`) permet de corréler les événements Suricata avec ceux de Zeek (même flux réseau, identifiant partagé).

Règles custom NETWATCH (SID 2000001–2000999, fichier `suricata/local.rules`) :
| SID | Détection |
|-----|-----------|
| 2000001 | ICMP Ping Sweep |
| 2000002 | SSH Brute Force |
| 2000003 | DNS Tunneling (requête longue) |
| 2000004-05 | TLS obsolète (TLSv1.0/1.1) |
| 2000006 | Mot de passe en clair HTTP |
| 2000007 | Transfert sortant massif |

---

## Pipeline Filebeat

Filebeat (`filebeat/filebeat.yml`) collecte les 3 sources avec un index par moteur :

| Input | Chemin | Index cible |
|-------|--------|-------------|
| Zeek | `/zeek/logs/current/*.log` | `zeek-YYYY.MM.DD` |
| Snort | `/var/log/snort/alert_json.txt` | `snort-YYYY.MM.DD` |
| Suricata | `/var/log/suricata/eve.json` | `suricata-YYYY.MM.DD` |

Le champ `engine` (zeek / snort / suricata) est ajouté à chaque document et utilisé dans le pattern d'index : `%{[engine]:unknown}-%{+yyyy.MM.dd}`.

Deux processeurs timestamp sont configurés pour couvrir les formats Zeek (`ts`) et Snort/Suricata (`timestamp`).

---

## Index Elasticsearch

| Index | Moteur | Champs clés |
|-------|--------|-------------|
| `zeek-YYYY.MM.DD` | Zeek | `id.orig_h`, `id.resp_h`, `id.resp_p`, `proto`, `query`, `method`, `note` |
| `snort-YYYY.MM.DD` | Snort 3 | `msg`, `priority`, `class_desc`, `src_addr`, `dst_addr`, `proto` |
| `suricata-YYYY.MM.DD` | Suricata 7 | `event_type`, `alert.signature`, `alert.severity`, `src_ip`, `dest_ip`, `community_id` |

---

## Datasources Grafana

| Datasource | UID | Index pattern |
|-----------|-----|---------------|
| Zeek-ES | `zeek-es` | `zeek-*` |
| Snort-ES | `snort-es` | `snort-*` |
| Suricata-ES | `suricata-es` | `suricata-*` |

Les 3 datasources sont auto-provisionnées depuis `grafana/provisioning/datasources/elasticsearch.yml` au démarrage de Grafana. Les 7 dashboards sont chargés depuis `grafana/dashboards/` (chemin monté en volume).

---

## Services Docker

| Conteneur | Image | CPU | RAM indicative | Volumes |
|-----------|-------|-----|----------------|---------|
| `netwatch-zeek` | `zeek/zeek:6.2` (custom) | 1-2 | 512 Mo | `zeek-logs`, `pcap` |
| `netwatch-snort` | `ubuntu:22.04` (build custom) | 1-2 | 512 Mo | `snort-logs`, `pcap` |
| `netwatch-suricata` | `jasonish/suricata:7.0` (custom) | 1-2 | 512 Mo | `suricata-logs`, `pcap` |
| `netwatch-filebeat` | `filebeat:8.13` | 0.5 | 256 Mo | `zeek-logs`, `snort-logs`, `suricata-logs` |
| `netwatch-elasticsearch` | `elasticsearch:8.13` | 2 | 2 Go (JVM) | `es-data` |
| `netwatch-grafana` | `grafana:10.4` | 0.5 | 256 Mo | `grafana-data`, dashboards |

**RAM minimale recommandée : 6 Go** (Elasticsearch prend 2 Go, le reste pour les 5 autres services).

### Configuration réseau

Tous les capteurs utilisent `network_mode: host` pour accéder directement aux interfaces réseau de la VM. L'interface de capture est configurée via la variable d'environnement `IFACE` dans `docker-compose.yml` (valeur par défaut : `eth0`).

Capabilities requises : `NET_ADMIN`, `NET_RAW` (+ `SYS_NICE` pour Suricata).

---

## Infrastructure cible

### Architecture 2 VMs (recommandée)

```
┌──────────────────────────────────────────────────────┐
│  Serveur physique — Shuttle / mini-rack               │
│  Proxmox VE                                          │
│                                                      │
│  ┌─────────────────────┐  ┌───────────────────────┐  │
│  │  VM Sensors          │  │  VM Data              │  │
│  │  Ubuntu 22.04        │  │  Ubuntu 22.04         │  │
│  │  6 vCPU / 6 Go RAM   │  │  4 vCPU / 8 Go RAM    │  │
│  │                     │  │                       │  │
│  │  netwatch-zeek       │  │  netwatch-elasticsearch│  │
│  │  netwatch-snort      │  │  netwatch-grafana     │  │
│  │  netwatch-suricata   │  │                       │  │
│  │  netwatch-filebeat   │  │                       │  │
│  └─────────────────────┘  └───────────────────────┘  │
│                                                      │
│  vSwitch (promiscuous) ← Port SPAN du switch physique │
└──────────────────────────────────────────────────────┘
```

### Architecture 1 VM (lab / démo)

Tous les 6 services sur une seule VM Ubuntu 22.04 avec au minimum 8 Go RAM.

---

## Commandes de diagnostic

```bash
# État des conteneurs
docker compose ps

# Logs d'un service
docker compose logs -f zeek
docker compose logs -f snort
docker compose logs -f suricata
docker compose logs -f filebeat

# Index Elasticsearch
curl "http://localhost:9200/_cat/indices?v&s=index"

# Nombre de documents par index
curl "http://localhost:9200/zeek-*/_count?pretty"
curl "http://localhost:9200/snort-*/_count?pretty"
curl "http://localhost:9200/suricata-*/_count?pretty"

# Rebuild un service (ex: Snort après modif des règles)
docker compose build snort --no-cache
docker compose up -d snort

# Réinitialiser Filebeat (registre des fichiers lus)
docker compose rm -sf filebeat && docker compose up -d filebeat
```
