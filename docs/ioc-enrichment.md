# IOC Enrichment — AbuseIPDB + ipinfo.io

Script NetWatch T_010 — Enrichissement de réputation IP sur le graphe IOC.

## Vue d'ensemble

`scripts/security/ioc-enrich.py` prend en entrée le graphe IOC généré par
`ioc-graph.py` (`ioc-graph-output.json`), interroge des APIs de réputation IP
pour chaque nœud IP public, et produit un graphe enrichi
(`ioc-graph-enriched.json`).

```
ioc-graph-output.json
        │
        ▼
  ioc-enrich.py  ←── ABUSEIPDB_API_KEY (optionnel)
        │              └── fallback : ipinfo.io (sans clé)
        ├──▶ ioc-enrich-cache.json   (cache persistant)
        └──▶ ioc-graph-enriched.json (graphe enrichi)
```

## Prérequis

- Python 3.10+ (stdlib uniquement — pas de dépendances externes)
- Accès Internet pour contacter AbuseIPDB / ipinfo.io

## Installation

Aucune installation supplémentaire requise. Le script utilise uniquement la
bibliothèque standard Python (`urllib`, `json`, `ipaddress`, `argparse`).

## Configuration

### Option 1 — AbuseIPDB (recommandée)

Créer un compte gratuit sur https://www.abuseipdb.com/ et générer une clé API.

Ajouter dans `.env` à la racine du projet :

```bash
ABUSEIPDB_API_KEY=votre_clé_ici
```

Le script charge automatiquement `.env` s'il existe. On peut aussi exporter la
variable directement :

```bash
export ABUSEIPDB_API_KEY=votre_clé_ici
```

Données disponibles avec AbuseIPDB :
- `abuse_score` — score de confiance abus (0-100)
- `country` — code pays (ISO 3166-1 alpha-2)
- `isp` — fournisseur d'accès Internet
- `usage_type` — type d'usage (Data Center/Web Hosting, ISP, etc.)
- `total_reports` — nombre total de signalements
- `domain` — domaine associé
- `is_whitelisted` — IP sur liste blanche AbuseIPDB

### Option 2 — ipinfo.io (fallback sans clé)

Si `ABUSEIPDB_API_KEY` n'est pas défini, le script utilise ipinfo.io
automatiquement sans nécessiter de clé.

Données disponibles avec ipinfo.io :
- `country` — code pays
- `org` — organisation / ASN (ex: `AS15169 Google LLC`)
- `hostname` — PTR DNS
- `city` — ville
- `region` — région/état

Pour augmenter les limites de taux (50 000 req/mois gratuit → 250 000),
s'inscrire sur https://ipinfo.io/ et ajouter :

```bash
IPINFO_TOKEN=votre_token  # non géré nativement, passer via --env si besoin
```

## Utilisation

### Exécution basique

```bash
# Depuis la racine du projet
python3 scripts/security/ioc-enrich.py
```

Utilise les chemins par défaut :
- Entrée  : `scripts/security/ioc-graph-output.json`
- Sortie  : `scripts/security/ioc-graph-enriched.json`
- Cache   : `scripts/security/ioc-enrich-cache.json`

### Chemins personnalisés

```bash
python3 scripts/security/ioc-enrich.py \
    --input  scripts/security/ioc-graph-output.json \
    --output scripts/security/ioc-graph-enriched.json \
    --cache  scripts/security/ioc-enrich-cache.json
```

### Pipeline complet

```bash
# 1. Générer le graphe IOC depuis Elasticsearch
python3 scripts/security/ioc-graph.py

# 2. Enrichir les IPs
python3 scripts/security/ioc-enrich.py

# 3. (futur) Visualiser dans le portail web
```

## Format de sortie

### Structure d'un nœud IP enrichi

```json
{
  "id": "ip_src::185.220.101.1",
  "type": "ip_src",
  "label": "185.220.101.1",
  "shape": "circle",
  "color": "#4A90D9",
  "alert_count": 42,
  "enrichment": {
    "source": "abuseipdb",
    "abuse_score": 100,
    "country": "DE",
    "isp": "Tor Exit Node Hosting",
    "usage_type": "Data Center/Web Hosting/Transit",
    "total_reports": 1847,
    "domain": "tor-exit.example.com",
    "is_whitelisted": false,
    "enriched_at": "2026-06-30T14:00:00+00:00"
  }
}
```

### Source ipinfo.io (fallback)

```json
{
  "id": "ip_dst::117.18.0.55",
  "type": "ip_dst",
  "label": "117.18.0.55",
  "enrichment": {
    "source": "ipinfo",
    "country": "HK",
    "org": "AS152194 CTG Server Limited",
    "hostname": null,
    "city": "Hong Kong",
    "region": "Hong Kong",
    "enriched_at": "2026-06-30T14:00:00+00:00"
  }
}
```

### IPs privées ignorées (RFC 1918)

```json
{
  "id": "ip_dst::192.168.15.2",
  "type": "ip_dst",
  "label": "192.168.15.2",
  "enrichment": {
    "source": "skipped",
    "reason": "private_ip"
  }
}
```

### Métadonnées enrichies dans `meta`

```json
{
  "meta": {
    "generated_at": "2026-06-30T08:54:09.879910+00:00",
    "source": "elasticsearch:http://localhost:9200",
    "alert_count_processed": 572,
    "node_count": 51,
    "edge_count": 40,
    "enriched_at": "2026-06-30T14:00:00+00:00",
    "enrichment_source": "ipinfo",
    "enriched_count": 8,
    "skipped_private": 21
  }
}
```

## Cache

Le cache (`ioc-enrich-cache.json`) évite de requêter deux fois la même IP lors
d'exécutions successives. Il est chargé au démarrage et sauvegardé à la fin.

```json
{
  "185.220.101.1": {
    "source": "ipinfo",
    "country": "DE",
    "org": "AS4134 Chinanet",
    "enriched_at": "2026-06-30T14:00:00+00:00"
  }
}
```

Pour forcer un re-fetch de toutes les IPs, supprimer le cache :

```bash
rm scripts/security/ioc-enrich-cache.json
```

## Plages d'IPs ignorées

Les plages suivantes sont ignorées et ne génèrent pas d'appel API :

| Réseau            | Description          |
|-------------------|----------------------|
| `10.0.0.0/8`      | RFC 1918 privé       |
| `172.16.0.0/12`   | RFC 1918 privé       |
| `192.168.0.0/16`  | RFC 1918 privé       |
| `127.0.0.0/8`     | Loopback             |
| `169.254.0.0/16`  | Link-local APIPA     |
| `::1/128`         | IPv6 loopback        |
| `fc00::/7`        | IPv6 ULA             |

## Limites de taux

Le script insère un délai de 100 ms entre chaque requête (`time.sleep(0.1)`)
pour rester dans les limites des tiers gratuits.

| Service    | Limite gratuite         | Avec clé              |
|------------|-------------------------|-----------------------|
| AbuseIPDB  | 1 000 req/jour          | idem (Free tier)      |
| ipinfo.io  | 50 000 req/mois         | 250 000 req/mois      |

## Résultats sur données live (T_010)

Sur le graphe généré depuis ES (572 alertes, 51 nœuds, 29 nœuds IP) :

- 21 IPs privées ignorées (192.168.x.x, 172.31.x.x)
- 8 IPs publiques enrichies via ipinfo.io
- IPs notables détectées :
  - `185.220.101.1` — Nœud Tor connu
  - `117.18.0.55` — HK / CTG Server Limited (hébergeur suspect)
  - `177.71.0.82` — Brésil / AS26615 TIM SA

## Intégration avec ioc-graph.py

`ioc-enrich.py` est conçu pour être chaîné après `ioc-graph.py` :

```bash
# Pipeline IOC complet
python3 scripts/security/ioc-graph.py --output scripts/security/ioc-graph-output.json
python3 scripts/security/ioc-enrich.py --input scripts/security/ioc-graph-output.json
```

Le fichier de sortie `ioc-graph-enriched.json` est compatible avec le même
format que `ioc-graph-output.json` — les champs `enrichment` sont ajoutés aux
nœuds IP, sans modifier la structure existante (nodes, edges, meta).

## Fichiers produits

| Fichier                                    | Description                          |
|--------------------------------------------|--------------------------------------|
| `scripts/security/ioc-enrich.py`           | Script d'enrichissement              |
| `scripts/security/ioc-graph-enriched.json` | Graphe enrichi (output principal)    |
| `scripts/security/ioc-enrich-cache.json`   | Cache persistant des lookups IP      |
