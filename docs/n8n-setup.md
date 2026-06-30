# n8n — Automatisation alertes NetWatch → Microsoft Teams

## Vue d'ensemble

n8n est intégré à NetWatch pour envoyer automatiquement les alertes de sévérité **HIGH** et **CRITICAL** vers un canal Microsoft Teams via webhook entrant.

**Pipeline** :
```
Elasticsearch (suricata-*, snort-*)
        ↓  polling toutes les 5 min
       n8n
        ↓  POST Adaptive Card
  Microsoft Teams
```

---

## Démarrage rapide

### 1. Lancer n8n

n8n est déclaré dans `docker-compose.yml` (service `n8n`, port 5678).

```bash
docker compose up -d n8n
# Vérifier :
docker compose ps n8n
curl http://localhost:5678
```

Accès UI : <http://localhost:5678>  
Credentials par défaut : `admin` / `netwatch2026`  
(Changer via `N8N_USER` et `N8N_PASSWORD` dans `.env`)

---

### 2. Configurer le webhook Microsoft Teams

> **IMPORTANT** : Sans cette étape, le nœud "Envoyer vers Teams" échouera.

**Procédure pour obtenir l'URL du webhook entrant Teams :**

1. Ouvrir Microsoft Teams
2. Naviguer vers le canal de destination (ex : *#netwatch-alertes*)
3. Cliquer sur `···` (Options du canal) → **Connecteurs**
4. Rechercher **Incoming Webhook** → **Configurer**
5. Nommer le connecteur : `NetWatch Alertes`
6. Optionnel : uploader le logo NetWatch (`docs/logos/netwatch-icon.png`)
7. Cliquer **Créer**
8. Copier l'URL générée (format : `https://xxx.webhook.office.com/webhookb2/...`)

**Renseigner l'URL dans n8n :**

Option A — Variable d'environnement (recommandé) :

```bash
# Dans .env :
TEAMS_WEBHOOK_URL=https://xxx.webhook.office.com/webhookb2/...
```

Puis dans `docker-compose.yml`, service `n8n`, ajouter :
```yaml
environment:
  - TEAMS_WEBHOOK_URL=${TEAMS_WEBHOOK_URL}
```

Option B — Interface n8n :
- Settings → Variables → Ajouter `TEAMS_WEBHOOK_URL` = `<url>`

---

### 3. Importer le workflow

```bash
# Méthode automatique (script) :
./scripts/automation/deploy-n8n-workflow.sh

# Méthode manuelle (UI n8n) :
# 1. http://localhost:5678 → Workflows → Import from file
# 2. Sélectionner : scripts/automation/n8n-alertes-teams.json
# 3. Activer le workflow (toggle ON)
```

---

## Architecture du workflow "NetWatch Alertes"

```
[Schedule: 5min] → [ES Query] → [IF hits>0] → [Formater] → [Build Teams Card] → [POST webhook]
                                      └─ [No alerts: NoOp]
```

### Nœuds

| Nœud | Type | Description |
|------|------|-------------|
| Toutes les 5 min | Schedule Trigger | Déclencheur cron |
| ES — Alertes High/Critical | HTTP Request | POST `/_search` sur `suricata-*,snort-*` |
| Alertes trouvées ? | IF | Vérifie `hits.total.value > 0` |
| Formater les alertes | Code (JS) | Extrait IP src, règle, sévérité, moteur |
| Construire message Teams | Code (JS) | Adaptive Card v1.4 — top 5 alertes |
| Envoyer vers Teams | HTTP Request | POST `$env.TEAMS_WEBHOOK_URL` |
| Aucune alerte — Stop | NoOp | Branche "pas d'alerte" |

### Requête Elasticsearch

- **Indices** : `suricata-*` et `snort-*`
- **Fenêtre temporelle** : `last 5 minutes` (`@timestamp >= now-5m`)
- **Filtre sévérité** : `alert.severity IN [1,2]` OU `event.severity_label IN [high,critical]` OU `severity IN [high,critical]`
- **Tri** : `@timestamp DESC`
- **Limit** : 50 hits max, top 5 dans la carte Teams

---

## Test avec simulate-traffic.py

```bash
# Injecter des alertes high/critical dans ES :
python3 simulate-traffic.py --hours 0.1 --intensity high --attack

# Vérifier dans ES (après Filebeat) :
curl 'http://localhost:9200/suricata-*/_search?q=alert.severity:1&size=3&pretty'

# Exécution manuelle dans n8n UI :
# → Workflows → NetWatch Alertes → Execute Workflow
```

Une notification Teams doit apparaître dans les secondes suivant l'exécution.

---

## Maintenance

### Changer les credentials n8n

```bash
# Dans .env :
N8N_USER=mon-admin
N8N_PASSWORD=mon-mot-de-passe-fort

docker compose restart n8n
```

### Modifier la fenêtre de polling

Éditer `scripts/automation/n8n-alertes-teams.json`, nœud `Toutes les 5 min`, paramètre `minutesInterval`.  
Réimporter via le script de déploiement.

### Logs n8n

```bash
docker compose logs -f n8n
```

### Sauvegarder les workflows

```bash
# Export manuel depuis l'UI n8n :
# Workflows → NetWatch Alertes → ··· → Export
# Sauvegarder dans scripts/automation/n8n-alertes-teams.json
```

---

## Dépannage

| Symptôme | Cause probable | Solution |
|----------|---------------|----------|
| n8n inaccessible | Service non démarré | `docker compose up -d n8n` |
| `401 Unauthorized` sur ES | (non applicable — ES sans auth) | Vérifier `host.docker.internal:9200` |
| Pas de hits dans ES | Aucun index suricata-*/snort-* | Lancer `simulate-traffic.py` puis Filebeat |
| Teams : `403` ou `410` | Webhook expiré/incorrect | Recréer le connecteur Teams |
| Teams : `400` | Payload mal formé | Vérifier le nœud "Construire message Teams" dans n8n |

---

## Fichiers associés

| Fichier | Description |
|---------|-------------|
| `docker-compose.yml` | Service `n8n` (port 5678, volume n8n-data) |
| `scripts/automation/n8n-alertes-teams.json` | Export du workflow n8n Teams |
| `scripts/automation/deploy-n8n-workflow.sh` | Script de déploiement via API REST |
| `docs/n8n-setup.md` | Ce fichier |

---

## Auto-tickets

### Vue d'ensemble

Le workflow **NetWatch Auto-Tickets** crée automatiquement des tickets YAML dans
`agents-deck/agents/security/tickets/drafts/` à chaque détection d'alerte critique
dans Elasticsearch. Le Security-agent peut ensuite prendre en charge ces tickets.

**Pipeline** :
```
n8n Schedule (10 min)
  → ES Query (suricata-*,snort-* | severity:critical | last 10 min)
  → IF (hits > 0 ?)
  → Extraire alertes (1 item par hit)
  → Execute Command : python3 create-ticket.py
      → agents-deck/agents/security/tickets/drafts/T_auto_YYYYMMDD_HHMMSS_<slug>.yml
```

---

### Script create-ticket.py

**Emplacement** : `scripts/automation/create-ticket.py`

Prend une alerte JSON en stdin ou en argument et génère un ticket YAML.

```bash
# Usage basique (stdin)
echo '<json_alerte>' | python3 scripts/automation/create-ticket.py

# Avec fichier
python3 scripts/automation/create-ticket.py --file alert.json

# Dry-run (affiche sans écrire)
echo '<json>' | python3 scripts/automation/create-ticket.py --dry-run

# Répertoire drafts/ personnalisé
echo '<json>' | python3 scripts/automation/create-ticket.py \
  --drafts-dir /chemin/vers/drafts/
```

**Format d'entrée** : JSON Suricata EVE, Snort alert_json, ou Elasticsearch hit `_source`.

**Champs extraits automatiquement** :

| Champ YAML | Sources JSON essayées (dans l'ordre) |
|------------|--------------------------------------|
| `signature` | `alert.signature`, `msg`, `signature`, `rule.name` |
| `src_ip` | `src_ip`, `source.ip`, `alert.src_ip` |
| `dest_ip` | `dest_ip`, `destination.ip`, `alert.dest_ip` |
| `timestamp` | `@timestamp`, `timestamp`, `alert.timestamp` |
| `severity` | `alert.severity` (1→critical, 2→high), `severity`, `event.severity_label` |

**Gestion anti-doublon** : avant de créer un ticket, le script parcourt tous les fichiers
`.yml` existants dans `drafts/` et compare la signature (insensible à la casse).
Si un ticket avec la même signature existe déjà, le script sort avec `SKIP` (exit 0)
sans créer de doublon.

**Format du ticket généré** :

```yaml
id: T_auto_20260630_142500
title: "AUTO: ET MALWARE Meterpreter Session Detected"
agent: Security-agent
phase: 2
priority: critical
category: incident
status: draft
created: "2026-06-30"
auto_generated: true
alert:
  src_ip: "10.10.1.50"
  dest_ip: "192.168.1.21"
  signature: "ET MALWARE Meterpreter Session Detected"
  timestamp: "2026-06-30T14:25:00Z"
  src_port: 4444
  dest_port: 443
  proto: "TCP"
  engine: "suricata"
  portal_url: "http://localhost:5050/alerts"
acceptance:
  - "Investiguer l'alerte : src_ip=10.10.1.50, dest_ip=192.168.1.21, contexte réseau"
  - "Vérifier si l'IP source est dans la watchlist Zeek Intel"
  - "Analyser les logs réseau associés dans Elasticsearch (suricata)"
  - "Documenter les conclusions et clore ou escalader le ticket"
```

---

### Workflow n8n — NetWatch Auto-Tickets

**Fichier** : `scripts/automation/n8n-auto-tickets.json`

#### Import dans n8n

```bash
# Import via API REST n8n
curl -s -u admin:netwatch2026 \
  -X POST http://localhost:5678/rest/workflows \
  -H "Content-Type: application/json" \
  -d @scripts/automation/n8n-auto-tickets.json

# Ou via UI :
# http://localhost:5678 → Workflows → Import from file → n8n-auto-tickets.json
# → Activer le workflow (toggle ON)
```

#### Architecture des nœuds

| Nœud | Type | Description |
|------|------|-------------|
| Toutes les 10 min | Schedule Trigger | Déclencheur cron toutes les 10 minutes |
| ES — Alertes critiques | HTTP Request | POST `/_search` sur `suricata-*,snort-*`, filtre `severity:critical`, `last 10m` |
| Alertes critiques trouvées ? | IF | Vérifie `hits.total.value > 0` |
| Extraire les alertes | Code (JS) | Sépare les hits en items individuels |
| Créer ticket YAML | Execute Command | `echo '<json>' \| python3 create-ticket.py` |
| Aucune alerte critique — Stop | NoOp | Branche "pas d'alerte" |

#### Requête Elasticsearch

- **Indices** : `suricata-*` et `snort-*`
- **Fenêtre temporelle** : `last 10 minutes` (`@timestamp >= now-10m`)
- **Filtre sévérité** : `alert.severity = 1` OU `severity = critical` OU `event.severity_label = critical`
- **Tri** : `@timestamp DESC`
- **Limite** : 20 hits max (chaque alerte génère un ticket, anti-doublon actif)

---

### Test manuel

```bash
# 1. Injecter une alerte critique dans ES (via simulate-traffic.py)
python3 simulate-traffic.py --hours 0.1 --intensity high --attack

# 2. Vérifier la présence d'alertes critiques dans ES
curl 'http://localhost:9200/suricata-*/_search?q=alert.severity:1&size=3&pretty'

# 3. Tester create-ticket.py directement
ALERT='{"@timestamp":"2026-06-30T14:25:00Z","src_ip":"10.10.1.50","dest_ip":"192.168.1.21","alert":{"signature":"ET MALWARE Test","severity":1},"event":{"module":"suricata"}}'
echo "$ALERT" | python3 scripts/automation/create-ticket.py

# 4. Vérifier le ticket créé
ls agents-deck/agents/security/tickets/drafts/

# 5. Exécution manuelle dans n8n UI :
# http://localhost:5678 → Workflows → NetWatch Auto-Tickets → Execute Workflow
```

---

### Fichiers associés (Auto-tickets)

| Fichier | Description |
|---------|-------------|
| `scripts/automation/create-ticket.py` | Script Python de génération de tickets |
| `scripts/automation/n8n-auto-tickets.json` | Export du workflow n8n Auto-Tickets |
| `agents-deck/agents/security/tickets/drafts/` | Répertoire des tickets auto-générés |

---

## Rapport hebdomadaire

### Vue d'ensemble

Le workflow **NetWatch Rapport Hebdomadaire** génère chaque lundi à 08h00 un rapport
JSON agrégé des 7 derniers jours d'alertes Elasticsearch et l'envoie vers Microsoft
Teams sous forme d'Adaptive Card.

**Pipeline** :
```
n8n Schedule (lundi 08h00, cron: 0 8 * * 1)
  → Execute Command : weekly-report.py --days 7 --save-docs
      → docs/reports/weekly-YYYY-WXX.json (archivage automatique)
  → Code JS : parse JSON + prépare données Teams
  → Code JS : construit Adaptive Card (chiffres clés, top 3 règles, sévérités)
  → POST webhook Teams
```

---

### Script weekly-report.py

**Emplacement** : `scripts/automation/weekly-report.py`

Agrège les alertes depuis Elasticsearch (`zeek-*`, `snort-*`, `suricata-*`) sur la
fenêtre temporelle demandée et produit un JSON structuré.

```bash
# Rapport des 7 derniers jours (par défaut)
python3 scripts/automation/weekly-report.py

# Rapport sur 14 jours, fichier de sortie personnalisé
python3 scripts/automation/weekly-report.py --days 14 --output /tmp/report.json

# Rapport + archivage dans docs/reports/
python3 scripts/automation/weekly-report.py --save-docs

# URL ES personnalisée
python3 scripts/automation/weekly-report.py --es-url http://192.168.1.10:9200
```

**Format JSON de sortie** :

```json
{
  "period": { "from": "2026-06-23T08:00:00Z", "to": "2026-06-30T08:00:00Z" },
  "generated_at": "2026-06-30T08:00:00Z",
  "total_alerts": 1247,
  "by_engine": { "zeek": 312, "snort": 418, "suricata": 517 },
  "top_rules": [
    { "name": "ET SCAN Nmap SYN Scan", "count": 89 },
    { "name": "ET MALWARE Meterpreter Session", "count": 42 }
  ],
  "top_src_ips": [
    { "ip": "10.10.1.50", "count": 213 }
  ],
  "severity": { "critical": 14, "high": 87, "medium": 632, "low": 514 },
  "mitre_ttps": [
    { "tactic": "reconnaissance", "count": 312 }
  ]
}
```

**Fonctionnement si ES vide** : chaque requête retourne 0, le rapport est généré avec
tous les compteurs à 0 — aucune erreur levée.

**Archivage automatique** (`--save-docs`) :
Le rapport est sauvegardé dans `docs/reports/weekly-YYYY-WXX.json`
(ex : `docs/reports/weekly-2026-W27.json`) selon la semaine ISO de génération.

---

### Workflow n8n — NetWatch Rapport Hebdomadaire

**Fichier** : `scripts/automation/n8n-weekly-report.json`

#### Import dans n8n

```bash
# Import via API REST n8n
curl -s -u admin:netwatch2026 \
  -X POST http://localhost:5678/rest/workflows \
  -H "Content-Type: application/json" \
  -d @scripts/automation/n8n-weekly-report.json

# Ou via UI :
# http://localhost:5678 → Workflows → Import from file → n8n-weekly-report.json
# → Activer le workflow (toggle ON)
```

#### Architecture des nœuds

| Nœud | Type | Description |
|------|------|-------------|
| Lundi 08h00 | Schedule Trigger | Cron `0 8 * * 1` — chaque lundi à 08h00 |
| Générer le rapport | Execute Command | `python3 weekly-report.py --days 7 --save-docs` |
| Parser le rapport | Code (JS) | Parse stdout JSON, calcule semaine ISO, prépare données |
| Construire carte Teams | Code (JS) | Adaptive Card v1.4 — chiffres clés, top 3 règles, sévérités par moteur |
| Envoyer vers Teams | HTTP Request | POST `$env.TEAMS_WEBHOOK_URL` |

#### Schedule

- **Cron** : `0 8 * * 1` (lundi, 08h00 UTC)
- **Timezone** : régler dans les paramètres n8n si besoin (`TZ=Europe/Paris`)

#### Adaptive Card Teams

La carte envoyée contient :
- **Titre** : `NetWatch — Rapport Hebdomadaire YYYY-WXX`
- **Chiffres clés** : total alertes, répartition par moteur (Zeek/Snort/Suricata), répartition par sévérité (Critical/High/Medium/Low)
- **Top 3 règles** : nom de la règle + nombre de déclenchements
- **Bouton** : lien vers le portail NetWatch (`http://localhost:5050`)

La couleur du titre s'adapte au volume (`Good` = 0 alerte, `Warning` < 100, `Attention` ≥ 100).

---

### Test manuel

```bash
# 1. Injecter des alertes sur la semaine (ES doit tourner)
python3 simulate-traffic.py --hours 1 --intensity high --attack

# 2. Générer le rapport directement
python3 scripts/automation/weekly-report.py --days 7 --output /tmp/report.json
cat /tmp/report.json | python3 -m json.tool | head -30

# 3. Générer avec archivage
python3 scripts/automation/weekly-report.py --save-docs
ls docs/reports/

# 4. Tester le workflow depuis n8n UI :
# http://localhost:5678 → Workflows → NetWatch Rapport Hebdomadaire → Execute Workflow
```

---

### Fichiers associés (Rapport hebdomadaire)

| Fichier | Description |
|---------|-------------|
| `scripts/automation/weekly-report.py` | Script Python d'agrégation ES → rapport JSON |
| `scripts/automation/n8n-weekly-report.json` | Export du workflow n8n Rapport Hebdomadaire |
| `docs/reports/weekly-YYYY-WXX.json` | Rapports archivés (un par semaine ISO) |

---

## Escalade automatique

### Vue d'ensemble

Le workflow **NetWatch Escalade Intelligente** détecte toutes les 5 minutes les IPs
présentant un **score de risque ≥ 80/100** et déclenche automatiquement 3 actions :

1. **Autoblock** — POST webhook Flask → blocage iptables
2. **Ticket critique** — Création ticket YAML via `create-ticket.py`
3. **Notification Teams urgente** — Adaptive Card rouge (si `TEAMS_WEBHOOK_URL` configurée)

Un mécanisme **anti-doublon TTL 4h** évite de re-escalader la même IP trop fréquemment
(`scripts/automation/escalade-history.json`).

**Pipeline** :
```
n8n Schedule (5 min)
  → Execute Command : escalade.py --verbose
      → Source scores (ioc-score.py > /api/ioc-scores > inline ES)
      → Filtre IP score >= 80 (configurable --threshold)
      → Anti-doublon TTL 4h (escalade-history.json)
      → Action 1 : POST http://localhost:5001/webhook/alert (autoblock)
      → Action 2 : echo '<json>' | python3 create-ticket.py (ticket critical)
      → Action 3 : POST TEAMS_WEBHOOK_URL (Adaptive Card rouge urgente)
  → Parser output + log (Code JS)
  → Si exit != 0 → Alerte erreur → Teams
```

---

### Script escalade.py

**Emplacement** : `scripts/automation/escalade.py`

```bash
# Exécution standard (seuil 80, sources auto)
python3 scripts/automation/escalade.py

# Seuil personnalisé
python3 scripts/automation/escalade.py --threshold 70

# Dry-run (simule sans bloquer ni créer de ticket)
python3 scripts/automation/escalade.py --dry-run --verbose

# ES distant
python3 scripts/automation/escalade.py --es-url http://192.168.1.10:9200

# Avec Teams webhook explicite
TEAMS_WEBHOOK_URL=https://xxx.webhook.office.com/... python3 escalade.py
```

#### Options

| Option | Défaut | Description |
|--------|--------|-------------|
| `--threshold` | `80` | Score minimum pour déclencher l'escalade |
| `--es-url` | `http://localhost:9200` | URL Elasticsearch (scoring inline) |
| `--autoblock-url` | `http://localhost:5001/webhook/alert` | Endpoint autoblock Flask |
| `--portal-url` | `http://localhost:5050` | Portail NetWatch (fallback `/api/ioc-scores`) |
| `--dry-run` | — | Simule les actions sans POST ni écriture |
| `--verbose` | — | Logs détaillés par étape |
| `--history-file` | `escalade-history.json` | Fichier JSON anti-doublon |
| `--ttl` | `4` | Durée cooldown en heures |

#### Sources de scores (ordre de priorité)

1. **`ioc-score.py` subprocess** (T_014 — quand mergé) — appel `python3 ioc-score.py --threshold N --output-json`
2. **HTTP `/api/ioc-scores`** — fallback portail NetWatch
3. **Scoring inline ES** — requête directe `suricata-*,snort-*,zeek-*` sur 30 min

**Formule de scoring inline** :
```
score = critical_count × 5 + high_count × 2
      + bonus_multi_engine (3 moteurs: +15, 2 moteurs: +8)
      + bonus_volume (≥20 alertes: +15, ≥10: +10)
      (plafonné à 100)
```

#### Anti-doublon

- Fichier : `scripts/automation/escalade-history.json`
- Format : `{"1.2.3.4": {"escalated_at": "2026-06-30T14:00:00+00:00", "score": 87}}`
- TTL : 4h par IP (configurable `--ttl`)
- Nettoyage automatique des entrées expirées à chaque exécution

#### Format autoblock (Action 1)

```json
{
  "alerts": [{
    "labels": {"ip": "1.2.3.4", "severity": "critical"},
    "annotations": {"summary": "Score risque 87/100 — escalade automatique"}
  }]
}
```

#### Format ticket (Action 2)

JSON passé en stdin à `create-ticket.py` :
```json
{
  "@timestamp": "2026-06-30T14:00:00+00:00",
  "src_ip": "1.2.3.4",
  "alert": {
    "signature": "ESCALADE AUTOMATIQUE — IP 1.2.3.4 (score 87/100)",
    "severity": 1,
    "category": "Escalade risque élevé"
  },
  "severity": "critical",
  "engine": "escalade",
  "escalade": {"score": 87, "reason": "15 alerte(s) · 8 critique(s) · 3 moteurs (suricata, snort, zeek)"}
}
```

#### Format Teams urgent (Action 3)

Adaptive Card rouge envoyée si `TEAMS_WEBHOOK_URL` est définie dans l'environnement :
```json
{
  "type": "message",
  "attachments": [{
    "contentType": "application/vnd.microsoft.card.adaptive",
    "content": {
      "type": "AdaptiveCard",
      "body": [
        {"type": "TextBlock", "text": "🚨 ESCALADE — IP 1.2.3.4 (score 87/100)", "size": "Large", "color": "Attention"},
        {"type": "TextBlock", "text": "Raison : 15 alerte(s) · 8 critique(s) · 3 moteurs"},
        {"type": "FactSet", "facts": [{"title": "IP", "value": "1.2.3.4"}, ...]}
      ]
    }
  }]
}
```

---

### Workflow n8n — NetWatch Escalade Intelligente

**Fichier** : `scripts/automation/n8n-escalade.json`

#### Import dans n8n

```bash
# Import via API REST
curl -s -u admin:netwatch2026 \
  -X POST http://localhost:5678/rest/workflows \
  -H "Content-Type: application/json" \
  -d @scripts/automation/n8n-escalade.json

# Ou via UI :
# http://localhost:5678 → Workflows → Import from file → n8n-escalade.json
# → Activer le workflow (toggle ON)
```

#### Architecture des nœuds

| Nœud | Type | Description |
|------|------|-------------|
| Toutes les 5 min | Schedule Trigger | Déclencheur cron toutes les 5 minutes |
| Exécuter escalade.py | Execute Command | `python3 /home/ourslow/code/netwatch/scripts/automation/escalade.py --verbose 2>&1` |
| Parser output + log | Code (JS) | Parse stdout, extrait IPs escaladées, log résumé dans n8n |
| Erreur d'escalade ? | IF | Vérifie `exitCode != 0` |
| Alerte erreur → Teams | HTTP Request | POST Teams card d'erreur si exit non-nul |
| Escalade OK — Stop | NoOp | Branche succès — rien à faire |

#### Variable d'environnement requise (optionnelle pour Teams)

```bash
# Dans .env :
TEAMS_WEBHOOK_URL=https://xxx.webhook.office.com/webhookb2/...

# Dans docker-compose.yml, service n8n :
environment:
  - TEAMS_WEBHOOK_URL=${TEAMS_WEBHOOK_URL}
```

---

### Test manuel

```bash
# 1. Injecter des alertes critiques massives dans ES
python3 simulate-traffic.py --hours 0.1 --intensity high --attack

# 2. Tester escalade.py en dry-run
python3 scripts/automation/escalade.py --dry-run --verbose

# 3. Tester avec threshold bas pour forcer une escalade
python3 scripts/automation/escalade.py --threshold 1 --dry-run --verbose

# 4. Vérifier l'historique anti-doublon
cat scripts/automation/escalade-history.json | python3 -m json.tool

# 5. Tester l'autoblock directement
curl -X POST http://localhost:5001/webhook/alert \
  -H "Content-Type: application/json" \
  -d '{"alerts": [{"labels": {"ip": "1.2.3.4", "severity": "critical"}, "annotations": {"summary": "Test manuel"}}]}'

# 6. Exécution manuelle dans n8n UI :
# http://localhost:5678 → Workflows → NetWatch Escalade Intelligente → Execute Workflow
```

---

### Fichiers associés (Escalade automatique)

| Fichier | Description |
|---------|-------------|
| `scripts/automation/escalade.py` | Script Python d'escalade intelligente (scoring + 3 actions) |
| `scripts/automation/escalade-history.json` | Historique anti-doublon TTL 4h (auto-créé) |
| `scripts/automation/n8n-escalade.json` | Export du workflow n8n Escalade Intelligente |
| `scripts/automation/create-ticket.py` | Générateur de tickets (appelé par escalade.py) |
