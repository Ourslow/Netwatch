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
| `scripts/automation/n8n-alertes-teams.json` | Export du workflow n8n |
| `scripts/automation/deploy-n8n-workflow.sh` | Script de déploiement via API REST |
| `docs/n8n-setup.md` | Ce fichier |
