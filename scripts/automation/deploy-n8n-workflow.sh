#!/usr/bin/env bash
# deploy-n8n-workflow.sh — Importe un workflow NetWatch dans n8n via API REST
# Usage : ./scripts/automation/deploy-n8n-workflow.sh [chemin-vers-workflow.json]
#   (par défaut : n8n-alertes-teams.json)
set -euo pipefail

N8N_URL="${N8N_URL:-http://localhost:5678}"
N8N_USER="${N8N_USER:-admin}"
N8N_PASS="${N8N_PASSWORD:?N8N_PASSWORD manquant}"
WORKFLOW_FILE="${1:-$(dirname "$0")/n8n-alertes-teams.json}"
WF_NAME="$(python3 -c "import json; print(json.load(open('$WORKFLOW_FILE'))['name'])")"

echo "=== NetWatch — Deploy n8n Workflow ==="
echo "URL  : $N8N_URL"
echo "File : $WORKFLOW_FILE"
echo "Nom  : $WF_NAME"
echo ""

# Attendre que n8n soit prêt
echo "[1/4] Attente démarrage n8n..."
for i in $(seq 1 30); do
  if curl -s -o /dev/null -w "%{http_code}" -u "$N8N_USER:$N8N_PASS" "$N8N_URL/rest/workflows" | grep -q "200"; then
    echo "      n8n est prêt."
    break
  fi
  echo "      Tentative $i/30 — attente 5s..."
  sleep 5
done

# Vérifier si le workflow existe déjà
echo "[2/4] Vérification workflow existant..."
EXISTING=$(curl -s -u "$N8N_USER:$N8N_PASS" "$N8N_URL/rest/workflows" | python3 -c "
import sys, json
data = json.load(sys.stdin)
workflows = data.get('data', [])
for wf in workflows:
    if wf.get('name') == '$WF_NAME':
        print(wf['id'])
        break
" 2>/dev/null || true)

if [ -n "$EXISTING" ]; then
  echo "      Workflow existant trouvé (id=$EXISTING) — mise à jour..."
  # Récupérer le workflow JSON et mettre à jour
  WORKFLOW_JSON=$(python3 -c "
import json
with open('$WORKFLOW_FILE') as f:
    wf = json.load(f)
# n8n attend nodes/connections/settings/name/tags
payload = {
    'name': wf['name'],
    'nodes': wf['nodes'],
    'connections': wf['connections'],
    'settings': wf.get('settings', {}),
    'staticData': wf.get('staticData'),
    'tags': [t['name'] for t in wf.get('tags', [])]
}
print(json.dumps(payload))
")
  RESPONSE=$(curl -s -X PUT "$N8N_URL/rest/workflows/$EXISTING" \
    -u "$N8N_USER:$N8N_PASS" \
    -H "Content-Type: application/json" \
    -d "$WORKFLOW_JSON")
  echo "      Mis à jour : $RESPONSE" | head -c 200
else
  echo "      Création du workflow..."
  WORKFLOW_JSON=$(python3 -c "
import json
with open('$WORKFLOW_FILE') as f:
    wf = json.load(f)
payload = {
    'name': wf['name'],
    'nodes': wf['nodes'],
    'connections': wf['connections'],
    'settings': wf.get('settings', {}),
    'staticData': wf.get('staticData'),
    'tags': [{'name': t['name']} for t in wf.get('tags', [])]
}
print(json.dumps(payload))
")
  RESPONSE=$(curl -s -X POST "$N8N_URL/rest/workflows" \
    -u "$N8N_USER:$N8N_PASS" \
    -H "Content-Type: application/json" \
    -d "$WORKFLOW_JSON")
  WF_ID=$(echo "$RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('data',{}).get('id','?'))" 2>/dev/null || echo "?")
  echo "      Créé — id=$WF_ID"
fi

# Activer le workflow
echo "[3/4] Activation du workflow..."
if [ -n "$EXISTING" ]; then
  WF_ID="$EXISTING"
fi
if [ "$WF_ID" != "?" ] && [ -n "$WF_ID" ]; then
  curl -s -X POST "$N8N_URL/rest/workflows/$WF_ID/activate" \
    -u "$N8N_USER:$N8N_PASS" \
    -H "Content-Type: application/json" > /dev/null && echo "      Workflow activé."
fi

# Vérification finale
echo "[4/4] Vérification..."
curl -s -u "$N8N_USER:$N8N_PASS" "$N8N_URL/rest/workflows" | python3 -c "
import sys, json
data = json.load(sys.stdin)
workflows = data.get('data', [])
for wf in workflows:
    if wf.get('name') == '$WF_NAME':
        active = 'ACTIF' if wf.get('active') else 'INACTIF'
        print(f'      Workflow : {wf[\"name\"]} [{active}] — id={wf[\"id\"]}')
" 2>/dev/null || echo "      (vérification manuelle requise)"

echo ""
echo "=== DONE ==="
echo ""
echo "IMPORTANT — Configurer le webhook Teams :"
echo "  1. Dans Teams : Gérer l'équipe → Connecteurs → Incoming Webhook"
echo "  2. Copier l'URL générée (https://xxx.webhook.office.com/...)"
echo "  3. Dans n8n : Settings → Variables → TEAMS_WEBHOOK_URL = <url>"
echo "     OU : docker compose exec n8n sh -c 'export TEAMS_WEBHOOK_URL=<url>'"
echo "     OU : ajouter N8N_CUSTOM_ENV_VARS=TEAMS_WEBHOOK_URL dans docker-compose.yml"
echo ""
echo "Portail : $N8N_URL"
