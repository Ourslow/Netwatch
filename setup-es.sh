#!/bin/bash
# setup-es.sh — Configuration initiale Elasticsearch pour NetWatch
# - Désactive les réplicas (nœud unique → ES toujours green)
# - Crée les templates d'index pour zeek-*, snort-*, suricata-*

set -euo pipefail
ES="${NETWATCH_ES_URL:-http://localhost:9200}"

# Wrapper curl : toujours retourner le body même sur erreur HTTP
es_put() {
  local url="$1"; shift
  curl -s -X PUT "$ES$url" -H "Content-Type: application/json" "$@"
}

es_ok() {
  local body="$1"
  echo "$body" | python3 -c "
import sys, json
raw = sys.stdin.read().strip()
if not raw:
    print('  WARN: réponse vide')
    sys.exit(0)
try:
    d = json.loads(raw)
    if d.get('acknowledged') or d.get('errors') == False:
        print('  OK')
    else:
        print('  ' + raw[:120])
except Exception:
    print('  ' + raw[:120])
"
}

echo "=== Configuration Elasticsearch ==="
echo "Cible : $ES"

# Attendre qu'ES soit disponible
echo -n "Attente ES..."
until curl -sf "$ES/_cluster/health" > /dev/null 2>&1; do
  echo -n "."
  sleep 2
done
echo " OK"

# 1. Réplicas à 0 sur tous les index existants
echo "[1/3] Réplicas → 0 sur les index existants..."
es_ok "$(es_put "/_settings" -d '{"index":{"number_of_replicas":0}}')"

# 2. Templates d'index (prio 500, réplicas 0 par défaut pour les nouveaux index)
echo "[2/3] Templates zeek-* / snort-* / suricata-*..."
for engine in zeek snort suricata; do
  body=$(es_put "/_index_template/netwatch-$engine" -d "{
    \"index_patterns\": [\"$engine-*\"],
    \"priority\": 500,
    \"template\": {
      \"settings\": {
        \"number_of_shards\": 1,
        \"number_of_replicas\": 0
      }
    }
  }")
  echo -n "  $engine : "
  es_ok "$body"
done

# 3. Vérification finale
echo ""
echo "[3/3] Statut cluster..."
curl -s "$ES/_cluster/health" | python3 -c "
import sys, json
d = json.loads(sys.stdin.read())
status = d.get('status','?')
color = {'green':'\033[32m', 'yellow':'\033[33m', 'red':'\033[31m'}.get(status,'')
reset = '\033[0m'
print(f'  Cluster : {color}{status.upper()}{reset}')
print(f'  Nœuds   : {d.get(\"number_of_nodes\",\"?\")}')
print(f'  Shards  : {d.get(\"active_shards\",\"?\")} actifs / {d.get(\"unassigned_shards\",\"?\")} non assignés')
"
echo ""
echo "Configuration terminée."
