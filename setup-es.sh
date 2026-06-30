#!/bin/bash
# setup-es.sh — Configuration initiale Elasticsearch pour NetWatch
# - Désactive les réplicas (nœud unique → ES toujours green)
# - Installe le pipeline GeoIP (netwatch-geoip)
# - Crée les index-templates pour zeek-*, snort-*, suricata-*
#   Priorité 500 → prend toujours le dessus sur le template Filebeat (150)
#
# Fix T_002 : setup-geoip.sh est désormais intégré ici pour éviter que les
# templates référencent un pipeline absent (default_pipeline: netwatch-geoip).

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
echo "[1/4] Réplicas → 0 sur les index existants..."
es_ok "$(es_put "/_settings" -d '{"index":{"number_of_replicas":0}}')"

# 2. Pipeline GeoIP (requis par les templates avant de créer des index)
echo "[2/4] Pipeline netwatch-geoip..."
PIPELINE_JSON=$(cat "$(dirname "$0")/elasticsearch/pipelines/netwatch-geoip.json")
es_ok "$(es_put "/_ingest/pipeline/netwatch-geoip" -d "$PIPELINE_JSON")"

# 3. Index-templates moteur (prio 500, réplicas 0, pipeline GeoIP par défaut)
#    Prio 500 > prio 150 du template Filebeat → les settings moteur priment.
#    NB: le template Filebeat "netwatch" a pattern "netwatch-*" (fix T_002) et
#    ne conflit donc plus avec ces templates zeek-*/snort-*/suricata-*.
echo "[3/4] Index-templates zeek-* / snort-* / suricata-*..."
for engine in zeek snort suricata; do
  body=$(es_put "/_index_template/netwatch-$engine" -d "{
    \"index_patterns\": [\"$engine-*\"],
    \"priority\": 500,
    \"template\": {
      \"settings\": {
        \"number_of_shards\": 1,
        \"number_of_replicas\": 0,
        \"default_pipeline\": \"netwatch-geoip\"
      }
    }
  }")
  echo -n "  $engine : "
  es_ok "$body"
done

# 4. Vérification finale
echo ""
echo "[4/4] Statut cluster..."
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
