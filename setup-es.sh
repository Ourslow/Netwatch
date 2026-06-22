#!/bin/bash
# setup-es.sh — Configuration initiale Elasticsearch pour NetWatch
# - Désactive les réplicas (nœud unique → ES toujours green)
# - Crée les templates d'index pour zeek-*, snort-*, suricata-*

set -euo pipefail
ES="${NETWATCH_ES_URL:-http://localhost:9200}"

echo "=== Configuration Elasticsearch ==="
echo "Cible : $ES"

# Attendre qu'ES soit disponible
echo -n "Attente ES..."
until curl -sf "$ES/_cluster/health" > /dev/null 2>&1; do
  echo -n "."
  sleep 2
done
echo " OK"

# 1. Réplicas à 0 sur tous les index existants (évite status yellow)
echo "[1/3] Réplicas → 0 sur les index existants..."
curl -sf -X PUT "$ES/_settings" \
  -H "Content-Type: application/json" \
  -d '{"index":{"number_of_replicas":0}}' | python3 -c "import sys,json; d=json.load(sys.stdin); print('  OK' if d.get('acknowledged') else '  WARN: ' + str(d))"

# 2. Template Zeek (plain index, prio 500, réplicas 0 par défaut)
echo "[2/3] Template index zeek-*..."
curl -sf -X PUT "$ES/_index_template/netwatch-zeek" \
  -H "Content-Type: application/json" \
  -d '{
    "index_patterns": ["zeek-*"],
    "priority": 500,
    "template": {
      "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0
      }
    }
  }' | python3 -c "import sys,json; d=json.load(sys.stdin); print('  OK' if d.get('acknowledged') else '  WARN: ' + str(d))"

# 3. Template Snort
echo "[3/3] Templates snort-* et suricata-*..."
for engine in snort suricata; do
  curl -sf -X PUT "$ES/_index_template/netwatch-$engine" \
    -H "Content-Type: application/json" \
    -d "{
      \"index_patterns\": [\"$engine-*\"],
      \"priority\": 500,
      \"template\": {
        \"settings\": {
          \"number_of_shards\": 1,
          \"number_of_replicas\": 0
        }
      }
    }" | python3 -c "import sys,json; d=json.load(sys.stdin); print('  $engine: OK' if d.get('acknowledged') else '  $engine WARN: ' + str(d))"
done

# Vérification finale
echo ""
echo "=== Résultat ==="
curl -sf "$ES/_cluster/health?pretty" | python3 -c "
import sys, json
d = json.load(sys.stdin)
status = d.get('status','?')
color = {'green':'\\033[32m', 'yellow':'\\033[33m', 'red':'\\033[31m'}.get(status,'')
reset = '\\033[0m'
print(f'  Cluster : {color}{status.upper()}{reset}')
print(f'  Nœuds   : {d.get(\"number_of_nodes\",\"?\")}')
print(f'  Shards  : {d.get(\"active_shards\",\"?\")} actifs / {d.get(\"unassigned_shards\",\"?\")} non assignés')
"
echo ""
echo "Configuration terminée."
