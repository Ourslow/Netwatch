#!/bin/bash
# setup-kibana.sh — Data views Kibana pour les index NetWatch (Discover prêt à l'emploi).
# Idempotent : une data view existante (même id) est laissée telle quelle.
# Ids fixes → le portail peut lier directement une data view (bouton « Kibana » sur /zeek).
set -euo pipefail
KB="${NETWATCH_KIBANA_URL:-http://localhost:5601}"
H=(-H "kbn-xsrf: netwatch" -H "Content-Type: application/json")

echo "=== Kibana : attente de disponibilité ($KB) ==="
for i in $(seq 1 60); do
  lvl=$(curl -s -m 5 "$KB/api/status" | python3 -c "import sys,json;print(json.load(sys.stdin)['status']['overall']['level'])" 2>/dev/null || true)
  [ "$lvl" = "available" ] && break; sleep 5
done
[ "$lvl" = "available" ] || { echo "ERREUR : Kibana indisponible (status=$lvl)"; exit 1; }

# id | titre (pattern) | champ temps | nom affiché
VIEWS="
netwatch-zeek|zeek-*|@timestamp|Zeek (conn, dns, http, ssl…)
netwatch-suricata|suricata-*|@timestamp|Suricata (alertes, flows)
netwatch-snort|snort-*|@timestamp|Snort (alertes)
netwatch-netflow|netflow-*|@timestamp|NetFlow / IPFIX / sFlow (GoFlow2)
netwatch-beacons|netwatch-beacons-*|@timestamp|Beacons (RITA-lite)
netwatch-arkime|arkime_sessions3-*|@timestamp|Arkime (sessions PCAP)
"
echo "$VIEWS" | grep -v '^\s*$' | while IFS='|' read -r id title tf name; do
  if curl -sf -m 10 "$KB/api/data_views/data_view/$id" >/dev/null 2>&1; then
    echo "  = $id ($title) existe"
  else
    body=$(python3 -c "import json,sys;print(json.dumps({'data_view':{'id':sys.argv[1],'title':sys.argv[2],'timeFieldName':sys.argv[3],'name':sys.argv[4],'allowNoIndex':True}}))" "$id" "$title" "$tf" "$name")
    curl -sf -m 20 "${H[@]}" -X POST "$KB/api/data_views/data_view" -d "$body" >/dev/null && echo "  + $id ($title) créée" || echo "  ! $id : échec de création"
  fi
done
curl -sf -m 10 "${H[@]}" -X POST "$KB/api/data_views/default" -d '{"data_view_id":"netwatch-zeek","force":true}' >/dev/null && echo "  * data view par défaut : netwatch-zeek"
echo "Terminé — Discover : $KB/app/discover#/?_a=(dataSource:(dataViewId:'netwatch-zeek',type:dataView))"
