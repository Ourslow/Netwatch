#!/bin/bash
# NetWatch — Setup GeoIP pipeline dans Elasticsearch
# A lancer une seule fois apres 'docker compose up -d'
# Usage : ./setup-geoip.sh [ES_URL]

ES_URL=${1:-http://localhost:9200}

echo "[NetWatch] Attente Elasticsearch..."
until curl -sf "$ES_URL/_cluster/health" > /dev/null 2>&1; do
  sleep 3
done
echo "[NetWatch] Elasticsearch pret."

# Creer le pipeline GeoIP
echo "[NetWatch] Creation du pipeline netwatch-geoip..."
curl -sf -X PUT "$ES_URL/_ingest/pipeline/netwatch-geoip" \
  -H 'Content-Type: application/json' \
  -d @elasticsearch/pipelines/netwatch-geoip.json \
  && echo " OK" || echo " ERREUR"

# Index template zeek-* avec pipeline par defaut
echo "[NetWatch] Index template zeek-*..."
curl -sf -X PUT "$ES_URL/_index_template/netwatch-zeek" \
  -H 'Content-Type: application/json' \
  -d '{"index_patterns":["zeek-*"],"priority":1,"template":{"settings":{"default_pipeline":"netwatch-geoip","number_of_shards":1,"number_of_replicas":0}}}' \
  && echo " OK" || echo " ERREUR"

# Index template snort-* avec pipeline par defaut
echo "[NetWatch] Index template snort-*..."
curl -sf -X PUT "$ES_URL/_index_template/netwatch-snort" \
  -H 'Content-Type: application/json' \
  -d '{"index_patterns":["snort-*"],"priority":1,"template":{"settings":{"default_pipeline":"netwatch-geoip","number_of_shards":1,"number_of_replicas":0}}}' \
  && echo " OK" || echo " ERREUR"

# Index template suricata-* avec pipeline par defaut
echo "[NetWatch] Index template suricata-*..."
curl -sf -X PUT "$ES_URL/_index_template/netwatch-suricata" \
  -H 'Content-Type: application/json' \
  -d '{"index_patterns":["suricata-*"],"priority":1,"template":{"settings":{"default_pipeline":"netwatch-geoip","number_of_shards":1,"number_of_replicas":0}}}' \
  && echo " OK" || echo " ERREUR"

echo ""
echo "[NetWatch] Setup GeoIP termine !"
echo "[NetWatch] Les nouveaux documents seront automatiquement enrichis."
echo "[NetWatch] Verifier : curl $ES_URL/_ingest/pipeline/netwatch-geoip"
