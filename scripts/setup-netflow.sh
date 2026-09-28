#!/usr/bin/env bash
# scripts/setup-netflow.sh — Initialise ES pour NetFlow / IPFIX / sFlow (T_017)
#
# Ce script :
#   1. Politique ILM netwatch-netflow via scripts/setup-ilm.sh (ES_RETENTION_NETFLOW_DAYS, 30 j)
#   2. Crée le composant mapping netwatch-netflow-mappings
#   3. Crée l'index template netwatch-netflow pour le pattern netflow-*
#
# Usage :
#   bash scripts/setup-netflow.sh
#   ES=http://localhost:9200 bash scripts/setup-netflow.sh

set -euo pipefail

ES="${ES:-http://localhost:9200}"
CURL_OPTS="-sf --max-time 15"

# ============================================================
# Couleurs
# ============================================================
C_GREEN='\033[0;32m'
C_RED='\033[0;31m'
C_BOLD='\033[1m'
C_RESET='\033[0m'

ok()   { printf "  ${C_GREEN}✓${C_RESET} %s\n" "$1"; }
err()  { printf "  ${C_RED}✗${C_RESET} %s\n" "$1" >&2; }
info() { printf "  → %s\n" "$1"; }

# ============================================================
# Attendre ES
# ============================================================
printf "\n${C_BOLD}NetWatch — Setup NetFlow Elasticsearch${C_RESET}\n"
printf "  ES : %s\n\n" "$ES"

info "Attente Elasticsearch..."
for i in $(seq 1 20); do
  if curl $CURL_OPTS "${ES}/_cluster/health" > /dev/null 2>&1; then
    ok "Elasticsearch accessible"
    break
  fi
  if [ "$i" -eq 20 ]; then
    err "Elasticsearch inaccessible après 20 tentatives"
    exit 1
  fi
  sleep 3
done

# ============================================================
# 1. Politique ILM — scripts/setup-ilm.sh (rétention ES_RETENTION_NETFLOW_DAYS, 30 j par défaut).
#    Les index netflow-* sont journaliers (Filebeat) : pas de rollover ni d'alias.
# ============================================================
info "Politique ILM netwatch-netflow (scripts/setup-ilm.sh)..."
if ES="$ES" bash "$(dirname "$0")/setup-ilm.sh" >/dev/null; then
  ok "Politiques ILM en place"
else
  err "scripts/setup-ilm.sh en échec"
  exit 1
fi

# ============================================================
# 2. Index template netflow-* avec mapping
# ============================================================
info "Création index template netwatch-netflow (pattern: netflow-*)..."

RESP=$(curl $CURL_OPTS -o /dev/null -w "%{http_code}" \
  -X PUT "${ES}/_index_template/netwatch-netflow" \
  -H "Content-Type: application/json" \
  -d '{
    "index_patterns": ["netflow-*"],
    "priority": 500,
    "template": {
      "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
        "index.lifecycle.name": "netwatch-netflow"
      },
      "mappings": {
        "dynamic": true,
        "properties": {
          "@timestamp": {
            "type": "date"
          },
          "netflow": {
            "properties": {
              "type": {
                "type": "keyword"
              },
              "src_addr": {
                "type": "ip"
              },
              "dst_addr": {
                "type": "ip"
              },
              "next_hop": {
                "type": "ip"
              },
              "sampler_addr": {
                "type": "ip"
              },
              "src_port": {
                "type": "integer"
              },
              "dst_port": {
                "type": "integer"
              },
              "in_if": {
                "type": "integer"
              },
              "out_if": {
                "type": "integer"
              },
              "src_as": {
                "type": "long"
              },
              "dst_as": {
                "type": "long"
              },
              "proto": {
                "type": "keyword"
              },
              "bytes": {
                "type": "long"
              },
              "packets": {
                "type": "long"
              },
              "start": {
                "type": "date",
                "format": "epoch_second||epoch_millis||strict_date_optional_time"
              },
              "end": {
                "type": "date",
                "format": "epoch_second||epoch_millis||strict_date_optional_time"
              }
            }
          },
          "engine": {
            "type": "keyword"
          },
          "log_type": {
            "type": "keyword"
          },
          "container": {
            "properties": {
              "name": { "type": "keyword" },
              "id":   { "type": "keyword" },
              "image": {
                "properties": {
                  "name": { "type": "keyword" }
                }
              }
            }
          }
        }
      }
    }
  }')

if [ "$RESP" = "200" ] || [ "$RESP" = "201" ]; then
  ok "Index template netwatch-netflow créé (priorité 500)"
else
  err "Echec création index template (HTTP ${RESP})"
  exit 1
fi

# ============================================================
# 3. Vérification
# ============================================================
info "Vérification du template..."

TMPL=$(curl $CURL_OPTS "${ES}/_index_template/netwatch-netflow" 2>/dev/null | \
  python3 -c "import sys,json; d=json.load(sys.stdin); print(d['index_templates'][0]['name'])" 2>/dev/null || echo "")

if [ "$TMPL" = "netwatch-netflow" ]; then
  ok "Template netwatch-netflow confirmé"
else
  err "Template non trouvé après création"
  exit 1
fi

# ============================================================
# Résumé
# ============================================================
printf "\n${C_GREEN}${C_BOLD}Setup NetFlow terminé.${C_RESET}\n"
printf "  ILM policy  : netwatch-netflow (ES_RETENTION_NETFLOW_DAYS, 30 j par défaut — make setup-ilm)\n"
printf "  Template     : netwatch-netflow  (pattern: netflow-*)\n"
printf "  Mapping     : src_addr/dst_addr(ip), bytes/packets(long),\n"
printf "                proto(keyword), ports(integer), timestamps(date)\n"
printf "\n"
printf "  Pour vérifier : curl '%s/_index_template/netwatch-netflow?pretty'\n" "$ES"
printf "  Indices actifs : curl '%s/_cat/indices/netflow-*?v'\n" "$ES"
printf "\n"
