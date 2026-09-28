#!/bin/bash
# scripts/setup-ilm.sh — Rétention des index Elasticsearch (ILM). Idempotent.
#
#   Politique             Index                                    Variable .env                 Défaut
#   netwatch-events       zeek-* snort-* suricata-*                ES_RETENTION_DAYS             30 j
#   netwatch-netflow      netflow-*                                ES_RETENTION_NETFLOW_DAYS     = ES_RETENTION_DAYS
#   netwatch-detections   netwatch-beacons-* netwatch-autoblock-*  ES_RETENTION_DETECTIONS_DAYS  90 j
#
# Les index sont journaliers (Filebeat, beacon-detect, autoblock) : pas de rollover, l'âge
# d'un index est celui de sa création. Phase warm à 2 jours : lecture seule + forcemerge
# (moins de segments, moins de heap). Les index existants sont rattachés ; un index netflow
# bloqué sur l'ancien rollover (sans alias) est réinscrit dans la politique.
#
# Modifier la rétention : éditer les variables dans .env puis `make setup-ilm` (ou setup-es).
# Vérifier : curl 'http://localhost:9200/zeek-*,netflow-*/_ilm/explain?pretty'
set -euo pipefail
cd "$(dirname "$0")/.."
ES="${NETWATCH_ES_URL:-${ES:-http://localhost:9200}}"

# Variables de rétention lues dans .env (le script peut être lancé sans `make`)
if [ -f .env ]; then
  while IFS='=' read -r k v; do
    v="${v//[^0-9]/}"; [ -n "$v" ] && export "$k=$v"
  done < <(grep -E '^ES_RETENTION_[A-Z_]+=' .env || true)
fi
DAYS="${ES_RETENTION_DAYS:-30}"
NF_DAYS="${ES_RETENTION_NETFLOW_DAYS:-$DAYS}"
DET_DAYS="${ES_RETENTION_DETECTIONS_DAYS:-90}"
for v in "$DAYS" "$NF_DAYS" "$DET_DAYS"; do
  [[ "$v" =~ ^[0-9]+$ ]] && [ "$v" -ge 1 ] || { echo "  ✗ rétention invalide : '$v' (jours, entier ≥ 1)" >&2; exit 1; }
done

ok()   { printf '  ✓ %s\n' "$1"; }
fail() { printf '  ✗ %s\n' "$1" >&2; exit 1; }
es() { # <méthode> <chemin> [body] → code HTTP, corps dans $BODY
  local m="$1" p="$2" d="${3:-}"
  BODY=$(curl -s -w '\n%{http_code}' -X "$m" "$ES$p" -H 'Content-Type: application/json' ${d:+-d "$d"})
  CODE="${BODY##*$'\n'}"; BODY="${BODY%$'\n'*}"
}

curl -sf "$ES/_cluster/health" >/dev/null || fail "Elasticsearch injoignable sur $ES"

# ── 1. Politiques ────────────────────────────────────────────────────────────
# Phase warm seulement si elle précède la suppression (ES exige des min_age croissants)
warm='"warm":{"min_age":"2d","actions":{"readonly":{},"forcemerge":{"max_num_segments":1},"set_priority":{"priority":50}}},'
[ "$DAYS" -le 2 ] && warm=""
hot='"hot":{"min_age":"0ms","actions":{"set_priority":{"priority":100}}}'

policy() { # <nom> <jours> <warm>
  es PUT "/_ilm/policy/$1" "{\"policy\":{\"phases\":{$hot,$3\"delete\":{\"min_age\":\"$2d\",\"actions\":{\"delete\":{}}}}}}"
  [ "$CODE" = 200 ] && ok "politique $1 : suppression après $2 j" || fail "politique $1 : HTTP $CODE ${BODY:0:200}"
}
policy netwatch-events      "$DAYS"     "$warm"
policy netwatch-netflow     "$NF_DAYS"  ""
policy netwatch-detections  "$DET_DAYS" ""

# ── 2. Template des détections (les templates zeek/snort/suricata sont dans setup-es.sh,
#       netflow dans scripts/setup-netflow.sh — ils référencent ces politiques) ───────────
es PUT "/_index_template/netwatch-detections" '{"index_patterns":["netwatch-beacons-*","netwatch-autoblock-*"],"priority":500,
  "template":{"settings":{"number_of_shards":1,"number_of_replicas":0,"index.lifecycle.name":"netwatch-detections"}}}'
[ "$CODE" = 200 ] && ok "template netwatch-detections (netwatch-beacons-*, netwatch-autoblock-*)" || fail "template netwatch-detections : HTTP $CODE"

# ── 3. Index existants ───────────────────────────────────────────────────────
attach() { # <pattern> <politique> [settings supplémentaires]
  es PUT "/$1/_settings?allow_no_indices=true&ignore_unavailable=true&expand_wildcards=open" \
     "{\"index.lifecycle.name\":\"$2\"${3:+,$3}}"
  case "$CODE" in
    200) ok "index $1 → $2" ;;
    404) ok "index $1 : aucun pour l'instant" ;;
    *)   fail "index $1 : HTTP $CODE ${BODY:0:200}" ;;
  esac
}
attach "zeek-*,snort-*,suricata-*"                 netwatch-events
attach "netwatch-beacons-*,netwatch-autoblock-*"   netwatch-detections
attach "netflow-*"                                 netwatch-netflow '"index.lifecycle.rollover_alias":null'

# Index netflow inscrits avant la 2.2.0 : bloqués sur l'étape rollover d'une phase déjà mise en
# cache (ILM ne relit une phase modifiée qu'en changeant de phase) → retrait puis réinscription.
es GET "/netflow-*/_ilm/explain?only_managed=true"
stuck=$(NW_BODY="$BODY" python3 - <<'PY'
import json, os
try:
    d = json.loads(os.environ["NW_BODY"]).get("indices", {})
except ValueError:
    d = {}
print(" ".join(k for k, v in d.items() if v.get("action") == "rollover" or v.get("step") == "ERROR"))
PY
)
for idx in $stuck; do
  es POST "/$idx/_ilm/remove"
  es PUT "/$idx/_settings" '{"index.lifecycle.name":"netwatch-netflow"}'
  [ "$CODE" = 200 ] && ok "index $idx réinscrit (ancien rollover)" || fail "index $idx : HTTP $CODE"
done

# ── 4. Résumé ────────────────────────────────────────────────────────────────
es GET "/zeek-*,snort-*,suricata-*,netflow-*,netwatch-beacons-*,netwatch-autoblock-*/_ilm/explain?only_managed=false"
NW_BODY="$BODY" python3 - <<'PY'
import json, os
d = json.loads(os.environ["NW_BODY"]).get("indices", {})
managed = sum(1 for v in d.values() if v.get("managed"))
print(f"  Rétention : événements {os.environ.get('ES_RETENTION_DAYS', '30')} j · NetFlow "
      f"{os.environ.get('ES_RETENTION_NETFLOW_DAYS') or os.environ.get('ES_RETENTION_DAYS', '30')} j · "
      f"détections {os.environ.get('ES_RETENTION_DETECTIONS_DAYS', '90')} j — {managed}/{len(d)} index gérés")
PY
