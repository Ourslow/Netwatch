#!/usr/bin/env bash
# scripts/health-check.sh — NetWatch Health Check
# Vérifie les 12 services NetWatch et produit un rapport coloré.
#
# Exit codes :
#   0  Tous les services OK
#   1  Dégradé (1+ services en warning/erreur non critique)
#   2  Critique (1+ services arrêtés ou ES en red)
#
# Usage :
#   bash scripts/health-check.sh
#   bash scripts/health-check.sh --json      # sortie JSON brute (pour intégration)
#   bash scripts/health-check.sh --no-color  # désactive les couleurs (CI)

set -euo pipefail

# ============================================================
# Configuration
# ============================================================
ES="${NETWATCH_ES_URL:-http://localhost:9200}"
GRAFANA_URL="${NETWATCH_GRAFANA_URL:-http://localhost:3000}"
N8N_URL="${NETWATCH_N8N_URL:-http://localhost:5678}"
FLASK_URL="${NETWATCH_FLASK_URL:-http://localhost:5050}"
PROMETHEUS_URL="${NETWATCH_PROMETHEUS_URL:-http://localhost:9090}"
OLLAMA_URL="${NETWATCH_OLLAMA_URL:-http://localhost:11434}"
CURL_TIMEOUT="${NETWATCH_CURL_TIMEOUT:-5}"
FILEBEAT_RECENT_MINUTES="${NETWATCH_FILEBEAT_RECENT:-5}"

JSON_OUTPUT=false
USE_COLOR=true
for arg in "$@"; do
  case "$arg" in
    --json)     JSON_OUTPUT=true ;;
    --no-color) USE_COLOR=false ;;
  esac
done

# ============================================================
# Couleurs et symboles
# ============================================================
if $USE_COLOR && [ -t 1 ]; then
  C_GREEN='\033[0;32m'
  C_YELLOW='\033[1;33m'
  C_RED='\033[0;31m'
  C_BOLD='\033[1m'
  C_RESET='\033[0m'
  C_DIM='\033[2m'
else
  C_GREEN='' C_YELLOW='' C_RED='' C_BOLD='' C_RESET='' C_DIM=''
fi

SYM_OK="${C_GREEN}✓${C_RESET}"
SYM_WARN="${C_YELLOW}⚠${C_RESET}"
SYM_ERR="${C_RED}✗${C_RESET}"

# ============================================================
# Compteurs globaux
# ============================================================
TOTAL=0
OK_COUNT=0
WARN_COUNT=0
ERR_COUNT=0
EXIT_CODE=0

# Tableau JSON (pour --json)
declare -a JSON_ENTRIES=()

# ============================================================
# Helpers
# ============================================================

# es_query <path> — curl vers ES, retourne le body ou "" si erreur
es_query() {
  curl -sf --max-time "$CURL_TIMEOUT" "${ES}${1}" 2>/dev/null || true
}

# http_get <url> — retourne le code HTTP (000 = timeout/erreur)
http_code() {
  curl -so /dev/null --max-time "$CURL_TIMEOUT" -w "%{http_code}" "${1}" 2>/dev/null || echo "000"
}

# http_body <url> — retourne le body complet
http_body() {
  curl -sf --max-time "$CURL_TIMEOUT" "${1}" 2>/dev/null || true
}

# docker_status <container_name> — retourne l'état du conteneur
docker_status() {
  docker inspect --format='{{.State.Status}}' "${1}" 2>/dev/null || echo "absent"
}

# json_extract <key> <json_string> — extraction légère sans jq
json_extract() {
  local key="$1" json="$2"
  echo "$json" | python3 -c "
import sys, json
try:
    d = json.loads(sys.stdin.read())
    val = d
    for k in '${key}'.split('.'):
        val = val[k]
    print(val)
except Exception:
    print('')
" 2>/dev/null || true
}

# report_service <name> <status:ok|warn|err> <detail>
report_service() {
  local name="$1" status="$2" detail="$3"
  TOTAL=$((TOTAL + 1))

  local sym label
  case "$status" in
    ok)   sym="$SYM_OK";   label="ok";   OK_COUNT=$((OK_COUNT + 1)) ;;
    warn) sym="$SYM_WARN"; label="warn"; WARN_COUNT=$((WARN_COUNT + 1)); [ $EXIT_CODE -lt 1 ] && EXIT_CODE=1 ;;
    err)  sym="$SYM_ERR";  label="err";  ERR_COUNT=$((ERR_COUNT + 1)); EXIT_CODE=2 ;;
  esac

  if ! $JSON_OUTPUT; then
    printf "  %s  %-20s %s\n" "$sym" "${C_BOLD}${name}${C_RESET}" "${C_DIM}${detail}${C_RESET}"
  fi

  JSON_ENTRIES+=("{\"service\":\"${name}\",\"status\":\"${label}\",\"detail\":\"${detail//\"/\\\"}\"}")
}

# ============================================================
# Checks
# ============================================================

check_elasticsearch() {
  local body
  body=$(es_query "/_cluster/health")
  if [ -z "$body" ]; then
    report_service "Elasticsearch" "err" "inaccessible (connexion refusée)"
    return
  fi

  local cluster_status nodes indices
  cluster_status=$(json_extract "status" "$body")
  nodes=$(json_extract "number_of_nodes" "$body")

  # Compter les indices
  local idx_body
  idx_body=$(es_query "/_cat/indices?h=index&s=index" 2>/dev/null) || idx_body=""
  indices=$(echo "$idx_body" | grep -c "." 2>/dev/null || echo "?")

  case "$cluster_status" in
    green)  report_service "Elasticsearch" "ok"   "green (${nodes} nodes, ${indices} indices)" ;;
    yellow) report_service "Elasticsearch" "warn" "yellow (${nodes} nodes, ${indices} indices) — réplicas non assignés" ;;
    red)    report_service "Elasticsearch" "err"  "RED — cluster dégradé (${nodes} nodes)" ;;
    *)      report_service "Elasticsearch" "err"  "status inconnu : ${cluster_status}" ;;
  esac
}

check_grafana() {
  local body
  body=$(http_body "${GRAFANA_URL}/api/health")
  if [ -z "$body" ]; then
    report_service "Grafana" "err" "inaccessible"
    return
  fi
  local gstate
  gstate=$(json_extract "database" "$body" 2>/dev/null || echo "")
  local version
  version=$(json_extract "version" "$body" 2>/dev/null || echo "")

  if echo "$body" | grep -q '"database":"ok"'; then
    report_service "Grafana" "ok" "OK${version:+ (v${version})}"
  else
    report_service "Grafana" "warn" "dégradé — db: ${gstate:-inconnu}"
  fi
}

check_filebeat() {
  # Vérifier les docs récents dans zeek-*, snort-*, suricata-*
  local now_ms since_ms
  now_ms=$(date +%s%3N)
  since_ms=$((now_ms - FILEBEAT_RECENT_MINUTES * 60 * 1000))

  local query
  query=$(cat <<ESQUERY
{"query":{"range":{"@timestamp":{"gte":${since_ms},"format":"epoch_millis"}}},"size":0}
ESQUERY
)

  local all_ok=true
  local details=()
  local any_err=false

  for engine in zeek snort suricata; do
    local result count
    result=$(curl -sf --max-time "$CURL_TIMEOUT" \
      -X POST "${ES}/${engine}-*/_search" \
      -H "Content-Type: application/json" \
      -d "$query" 2>/dev/null || true)

    if [ -z "$result" ]; then
      details+=("${engine}: inaccessible")
      any_err=true
      continue
    fi

    count=$(json_extract "hits.total.value" "$result" 2>/dev/null || echo "0")
    if [ -z "$count" ]; then count="0"; fi

    if [ "$count" -gt 0 ] 2>/dev/null; then
      details+=("${engine}: ${count} docs")
    else
      details+=("${engine}: 0 docs (inactif?)")
      all_ok=false
    fi
  done

  local detail_str
  detail_str=$(IFS=', '; echo "${details[*]}")

  if $any_err; then
    report_service "Filebeat" "err" "ES inaccessible — ${detail_str}"
  elif $all_ok; then
    report_service "Filebeat" "ok" "OK (${detail_str})"
  else
    report_service "Filebeat" "warn" "ingestion lente (${detail_str})"
  fi
}

check_n8n() {
  local code
  code=$(http_code "${N8N_URL}/healthz")
  case "$code" in
    200) report_service "n8n" "ok" "OK" ;;
    000) report_service "n8n" "warn" "dégradé (timeout ${CURL_TIMEOUT}s)" ;;
    *)   report_service "n8n" "warn" "HTTP ${code}" ;;
  esac
}

check_flask_portal() {
  local code
  code=$(http_code "${FLASK_URL}/")
  case "$code" in
    200|302) report_service "Portail Flask" "ok" "HTTP ${code}" ;;
    000)     report_service "Portail Flask" "warn" "inaccessible (timeout)" ;;
    401|403) report_service "Portail Flask" "ok" "HTTP ${code} (auth requis — normal)" ;;
    *)       report_service "Portail Flask" "err" "HTTP ${code}" ;;
  esac
}

check_crowdsec() {
  local output
  output=$(docker exec netwatch-crowdsec cscli version 2>/dev/null || echo "")
  if [ -z "$output" ]; then
    # Vérifier si le container existe mais est arrêté
    local state
    state=$(docker_status "netwatch-crowdsec")
    case "$state" in
      running) report_service "CrowdSec" "warn" "container running mais cscli KO" ;;
      exited)  report_service "CrowdSec" "err"  "arrêté (exited)" ;;
      absent)  report_service "CrowdSec" "err"  "container absent" ;;
      *)       report_service "CrowdSec" "err"  "état: ${state}" ;;
    esac
    return
  fi
  local ver
  ver=$(echo "$output" | head -1 | tr -d '\n')
  report_service "CrowdSec" "ok" "${ver}"
}

check_prometheus() {
  local code
  code=$(http_code "${PROMETHEUS_URL}/-/healthy")
  case "$code" in
    200) report_service "Prometheus" "ok" "healthy" ;;
    000) report_service "Prometheus" "err" "inaccessible (timeout)" ;;
    *)   report_service "Prometheus" "warn" "HTTP ${code}" ;;
  esac
}

check_ollama() {
  local body
  body=$(http_body "${OLLAMA_URL}/api/version")
  if [ -z "$body" ]; then
    report_service "Ollama" "warn" "inaccessible (GPU/LLM optionnel)"
    return
  fi
  local ver
  ver=$(json_extract "version" "$body" 2>/dev/null || echo "?")
  report_service "Ollama" "ok" "v${ver}"
}

# Check générique pour un container Docker via inspect
check_docker_container() {
  local display_name="$1"
  local container_name="$2"

  local state
  state=$(docker_status "$container_name")
  case "$state" in
    running) report_service "$display_name" "ok" "running" ;;
    exited)  report_service "$display_name" "err" "arrêté (exited)" ;;
    absent)  report_service "$display_name" "err" "container absent" ;;
    paused)  report_service "$display_name" "warn" "en pause" ;;
    *)       report_service "$display_name" "warn" "état: ${state}" ;;
  esac
}

check_goflow2() {
  # 1. Vérifier que le container est running
  local state
  state=$(docker_status "netwatch-goflow2")

  if [ "$state" != "running" ]; then
    case "$state" in
      exited) report_service "GoFlow2" "err" "container arrêté (exited)" ;;
      absent) report_service "GoFlow2" "err" "container absent" ;;
      *)      report_service "GoFlow2" "err" "état: ${state}" ;;
    esac
    return
  fi

  # 2. Vérifier la présence d'index netflow-* dans ES
  local idx_body idx_count
  idx_body=$(es_query "/_cat/indices/netflow-*?h=index,docs.count&s=index" 2>/dev/null) || idx_body=""

  if [ -z "$idx_body" ]; then
    # Container running mais pas encore d'index (goflow2 n'a pas encore reçu de flux)
    report_service "GoFlow2" "warn" "running — aucun index netflow-* (aucun flux reçu ?)"
    return
  fi

  idx_count=$(echo "$idx_body" | grep -c "netflow-" 2>/dev/null || echo "0")
  local total_docs
  total_docs=$(echo "$idx_body" | awk '{sum+=$2} END {print sum+0}' 2>/dev/null || echo "0")

  report_service "GoFlow2" "ok" "running — ${idx_count} index netflow-* (${total_docs} docs)"
}

# ============================================================
# Main
# ============================================================

TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

if ! $JSON_OUTPUT; then
  printf "\n"
  printf "${C_BOLD}NetWatch Health Check — %s${C_RESET}\n" "$TIMESTAMP"
  printf "${C_DIM}════════════════════════════════════════${C_RESET}\n"
fi

# --- Services HTTP / API ---
check_elasticsearch
check_grafana
check_filebeat
check_n8n
check_flask_portal
check_prometheus
check_ollama

# --- CrowdSec ---
check_crowdsec

# --- Containers Docker (inspect) ---
check_docker_container "Autoblock"     "netwatch-autoblock"
check_docker_container "Beacon-detect" "netwatch-beacon-detect"
check_docker_container "Zeek"          "netwatch-zeek"
check_docker_container "Snort"         "netwatch-snort"
check_docker_container "Suricata"      "netwatch-suricata"

# --- GoFlow2 (NetFlow / IPFIX / sFlow) ---
check_goflow2

# ============================================================
# Résumé
# ============================================================
if ! $JSON_OUTPUT; then
  printf "${C_DIM}════════════════════════════════════════${C_RESET}\n"

  local_total=$TOTAL
  local_ok=$OK_COUNT
  case $EXIT_CODE in
    0) printf "Status: ${C_GREEN}${C_BOLD}OK${C_RESET} (${local_ok}/${local_total} services)\n\n" ;;
    1) printf "Status: ${C_YELLOW}${C_BOLD}DÉGRADÉ${C_RESET} (${local_ok}/${local_total} OK, ${WARN_COUNT} warning, ${ERR_COUNT} erreur)\n\n" ;;
    2) printf "Status: ${C_RED}${C_BOLD}CRITIQUE${C_RESET} (${local_ok}/${local_total} OK, ${ERR_COUNT} service(s) en erreur)\n\n" ;;
  esac
fi

# Sortie JSON
if $JSON_OUTPUT; then
  printf '{"timestamp":"%s","total":%d,"ok":%d,"warn":%d,"err":%d,"exit_code":%d,"services":[%s]}\n' \
    "$TIMESTAMP" "$TOTAL" "$OK_COUNT" "$WARN_COUNT" "$ERR_COUNT" "$EXIT_CODE" \
    "$(IFS=','; echo "${JSON_ENTRIES[*]}")"
fi

exit $EXIT_CODE
