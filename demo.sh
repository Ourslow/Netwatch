#!/usr/bin/env bash
# NetWatch v2 — Script de démonstration
# Usage : ./demo.sh [--fast] [--no-sim]
#   --fast    : simulation 1h au lieu de 6h (démo rapide)
#   --no-sim  : skip la simulation (données déjà présentes)

set -euo pipefail

# ============================================================
# Couleurs et helpers
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

ES="${ES_URL:-http://localhost:9200}"
GRAFANA_PORT="${GRAFANA_PORT:-3000}"
FAST=false
NO_SIM=false

for arg in "$@"; do
    case $arg in
        --fast)   FAST=true ;;
        --no-sim) NO_SIM=true ;;
    esac
done

banner() {
    echo ""
    echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${CYAN}${BOLD}║         NetWatch v2 — Démonstration Live                 ║${RESET}"
    echo -e "${CYAN}${BOLD}║   Zeek · Snort 3 · Suricata 7 · RITA-lite · AutoBlock    ║${RESET}"
    echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════════════╝${RESET}"
    echo ""
}

step() {
    echo -e "\n${BOLD}${BLUE}━━━ $1 ${RESET}"
}

ok()   { echo -e "  ${GREEN}✓${RESET} $1"; }
warn() { echo -e "  ${YELLOW}⚠${RESET}  $1"; }
info() { echo -e "  ${CYAN}→${RESET} $1"; }
err()  { echo -e "  ${RED}✗${RESET} $1"; }

count_docs() {
    local index="$1"
    curl -sf "${ES}/${index}/_count" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))" 2>/dev/null || echo "0"
}

# ============================================================
# Étape 1 — Prérequis
# ============================================================

banner

step "1/6 — Vérification des prérequis"

if ! command -v docker &>/dev/null; then
    err "Docker non trouvé. Installer avec : curl -fsSL https://get.docker.com | sh"
    exit 1
fi
ok "Docker $(docker --version | awk '{print $3}' | tr -d ',')"

if ! docker compose version &>/dev/null; then
    err "Docker Compose v2 non trouvé."
    exit 1
fi
ok "Docker Compose $(docker compose version --short)"

if ! command -v python3 &>/dev/null; then
    err "Python3 non trouvé (requis pour simulate-traffic.py)"
    exit 1
fi
ok "Python $(python3 --version 2>&1 | awk '{print $2}')"

# ============================================================
# Étape 2 — Lancement du stack
# ============================================================

step "2/6 — Démarrage du stack NetWatch"

RUNNING=$(docker compose ps --services --filter "status=running" 2>/dev/null | wc -l)

if [ "$RUNNING" -lt 3 ]; then
    info "Démarrage des services..."
    docker compose up -d
else
    ok "$RUNNING services déjà actifs"
fi

# ============================================================
# Étape 3 — Attente Elasticsearch
# ============================================================

step "3/6 — Attente Elasticsearch"

info "En attente que l'index soit healthy..."
MAX_WAIT=120
WAITED=0
while true; do
    STATUS=$(curl -sf "${ES}/_cluster/health" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','?'))" 2>/dev/null || echo "down")
    if [[ "$STATUS" == "green" || "$STATUS" == "yellow" ]]; then
        ok "Elasticsearch ${STATUS} (${WAITED}s)"
        break
    fi
    if [ "$WAITED" -ge "$MAX_WAIT" ]; then
        err "Elasticsearch ne répond pas après ${MAX_WAIT}s"
        err "Vérifier : docker compose logs elasticsearch"
        exit 1
    fi
    printf "  [%3ds] status: %s\r" "$WAITED" "$STATUS"
    sleep 5
    WAITED=$((WAITED + 5))
done

# ============================================================
# Étape 4 — Simulation de trafic
# ============================================================

step "4/6 — Simulation de trafic réseau"

if [ "$NO_SIM" = true ]; then
    warn "Mode --no-sim : simulation ignorée"
else
    if $FAST; then
        SIM_HOURS=1
        SIM_INTENSITY="high"
    else
        SIM_HOURS=6
        SIM_INTENSITY="medium"
    fi

    info "Injection de ${SIM_HOURS}h de trafic (intensité: ${SIM_INTENSITY}) avec scénarios d'attaque..."
    python3 simulate-traffic.py \
        --hours "$SIM_HOURS" \
        --intensity "$SIM_INTENSITY" \
        --es "$ES" \
        --attack
    ok "Simulation terminée"
fi

# ============================================================
# Étape 5 — Récapitulatif des données injectées
# ============================================================

step "5/6 — Données indexées"

echo ""
printf "  %-30s %s\n" "Index" "Documents"
printf "  %-30s %s\n" "─────────────────────────────" "──────────"

for index in "zeek-*" "snort-*" "suricata-*" "netwatch-beacons-*" "netwatch-autoblock-*"; do
    count=$(count_docs "$index")
    if [ "$count" -gt 0 ]; then
        printf "  ${GREEN}%-30s${RESET} ${BOLD}%s${RESET}\n" "$index" "$count"
    else
        printf "  ${YELLOW}%-30s${RESET} %s\n" "$index" "0 (en attente Filebeat)"
    fi
done

echo ""

# Détails des détections si beacon-detect a tourné
BEACON_COUNT=$(count_docs "netwatch-beacons-*")
if [ "$BEACON_COUNT" -gt 0 ]; then
    echo -e "  ${BOLD}Détections comportementales (RITA-lite) :${RESET}"

    BEACONING=$(curl -sf "${ES}/netwatch-beacons-*/_count?q=detection_type:beaconing" 2>/dev/null \
        | python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))" 2>/dev/null || echo "0")
    LONG_CONN=$(curl -sf "${ES}/netwatch-beacons-*/_count?q=detection_type:long_connection" 2>/dev/null \
        | python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))" 2>/dev/null || echo "0")
    DNS_TUN=$(curl -sf "${ES}/netwatch-beacons-*/_count?q=detection_type:dns_tunneling" 2>/dev/null \
        | python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))" 2>/dev/null || echo "0")

    echo -e "    ${RED}⚠${RESET}  Beacons C2 détectés    : ${BOLD}${BEACONING}${RESET}"
    echo -e "    ${YELLOW}⚠${RESET}  Longues connexions     : ${BOLD}${LONG_CONN}${RESET}"
    echo -e "    ${YELLOW}⚠${RESET}  DNS Tunneling          : ${BOLD}${DNS_TUN}${RESET}"
    echo ""
fi

# Top 3 alertes Suricata
echo -e "  ${BOLD}Top alertes Suricata :${RESET}"
curl -sf "${ES}/suricata-*/_search" \
    -H 'Content-Type: application/json' \
    -d '{
      "size": 0,
      "query": {"term": {"event_type": "alert"}},
      "aggs": {
        "top_sigs": {
          "terms": {"field": "alert.signature.keyword", "size": 3}
        }
      }
    }' 2>/dev/null \
    | python3 -c "
import sys, json
d = json.load(sys.stdin)
buckets = d.get('aggregations', {}).get('top_sigs', {}).get('buckets', [])
for b in buckets:
    print(f\"    \033[0;31m►\033[0m  {b['key'][:55]:<55} ({b['doc_count']})\")
" 2>/dev/null || true

echo ""

# Top 3 alertes Snort
echo -e "  ${BOLD}Top alertes Snort :${RESET}"
curl -sf "${ES}/snort-*/_search" \
    -H 'Content-Type: application/json' \
    -d '{
      "size": 0,
      "aggs": {
        "top_sigs": {
          "terms": {"field": "msg.keyword", "size": 3}
        }
      }
    }' 2>/dev/null \
    | python3 -c "
import sys, json
d = json.load(sys.stdin)
buckets = d.get('aggregations', {}).get('top_sigs', {}).get('buckets', [])
for b in buckets:
    print(f\"    \033[0;31m►\033[0m  {b['key'][:55]:<55} ({b['doc_count']})\")
" 2>/dev/null || true

echo ""

# ============================================================
# Étape 6 — Récapitulatif final
# ============================================================

step "6/6 — Stack opérationnel"

VM_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "localhost")

echo ""
echo -e "  ${BOLD}Accès aux interfaces :${RESET}"
echo -e "  ${GREEN}●${RESET}  Grafana      →  ${BOLD}http://${VM_IP}:${GRAFANA_PORT}${RESET}  (login: admin / voir .env)"
echo -e "  ${GREEN}●${RESET}  Elasticsearch →  ${BOLD}http://${VM_IP}:9200${RESET}"
echo -e "  ${GREEN}●${RESET}  Prometheus    →  ${BOLD}http://${VM_IP}:9090${RESET}"
echo -e "  ${CYAN}●${RESET}  AutoBlock     →  ${BOLD}http://${VM_IP}:5001/health${RESET}"
echo ""
echo -e "  ${BOLD}Dashboards recommandés pour la démo :${RESET}"
echo -e "  1. ${BOLD}Corrélation Multi-Moteurs${RESET} — vue d'ensemble Zeek + Snort + Suricata"
echo -e "  2. ${BOLD}Beacon Detector${RESET}           — beaconing C2, longues connexions, DNS tunneling"
echo -e "  3. ${BOLD}Alertes Suricata 7${RESET}        — panel MITRE ATT&CK (onglet bas)"
echo -e "  4. ${BOLD}JA3 / HASSH${RESET}               — fingerprints TLS/SSH suspects"
echo -e "  5. ${BOLD}Top Talkers${RESET}               — top IPs par volume"
echo ""
echo -e "  ${BOLD}Commandes utiles pendant la démo :${RESET}"
echo -e "  ${CYAN}docker compose logs -f beacon-detect${RESET}   # détections en direct"
echo -e "  ${CYAN}curl http://localhost:5001/health${RESET}       # état autoblock"
echo -e "  ${CYAN}docker compose ps${RESET}                       # état des 10 services"
echo ""
echo -e "${GREEN}${BOLD}  NetWatch v2 prêt pour la démonstration.${RESET}"
echo ""
