#!/usr/bin/env bash
# NetWatch v2 — Script de démonstration client (pipeline NDR complet)
# Usage : ./demo.sh [--auto] [--step N]
#   --auto    : enchaîne les étapes sans pause ENTRÉE (sleep 3s entre chaque)
#   --step N  : commence à l'étape N (1-5), utile pour reprendre une démo interrompue

set -euo pipefail

# ============================================================
# Couleurs & helpers
# ============================================================

if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    DIM='\033[2m'
    RESET='\033[0m'
else
    RED='' GREEN='' YELLOW='' BLUE='' CYAN='' BOLD='' DIM='' RESET=''
fi

ES="${ES_URL:-http://localhost:9200}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

AUTO=false
START_STEP=1

for arg in "$@"; do
    case "$arg" in
        --auto)   AUTO=true ;;
        --step)   : ;;   # handled below with shift logic
    esac
done

# Parse --step N properly
args=("$@")
for i in "${!args[@]}"; do
    if [[ "${args[$i]}" == "--step" ]]; then
        next=$((i + 1))
        if [[ -n "${args[$next]+x}" && "${args[$next]}" =~ ^[1-5]$ ]]; then
            START_STEP="${args[$next]}"
        else
            echo "Usage: --step N  (N entre 1 et 5)" >&2
            exit 1
        fi
    fi
done

# ============================================================
# Fonctions utilitaires
# ============================================================

sep() {
    echo -e "${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
}

ok()    { echo -e "  ${GREEN}✓${RESET} $*"; }
warn()  { echo -e "  ${YELLOW}⚠${RESET}  $*"; }
info()  { echo -e "  ${CYAN}→${RESET} $*"; }
err()   { echo -e "  ${RED}✗${RESET} $*"; }
bullet(){ echo -e "  ${BLUE}►${RESET} $*"; }

step_header() {
    local num="$1" title="$2"
    echo ""
    echo -e "${BOLD}${BLUE}[${num}/5] ${title}${RESET}"
    sep
}

pause_or_auto() {
    if $AUTO; then
        sleep 3
    else
        echo ""
        echo -e "  ${DIM}[Appuyer sur ENTRÉE pour continuer...]${RESET}"
        read -r
    fi
}

skip_step() {
    local num="$1"
    if [ "$num" -lt "$START_STEP" ]; then
        return 0   # true → skip
    fi
    return 1       # false → execute
}

# ============================================================
# Bannière
# ============================================================

banner() {
    echo ""
    echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════╗${RESET}"
    echo -e "${CYAN}${BOLD}║   NetWatch v2 — Démonstration Pipeline NDR      ║${RESET}"
    echo -e "${CYAN}${BOLD}║   Zeek · Snort 3 · Suricata 7 · IOC Graph       ║${RESET}"
    echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════╝${RESET}"
    echo ""
    if $AUTO; then
        info "Mode ${BOLD}--auto${RESET}${CYAN} activé — enchaînement automatique (sleep 3s)"
    fi
    if [ "$START_STEP" -gt 1 ]; then
        warn "Reprise à l'étape ${START_STEP}/5"
    fi
    echo ""
}

# ============================================================
# [1/5] Stack Health
# ============================================================

run_step1() {
    step_header "1/5" "Vérification de la stack"

    if ! bash "${SCRIPT_DIR}/scripts/health-check.sh"; then
        local rc=$?
        echo ""
        if [ "$rc" -eq 1 ]; then
            warn "Stack dégradée — certains services en warning"
        else
            err "Stack critique — vérifier les services avant la démo"
            echo ""
            info "Commande : docker compose ps"
        fi
    fi

    echo ""
    pause_or_auto
}

# ============================================================
# [2/5] Simulation de trafic
# ============================================================

run_step2() {
    step_header "2/5" "Simulation d'une attaque réseau"

    info "Lancement de la simulation en arrière-plan (intensité: medium, scénarios d'attaque)..."
    echo ""

    python3 "${SCRIPT_DIR}/simulate-traffic.py" \
        --hours 1 \
        --intensity medium \
        --es "$ES" \
        --attack &
    SIM_PID=$!

    echo -e "  ${GREEN}✓${RESET} Simulation démarrée (PID: ${SIM_PID})"
    echo ""

    # Compteur visible 10 secondes
    for i in $(seq 1 10); do
        printf "\r  ${CYAN}→${RESET} Injection en cours... ${BOLD}%2ds${RESET}" "$i"
        sleep 1
    done
    printf "\n"

    # Arrêt propre
    if kill -0 "$SIM_PID" 2>/dev/null; then
        kill "$SIM_PID" 2>/dev/null || true
        wait "$SIM_PID" 2>/dev/null || true
        ok "Simulation arrêtée après 10s — événements injectés dans ES"
    else
        ok "Simulation terminée naturellement"
    fi

    echo ""
    pause_or_auto
}

# ============================================================
# [3/5] Détection — top 3 règles déclenchées
# ============================================================

run_step3() {
    step_header "3/5" "Détection — règles déclenchées"

    info "Interrogation Elasticsearch — agrégation des alertes..."
    echo ""

    # Top 3 Suricata
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
try:
    d = json.load(sys.stdin)
    buckets = d.get('aggregations', {}).get('top_sigs', {}).get('buckets', [])
    if not buckets:
        print('    \033[2m(aucune alerte — stack démarrée ?\033[0m)')
    for b in buckets:
        label = b['key'][:56]
        count = b['doc_count']
        print(f'    \033[0;31m►\033[0m  {label:<56} \033[1m({count})\033[0m')
except Exception:
    print('    \033[2m(ES non joignable)\033[0m')
" 2>/dev/null || echo -e "    ${DIM}(ES non joignable)${RESET}"

    echo ""

    # Top 3 Snort
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
try:
    d = json.load(sys.stdin)
    buckets = d.get('aggregations', {}).get('top_sigs', {}).get('buckets', [])
    if not buckets:
        print('    \033[2m(aucune alerte — stack démarrée ?\033[0m)')
    for b in buckets:
        label = b['key'][:56]
        count = b['doc_count']
        print(f'    \033[0;31m►\033[0m  {label:<56} \033[1m({count})\033[0m')
except Exception:
    print('    \033[2m(ES non joignable)\033[0m')
" 2>/dev/null || echo -e "    ${DIM}(ES non joignable)${RESET}"

    echo ""

    # Beacons RITA-lite
    echo -e "  ${BOLD}Détections comportementales (RITA-lite) :${RESET}"
    curl -sf "${ES}/netwatch-beacons-*/_count" 2>/dev/null \
        | python3 -c "
import sys, json
try:
    total = json.load(sys.stdin).get('count', 0)
    if total == 0:
        print('    \033[2m(aucune détection beacon)\033[0m')
    else:
        print(f'    \033[0;31m⚠\033[0m  Beacons / comportements suspects détectés : \033[1m{total}\033[0m')
except Exception:
    print('    \033[2m(index non disponible)\033[0m')
" 2>/dev/null || true

    echo ""
    pause_or_auto
}

# ============================================================
# [4/5] Graphe IOC
# ============================================================

run_step4() {
    step_header "4/5" "Graphe de connaissance IOC"

    local ioc_script="${SCRIPT_DIR}/scripts/security/ioc-graph.py"

    if [ ! -f "$ioc_script" ]; then
        warn "ioc-graph.py introuvable — ignoré"
        pause_or_auto
        return
    fi

    info "Construction du graphe IOC (entités : IPs, domaines, règles, MITRE TTPs)..."
    echo ""

    OUTPUT=$(python3 "$ioc_script" 2>/dev/null) || true

    # Lecture du fichier de sortie JSON pour les stats
    local graph_file="${SCRIPT_DIR}/scripts/security/ioc-graph-output.json"
    if [ -f "$graph_file" ]; then
        python3 -c "
import json, sys
try:
    with open('${graph_file}') as f:
        data = json.load(f)
    nodes = data.get('nodes', [])
    edges = data.get('edges', data.get('links', []))
    node_count = len(nodes)
    edge_count = len(edges)

    # Top IPs
    ip_nodes = [n for n in nodes if n.get('type') == 'ip']
    ip_nodes_sorted = sorted(ip_nodes, key=lambda n: n.get('weight', n.get('degree', 0)), reverse=True)
    top_ips = ip_nodes_sorted[:3]

    print(f'  \033[1mStatistiques du graphe :\033[0m')
    print(f'    \033[0;32m✓\033[0m  Nœuds    : \033[1m{node_count}\033[0m')
    print(f'    \033[0;32m✓\033[0m  Edges    : \033[1m{edge_count}\033[0m')
    if top_ips:
        print()
        print(f'  \033[1mTop IPs suspectes :\033[0m')
        for ip in top_ips:
            label = ip.get('id', ip.get('label', '?'))
            weight = ip.get('weight', ip.get('degree', '?'))
            print(f'    \033[0;31m►\033[0m  {label:<20}  score={weight}')
except Exception as e:
    print(f'  \033[2m(impossible de lire le fichier graphe : {e})\033[0m')
" 2>/dev/null || warn "Impossible de lire ioc-graph-output.json"
    else
        # Essayer de parser la sortie console
        if [ -n "$OUTPUT" ]; then
            echo "$OUTPUT" | grep -E "(node|edge|nœud|arête|IP|Nodes|Edges)" | head -10 \
                | while IFS= read -r line; do info "$line"; done || true
        else
            warn "Graphe généré — aucune statistique disponible"
        fi
    fi

    echo ""
    ok "Graphe IOC disponible dans le portail : ${BOLD}http://localhost:5050/graph${RESET}"
    echo ""
    pause_or_auto
}

# ============================================================
# [5/5] Score de risque
# ============================================================

run_step5() {
    step_header "5/5" "Score de risque global"

    local score_script="${SCRIPT_DIR}/scripts/security/ioc-score.py"

    if [ ! -f "$score_script" ]; then
        echo ""
        echo -e "  ${YELLOW}${BOLD}Disponible après Phase 4${RESET}"
        echo ""
        info "Le scoring dynamique (ioc-score.py) sera intégré lors du déploiement"
        info "physique sur la VM Shuttle (Phase 4 — v3 roadmap)."
        echo ""
        bullet "Fonctionnalités prévues :"
        bullet "  - Score global de risque réseau (0-100)"
        bullet "  - Pondération par type d'attaque (C2, scan, exfil, lateral)"
        bullet "  - Historique des scores sur 30 jours"
        bullet "  - Seuils d'alerte configurables"
    else
        info "Calcul du score de risque sur les dernières 24h..."
        echo ""
        python3 "$score_script" --days 1 2>/dev/null || warn "ioc-score.py a rencontré une erreur"
    fi

    echo ""
    pause_or_auto
}

# ============================================================
# Récapitulatif final
# ============================================================

run_final() {
    echo ""
    sep
    echo ""
    echo -e "  ${GREEN}${BOLD}✓ Démonstration Pipeline NDR terminée${RESET}"
    echo ""

    VM_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "localhost")

    echo -e "  ${BOLD}Accès aux interfaces :${RESET}"
    echo -e "  ${GREEN}●${RESET}  Grafana        →  ${BOLD}http://${VM_IP}:3000${RESET}"
    echo -e "  ${GREEN}●${RESET}  Portail NetWatch→  ${BOLD}http://${VM_IP}:5050${RESET}"
    echo -e "  ${GREEN}●${RESET}  Elasticsearch  →  ${BOLD}http://${VM_IP}:9200${RESET}"
    echo -e "  ${CYAN}●${RESET}  AutoBlock      →  ${BOLD}http://${VM_IP}:5001/health${RESET}"
    echo ""
    echo -e "  ${BOLD}Dashboards clés :${RESET}"
    echo -e "  1. ${BOLD}Corrélation Multi-Moteurs${RESET}  — Zeek + Snort + Suricata"
    echo -e "  2. ${BOLD}Beacon Detector${RESET}            — C2, longues connexions, DNS tunneling"
    echo -e "  3. ${BOLD}Graphe IOC${RESET}                 — /graph (portail)"
    echo ""
    echo -e "${DIM}  NetWatch v2 — open-source NDR stack${RESET}"
    echo ""
}

# ============================================================
# Main
# ============================================================

banner

[ "$START_STEP" -le 1 ] && run_step1
[ "$START_STEP" -le 2 ] && run_step2
[ "$START_STEP" -le 3 ] && run_step3
[ "$START_STEP" -le 4 ] && run_step4
[ "$START_STEP" -le 5 ] && run_step5

run_final
