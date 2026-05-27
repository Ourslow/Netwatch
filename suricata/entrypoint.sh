#!/bin/bash
# NetWatch — Suricata entrypoint avec mise a jour automatique des regles
set -e

IFACE=${IFACE:-eth0}

echo "[Suricata] Interface : $IFACE"
echo "[Suricata] Mise a jour initiale des regles ET Open..."
suricata-update 2>&1 | grep -E "(Updated|Skipped|Added|Removed|Warning|Error)" || true
echo "[Suricata] Regles a jour."

# Lancer Suricata en arriere-plan
echo "[Suricata] Demarrage..."
suricata -c /etc/suricata/suricata.yaml -i "$IFACE" &
SURICATA_PID=$!
echo "[Suricata] PID=$SURICATA_PID"

# Boucle de mise a jour quotidienne des regles (sans redemarrage)
while kill -0 $SURICATA_PID 2>/dev/null; do
    sleep 86400
    echo "[Suricata] Mise a jour quotidienne des regles..."
    suricata-update 2>&1 | grep -E "(Updated|Skipped|Added|Removed|Warning|Error)" || true
    # SIGUSR2 = rechargement des regles a chaud (live reload)
    if kill -USR2 $SURICATA_PID 2>/dev/null; then
        echo "[Suricata] Regles rechargees via SIGUSR2 (sans redemarrage)."
    else
        echo "[Suricata] Avertissement: SIGUSR2 echoue."
    fi
done

echo "[Suricata] Processus termine."
