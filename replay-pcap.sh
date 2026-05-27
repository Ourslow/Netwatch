#!/bin/bash
# NetWatch v2 — Replay PCAP through all engines
# Usage: ./replay-pcap.sh <fichier.pcap> [--engines zeek,snort,suricata]

set -e

PCAP_FILE="${1:-}"
ENGINES="${2:-all}"

if [ -z "$PCAP_FILE" ]; then
    echo "Usage: $0 <fichier.pcap> [--engines zeek,snort,suricata|all]"
    echo ""
    echo "Exemples:"
    echo "  $0 pcap/sample.pcap                  # Replay sur les 3 moteurs"
    echo "  $0 pcap/sample.pcap --engines zeek    # Zeek uniquement"
    echo "  $0 pcap/capture.pcap --engines zeek,suricata"
    exit 1
fi

if [ ! -f "$PCAP_FILE" ]; then
    echo "[ERREUR] Fichier introuvable: $PCAP_FILE"
    exit 1
fi

PCAP_BASENAME=$(basename "$PCAP_FILE")

# Copier le PCAP dans le dossier pcap/ si besoin
if [ "$(dirname "$PCAP_FILE")" != "pcap" ]; then
    cp "$PCAP_FILE" "pcap/$PCAP_BASENAME"
    echo "[+] PCAP copie dans pcap/$PCAP_BASENAME"
fi

# Parse engines
if [ "$ENGINES" = "all" ] || [ "$ENGINES" = "--engines" ]; then
    shift 2 2>/dev/null || true
    ENGINES="${1:-zeek,snort,suricata}"
fi
ENGINES=$(echo "$ENGINES" | tr ',' ' ')

echo "============================================"
echo "  NetWatch v2 — Replay PCAP"
echo "  Fichier : $PCAP_BASENAME"
echo "  Moteurs : $ENGINES"
echo "============================================"
echo ""

# --- ZEEK ---
if echo "$ENGINES" | grep -q "zeek"; then
    echo "[*] Replay Zeek..."
    docker compose run --rm --entrypoint "" zeek bash -c \
        "mkdir -p /zeek/logs/current && cd /zeek/logs/current && \
         zeek -C -r /pcap/$PCAP_BASENAME /usr/local/zeek/share/zeek/site/local.zeek" \
        2>/dev/null
    echo "[+] Zeek : logs generes"
fi

# --- SNORT ---
if echo "$ENGINES" | grep -q "snort"; then
    echo "[*] Replay Snort 3..."
    docker compose run --rm --entrypoint "" snort bash -c \
        "snort -c /usr/local/etc/snort/snort.lua \
         -r /pcap/$PCAP_BASENAME \
         -l /var/log/snort \
         --plugin-path /usr/local/lib/snort \
         -q" \
        2>/dev/null
    echo "[+] Snort : alertes generees"
fi

# --- SURICATA ---
if echo "$ENGINES" | grep -q "suricata"; then
    echo "[*] Replay Suricata..."
    docker compose run --rm --entrypoint "" suricata bash -c \
        "suricata -c /etc/suricata/suricata.yaml \
         -r /pcap/$PCAP_BASENAME \
         -l /var/log/suricata \
         --set outputs.0.eve-log.filename=/var/log/suricata/eve.json" \
        2>/dev/null
    echo "[+] Suricata : EVE JSON genere"
fi

echo ""
echo "[*] Relance de Filebeat pour ingestion..."
docker compose restart filebeat
sleep 15

echo ""
echo "[+] Verification des index Elasticsearch :"
for idx in zeek snort suricata; do
    COUNT=$(curl -s "http://localhost:9200/${idx}-*/_count" 2>/dev/null | grep -o '"count":[0-9]*' | cut -d: -f2)
    echo "    $idx-* : ${COUNT:-0} documents"
done

echo ""
echo "[+] Replay termine ! Ouvrez Grafana : http://localhost:3000"
