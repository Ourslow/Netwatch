#!/bin/bash
# NetWatch — Mise à jour des feeds Threat Intelligence pour Zeek Intel Framework
# Usage : ./update-intel.sh
# Cron suggéré : 0 6 * * * /path/to/netwatch/update-intel.sh

set -e

INTEL_DIR="$(dirname "$0")/zeek/intel"
TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT

echo "[NetWatch Intel] Mise à jour des feeds TI..."

# ============================================================
# FEED 1 — Feodo Tracker (Emotet/TrickBot/QakBot C2 IPs)
# ============================================================
echo "[NetWatch Intel] Feodo Tracker..."
curl -sf --max-time 30 \
  "https://feodotracker.abuse.ch/downloads/ipblocklist.csv" \
  -o "$TEMP_DIR/feodo_raw.csv" || { echo " ERREUR téléchargement Feodo"; }

if [ -f "$TEMP_DIR/feodo_raw.csv" ]; then
  printf '#fields\tindicator\tindicator_type\tmeta.source\tmeta.desc\tmeta.url\n' > "$INTEL_DIR/ip_watchlist.dat"
  # Format CSV Feodo : first_seen_utc,dst_ip,dst_port,c2_status,last_online,malware
  grep -v "^#" "$TEMP_DIR/feodo_raw.csv" | grep ",online," | while IFS=',' read -r first_seen ip port status last malware; do
    ip=$(echo "$ip" | tr -d '"')
    malware=$(echo "$malware" | tr -d '"' | tr -d '\r')
    printf '%s\tIntel::ADDR\tFeodo Tracker\t%s C2\thttps://feodotracker.abuse.ch\n' "$ip" "$malware"
  done >> "$INTEL_DIR/ip_watchlist.dat"
  count=$(grep -c "Intel::ADDR" "$INTEL_DIR/ip_watchlist.dat" 2>/dev/null || echo 0)
  echo " OK — $count IPs chargées"
fi

# ============================================================
# FEED 2 — URLhaus (domaines distribution malware)
# ============================================================
echo "[NetWatch Intel] URLhaus domains..."
curl -sf --max-time 30 \
  "https://urlhaus.abuse.ch/downloads/text/" \
  -o "$TEMP_DIR/urlhaus_raw.txt" || { echo " ERREUR téléchargement URLhaus"; }

if [ -f "$TEMP_DIR/urlhaus_raw.txt" ]; then
  printf '#fields\tindicator\tindicator_type\tmeta.source\tmeta.desc\tmeta.url\n' > "$INTEL_DIR/domain_watchlist.dat"
  grep -v "^#" "$TEMP_DIR/urlhaus_raw.txt" | grep -v "^$" | while read -r url; do
    # Extraire le domaine depuis l'URL
    domain=$(echo "$url" | sed -E 's|https?://([^/]+)/.*|\1|' | sed 's|:[0-9]*$||')
    if [ -n "$domain" ] && echo "$domain" | grep -qE "^[a-zA-Z0-9][a-zA-Z0-9._-]+\.[a-zA-Z]{2,}$"; then
      printf '%s\tIntel::DOMAIN\tURLhaus\tMalware distribution\thttps://urlhaus.abuse.ch\n' "$domain"
    fi
  done | sort -u | head -5000 >> "$INTEL_DIR/domain_watchlist.dat"
  count=$(grep -c "Intel::DOMAIN" "$INTEL_DIR/domain_watchlist.dat" 2>/dev/null || echo 0)
  echo " OK — $count domaines chargés"
fi

# ============================================================
# Redémarrer Zeek pour recharger les fichiers intel
# ============================================================
echo ""
echo "[NetWatch Intel] Rechargement Zeek..."
if docker ps --format '{{.Names}}' | grep -q "netwatch-zeek"; then
  docker restart netwatch-zeek
  echo " OK — Zeek redémarré"
else
  echo " INFO — Conteneur netwatch-zeek non trouvé, redémarrez manuellement"
fi

echo ""
echo "[NetWatch Intel] Mise à jour terminée !"
echo "[NetWatch Intel] IPs : $(grep -c "Intel::ADDR" "$INTEL_DIR/ip_watchlist.dat" 2>/dev/null || echo 0)"
echo "[NetWatch Intel] Domaines : $(grep -c "Intel::DOMAIN" "$INTEL_DIR/domain_watchlist.dat" 2>/dev/null || echo 0)"
