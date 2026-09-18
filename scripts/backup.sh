#!/usr/bin/env bash
# scripts/backup.sh — Sauvegarde de NetWatch dans une archive autonome
#
# Contenu (tout ce qui n'est pas dans git ni re-téléchargeable) :
#   config/        .env, portal/.env, portal/data (hostgroups, seuils, disposition),
#                  reports/, prometheus/blackbox-targets.yml, zeek/intel, règles locales,
#                  caddy/certs
#   volumes/       grafana-data, prometheus-data, n8n-data, crowdsec-db, arkime-etc,
#                  caddy-data, netbox-media, netbox-reports, netbox-scripts
#   netbox.sql.gz  pg_dump de la base NetBox
#   elasticsearch/ snapshot ES (indices zeek-*, snort-*, suricata-*, netflow-*, netwatch-*,
#                  arkime_*…) via le dépôt fs du volume es-snapshots
#   manifest.txt   version, commit, date, contenu
# Exclus : es-data brut (remplacé par le snapshot), ollama-data (modèle re-téléchargeable),
#          ntopng-data (cache), logs des moteurs (déjà dans ES), arkime/raw (PCAP — à
#          sauvegarder à part si nécessaire, volume dédié recommandé).
#
# Usage :
#   scripts/backup.sh                      # sauvegarde complète → backups/netwatch-<version>-<date>.tar.gz
#   scripts/backup.sh --config-only        # configuration + état du portail seulement (à chaud, secondes)
#   scripts/backup.sh --out /mnt/nas/netwatch --keep 7
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

CONFIG_ONLY=false
OUT_DIR="$ROOT/backups"
KEEP=0
while [ $# -gt 0 ]; do
  case "$1" in
    --config-only) CONFIG_ONLY=true ;;
    --out)  OUT_DIR="${2:?--out attend un répertoire}"; shift ;;
    --keep) KEEP="${2:?--keep attend un nombre}"; shift ;;
    -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
    *) echo "Option inconnue : $1" >&2; exit 2 ;;
  esac
  shift
done

ES="${NETWATCH_ES_URL:-http://localhost:9200}"
ES_REPO_PATH="/usr/share/elasticsearch/snapshots"
VERSION="$(cat VERSION 2>/dev/null || echo unknown)"
STAMP="$(date +%Y%m%d-%H%M%S)"
NAME="netwatch-${VERSION}-${STAMP}"
$CONFIG_ONLY && NAME="netwatch-config-${VERSION}-${STAMP}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$OUT_DIR" "$WORK/config"

ok()   { printf '  ✓ %s\n' "$1"; }
warn() { printf '  ! %s\n' "$1" >&2; }

# Nom du projet compose (préfixe des volumes) — docker peut être indisponible en --config-only
project() { docker compose config --format json 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)["name"])' 2>/dev/null || echo netwatch; }

echo "=== Sauvegarde NetWatch $VERSION → $OUT_DIR/$NAME.tar.gz ==="

# ── Configuration et état du portail ─────────────────────────────────────────
for p in .env portal/.env portal/data reports prometheus/blackbox-targets.yml zeek/intel \
         snort/local.rules suricata/local.rules snort/snort.local.lua caddy/certs; do
  [ -e "$p" ] && cp -a --parents "$p" "$WORK/config/"
done
ok "configuration + état du portail"

{
  echo "name=$NAME"
  echo "version=$VERSION"
  echo "commit=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
  echo "date=$(date -Iseconds)"
  echo "host=$(hostname)"
  echo "mode=$($CONFIG_ONLY && echo config-only || echo full)"
} > "$WORK/manifest.txt"

if ! $CONFIG_ONLY; then
  command -v docker >/dev/null || { echo "docker requis pour une sauvegarde complète (--config-only sinon)" >&2; exit 1; }
  PROJECT="$(project)"
  mkdir -p "$WORK/volumes" "$WORK/elasticsearch"

  # ── Volumes Docker (copie à froid par conteneur utilitaire) ────────────────
  for v in grafana-data prometheus-data n8n-data crowdsec-db arkime-etc caddy-data netbox-media netbox-reports netbox-scripts; do
    vol="${PROJECT}_${v}"
    if docker volume inspect "$vol" >/dev/null 2>&1; then
      docker run --rm -v "$vol:/src:ro" -v "$WORK/volumes:/dst" alpine:3.20 tar czf "/dst/$v.tar.gz" -C /src .
      echo "volume=$v" >> "$WORK/manifest.txt"
      ok "volume $v"
    fi
  done

  # ── NetBox : pg_dump (cohérent, contrairement à une copie du data dir) ─────
  if docker ps --format '{{.Names}}' | grep -qx netwatch-netbox-postgres; then
    docker exec netwatch-netbox-postgres pg_dump -U netbox -d netbox --no-owner | gzip > "$WORK/netbox.sql.gz"
    echo "netbox=pg_dump" >> "$WORK/manifest.txt"
    ok "NetBox (pg_dump)"
  else
    warn "NetBox absent ou arrêté : base non sauvegardée"
  fi

  # ── Elasticsearch : snapshot fs → volume es-snapshots → archive ────────────
  if curl -sf "$ES/_cluster/health" >/dev/null 2>&1; then
    reg="$(curl -s -X PUT "$ES/_snapshot/netwatch" -H 'Content-Type: application/json' \
           -d "{\"type\":\"fs\",\"settings\":{\"location\":\"$ES_REPO_PATH\",\"compress\":true}}")"
    if echo "$reg" | grep -q '"acknowledged":true'; then
      snap="$(echo "$NAME" | tr '[:upper:]' '[:lower:]')"
      res="$(curl -s -X PUT "$ES/_snapshot/netwatch/$snap?wait_for_completion=true" -H 'Content-Type: application/json' \
             -d '{"indices":"*,-.*","include_global_state":false,"ignore_unavailable":true}')"
      state="$(echo "$res" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("snapshot",{}).get("state","?"))' 2>/dev/null || echo "?")"
      if [ "$state" = "SUCCESS" ]; then
        docker run --rm -v "${PROJECT}_es-snapshots:/src:ro" -v "$WORK/elasticsearch:/dst" alpine:3.20 tar czf /dst/es-snapshots.tar.gz -C /src .
        curl -s -X DELETE "$ES/_snapshot/netwatch/$snap" >/dev/null   # l'archive fait foi, le dépôt reste léger
        echo "es_snapshot=$snap" >> "$WORK/manifest.txt"
        ok "Elasticsearch (snapshot $snap)"
      else
        warn "snapshot Elasticsearch en échec (state=$state) : ${res:0:200}"
      fi
    else
      warn "dépôt de snapshots ES indisponible — path.repo manquant ? (docker compose up -d elasticsearch après mise à jour) : ${reg:0:160}"
    fi
  else
    warn "Elasticsearch injoignable ($ES) : index non sauvegardés"
  fi
fi

# ── Archive finale ───────────────────────────────────────────────────────────
tar czf "$OUT_DIR/$NAME.tar.gz" -C "$WORK" .
chmod 600 "$OUT_DIR/$NAME.tar.gz"
echo
echo "Archive : $OUT_DIR/$NAME.tar.gz ($(du -h "$OUT_DIR/$NAME.tar.gz" | cut -f1))"
echo "Restaurer : scripts/restore.sh $OUT_DIR/$NAME.tar.gz"

if [ "$KEEP" -gt 0 ]; then
  pattern="netwatch-$VERSION-*.tar.gz"; $CONFIG_ONLY && pattern="netwatch-config-*.tar.gz"
  # shellcheck disable=SC2012,SC2086
  ls -1t "$OUT_DIR"/$pattern 2>/dev/null | tail -n +"$((KEEP + 1))" | while read -r old; do rm -f "$old"; echo "supprimé : $old"; done
fi
