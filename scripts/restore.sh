#!/usr/bin/env bash
# scripts/restore.sh — Restauration d'une archive produite par scripts/backup.sh
#
# Remet en place, dans l'ordre : configuration et état du portail, volumes Docker,
# base NetBox (pg_dump), index Elasticsearch (snapshot), puis redémarre la stack,
# rejoue setup-es.sh et relance le portail. Les .env courants sont conservés en
# .env.bak-<date> avant écrasement.
#
# Usage :
#   scripts/restore.sh backups/netwatch-2.1.0-20260918-1200.tar.gz
#   scripts/restore.sh ARCHIVE --yes            # sans confirmation
#   scripts/restore.sh ARCHIVE --config-only    # ignorer volumes, NetBox et Elasticsearch
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

ARCHIVE=""
YES=false
CONFIG_ONLY=false
while [ $# -gt 0 ]; do
  case "$1" in
    --yes) YES=true ;;
    --config-only) CONFIG_ONLY=true ;;
    -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
    -*) echo "Option inconnue : $1" >&2; exit 2 ;;
    *) ARCHIVE="$1" ;;
  esac
  shift
done
[ -n "$ARCHIVE" ] && [ -f "$ARCHIVE" ] || { echo "Usage : scripts/restore.sh ARCHIVE [--yes] [--config-only]" >&2; exit 2; }

ES="${NETWATCH_ES_URL:-http://localhost:9200}"
ES_REPO_PATH="/usr/share/elasticsearch/snapshots"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
tar xzf "$ARCHIVE" -C "$WORK"
[ -f "$WORK/manifest.txt" ] || { echo "Archive invalide : manifest.txt absent" >&2; exit 1; }

ok()   { printf '  ✓ %s\n' "$1"; }
warn() { printf '  ! %s\n' "$1" >&2; }
manifest() { grep -E "^$1=" "$WORK/manifest.txt" | cut -d= -f2- | tail -1; }
project() { docker compose config --format json 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)["name"])' 2>/dev/null || echo netwatch; }
wait_es() {
  printf '  attente Elasticsearch'
  for _ in $(seq 1 60); do curl -sf "$ES/_cluster/health" >/dev/null 2>&1 && { echo; return 0; }; printf '.'; sleep 5; done
  echo; return 1
}

echo "=== Restauration NetWatch depuis $ARCHIVE ==="
sed 's/^/  /' "$WORK/manifest.txt"
[ "$(manifest mode)" = "config-only" ] && CONFIG_ONLY=true
echo
if ! $YES; then
  read -r -p "Écraser la configuration$($CONFIG_ONLY || echo ', les volumes, NetBox et les index Elasticsearch') actuels ? [o/N] " answer
  [ "$answer" = "o" ] || [ "$answer" = "O" ] || { echo "Abandon."; exit 0; }
fi

HAVE_DOCKER=false
command -v docker >/dev/null && docker info >/dev/null 2>&1 && HAVE_DOCKER=true

# ── 1. Configuration ─────────────────────────────────────────────────────────
stamp="$(date +%Y%m%d-%H%M%S)"
for f in .env portal/.env; do [ -f "$f" ] && cp -a "$f" "$f.bak-$stamp"; done
cp -a "$WORK/config/." "$ROOT/"
chmod 600 .env portal/.env 2>/dev/null || true
ok "configuration et état du portail (anciens .env → *.bak-$stamp)"

if ! $CONFIG_ONLY; then
  $HAVE_DOCKER || { echo "docker requis pour restaurer volumes, NetBox et Elasticsearch" >&2; exit 1; }
  PROJECT="$(project)"
  echo "  arrêt de la stack"
  docker compose down --remove-orphans >/dev/null 2>&1 || true

  # ── 2. Volumes ─────────────────────────────────────────────────────────────
  for tgz in "$WORK"/volumes/*.tar.gz; do
    [ -e "$tgz" ] || break
    v="$(basename "$tgz" .tar.gz)"; vol="${PROJECT}_${v}"
    docker volume create "$vol" >/dev/null
    docker run --rm -v "$vol:/dst" -v "$WORK/volumes:/src:ro" alpine:3.20 \
      sh -c "find /dst -mindepth 1 -delete && tar xzf /src/$v.tar.gz -C /dst"
    ok "volume $v"
  done

  # ── 3. NetBox (pg_dump) ────────────────────────────────────────────────────
  if [ -f "$WORK/netbox.sql.gz" ]; then
    docker compose up -d netbox-postgres >/dev/null
    printf '  attente PostgreSQL'
    for _ in $(seq 1 30); do docker exec netwatch-netbox-postgres pg_isready -U netbox -q 2>/dev/null && break; printf '.'; sleep 2; done; echo
    docker exec netwatch-netbox-postgres psql -U netbox -d postgres -q -v ON_ERROR_STOP=1 \
      -c "DROP DATABASE IF EXISTS netbox WITH (FORCE);" -c "CREATE DATABASE netbox OWNER netbox;"
    gunzip -c "$WORK/netbox.sql.gz" | docker exec -i netwatch-netbox-postgres psql -U netbox -d netbox -q -v ON_ERROR_STOP=1 >/dev/null
    ok "NetBox (base restaurée)"
  fi

  # ── 4. Elasticsearch (snapshot) ────────────────────────────────────────────
  snap="$(manifest es_snapshot)"
  if [ -n "$snap" ] && [ -f "$WORK/elasticsearch/es-snapshots.tar.gz" ]; then
    vol="${PROJECT}_es-snapshots"
    docker volume create "$vol" >/dev/null
    docker run --rm -v "$vol:/dst" -v "$WORK/elasticsearch:/src:ro" alpine:3.20 \
      sh -c "find /dst -mindepth 1 -delete && tar xzf /src/es-snapshots.tar.gz -C /dst && chown -R 1000:0 /dst"
    docker compose up -d elasticsearch >/dev/null
    wait_es || { echo "Elasticsearch ne répond pas" >&2; exit 1; }
    curl -s -X PUT "$ES/_snapshot/netwatch" -H 'Content-Type: application/json' \
      -d "{\"type\":\"fs\",\"settings\":{\"location\":\"$ES_REPO_PATH\",\"compress\":true}}" >/dev/null
    indices="$(curl -s "$ES/_snapshot/netwatch/$snap" | python3 -c 'import json,sys; print(",".join(json.load(sys.stdin)["snapshots"][0]["indices"]))')"
    [ -n "$indices" ] && curl -s -X DELETE "$ES/$indices?ignore_unavailable=true" >/dev/null
    res="$(curl -s -X POST "$ES/_snapshot/netwatch/$snap/_restore?wait_for_completion=true" -H 'Content-Type: application/json' \
           -d '{"indices":"*,-.*","include_global_state":false}')"
    echo "$res" | grep -q '"failed":0' && ok "Elasticsearch (snapshot $snap)" || warn "restauration ES incomplète : ${res:0:200}"
    curl -s -X DELETE "$ES/_snapshot/netwatch/$snap" >/dev/null
  fi

  # ── 5. Redémarrage ─────────────────────────────────────────────────────────
  docker compose up -d --remove-orphans >/dev/null
  wait_es && bash setup-es.sh >/dev/null && ok "stack redémarrée, setup-es rejoué"
fi

# ── Portail ──────────────────────────────────────────────────────────────────
if systemctl is-enabled -q netwatch-portal 2>/dev/null; then
  sudo systemctl restart netwatch-portal && ok "portail redémarré (systemd)"
else
  make -s portal-stop >/dev/null 2>&1 || true
  make -s portal >/dev/null 2>&1 && ok "portail redémarré" || warn "portail non redémarré : make portal"
fi
echo "Restauration terminée."
