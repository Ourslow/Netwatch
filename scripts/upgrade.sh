#!/usr/bin/env bash
# scripts/upgrade.sh — Mise à jour de NetWatch vers une version publiée
#
#   1. Sauvegarde de la configuration (scripts/backup.sh --config-only)
#   2. git : dernière version taguée (vX.Y.Z) — ou la référence donnée, ou origin/main
#   3. Dépendances du portail, images (pull) et moteurs (build)
#   4. docker compose up -d, initialisations idempotentes (setup-es, netflow, kibana)
#   5. Redémarrage du portail, health check, résumé des changements
# Aucune donnée n'est touchée : volumes et index restent en place. En cas de
# problème : scripts/restore.sh backups/netwatch-config-… puis git checkout <ancienne version>.
#
# Usage :
#   scripts/upgrade.sh              # dernière version taguée (sinon origin/main)
#   scripts/upgrade.sh v2.2.0       # version précise
#   scripts/upgrade.sh origin/main  # suivre la branche principale
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

TARGET="${1:-}"
ES="${NETWATCH_ES_URL:-http://localhost:9200}"
ok()   { printf '  ✓ %s\n' "$1"; }
warn() { printf '  ! %s\n' "$1" >&2; }
die()  { printf '  ✗ %s\n' "$1" >&2; exit 1; }

command -v git >/dev/null || die "git requis"
command -v docker >/dev/null || die "docker requis"
[ -z "$(git status --porcelain --untracked-files=no)" ] || die "modifications locales non commitées — git stash ou git commit d'abord"

OLD_VERSION="$(cat VERSION 2>/dev/null || echo unknown)"
OLD_COMMIT="$(git rev-parse HEAD)"

echo "=== Mise à jour NetWatch (actuellement $OLD_VERSION, $(git rev-parse --short HEAD)) ==="
git fetch -q --tags origin
if [ -z "$TARGET" ]; then
  TARGET="$(git tag --list 'v[0-9]*' --sort=-v:refname | head -1)"
  [ -n "$TARGET" ] || TARGET="origin/main"
fi
NEW_COMMIT="$(git rev-parse "$TARGET^{commit}" 2>/dev/null || die "référence introuvable : $TARGET")"
if [ "$NEW_COMMIT" = "$OLD_COMMIT" ]; then
  echo "  déjà à jour ($TARGET)."; exit 0
fi
echo "  cible : $TARGET ($(git rev-parse --short "$NEW_COMMIT"))"

# ── 1. Sauvegarde de la configuration ───────────────────────────────────────
bash scripts/backup.sh --config-only --keep 10 | tail -2

# ── 2. Code ──────────────────────────────────────────────────────────────────
case "$TARGET" in
  origin/*)
    branch="${TARGET#origin/}"
    git checkout -q "$branch" 2>/dev/null || git checkout -q -b "$branch" "$TARGET"
    git merge -q --ff-only "$TARGET" ;;
  *) git checkout -q "$TARGET" ;;
esac
NEW_VERSION="$(cat VERSION 2>/dev/null || echo unknown)"
ok "code : $OLD_VERSION → $NEW_VERSION"

# ── 3. Dépendances et images ─────────────────────────────────────────────────
if [ -x portal/.venv/bin/pip ]; then
  portal/.venv/bin/pip install -q -r portal/requirements.txt && ok "dépendances du portail"
fi
docker compose pull -q --ignore-buildable 2>/dev/null || docker compose pull -q 2>/dev/null || warn "pull partiel (hors ligne ?)"
docker compose build -q --pull >/dev/null 2>&1 || docker compose build -q || warn "build en échec — voir docker compose build"
ok "images à jour"

# ── 4. Stack ─────────────────────────────────────────────────────────────────
docker compose up -d --remove-orphans
printf '  attente Elasticsearch'
for _ in $(seq 1 60); do curl -sf "$ES/_cluster/health" >/dev/null 2>&1 && break; printf '.'; sleep 5; done; echo
bash setup-es.sh >/dev/null && ok "setup-es"
ES="$ES" bash scripts/setup-netflow.sh >/dev/null 2>&1 && ok "setup-netflow" || warn "setup-netflow en échec (make setup-netflow)"
bash scripts/setup-kibana.sh >/dev/null 2>&1 && ok "data views Kibana" || warn "Kibana pas prêt (make kibana-setup plus tard)"

# ── 5. Portail ───────────────────────────────────────────────────────────────
if systemctl is-enabled -q netwatch-portal 2>/dev/null; then
  sudo systemctl restart netwatch-portal && ok "portail redémarré (systemd)"
else
  make -s portal-stop >/dev/null 2>&1 || true
  make -s portal >/dev/null 2>&1 && ok "portail redémarré" || warn "portail non redémarré : make portal"
fi

bash scripts/health-check.sh --no-color || true

echo
echo "=== NetWatch $OLD_VERSION → $NEW_VERSION ==="
git log --oneline --no-decorate "$OLD_COMMIT..$NEW_COMMIT" | head -40
echo "Détails : CHANGELOG.md — retour arrière : git checkout $(git rev-parse --short "$OLD_COMMIT") && docker compose up -d"
