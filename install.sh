#!/usr/bin/env bash
# install.sh — Installation de NetWatch en une commande (Ubuntu 22.04 / 24.04, Debian 12)
#
# Idempotent et relançable : rien de déjà en place n'est refait, aucune valeur
# personnalisée de .env n'est écrasée.
#   1. Docker Engine + Compose v2 (script officiel) si absents ; utilisateur dans le groupe docker
#   2. Prérequis : vm.max_map_count (Elasticsearch), python3-venv, curl, git
#   3. .env et portal/.env créés depuis les .example — secrets aléatoires, interface de capture
#      et IP du serveur détectées, édition (Core / IA) et point d'entrée HTTPS selon les options
#   4. Environnement Python du portail (portal/.venv)
#   5. Démarrage de la stack, initialisations Elasticsearch, NetFlow, Kibana, Arkime (une fois)
#   6. Portail en service systemd (netwatch-portal) + health check
#
# Usage :
#   ./install.sh                                  # édition Core, accès direct par port
#   ./install.sh --ia                             # édition IA (Ollama + modèle mistral)
#   ./install.sh --public-url https://192.168.1.10   # point d'entrée HTTPS unique (profil proxy)
#   ./install.sh --iface ens18                    # interface de capture (défaut : route par défaut)
#   ./install.sh --no-start                       # préparer (Docker, .env, venv) sans démarrer
#   ./install.sh --no-service                     # ne pas installer le service systemd du portail
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

OPT_IA=false
OPT_PUBLIC_URL=""
OPT_IFACE=""
OPT_START=true
OPT_SERVICE=true
while [ $# -gt 0 ]; do
  case "$1" in
    --ia)          OPT_IA=true ;;
    --public-url)  OPT_PUBLIC_URL="${2:?--public-url attend une URL}"; shift ;;
    --iface)       OPT_IFACE="${2:?--iface attend une interface (ex. ens18)}"; shift ;;
    --no-start)    OPT_START=false ;;
    --no-service)  OPT_SERVICE=false ;;
    -h|--help)     sed -n '2,22p' "$0"; exit 0 ;;
    *) echo "Option inconnue : $1 (voir --help)" >&2; exit 2 ;;
  esac
  shift
done

# ── Affichage ────────────────────────────────────────────────────────────────
if [ -t 1 ]; then B=$'\033[1m'; G=$'\033[32m'; Y=$'\033[33m'; R=$'\033[31m'; N=$'\033[0m'; else B=""; G=""; Y=""; R=""; N=""; fi
step() { printf '\n%s== %s ==%s\n' "$B" "$1" "$N"; }
ok()   { printf '  %s✓%s %s\n' "$G" "$N" "$1"; }
warn() { printf '  %s!%s %s\n' "$Y" "$N" "$1"; }
die()  { printf '  %s✗ %s%s\n' "$R" "$1" "$N" >&2; exit 1; }

# ── Droits ───────────────────────────────────────────────────────────────────
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  command -v sudo >/dev/null || die "sudo requis (ou lancer en root)"
  SUDO="sudo"
fi
RUN_USER="${SUDO_USER:-$(id -un)}"
RUN_GROUP="$(id -gn "$RUN_USER")"

command -v apt-get >/dev/null || warn "apt-get absent : paquets système non installés automatiquement (Ubuntu/Debian attendu)"

# ── 1. Docker ────────────────────────────────────────────────────────────────
step "1/6 Docker Engine + Compose v2"
if command -v docker >/dev/null && docker compose version >/dev/null 2>&1; then
  ok "présent : $(docker --version | cut -d, -f1) · $(docker compose version --short 2>/dev/null || echo compose)"
else
  command -v curl >/dev/null || $SUDO apt-get install -y -qq curl >/dev/null
  curl -fsSL https://get.docker.com | $SUDO sh
  ok "Docker installé"
fi
if [ "$RUN_USER" != "root" ] && ! id -nG "$RUN_USER" | tr ' ' '\n' | grep -qx docker; then
  $SUDO usermod -aG docker "$RUN_USER"
  warn "$RUN_USER ajouté au groupe docker — effectif à la prochaine connexion (make/docker sans sudo)"
fi
HAS_SYSTEMD=false; [ -d /run/systemd/system ] && HAS_SYSTEMD=true
DOCKER="docker"
docker info >/dev/null 2>&1 || DOCKER="$SUDO docker"
if ! $DOCKER info >/dev/null 2>&1; then
  # WSL / conteneur sans systemd : le démon n'est pas lancé après l'installation
  $HAS_SYSTEMD && $SUDO systemctl start docker || $SUDO service docker start
  sleep 3
  $DOCKER info >/dev/null 2>&1 || die "le démon Docker ne répond pas (sudo service docker start ; sous WSL : systemd=true dans /etc/wsl.conf puis wsl --shutdown)"
fi

# ── 2. Prérequis système ─────────────────────────────────────────────────────
step "2/6 Prérequis système"
if command -v apt-get >/dev/null; then
  missing=""
  for p in python3 python3-venv python3-pip curl git make; do dpkg -s "$p" >/dev/null 2>&1 || missing="$missing $p"; done
  if [ -n "$missing" ]; then
    $SUDO apt-get update -qq
    # shellcheck disable=SC2086
    $SUDO apt-get install -y -qq $missing >/dev/null
    ok "paquets installés :$missing"
  else
    ok "python3, venv, curl, git présents"
  fi
fi
if [ "$(sysctl -n vm.max_map_count 2>/dev/null || echo 0)" -lt 262144 ]; then
  echo "vm.max_map_count=262144" | $SUDO tee /etc/sysctl.d/99-netwatch.conf >/dev/null
  $SUDO sysctl -q --system >/dev/null 2>&1 || $SUDO sysctl -qw vm.max_map_count=262144
  ok "vm.max_map_count=262144 (Elasticsearch)"
else
  ok "vm.max_map_count déjà suffisant"
fi

# ── 3. Fichiers .env ─────────────────────────────────────────────────────────
step "3/6 Configuration (.env, portal/.env)"

gen_hex()  { python3 -c "import secrets; print(secrets.token_hex($1))"; }
gen_pass() { python3 -c "import secrets, string; a = string.ascii_letters + string.digits; print(''.join(secrets.choice(a) for _ in range(20)))"; }

# env_set FICHIER CLÉ VALEUR [force]
#   Sans force : ne remplace la valeur que si elle est absente, commentée ou un
#   placeholder (vide, changeme…, votre_…, x.x.x.x) — jamais une valeur réelle.
env_set() {
  python3 - "$1" "$2" "$3" "${4:-}" <<'PY'
import re, sys
path, key, value, force = sys.argv[1:5]
lines = open(path, encoding="utf-8").read().splitlines()
placeholder = re.compile(r"^(|changeme.*|votre_.*|x\.x\.x\.x)$")
pattern = re.compile(r"^(#\s*)?" + re.escape(key) + r"=(.*)$")
done = False
for i, line in enumerate(lines):
    m = pattern.match(line)
    if not m or done:
        continue
    current = m.group(2).split(" #", 1)[0].strip()
    if force or m.group(1) or placeholder.match(current):
        lines[i] = f"{key}={value}"
    done = True
if not done:
    lines.append(f"{key}={value}")
open(path, "w", encoding="utf-8").write("\n".join(lines) + "\n")
PY
}
env_get() { grep -E "^$2=" "$1" | tail -1 | cut -d= -f2- | sed 's/[[:space:]]*#.*$//'; }

[ -f .env ]        || { cp .env.example .env; ok ".env créé depuis .env.example"; }
[ -f portal/.env ] || { cp portal/.env.example portal/.env; ok "portal/.env créé depuis portal/.env.example"; }
chmod 600 .env portal/.env

# Interface de capture + IP locale
IFACE="${OPT_IFACE:-$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}' || true)}"
[ -n "$IFACE" ] || IFACE="eth0"
HOST_IP="$(ip -4 addr show "$IFACE" 2>/dev/null | awk '/inet /{print $2; exit}' | cut -d/ -f1 || true)"
force_iface=""; [ -n "$OPT_IFACE" ] && force_iface="force"
env_set .env IFACE "$IFACE" "$force_iface"
[ -n "$HOST_IP" ] && env_set .env SNORT_MONITORED_SERVER "$HOST_IP"
ok "interface de capture : $IFACE${HOST_IP:+ ($HOST_IP)}"

# Secrets — tous ceux que docker-compose exige (${VAR:?}) et ceux du portail
env_set .env GRAFANA_ADMIN_PASSWORD     "$(gen_pass)"
env_set .env N8N_PASSWORD               "$(gen_pass)"
env_set .env AUTOBLOCK_WEBHOOK_SECRET   "$(gen_hex 32)"
env_set .env ARKIME_PASSWORD_SECRET     "$(gen_hex 32)"
env_set .env NETBOX_DB_PASSWORD         "$(gen_pass)"
env_set .env NETBOX_REDIS_PASSWORD      "$(gen_pass)"
env_set .env NETBOX_SECRET_KEY          "$(gen_hex 32)"
env_set .env NETBOX_API_TOKEN_PEPPER    "$(gen_hex 32)"
env_set .env NETBOX_SUPERUSER_PASSWORD  "$(gen_pass)"
env_set .env NETBOX_TOKEN_KEY           "$(gen_hex 6)"
env_set .env NETBOX_TOKEN               "$(gen_hex 20)"
env_set .env KIBANA_ENCRYPTION_KEY      "$(gen_hex 32)"
env_set portal/.env FLASK_SECRET_KEY    "$(gen_hex 32)"
env_set portal/.env PORTAL_PASSWORD     "$(gen_pass)"
ok "secrets générés (les valeurs déjà personnalisées sont conservées)"

# Édition et point d'entrée — l'édition est décidée par le .env racine ; portal/.env
# ne doit pas la contredire (son .example pointe Ollama par défaut).
profiles="$(env_get .env COMPOSE_PROFILES | tr ',' '\n' | grep -v '^$' || true)"
if $OPT_IA; then
  profiles="$(printf '%s\nia\n' "$profiles")"
  env_set .env OLLAMA_URL "http://localhost:11434" force
  env_set portal/.env OLLAMA_URL "http://localhost:11434" force
  ok "édition IA (Ollama)"
else
  if ! printf '%s\n' "$profiles" | grep -qx ia; then
    env_set portal/.env OLLAMA_URL "" force
    ok "édition Core"
  fi
fi
if [ -n "$OPT_PUBLIC_URL" ]; then
  profiles="$(printf '%s\nproxy\n' "$profiles")"
  env_set .env NETWATCH_PUBLIC_URL   "$OPT_PUBLIC_URL" force
  env_set .env NETWATCH_TLS          "internal"
  env_set .env ARKIME_WEB_BASE_PATH  "/arkime/" force
  env_set .env NETWATCH_NETBOX_URL   "http://localhost:8000/netbox" force
  ok "point d'entrée HTTPS unique : $OPT_PUBLIC_URL (profil proxy, CA locale)"
fi
profiles="$(printf '%s\n' "$profiles" | awk 'NF && !seen[$0]++' | paste -sd, -)"
env_set .env COMPOSE_PROFILES "$profiles" force

# Filebeat exige un fichier de config appartenant à root
$SUDO chown root:root filebeat/filebeat.yml && $SUDO chmod 644 filebeat/filebeat.yml
ok "permissions filebeat.yml"

# ── 4. Environnement Python du portail ───────────────────────────────────────
step "4/6 Portail — environnement Python"
if [ ! -x portal/.venv/bin/python3 ]; then
  python3 -m venv portal/.venv
fi
portal/.venv/bin/pip install -q --upgrade pip >/dev/null
portal/.venv/bin/pip install -q -r portal/requirements.txt
ok "portal/.venv prêt"

if ! $OPT_START; then
  step "Terminé (--no-start)"
  echo "  Démarrer ensuite : make start && make portal   (ou relancer ./install.sh)"
  exit 0
fi

# ── 5. Stack ─────────────────────────────────────────────────────────────────
step "5/6 Démarrage de la stack"
echo "  (premier lancement : la compilation de Snort prend 10-15 min)"
$DOCKER compose up -d --remove-orphans
ES="${NETWATCH_ES_URL:-http://localhost:9200}"
printf '  attente Elasticsearch'
for _ in $(seq 1 120); do
  curl -sf "$ES/_cluster/health" >/dev/null 2>&1 && break
  printf '.'; sleep 5
done
echo
curl -sf "$ES/_cluster/health" >/dev/null 2>&1 || die "Elasticsearch ne répond pas sur $ES ($DOCKER compose logs elasticsearch)"
bash setup-es.sh
ES="$ES" bash scripts/setup-netflow.sh || warn "setup-netflow.sh en échec (relancer : make setup-netflow)"
if [ -z "$(curl -s "$ES/_cat/indices/arkime_*?h=index" 2>/dev/null)" ]; then
  echo "  Arkime : initialisation de la base (une fois)"
  $DOCKER compose run --rm arkime db.pl --wait-for-db http://127.0.0.1:9200 -- http://127.0.0.1:9200 init \
    || warn "init Arkime en échec (relancer : make arkime-init)"
fi
bash scripts/setup-kibana.sh || warn "Kibana pas encore prêt — relancer plus tard : make kibana-setup"
if $OPT_IA; then
  model="$(env_get .env OLLAMA_MODEL)"; model="${model:-mistral}"
  $DOCKER exec netwatch-ollama ollama pull "$model" || warn "téléchargement du modèle $model en échec (make llm-pull)"
fi
ok "stack démarrée"

# ── 6. Service systemd du portail ────────────────────────────────────────────
step "6/6 Portail"
if $OPT_SERVICE && $HAS_SYSTEMD; then
  sed -e "s#/home/netwatch/netwatch#$ROOT#g" \
      -e "s#^User=.*#User=$RUN_USER#" \
      -e "s#^Group=.*#Group=$RUN_GROUP#" \
      -e "s#/usr/bin/python3#$ROOT/portal/.venv/bin/python3#" \
      systemd/netwatch-portal.service | $SUDO tee /etc/systemd/system/netwatch-portal.service >/dev/null
  mkdir -p logs
  $SUDO systemctl daemon-reload
  $SUDO systemctl enable -q netwatch-portal
  $SUDO systemctl restart netwatch-portal
  sleep 3
  systemctl is-active -q netwatch-portal && ok "service netwatch-portal actif" || warn "service netwatch-portal inactif : journalctl -u netwatch-portal"
else
  $HAS_SYSTEMD || warn "pas de systemd (WSL ?) : portail lancé avec make portal, à relancer après chaque redémarrage"
  make portal
fi

bash scripts/health-check.sh --no-color || true

# ── Récapitulatif ────────────────────────────────────────────────────────────
step "Installation terminée — NetWatch $(cat VERSION)"
if [ -n "$OPT_PUBLIC_URL" ]; then
  echo "  Portail        : $OPT_PUBLIC_URL/   (puis /grafana/, /kibana/, /arkime/, /ntopng/, /netbox/)"
  echo "  Certificat     : CA locale Caddy — make proxy-ca puis importer netwatch-ca.crt sur les postes"
else
  echo "  Portail        : http://${HOST_IP:-<IP>}:5050"
  echo "  Grafana        : http://${HOST_IP:-<IP>}:3000   (les autres outils sont liés à localhost — voir README « Accès unifié HTTPS »)"
fi
echo "  Portail admin  : $(env_get portal/.env PORTAL_USERNAME) / $(env_get portal/.env PORTAL_PASSWORD)"
echo "  Grafana admin  : admin / $(env_get .env GRAFANA_ADMIN_PASSWORD)"
echo "  NetBox admin   : $(env_get .env NETBOX_SUPERUSER_NAME) / $(env_get .env NETBOX_SUPERUSER_PASSWORD)"
echo "  Ces valeurs sont dans .env et portal/.env (chmod 600). Sauvegarde : make backup"
[ "$DOCKER" = "docker" ] || echo "  Reconnectez-vous pour utiliser docker/make sans sudo."
