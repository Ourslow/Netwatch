.PHONY: start stop restart status logs demo demo-fast demo-client sim build clean update-intel setup-geoip llm-pull install install-service portal portal-stop portal-log setup-es setup-netflow netflow-test health health-json health-no-color help arkime-init arkime-reset observability observability-stop demo-netbox kibana-setup test lint check proxy-ca backup backup-config restore upgrade version

# ============================================================
# Exploitation — installation, sauvegarde, restauration, mise à jour
# ============================================================

# Installation complète en une commande (Docker, .env, venv, stack, systemd) — ./install.sh --help
install:
	@./install.sh

version:
	@cat VERSION

# Sauvegarde complète (config, volumes, NetBox, snapshot ES) → backups/ ; KEEP=n pour ne garder que n archives
backup:
	@bash scripts/backup.sh $(if $(KEEP),--keep $(KEEP),)

# Configuration + état du portail seulement (à chaud, quelques secondes)
backup-config:
	@bash scripts/backup.sh --config-only $(if $(KEEP),--keep $(KEEP),)

# make restore ARCHIVE=backups/netwatch-2.1.0-20260918-1200.tar.gz
restore:
	@test -n "$(ARCHIVE)" || { echo "Usage : make restore ARCHIVE=backups/<archive>.tar.gz"; exit 2; }
	@bash scripts/restore.sh "$(ARCHIVE)"

# Mise à jour vers la dernière version taguée (ou REF=v2.2.0 / REF=origin/main)
upgrade:
	@bash scripts/upgrade.sh $(REF)

# ============================================================
# Point d'entrée HTTPS unique (Caddy, profil « proxy ») — voir caddy/Caddyfile
# ============================================================

# Exporte la CA locale générée par Caddy (NETWATCH_TLS=internal) : à importer
# dans le navigateur / le magasin de certificats des postes pour éviter l'avertissement.
proxy-ca:
	@docker cp netwatch-caddy:/data/caddy/pki/authorities/local/root.crt ./netwatch-ca.crt \
		&& echo "→ netwatch-ca.crt exporté (importer comme autorité de confiance sur les postes)"

# ============================================================
# Qualité — mêmes commandes que la CI (.github/workflows/ci.yml)
#   pip install -r portal/requirements.txt pytest ruff
# ============================================================

test:
	@python3 -m pytest

lint:
	@python3 -m ruff check portal scripts simulate-traffic.py
	@find . -name "*.sh" -not -path "./.git/*" -print0 | xargs -0 bash -n && echo "bash -n : OK"

check: lint test

# ============================================================
# Services d'observabilité complémentaires
#   Blackbox (sondes actives) · Kibana · ntopng (nDPI) · Arkime (PCAP) · NetBox (IPAM)
# ============================================================

# Démarrer / arrêter uniquement les services complémentaires (le cœur reste intact)
observability:
	docker compose up -d blackbox kibana ntopng arkime netbox-postgres netbox-redis netbox-redis-cache netbox netbox-worker
	@echo ""
	@echo "Kibana  → http://localhost:5601      ntopng → http://localhost:3001"
	@echo "Arkime  → http://localhost:8005      NetBox → http://localhost:8000"
	@echo "Blackbox→ http://localhost:9115      (cibles : prometheus/blackbox-targets.yml)"

observability-stop:
	docker compose stop blackbox kibana ntopng arkime netbox-worker netbox netbox-redis netbox-redis-cache netbox-postgres

# Data views Kibana (zeek-*, suricata-*, snort-*, netflow-*, beacons, arkime) — Discover prêt à l'emploi
kibana-setup:
	bash scripts/setup-kibana.sh

# Données de démo dans NetBox (site, préfixes, IP nommées) → /ip/<ip> et import hostgroups parlants
demo-netbox:
	bash scripts/demo/netbox-seed.sh

# Premier lancement d'Arkime : création des index ES (arkime_*). L'utilisateur
# admin/admin est créé au démarrage du service (--add-admin) — changer le mot de
# passe ensuite dans le viewer (Users). Répondre INIT si db.pl le demande.
arkime-init:
	@echo "=== Arkime : initialisation de la base (index ES arkime_*) ==="
	docker compose run --rm arkime db.pl --wait-for-db http://127.0.0.1:9200 -- http://127.0.0.1:9200 init

# Repartir de zéro (démo, changement d'ARKIME_PASSWORD_SECRET…) : db.pl détecte une
# installation existante via les templates ES, qui survivent à la suppression des index —
# on purge donc index ET templates avant de ré-initialiser sans prompt.
arkime-reset:
	@echo "=== Arkime : purge des index + templates arkime_* puis ré-initialisation ==="
	docker compose stop arkime
	@for i in $$(curl -s "$(ES)/_cat/indices/arkime*?h=index"); do echo "  index $$i : $$(curl -s -o /dev/null -w '%{http_code}' -XDELETE "$(ES)/$$i")"; done
	@echo "  templates legacy : $$(curl -s -o /dev/null -w '%{http_code}' -XDELETE "$(ES)/_template/arkime*")"
	@for t in $$(curl -s "$(ES)/_index_template" | python3 -c "import sys,json;[print(t['name']) for t in json.load(sys.stdin)['index_templates'] if t['name'].startswith('arkime')]"); do echo "  template $$t : $$(curl -s -o /dev/null -w '%{http_code}' -XDELETE "$(ES)/_index_template/$$t")"; done
	docker compose run --rm arkime db.pl --wait-for-db http://127.0.0.1:9200 -- http://127.0.0.1:9200 init
	docker compose up -d arkime

ES     ?= http://localhost:9200
OLLAMA ?= http://localhost:11434
MODEL  ?= mistral
SVC    ?=

# ============================================================
# Stack
# ============================================================

# ============================================================
# Installation système (à lancer une seule fois sur la VM)
# ============================================================

# Service systemd du portail seul (chemins de systemd/netwatch-portal.service) —
# install.sh l'installe déjà, adapté au répertoire et à l'utilisateur courants.
install-service:
	@echo "=== Installation service systemd netwatch-portal ==="
	cp systemd/netwatch-portal.service /etc/systemd/system/
	systemctl daemon-reload
	systemctl enable netwatch-portal
	systemctl start netwatch-portal
	@echo ""
	@echo "Portail installé comme service systemd."
	@echo "  make portal-log   → voir les logs"
	@echo "  systemctl status netwatch-portal"

setup-es:
	bash setup-es.sh

setup-netflow:
	bash scripts/setup-netflow.sh

# ============================================================
# Portail Flask (sans systemd, pour dev/debug)
# ============================================================

portal:
	@mkdir -p logs
	@echo "Démarrage portail Flask en arrière-plan..."
	@cd portal && nohup $$( [ -x .venv/bin/python3 ] && echo .venv/bin/python3 || echo python3 ) app.py >> ../logs/portal.log 2>&1 & echo $$! > ../logs/portal.pid
	@sleep 2
	@curl -sf http://localhost:5050/login > /dev/null && echo "Portail OK → http://localhost:5050" || echo "WARN: portail non joignable, voir logs/portal.log"

portal-stop:
	@if [ -f logs/portal.pid ]; then \
	  kill $$(cat logs/portal.pid) 2>/dev/null && echo "Portail arrêté." || echo "Déjà arrêté."; \
	  rm -f logs/portal.pid; \
	else \
	  echo "Aucun PID enregistré."; \
	fi

portal-log:
	tail -f logs/portal.log

# ============================================================
# Stack
# ============================================================

start:
	docker compose up -d
	@echo ""
	@echo "Grafana      → http://localhost:3000"
	@echo "Elasticsearch→ http://localhost:9200"
	@echo "Prometheus   → http://localhost:9090"
	@echo "Ollama       → http://localhost:11434 (édition IA : COMPOSE_PROFILES=ia dans .env, puis 'make llm-pull')"

stop:
	docker compose down

restart:
ifdef SVC
	docker compose restart $(SVC)
else
	docker compose restart
endif

status:
	docker compose ps

logs:
ifdef SVC
	docker compose logs -f $(SVC)
else
	docker compose logs -f
endif

# ============================================================
# Build
# ============================================================

build:
ifdef SVC
	docker compose build --no-cache $(SVC)
	docker compose up -d $(SVC)
else
	docker compose build --no-cache
	docker compose up -d
endif

# ============================================================
# Démonstration
# ============================================================

demo:
	bash demo.sh

demo-fast:
	bash demo.sh --fast

demo-client:
	bash demo.sh --auto

sim:
	python3 simulate-traffic.py --hours 6 --intensity medium --attack --es $(ES)

sim-fast:
	python3 simulate-traffic.py --hours 1 --intensity high --attack --es $(ES)

# ============================================================
# Maintenance
# ============================================================

update-intel:
	bash update-intel.sh

setup-geoip:
	bash setup-geoip.sh

llm-pull:
	docker exec netwatch-ollama ollama pull $(MODEL)
	@echo "Modèle '$(MODEL)' prêt — assistant IA disponible dans le portail (/alerts, /report)"

clean:
	docker compose down -v --remove-orphans
	@echo "Volumes supprimés (données ES, Grafana, Prometheus effacées)"

# ============================================================
# NetFlow — simulation et test (T_017)
# ============================================================

netflow-test:
	@echo "=== Test NetFlow — envoi de paquets UDP de simulation ==="
	@echo ""
	@if command -v softflowd >/dev/null 2>&1; then \
	  echo "softflowd détecté — simulation de flux NetFlow v9 vers localhost:2055..."; \
	  softflowd -n 127.0.0.1:2055 -v 9 -t 5 -c 20 -i lo 2>/dev/null & \
	  SFPID=$$!; \
	  sleep 6; \
	  kill $$SFPID 2>/dev/null || true; \
	  echo "Simulation softflowd terminée (20 flows envoyés)."; \
	else \
	  echo "softflowd absent — envoi de paquets UDP bruts via Python..."; \
	  python3 -c " \
import socket, struct, time, random; \
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); \
def rand_ip(): return bytes([random.randint(1,254) for _ in range(4)]); \
def nf9_pkt(src, dst, sport, dport, proto, pkts, byt): \
    now = int(time.time()); \
    sys_up = (now % 86400) * 1000; \
    hdr = struct.pack('>HHIII', 9, 1, sys_up, now, random.randint(1,9999)); \
    tpl = struct.pack('>HHHH HH HH HH HH HH HH HH HH HH HH HH HH', \
        0, 28, 256, 13, \
        8,4, 12,4, 7,2, 11,2, 4,1, 2,4, 1,4, 21,4, 22,4, 10,2, 14,2, 16,2, 17,2); \
    flow = struct.pack('>4s4sHHBIIIIHHHH', src, dst, sport, dport, proto, pkts, byt, now-5, now, 0, 0, 0, 0); \
    data_hdr = struct.pack('>HH', 256, 4+len(flow)); \
    return hdr + struct.pack('>HH',0,4+len(tpl)) + tpl + data_hdr + flow; \
flows = [nf9_pkt(rand_ip(),rand_ip(),random.randint(1024,65535),random.choice([80,443,53,22,25,3389]),random.choice([6,17]),random.randint(1,1000),random.randint(64,1500000)) for _ in range(10)]; \
[sock.sendto(p,('127.0.0.1',2055)) for p in flows]; \
print(f'  10 paquets NetFlow v9 envoyés vers 127.0.0.1:2055'); \
sock.close() \
"; \
	fi
	@echo ""
	@echo "Vérification dans ES (attente 10s pour ingestion Filebeat)..."
	@sleep 10
	@curl -sf "$(ES)/netflow-*/_count" 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'  Documents netflow-* dans ES : {d[\"count\"]}')" 2>/dev/null || echo "  Aucun index netflow-* trouvé (goflow2 en cours de démarrage ?)"
	@echo ""

# ============================================================
# Diagnostic
# ============================================================

health:
	@bash scripts/health-check.sh

health-json:
	@bash scripts/health-check.sh --json

health-no-color:
	@bash scripts/health-check.sh --no-color

# ============================================================
# Aide
# ============================================================

help:
	@echo ""
	@echo "NetWatch v2 — Commandes disponibles"
	@echo "────────────────────────────────────────────────────"
	@echo "  make start           Démarrer les 11 services"
	@echo "  make stop            Arrêter le stack"
	@echo "  make restart         Redémarrer tous les services"
	@echo "  make restart SVC=snort  Redémarrer un service"
	@echo "  make status          État des conteneurs"
	@echo "  make logs            Logs de tous les services"
	@echo "  make logs SVC=zeek   Logs d'un service"
	@echo ""
	@echo "  make build           Rebuild tous les services"
	@echo "  make build SVC=snort Rebuild un service"
	@echo ""
	@echo "  make install         Installation complète en une commande (./install.sh --help)"
	@echo "  make backup          Sauvegarde complète → backups/ (make backup-config : config seule)"
	@echo "  make restore ARCHIVE=backups/<archive>.tar.gz"
	@echo "  make upgrade         Mise à jour vers la dernière version taguée (REF=… pour cibler)"
	@echo "  make version         Version installée (VERSION)"
	@echo ""
	@echo "  make test            Tests portail + conventions (pytest)"
	@echo "  make lint            ruff + bash -n"
	@echo "  make check           lint + test (ce que fait la CI)"
	@echo ""
	@echo "  make demo            Démonstration complète (6h de trafic)"
	@echo "  make demo-fast       Démonstration rapide (1h, intensité high)"
	@echo "  make demo-client     Démo client pipeline NDR (--auto, < 5 min)"
	@echo "  make observability   Démarrer Blackbox, Kibana, ntopng, Arkime, NetBox"
	@echo "  make arkime-init     Arkime : créer les index ES (premier lancement)"
	@echo "  make arkime-reset    Arkime : repartir de zéro (index + templates)"
	@echo "  make kibana-setup    Kibana : data views des index NetWatch (Discover)"
	@echo "  make proxy-ca        Profil proxy : exporter la CA locale Caddy (netwatch-ca.crt)"
	@echo "  make demo-netbox     Données de démo NetBox (site, préfixes, IP nommées)"
	@echo "  make sim             Simuler 6h de trafic avec attaques"
	@echo "  make sim-fast        Simuler 1h de trafic rapide"
	@echo ""
	@echo "  make update-intel    Mettre à jour les listes threat intel Zeek"
	@echo "  make setup-geoip     Initialiser le pipeline GeoIP Elasticsearch"
	@echo "  make llm-pull        Télécharger le modèle IA local (Ollama, défaut: mistral)"
	@echo "  make health          Health check complet des 12 services (coloré, exit code 0/1/2)
	@echo "  make health-json     Health check sortie JSON (intégration CI/monitoring)"
	@echo "  make health-no-color Health check sans couleurs (logs, cron)""
	@echo "  make clean           Supprimer le stack ET les données (irréversible)"
	@echo ""
	@echo "  make portal          Lancer le portail Flask en arrière-plan"
	@echo "  make portal-stop     Arrêter le portail Flask"
	@echo "  make portal-log      Suivre les logs du portail"
	@echo ""
	@echo "  make install         Installer le portail comme service systemd (root requis)"
	@echo "  make setup-es        Configurer ES (réplicas 0, templates)"
	@echo "  make setup-netflow   Créer template ES netflow-* + ILM policy 30 jours"
	@echo "  make netflow-test    Envoyer des paquets NetFlow de test (softflowd ou Python)"
	@echo ""
