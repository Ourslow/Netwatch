.PHONY: start stop restart status logs demo sim build clean update-intel setup-geoip llm-pull install portal portal-stop portal-log setup-es health health-json health-no-color help

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

install:
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

# ============================================================
# Portail Flask (sans systemd, pour dev/debug)
# ============================================================

portal:
	@mkdir -p logs
	@echo "Démarrage portail Flask en arrière-plan..."
	@cd portal && nohup python3 app.py >> ../logs/portal.log 2>&1 & echo $$! > ../logs/portal.pid
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
	@echo "Ollama       → http://localhost:11434 (lancer 'make llm-pull' si premier démarrage)"

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
	@echo "  make demo            Démonstration complète (6h de trafic)"
	@echo "  make demo-fast       Démonstration rapide (1h, intensité high)"
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
	@echo ""
