.PHONY: start stop restart status logs demo sim build clean update-intel setup-geoip help

ES  ?= http://localhost:9200
SVC ?=

# ============================================================
# Stack
# ============================================================

start:
	docker compose up -d
	@echo ""
	@echo "Grafana      → http://localhost:3000"
	@echo "Elasticsearch→ http://localhost:9200"
	@echo "Prometheus   → http://localhost:9090"

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

clean:
	docker compose down -v --remove-orphans
	@echo "Volumes supprimés (données ES, Grafana, Prometheus effacées)"

# ============================================================
# Diagnostic
# ============================================================

health:
	@echo "=== Cluster ES ===" && curl -sf $(ES)/_cluster/health?pretty
	@echo ""
	@echo "=== Index ===" && curl -sf "$(ES)/_cat/indices?v&s=index&h=index,docs.count,store.size"
	@echo ""
	@echo "=== AutoBlock ===" && curl -sf http://localhost:5001/health || echo "autoblock non disponible"

# ============================================================
# Aide
# ============================================================

help:
	@echo ""
	@echo "NetWatch v2 — Commandes disponibles"
	@echo "────────────────────────────────────────────────────"
	@echo "  make start           Démarrer les 10 services"
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
	@echo "  make health          Vérifier l'état du stack (ES + index + autoblock)"
	@echo "  make clean           Supprimer le stack ET les données (irréversible)"
	@echo ""
