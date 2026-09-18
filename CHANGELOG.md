# Changelog

Format : [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/), versions [SemVer](https://semver.org/lang/fr/).
La version courante est dans `VERSION` ; `scripts/upgrade.sh` affiche les commits entre deux versions.

## 2.1.0 — 2026-09-18 (en cours)

Passage de « labo / SideQuest » à produit : voir `docs/positionnement-produit.md`.

### Ajouté
- Positionnement produit : éditions Community (AGPL v3) / Pro, cibles PME et MSP, découpage
  fonctionnel, écart labo → produit, validation terrain avant code.
- Tests (`pytest`, 140+ tests sans stack) et CI GitHub Actions (ruff, pytest, `docker compose
  config`, promtool, shellcheck, `caddy validate`). `make test` / `make lint` / `make check`.
- Point d'entrée HTTPS unique : Caddy (profil compose `proxy`), TLS (CA locale, Let's Encrypt ou
  certificat fourni), outils sous `/grafana/`, `/kibana/`, `/arkime/`, `/ntopng/`, `/netbox/`,
  authentification unifiée par la session du portail (`/auth/check`, Grafana en auth proxy).
- Installation en une commande (`install.sh`) : Docker, prérequis noyau, secrets générés,
  interface détectée, venv portail, service systemd, initialisations ES/NetFlow/Kibana/Arkime.
- Sauvegarde / restauration (`scripts/backup.sh`, `scripts/restore.sh`) : configuration, état du
  portail, rapports, volumes Grafana/Prometheus/n8n/CrowdSec/Arkime/Caddy, `pg_dump` NetBox,
  snapshot Elasticsearch (dépôt `fs` sur le volume `es-snapshots`).
- Mise à jour (`scripts/upgrade.sh`) : sauvegarde de la configuration, `git` vers la dernière
  version, `pull`/`build`, initialisations idempotentes, redémarrage du portail, health check.
- `VERSION` et ce changelog.

### Modifié
- Elasticsearch : `path.repo` + volume `es-snapshots` (prérequis des snapshots).
- Le portail derrière Caddy : `ProxyFix`, cookie `Secure` automatique en https, liens vers les
  outils réécrits en préfixes publics.
- `make portal` utilise `portal/.venv` s'il existe.

### Corrigé
- 11 f-strings sans placeholder dans les scripts d'automatisation.

## 2.0.0 — 2026-09-14

Stack v2 telle que validée en labo sur la VM WSL puis le Shuttle : 24 services (Zeek 6.2,
Snort 3.3.5, Suricata 7, Filebeat, Elasticsearch/Kibana 8.13, Grafana 10.4, Prometheus,
Blackbox, node-exporter, GoFlow2, beacon-detect, AutoBlock, CrowdSec, n8n, Ollama, ntopng,
Arkime, NetBox), portail Flask 22 pages, éditions Core / IA, répartition 2 VMs, parcours de
démonstration, health check 24 services. Historique détaillé : `git log` jusqu'à `0e7ee7c`.
