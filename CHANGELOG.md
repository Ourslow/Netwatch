# Changelog

Format : [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/), versions [SemVer](https://semver.org/lang/fr/).
La version courante est dans `VERSION` ; `scripts/upgrade.sh` affiche les commits entre deux versions.

## 2.2.0 — en cours

### Ajouté
- Images des cinq moteurs construits par le projet (Zeek, Snort, Suricata, beacon-detect, AutoBlock)
  publiées sur GHCR (`ghcr.io/ourslow/netwatch-<service>:<version>`, workflow `images.yml`, tags
  `<version>`, `latest`, `sha-<commit>`). `install.sh` et `scripts/upgrade.sh` les tirent au lieu de
  les compiler (≈ 3 min au lieu de 10-15) et reconstruisent en local si GHCR est inaccessible.
  `NETWATCH_IMAGE_TAG` dans `.env` fixe la version.
- Content-Security-Policy sur le portail : `default-src 'self'`, nonce par requête sur les scripts
  inline (plus aucun `onclick=`), `frame-ancestors 'none'`, `form-action 'self'`, `object-src 'none'`,
  violations reçues sur `POST /csp-report` (journal). `NETWATCH_CSP=enforce` (défaut) | `report-only`
  (rodage) | `off`. Test de convention : tout `<script>` inline sans nonce ou gestionnaire inline fait
  échouer `make test`.
- Rétention Elasticsearch (ILM) pour tous les index NetWatch : `scripts/setup-ilm.sh` (appelé par
  `setup-es.sh`, `install.sh`, `upgrade.sh`, `make setup-ilm`) — `netwatch-events` (zeek/snort/suricata,
  `ES_RETENTION_DAYS` 30 j, lecture seule + forcemerge à 2 j), `netwatch-netflow`
  (`ES_RETENTION_NETFLOW_DAYS`), `netwatch-detections` (beacons/autoblock, `ES_RETENTION_DETECTIONS_DAYS`
  90 j) ; index existants rattachés ; ligne « Rétention ES » dans `make health` ; `make arkime-expire`.

### Corrigé
- La politique ILM `netflow-*` attendait un rollover sur un alias inexistant : les index restaient
  bloqués à `check-rollover-ready` et n'étaient jamais supprimés. Plus de rollover (index journaliers),
  les index bloqués sont réinscrits automatiquement.

## 2.1.0 — 2026-09-28

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
- Observabilité complémentaire (Blackbox, Kibana, ntopng, Arkime, NetBox) intégrée au portail
  (sondes actives, data views, full PCAP, contexte IPAM), éditions Core / IA (`COMPOSE_PROFILES=ia`),
  déploiement 2 VM (`docker-compose.sensors.yml` / `data.yml`).
- Jeu de données de démonstration reproductible (`make demo-netbox`, `make demo-data`) et parcours
  de démo (`docs/demo-parcours.md`).
- Site produit statique (`site/`) publié sur GitHub Pages ; deck de présentation (`docs/presentation/`).
- Portail : anti-force-brute sur `/login` (5 échecs → 60 s), sonde Proxmox asynchrone (plus de
  page bloquée par un hôte injoignable).
- Validation sur machine neuve (`docs/validation-vm.md`) : installation 11 min, sauvegarde 11 s,
  restauration complète 61 s, mise à jour 13 s.

### Modifié
- Elasticsearch : `path.repo` + volume `es-snapshots` (prérequis des snapshots).
- Le portail derrière Caddy : `ProxyFix`, cookie `Secure` automatique en https, liens vers les
  outils réécrits en préfixes publics.
- `make portal` utilise `portal/.venv` s'il existe.

### Corrigé
- 11 f-strings sans placeholder dans les scripts d'automatisation.
- Installation neuve : la valeur d'exemple `IFACE=ens18` survivait à la détection (aucune
  capture), placeholders ITSM restants, Grafana « dégradé » à tort dans `health-check.sh`.
- Sauvegarde : snapshot Elasticsearch impossible (volume `es-snapshots` root:root vs uid 1000) ;
  `alpine:3.20` pré-tirée pour fonctionner hors ligne.
- Restauration : dépôt de snapshots ré-enregistré à neuf (sinon désactivé par ES), stack relancée
  en cas d'erreur, état du portail remplacé par celui de l'archive.
- Mise à jour : seuls les tags `vX.Y.Z` sont candidats ; attente du portail avant le health.
- `Makefile` : recette `demo-data-clean` invalide (`make` inutilisable) — contrôle `make -n` en CI.
- Portail : sondes Blackbox absentes de `/status`, `.env` du stack non lu par le portail,
  `app-classifier` en échec sur `HEAD netflow-*`.

## 2.0.0 — 2026-09-14

Stack v2 telle que validée en labo sur la VM WSL puis le Shuttle : 24 services (Zeek 6.2,
Snort 3.3.5, Suricata 7, Filebeat, Elasticsearch/Kibana 8.13, Grafana 10.4, Prometheus,
Blackbox, node-exporter, GoFlow2, beacon-detect, AutoBlock, CrowdSec, n8n, Ollama, ntopng,
Arkime, NetBox), portail Flask 22 pages, éditions Core / IA, répartition 2 VMs, parcours de
démonstration, health check 24 services. Historique détaillé : `git log` jusqu'à `0e7ee7c`.
