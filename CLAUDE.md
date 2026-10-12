# NetWatch — Contexte projet pour Claude Code

## IDENTITÉ
- Projet : NetWatch — sonde d'observabilité réseau (NPM) et de détection (NDR) self-hosted, open-source (AGPL v3).
- Auteur : Nicolas Malok (GitHub `Ourslow`). Projet personnel visant un produit commercialisable (éditions Community / Pro).
- Dépôt : https://github.com/Ourslow/Netwatch — site : https://ourslow.github.io/Netwatch/
- **Neutralité** : le dépôt, le site et le portail ne mentionnent aucun employeur, école, client ni éditeur nommé en comparaison publique. `tests/test_neutrality.py` le vérifie. Les documents internes (positionnement, présentations, archives de gestion de projet) sont dans `private/` (ignoré par git).
- **Nom** : « NetWatch » est un nom de code (non utilisable commercialement : homonymes existants). Candidat retenu le 28/09/2026 : **NetPiquet** (non vérifié INPI/TMview — ne pas renommer avant vérification ; le nom est centralisé dans `portal/config.py` et `brand/`).

## CAP PRODUIT
Référence : `private/docs/positionnement-produit.md`. Résumé :
- Sonde NPM + NDR self-hosted pour PME 50-500 postes et MSP francophones. Pas de SaaS de données (control plane hébergé envisagé en phase 2, § 6.5).
- Édition **Community** (AGPL v3, ce dépôt, complète pour une sonde utile) + édition **Pro** (abonnement, clé de licence : IA, rapports, conformité, ITSM, RBAC, support). Jamais payant : doc, moteurs, dashboards Grafana, install, health.
- Fait (12/10/2026) : tests + CI, proxy TLS + auth unifiée (Caddy), install/upgrade/backup validés sur machine neuve, tags v2.1.0 / v2.2.0, images GHCR, CSP, ILM, RBAC, licence hors ligne. Split Community / Pro fait le 12/10 : mécanisme d'extension (`portal/netwatch/extensions.py`) + paquet `pro/netwatch_pro` (IA, rapports, conformité, comptes et rôles) et `pro/scripts/` (PDF, ITSM) chargés par le portail s'ils sont présents (`docs/edition-pro.md`). Le paquet reste dans le dépôt jusqu'à la fin de la validation terrain ; le dépôt privé `netwatch-pro` n'existe pas encore (procédure § 6 du doc). Reste aussi : validation terrain (10 conversations + pilote), nom (INPI/TMview).
- **Prochaine étape (après le 12/10)** : côté Nicolas — vérifier NetPiquet / NetPicket (INPI classes 9 et 42, TMview, domaines), relancer le labo WSL sur `main` et vérifier la page Statut (« Extension Pro : netwatch-pro 0.1.0 (pro/ …) — ia, reports, compliance, rbac ») et la page Comptes et rôles ; côté code — rien de bloquant avant la validation terrain ; le renommage attend la confirmation du nom, le split physique (`git subtree split --prefix=pro`) attend la fin de la validation.
- Prérequis avant le premier euro : clarification écrite de la propriété intellectuelle (§ 9 du positionnement).

## CONCEPT
Trois moteurs d'analyse (Zeek, Snort 3, Suricata 7) sur le même trafic, NetFlow/IPFIX (GoFlow2), sondes actives (Blackbox), Elasticsearch + Grafana + Kibana + Arkime + ntopng + NetBox, un portail Flask unifié (flux, ART, santé TCP, SLA, alertes, incidents, rapports, conformité), IA locale optionnelle (Ollama, édition IA).

## STACK TECHNIQUE
- Zeek 6.2 · Snort 3.3.5 · Suricata 7 · Filebeat 8.13 · Elasticsearch 8.13 · Grafana 10.4 · Prometheus · GoFlow2 · Blackbox · Kibana · ntopng · Arkime · NetBox · CrowdSec · n8n · Caddy (profil `proxy`) · Ollama (profil `ia`)
- Docker Compose (24 services) ; images des moteurs publiées sur `ghcr.io/ourslow/netwatch-*`
- Ubuntu 22.04 / 24.04 LTS, VM 4 vCPU / 16 Go ; déploiement 2 VM possible (`docker-compose.sensors.yml` / `data.yml`)

## INFRASTRUCTURE CIBLE
- Une VM avec un port SPAN (ou TAP) ; variante physique Shuttle Proxmox (2 ports de capture, vSwitch promiscuous).

## CONVENTIONS
- Fichiers de config et docs en français ; code et scripts en anglais (variables, fonctions).
- Logs Zeek en JSON ; index ES `{engine}-{date}` (zeek-2026.05.27…), rétention ILM (`scripts/setup-ilm.sh`).
- Conteneurs préfixés `netwatch-` ; règles custom Snort SID 1000001-1000999, Suricata SID 2000001-2000999.
- Pas de gestionnaire `onclick=` inline ni de `<script>` sans `nonce="{{ csp_nonce }}"` dans les templates (CSP, `test_csp.py`).
- Aucune mention d'employeur / école / client dans le dépôt (`test_neutrality.py`).
- Toute nouvelle fonction Pro va dans `pro/netwatch_pro/` (blueprint `pro`, templates sous `templates/pro/`, `api.pro_required(<clé de PRO_FEATURES>)`), jamais dans `portal/app.py` ; le paquet importe `config` et `netwatch.*`, jamais `app`.

## FICHIERS CLÉS
- `docker-compose.yml` (+ `sensors.yml`, `data.yml`) — orchestration
- `install.sh`, `scripts/upgrade.sh`, `scripts/backup.sh`, `scripts/restore.sh`, `scripts/health-check.sh`, `scripts/setup-ilm.sh`, `setup-es.sh` — exploitation
- `caddy/Caddyfile` — point d'entrée HTTPS unique, auth unifiée via `/auth/check`
- `portal/` — portail Flask (app.py, config.py, templates, static, tests) ; `portal/config.py` porte le nom, la version (`VERSION`) et la licence
- `pro/netwatch_pro/` — extension de l'édition Pro (IA, rapports PDF, conformité, comptes et rôles) chargée par `portal/netwatch/extensions.py` ; `pro/scripts/` (PDF, ITSM) ; contrat et procédure de split dans `docs/edition-pro.md`
- `brand/` — logo et charte ; `site/` — site GitHub Pages ; `docs/` — documentation publique
- `VERSION`, `CHANGELOG.md`, `.github/workflows/` (ci, images, pages)

## COMMANDES UTILES
```bash
./install.sh --public-url https://sonde.exemple.fr   # installation complète
make health          # 20 contrôles
make test lint       # pytest + ruff
make backup / make upgrade / make setup-ilm
```
