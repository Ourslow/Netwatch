# Checklist de validation sur la VM — chantiers du 18/09

Tout ce qui a été ajouté le 18/09 (proxy HTTPS, `install.sh`, sauvegarde /
restauration, mise à jour) a été validé **sans stack** : tests unitaires, `docker
compose config`, `caddy validate`, shellcheck. Aucun conteneur n'a tourné. Cette
checklist est le vrai test, dans l'ordre du moindre risque : d'abord vérifier que
le labo n'a pas bougé, puis chaque nouveauté, puis l'installation à blanc.

Compter **2 h 30** hors compilation Snort. Cocher au fur et à mesure ; pour
chaque échec, coller dans le rapport (§ 7) la sortie des commandes indiquées.

## 0. Avant de commencer (10 min)

- [ ] RAM : `.wslconfig` avec `memory=12GB` (ou VM ≥ 12 Go) — la stack complète
      en édition IA a déjà tué WSL à 600 Mo libres.
- [ ] Le clone de la VM est sur `main` et à jour :
      ```bash
      cd ~/netwatch && git status --short          # doit être vide (sinon git stash)
      git pull origin main && cat VERSION           # 2.1.0
      ```
- [ ] **Sauvegarde de sécurité avant tout**, avec l'ancien mécanisme (copie brute) :
      ```bash
      cp .env ../env.avant-validation && cp portal/.env ../portal-env.avant-validation
      cp -r portal/data ../portal-data.avant-validation 2>/dev/null || true
      ```
- [ ] Noter l'état de référence :
      ```bash
      curl -s "localhost:9200/_cat/indices?h=index,docs.count&s=index" > ../indices.avant.txt
      docker compose ps --format '{{.Name}} {{.Status}}' > ../ps.avant.txt
      ```

## 1. Le labo n'a pas bougé (15 min)

Objectif : avec le `.env` actuel (édition IA, pas de `NETWATCH_PUBLIC_URL`), rien ne
change. Les nouveaux réglages compose sont tous en `${VAR:+…}` et doivent rester vides.

- [ ] `docker compose config --quiet` → aucune erreur.
- [ ] `docker compose config | grep -E "GF_AUTH_PROXY_ENABLED|SERVER_BASEPATH|BASE_PATH:|http-prefix|webBasePath|path.repo"`
      → attendu : `GF_AUTH_PROXY_ENABLED: ""`, `SERVER_BASEPATH: ""`, `BASE_PATH: ""`,
      `--http-prefix=`, `webBasePath: /`, `path.repo: /usr/share/elasticsearch/snapshots`.
- [ ] `make start` → Elasticsearch est **recréé** (nouvelle variable `path.repo` + volume
      `es-snapshots`) : c'est normal, les données sont dans `es-data`. Kibana, NetBox,
      Grafana, ntopng, Arkime sont recréés aussi (env modifié) — normal.
- [ ] Après 2 min : `make health` → même état qu'hier. Si Grafana/Kibana « down » :
      attendre 1 min de plus (redémarrage), puis `docker compose logs --tail 50 grafana kibana`.
- [ ] `curl -s "localhost:9200/_cat/indices?h=index,docs.count&s=index" | diff - ../indices.avant.txt`
      → **aucune ligne perdue** (des `docs.count` en hausse sont normaux).
- [ ] `curl -s localhost:9200/_nodes/settings | grep -o '"repo":\[[^]]*\]'` →
      `"repo":["/usr/share/elasticsearch/snapshots"]`.
- [ ] Portail : `make portal-stop && make portal` puis ouvrir `http://<IP>:5050` —
      login OK, home, `/status`, `/alerts`, un clic sur « Grafana » dans le menu ouvre
      bien `http://<IP>:3000` (comportement d'hier, mode direct).
- [ ] ntopng démarre malgré `--http-prefix=` vide : `docker compose logs ntopng | grep -i prefix`
      → un avertissement « must begin with '/' … skipped » est **attendu et sans effet** ;
      `curl -s -o /dev/null -w '%{http_code}' localhost:3001/` → `200` ou `302`.
- [ ] Reliquat d'hier : passer temporairement en Core (`COMPOSE_PROFILES=` et
      `OLLAMA_URL=` vides dans `.env`) → `make health` affiche
      « Ollama désactivé (édition Core) » et n'est pas en erreur ; remettre l'édition IA.

Si un point échoue ici, **s'arrêter** et remonter : `docker compose config`,
`docker compose logs --tail 100 <service>`, `make health-no-color`.

## 2. Sauvegarde et restauration (30 min)

- [ ] `make backup` → dans la sortie : « configuration + état du portail », un « volume »
      par volume existant, « NetBox (pg_dump) », « Elasticsearch (snapshot …) ». Noter la taille.
      Si « dépôt de snapshots ES indisponible » : Elasticsearch n'a pas été recréé
      (`docker compose up -d --force-recreate elasticsearch`, attendre, refaire).
- [ ] Contenu de l'archive : `tar tzf backups/netwatch-2.1.0-*.tar.gz | head -40` →
      `manifest.txt`, `config/.env`, `config/portal/data/...`, `volumes/grafana-data.tar.gz`,
      `netbox.sql.gz`, `elasticsearch/es-snapshots.tar.gz`.
- [ ] `make backup-config` → archive en quelques secondes, sans arrêter quoi que ce soit.
- [ ] **Restauration config seule** (sans risque) :
      `bash scripts/restore.sh backups/netwatch-config-*.tar.gz --yes` → `.env.bak-<date>`
      créé, portail redémarré, `diff .env .env.bak-*` vide.
- [ ] **Restauration complète** — c'est le test qui compte. Créer d'abord une trace à
      perdre : dans le portail, ajouter un hostgroup bidon « A-SUPPRIMER » ; puis :
      ```bash
      bash scripts/restore.sh backups/netwatch-2.1.0-*.tar.gz --yes
      ```
      Attendu, dans l'ordre : configuration ✓, chaque volume ✓, « NetBox (base restaurée) »,
      « attente Elasticsearch… », « Elasticsearch (snapshot …) », « stack redémarrée,
      setup-es rejoué », portail redémarré. Durée : 3-8 min.
- [ ] Vérifications après restauration :
      - le hostgroup « A-SUPPRIMER » a **disparu** (état du portail restauré) ;
      - `curl -s "localhost:9200/_cat/indices?h=index,docs.count&s=index" | diff - ../indices.avant.txt`
        → mêmes index (les compteurs peuvent différer légèrement : trafic entre-temps) ;
      - Grafana : dashboards présents, mot de passe admin inchangé ;
      - NetBox : `http://localhost:8000` login OK, les données de démo sont là
        (`make demo-netbox` d'hier) ;
      - `make health` au vert/orange comme avant.

Si la restauration ES échoue : `curl -s localhost:9200/_snapshot/netwatch/_all | python3 -m json.tool | head -40`
et `docker compose logs --tail 50 elasticsearch`.

## 3. Point d'entrée HTTPS unique (40 min)

C'est le chantier le **moins sûr** : les sous-chemins de chaque outil n'ont jamais tourné.
Tester outil par outil, noter précisément ce qui casse.

- [ ] Dans `.env` : `COMPOSE_PROFILES=proxy,ia`, puis décommenter le bloc « POINT
      D'ENTRÉE HTTPS UNIQUE » avec `NETWATCH_PUBLIC_URL=https://<IP de la VM>`,
      `NETWATCH_TLS=internal`, `ARKIME_WEB_BASE_PATH=/arkime/`,
      `NETWATCH_NETBOX_URL=http://localhost:8000/netbox`.
- [ ] `docker compose config | grep -E "GF_SERVER_ROOT_URL|SERVER_BASEPATH|BASE_PATH:|http-prefix|webBasePath"`
      → `https://<IP>/grafana/`, `/kibana`, `netbox/`, `/ntopng`, `/arkime/`.
- [ ] `make start` (recrée Grafana, Kibana, NetBox, ntopng, Arkime, lance `netwatch-caddy`) ;
      `make portal-stop && make portal` (le portail lit `NETWATCH_PUBLIC_URL`).
- [ ] `docker compose logs caddy | tail -20` → pas d'erreur ; `sudo ss -tlnp | grep -E ':443|:80 '` → caddy.
- [ ] Depuis **un autre poste** (pas la VM), navigateur : `https://<IP>/` → avertissement
      de certificat (CA locale, attendu) → page de login du portail → login OK.
      `make proxy-ca` puis importer `netwatch-ca.crt` fait disparaître l'avertissement
      (optionnel aujourd'hui).
- [ ] Sans être connecté (navigation privée) : `https://<IP>/grafana/` → **redirigé vers
      `/login?next=/grafana/`**, et après login retour sur Grafana. C'est `forward_auth`.
- [ ] Chaque outil, connecté au portail — noter OK / KO et le symptôme :

  | URL | Attendu | Si KO, regarder |
  |---|---|---|
  | `/grafana/` | Grafana ouvert **sans login Grafana** (auth proxy, utilisateur `admin`), dashboards listés, un dashboard s'affiche avec ses données | `docker compose logs grafana \| grep -iE "auth.proxy\|root_url"` ; si page blanche / 404 sur `/public/build/…` → problème de `serve_from_sub_path` (à me remonter) |
  | `/kibana/` | Kibana, Discover fonctionne (data view `netwatch-zeek`) | `docker compose logs kibana \| grep -iE "basePath\|rewriteBasePath"` |
  | `/arkime/` | viewer Arkime, sessions listées | `docker compose logs arkime \| grep -i basePath` ; si assets 404 → webBasePath attend peut-être le préfixe **retiré** (à me remonter, correctif Caddy `handle_path`) |
  | `/ntopng/` | interface ntopng | `docker compose logs ntopng \| grep -i prefix` |
  | `/netbox/` | page de login NetBox, login OK, une page IPAM | erreur CSRF → `CSRF_TRUSTED_ORIGINS` ; 404 → `BASE_PATH` |
  | `/status` (portail) | les boutons « ouvrir » des outils pointent sur `/grafana`, `/kibana`… (plus sur `:3000`) | c'est `browser_url` en mode proxy |
  | `/ip/<ip>` | boutons Arkime / Kibana ouvrent les outils filtrés, sous `/arkime/…`, `/kibana/…` | |

- [ ] En **2 VMs** (si le Shuttle est monté) : même chose avec `docker-compose.data.yml`,
      `NETWATCH_UPSTREAM_ARKIME=192.168.100.11:8005`, `NETWATCH_UPSTREAM_NTOPNG=192.168.100.11:3001`.
- [ ] Retour au mode direct : recommenter le bloc, `COMPOSE_PROFILES=ia`,
      `docker compose --profile proxy down caddy` (ou `docker rm -f netwatch-caddy`),
      `make start`, `make portal-stop && make portal` → `http://<IP>:5050` comme en § 1.

Un outil KO n'est pas bloquant pour les autres : le proxy est opt-in. Le rapport
outil par outil suffit pour corriger à distance.

## 4. Mise à jour (10 min)

Simule ce que fera un client : `scripts/upgrade.sh` sur une installation existante.

- [ ] Se placer un commit en arrière pour avoir quelque chose à mettre à jour :
      `git checkout -q HEAD~1` (arbre propre requis).
- [ ] `make upgrade REF=origin/main` → « sauvegarde config », « code : 2.1.0 → 2.1.0 »,
      dépendances, images, `up -d`, setup-es / netflow / kibana ✓, portail redémarré,
      health, liste des commits. Aucun index perdu (`diff` avec `../indices.avant.txt`).
- [ ] `git branch --show-current` → `main` (le script est revenu sur la branche).

## 5. Installation à blanc — le test le plus important (45 min + compilation Snort)

`install.sh` n'a de sens que sur une machine **vierge**. Options : une nouvelle VM
Ubuntu 22.04/24.04 dans Proxmox (4 vCPU / 8 Go / 60 Go suffisent), un LXC privilégié
avec nesting, ou une distribution WSL fraîche (`wsl --install -d Ubuntu-24.04`).

- [ ] ```bash
      git clone https://github.com/Ourslow/netwatch.git && cd netwatch
      ./install.sh --public-url https://<IP de cette machine>
      ```
      (ajouter `--ia` seulement si ≥ 12 Go). Chronométrer.
- [ ] Étapes attendues dans cet ordre : 1/6 Docker (installé ou « présent »),
      2/6 paquets + `vm.max_map_count`, 3/6 `.env` créé, interface détectée (vérifier
      que c'est la bonne : `ip a`), secrets générés, « point d'entrée HTTPS unique »,
      4/6 venv, 5/6 stack + attente Elasticsearch + setup-es + netflow + init Arkime +
      Kibana, 6/6 service systemd actif, health, récapitulatif avec les mots de passe.
- [ ] Vérifier : `sudo systemctl status netwatch-portal` actif ; `cat .env | grep -cE "changeme|^[A-Z_]+=$"`
      → seuls les champs volontairement vides (`SLACK_WEBHOOK_URL`, ITSM…) restent vides,
      **aucun `changeme`** ; `https://<IP>/` login avec le mot de passe affiché.
- [ ] Relancer `./install.sh --public-url https://<IP>` une 2e fois → rien n'est régénéré
      (mêmes mots de passe), pas d'erreur, « déjà présent » partout.
- [ ] Après déconnexion/reconnexion : `make health` sans sudo fonctionne (groupe docker).
- [ ] Puis dérouler § 2 (backup/restore) sur cette machine neuve : c'est là que
      `make restore` d'une archive de la **première** VM prouverait une migration
      complète (bonus, si le temps le permet).

## 6. Nettoyage

- [ ] Sur la VM de labo : `.env` remis comme avant (`diff .env ../env.avant-validation`),
      édition IA, mode direct ; `rm -rf backups/*.tar.gz` si l'espace manque (garder au
      moins une archive complète).
- [ ] `git status --short` vide ; `git checkout main` si encore en détaché.

## 7. Ce qu'il faut me rapporter

Un message par section, même en une ligne (« § 1 OK », « § 3 : Grafana OK, Kibana KO »).
Pour chaque KO :

```bash
docker compose logs --tail 100 <service> 2>&1 | tail -60
docker compose config | grep -A30 "^  <service>:" | grep -E "environment|command|- "
make health-no-color
```

et, pour le proxy, l'URL tapée + le code HTTP vu dans l'onglet réseau du navigateur
(F12) sur la requête qui échoue. Avec ça je corrige sans la VM.

Les corrections probables sont toutes locales et petites : un `handle` ↔
`handle_path` dans `caddy/Caddyfile`, une variable d'environnement d'un service,
un ordre d'attente dans `restore.sh`. Rien ne remet en cause l'architecture.
