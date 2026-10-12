# Édition Pro — découpage Community / Pro et extension du portail

NetWatch se distribue en deux éditions (voir `docs/licence.md` pour la licence) :

- **Community** — ce dépôt, AGPL v3, complet pour une sonde utile : moteurs, dashboards, portail
  (flux, ART, santé TCP, SLA, alertes, incidents, audit, rapport exécutif), installation, santé,
  sauvegarde, mise à jour. Jamais bridé, jamais payant.
- **Pro** — abonnement par sonde : assistant IA, rapports PDF planifiables, conformité
  multi-référentiels, intégration ITSM, comptes et rôles, support éditeur.

Le code Pro n'est pas une branche du dépôt Community ni une série de `if licence` : c'est un
**paquet Python séparé, `netwatch_pro`, chargé par le portail au démarrage s'il est présent**.
Le portail Community ne le connaît que par un contrat d'extension stable (ci-dessous). Sans le
paquet, le portail est l'édition Community, sans erreur ni menu fantôme.

## 1. Où vit le code

| Phase | Emplacement du paquet | Pourquoi |
|---|---|---|
| **Validation terrain (maintenant)** | `pro/netwatch_pro/` dans ce dépôt | rien n'est retiré ni bridé avant la fin de la validation ; le mécanisme d'extension est exercé par la CI à chaque commit |
| Split (après validation) | dépôt privé `netwatch-pro` (`git subtree split --prefix=pro`) | le code Pro publié jusque-là reste sous AGPL (il l'est déjà) ; la valeur de l'édition Pro est dans les évolutions, le support et la licence, pas dans la rétroactivité |

Le fichier `pro/README.md` décrit le paquet lui-même.

## 2. Recherche du paquet au démarrage (`portal/netwatch/extensions.py`)

Dans l'ordre :

1. `NETWATCH_PRO=off` dans `.env` → jamais chargé (tests, démonstration Community).
2. `NETWATCH_PRO_PATH=/opt/netwatch-pro` → le dossier est ajouté à `sys.path` ; c'est la forme
   de déploiement chez un client (copie du dépôt privé ou archive livrée avec la licence).
3. `pro/` à la racine du dépôt → copie de travail pendant la validation.
4. Paquet installé dans l'environnement du portail (`pip install …/netwatch-pro`).

Trouvé → `netwatch_pro.register(api)` est appelé. Une exception dans `register()` est journalisée
et le portail **continue en Community** : rien de ce que l'extension a déclaré à moitié n'est
conservé. L'état est visible sur la page *Statut* (carte *Édition et licence*, ligne « Extension
Pro ») et dans `make license-status`.

## 3. Contrat d'extension (`ExtensionAPI`)

L'extension s'exécute dans le processus du portail, avec `portal/` sur `sys.path` : elle peut
importer `config` et `netwatch.*` (client Elasticsearch, licence, hostgroups…). Le portail lui
fournit :

| Méthode | Rôle |
|---|---|
| `api.describe(nom, version, fonctions)` | identité du paquet et clés de `netwatch.license.PRO_FEATURES` qu'il fournit |
| `api.register_blueprint(bp)` | routes et templates (préfixe de template `pro/` obligatoire pour ne jamais masquer ceux du portail) |
| `api.add_nav(section, label, endpoint, icône, i18n=, admin_only=, blank=)` | entrée de menu latéral ; sections `obs`, `sec`, `report`, `infra` |
| `api.add_command(label, url, icône, hint=, key=)` | entrée de la palette de commandes (Ctrl+K) |
| `api.add_partial(slot, template)` | fragment inséré dans une page Community (slot `status` : cartes de la page *Statut*) |
| `api.add_status_provider(nom, fn)` | donnée calculée pour la page *Statut*, exposée en `ext.<nom>` aux fragments ; une erreur ne masque pas les autres cartes |
| `api.provide(nom, valeur)` | variable de template globale (ex. `ai_enabled`, lue par les boutons ✨ des pages Community) |
| `api.login_required`, `api.admin_required`, `api.pro_required(fonction)` | les décorateurs du portail — `pro_required` répond 402 sans licence quand `LICENSE_ENFORCE=true` |
| `api.config`, `api.app` | configuration du portail et application Flask |

Les URL des fonctions Pro sont stables (`/api/explain`, `/api/summary`,
`/api/pcap-analysis/explain`, `/reports`, `/api/reports/generate`, `/compliance`) : les templates
Community les appellent directement et n'ont pas à savoir qui les sert.

## 4. Ce qui est dans `netwatch_pro` aujourd'hui (0.1.0)

| Fonction (`PRO_FEATURES`) | Module | Contenu |
|---|---|---|
| `ia` | `ia.py`, `llm_client.py`, `llmops.py` | explication d'alertes, résumé exécutif, narration PCAP (Ollama, 100 % on-prem), carte LLMOps de la page Statut, variable `ai_enabled` |
| `reports` | `reports.py`, `templates/pro/reports.html`, `pro/scripts/generate-report-pdf.py` | historique, génération à la demande ou planifiée (n8n, cron), téléchargement |
| `compliance` | `compliance.py`, `templates/pro/compliance.html` | NIST CSF 2.0, ANSSI, ISO 27001 ; NIS2 reste dans `netwatch/referentials.py` (Community, utilisé par le rapport exécutif) |
| `rbac` | `rbac.py`, `templates/pro/admin_users.html` | magasin de comptes nominatifs (`portal/data/users.json`, scrypt), rôles lecture / opérateur / administrateur, page *Comptes et rôles* |
| `itsm` | `pro/scripts/itsm-sync.py`, `n8n-servicenow.json`, `n8n-jira.json` | synchronisation des tickets vers ServiceNow / Jira (`docs/itsm-setup.md`) |

Côté Community, ce qui est partagé par les deux éditions et reste dans `portal/` :

- **Authentification** (`netwatch/users.py`) : compte d'amorçage `PORTAL_USERNAME` /
  `PORTAL_PASSWORD` (administrateur), rôles, garde-fou « rôle lecture » (`before_request`),
  journal `portal/data/auth.log`, `/auth/check` pour Caddy / Grafana. L'extension y enregistre son
  magasin de comptes (`api.set_user_store`) : les comptes stockés sont interrogés en premier, le
  compte d'amorçage reste un secours. Sans extension : un seul compte, administrateur.
- **Tickets locaux et automatisations** (`scripts/automation/`) : `create-ticket.py` (tickets YAML
  dans `tickets/drafts/`, utilisé par `npm-alerts.py`, `iface-saturation.py`, `escalade.py`),
  `weekly-report.py`, `daily-npm-report.py` et leurs workflows n8n. Seule la **poussée vers un
  ITSM** est Pro.
- **Support** (`support`) : pas de code, c'est le contrat.

## 5. Déploiement chez un client (après le split)

```bash
# sur la sonde, à côté du dépôt Community installé par install.sh
sudo git clone git@github.com:Ourslow/netwatch-pro.git /opt/netwatch-pro   # ou l'archive livrée
echo "NETWATCH_PRO_PATH=/opt/netwatch-pro" | sudo tee -a /chemin/netwatch/.env
sudo systemctl restart netwatch-portal
make license-status      # « Extension Pro : netwatch-pro x.y.z … »
```

Puis coller la licence dans la page *Licence* du portail. `scripts/upgrade.sh` ne touche pas à
`/opt/netwatch-pro` : la mise à jour de l'extension est un `git pull` (ou une nouvelle archive)
dans ce dossier, documentée avec chaque version Pro. Les versions se suivent : une version Pro
déclare la version minimale du portail Community qu'elle requiert (à ajouter dans
`register()` avant la première livraison).

## 6. Procédure de split (le jour J)

1. `git subtree split --prefix=pro -b pro-export` puis push de cette branche dans le dépôt privé
   `netwatch-pro` (historique conservé).
2. Dans ce dépôt : `git rm -r pro/`, le test `test_intree_extension_is_loaded` devient un test de
   l'absence (Community pure), `test_pro_rbac.py` part avec le paquet, `pytest.ini` / `make lint` /
   la CI retirent `pro` de leurs chemins.
3. CI du dépôt privé : les mêmes tests que `portal/tests/test_extensions.py`, lancés contre un
   checkout du dépôt Community à la version minimale supportée.
4. `docs/licence.md`, le site et ce document : remplacer « pendant la validation » par la
   procédure de déploiement du § 5.

## 7. Tests

- `portal/tests/test_extensions.py` : chargeur (désactivé, absent, paquet factice, paquet cassé),
  extension `pro/` du dépôt (menu, palette, routes, carte de statut).
- `portal/tests/test_license.py` : bridage 402 des routes Pro quand `LICENSE_ENFORCE=true`.
- `portal/tests/test_pro_rbac.py` : magasin de comptes de l'extension (création, rôles, garde-fous,
  journal) ; `test_community_auth_without_user_store` : compte d'amorçage seul.
- `portal/tests/test_csp.py` : les templates de `pro/` suivent les mêmes règles CSP (nonce, pas de
  gestionnaire inline).
- `make lint` et la CI passent `ruff` sur `pro/`.
