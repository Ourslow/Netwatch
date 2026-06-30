# ITSM Setup — ServiceNow + JIRA via n8n

Guide de configuration de l'intégration ITSM de NetWatch.  
Script : `scripts/automation/itsm-sync.py`  
Workflows n8n : `scripts/automation/n8n-servicenow.json` / `n8n-jira.json`

---

## ServiceNow

### 1. Créer un utilisateur API

1. Aller dans **User Management > Users** (`/now/nav/ui/classic/params/target/sys_user_list.do`)
2. Créer un nouvel utilisateur : `netwatch-api`
3. Cocher **Web service access only**
4. Définir un mot de passe fort
5. Attribuer le rôle `itil` (onglet **Roles** → Add role → `itil`)

> Le rôle `itil` donne accès en lecture/écriture aux incidents (`incident` table).

### 2. Tester avec curl

```bash
SNOW_INSTANCE=mycompany
SNOW_USER=netwatch-api
SNOW_PASSWORD=votre_motdepasse

# Créer un incident de test
curl -s -u "${SNOW_USER}:${SNOW_PASSWORD}" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -X POST \
  "https://${SNOW_INSTANCE}.service-now.com/api/now/table/incident" \
  -d '{
    "short_description": "Test NetWatch ITSM",
    "urgency": "3",
    "category": "network",
    "description": "Test de connexion depuis itsm-sync.py"
  }' | python3 -m json.tool | grep '"number"'
```

Réponse attendue : `"number": "INC0012345"`

### 3. Configurer les variables d'environnement

Dans `.env` (copié depuis `.env.example`) :

```env
ITSM_BACKEND=servicenow
SNOW_INSTANCE=mycompany
SNOW_USER=netwatch-api
SNOW_PASSWORD=votre_motdepasse
```

### 4. Mapping des champs

| NetWatch YAML | ServiceNow       | Notes                          |
|---------------|------------------|--------------------------------|
| `title`       | `short_description` |                             |
| `priority: critical` | `urgency: 1` | Haute priorité              |
| `priority: high`     | `urgency: 2` |                             |
| `priority: medium`   | `urgency: 3` | Défaut                      |
| `priority: low`      | `urgency: 4` |                             |
| `category`    | `category`       |                                |
| Lignes `acceptance:` | `description` | Concaténées              |

---

## JIRA

### 1. Créer un API token Atlassian

1. Aller sur https://id.atlassian.com/manage-profile/security/api-tokens
2. Cliquer **Create API token**
3. Nom : `netwatch-itsm`
4. Copier le token généré (affiché une seule fois)

> Le token est lié au compte utilisateur : utiliser un compte de service dédié en production.

### 2. Tester avec curl

```bash
JIRA_URL=https://mycompany.atlassian.net
JIRA_USER=user@company.com
JIRA_TOKEN=votre_token
JIRA_PROJECT_KEY=NOC

# Créer une issue de test
curl -s -u "${JIRA_USER}:${JIRA_TOKEN}" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -X POST \
  "${JIRA_URL}/rest/api/3/issue" \
  -d '{
    "fields": {
      "project": {"key": "'"${JIRA_PROJECT_KEY}"'"},
      "summary": "Test NetWatch ITSM",
      "issuetype": {"name": "Bug"},
      "priority": {"name": "Medium"},
      "labels": ["network", "netwatch"],
      "description": {
        "type": "doc",
        "version": 1,
        "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Test de connexion depuis itsm-sync.py"}]}]
      }
    }
  }' | python3 -m json.tool | grep '"key"'
```

Réponse attendue : `"key": "NOC-42"`

### 3. Configurer les variables d'environnement

Dans `.env` :

```env
ITSM_BACKEND=jira
JIRA_URL=https://mycompany.atlassian.net
JIRA_USER=user@company.com
JIRA_TOKEN=votre_token
JIRA_PROJECT_KEY=NOC
```

### 4. Mapping des champs

| NetWatch YAML | JIRA              | Notes                        |
|---------------|-------------------|------------------------------|
| `title`       | `summary`         |                              |
| `priority: critical` | `priority: Critical` |                    |
| `priority: high`     | `priority: High`     |                    |
| `priority: medium`   | `priority: Medium`   | Défaut               |
| `priority: low`      | `priority: Low`      |                    |
| `category`    | `labels[0]`       | `["category", "netwatch"]`   |
| Lignes `acceptance:` | `description` | Format ADF (doc v1)      |

---

## n8n

### 1. Pré-requis

- n8n démarré via `docker compose up -d` (service `netwatch-n8n`)
- Accès : http://localhost:5678
- Variable d'environnement `TEAMS_WEBHOOK_URL` configurée dans n8n (Settings > Variables)

### 2. Importer le workflow ServiceNow

1. Dans n8n : **Workflows > Import from file**
2. Sélectionner `scripts/automation/n8n-servicenow.json`
3. Activer le workflow (bouton toggle en haut à droite)

Le workflow :
- Se déclenche toutes les **10 minutes** (Schedule Trigger)
- Exécute `itsm-sync.py --backend servicenow --verbose`
- Parse stdout avec un nœud Code JS : extrait les numéros `INC\d+`
- Si au moins 1 incident créé → envoie une Teams Adaptive Card

### 3. Importer le workflow JIRA

1. **Workflows > Import from file**
2. Sélectionner `scripts/automation/n8n-jira.json`
3. Activer le workflow

Le workflow :
- Même structure que ServiceNow mais avec `--backend jira`
- Regex : `\b([A-Z][A-Z0-9]+-\d+)\b` pour capturer les clés JIRA (ex: `NOC-42`)
- Teams card : "X issue(s) créée(s) dans JIRA [NOC]"

### 4. Vérifier l'exécution

Dans n8n : **Executions** — chaque run affiche stdout, le résultat du parsing et le statut du POST Teams.

### 5. Mode dry-run pour tester

```bash
# Tester sans créer de tickets ITSM
python3 /home/ourslow/code/netwatch/scripts/automation/itsm-sync.py \
  --backend servicenow --dry-run --verbose

# Lister les tickets en attente (aucune action ITSM)
python3 /home/ourslow/code/netwatch/scripts/automation/itsm-sync.py \
  --backend none --verbose
```

---

## Note sécurité

- Les credentials (`SNOW_PASSWORD`, `JIRA_TOKEN`) ne sont **jamais loggés en clair**
- En mode `--verbose`, le champ `auth` est masqué : `user:***`
- Ne jamais commiter `.env` sur git (déjà dans `.gitignore`)
- Utiliser un compte de service dédié avec droits minimaux (rôle `itil` pour ServiceNow, accès projet uniquement pour JIRA)
