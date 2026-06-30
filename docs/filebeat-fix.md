# T_002 — Fix Filebeat → Elasticsearch : data-stream bug

## Cause racine

### BUG 1 — `setup.template.pattern` comma-séparé invalide (critique)

Dans `filebeat/filebeat.yml`, le paramètre :
```yaml
setup.template.pattern: "zeek-*,snort-*,suricata-*,netwatch-*"
```
est traité par ES 8.x comme une **chaîne unique** (pas un tableau). Elasticsearch
normalisait ce pattern en `*` dans le composable index template résultant. Le template
`netwatch` avait donc `index_patterns: ["*"]`, ce qui le rendait catch-all (priorité 150,
s'appliquait à TOUS les index).

**Conséquence directe :** lors des reconnexions Filebeat, le callback `onConnect`
appelait `putDataStream("netwatch")`. ES cherchait un template avec `data_stream`
activé pour le data stream `netwatch` ; il trouvait le template catch-all `netwatch [*]`
qui n'a pas de section `data_stream`, donc `_data_stream_timestamp` était implicitement
désactivé → erreur **500** :
```
[_data_stream_timestamp] meta field has been disabled
```
Cette erreur 500 bloquait toutes les reconnexions Filebeat en boucle infinie.

### BUG 2 — `putDataStream()` appelé malgré `setup.ilm.enabled: false`

Filebeat 8.x appelle systématiquement `putDataStream()` dans son callback `onConnect`
lors de chaque reconnexion à ES 8.x, même quand `setup.ilm.enabled: false`. Cette
fonction tente de créer le data stream correspondant au nom du template. Si `setup.ilm`
est désactivé mais que la gestion de templates reste active (`setup.template.enabled: true`
par défaut), la boucle de reconnexion échoue à chaque tentative.

### BUG 3 — Pipeline `netwatch-geoip` absent

`setup-es.sh` créait les index templates `netwatch-zeek/snort/suricata` avec
`"default_pipeline": "netwatch-geoip"` mais ne créait **pas** le pipeline. Le pipeline
n'était créé que par `setup-geoip.sh`, qui n'avait jamais été appelé dans le workflow
docker compose standard. Les index créés par les templates référençant ce pipeline
auraient échoué à insérer des documents.

### BUG 4 — Scripts `setup-es.sh` et `setup-geoip.sh` non coordonnés

Les deux scripts créaient les mêmes templates `netwatch-zeek/snort/suricata` avec des
priorités différentes (500 vs 1), créant une incohérence selon l'ordre d'exécution.

---

## Séquence d'erreurs observées

```
# Au démarrage (ES pas encore prêt) :
"failed to publish events: temporary bulk send failure"

# Sur reconnexion (template catch-all [*]) :
"Try loading data stream netwatch to Elasticsearch"
"failed to put data stream: could not put data stream: 500 Internal Server Error:
 [_data_stream_timestamp] meta field has been disabled"
```

---

## Fix appliqué

### 1. `filebeat/filebeat.yml` — Désactivation complète de la gestion templates

```yaml
# Avant (bugué) :
setup.template.name: "netwatch"
setup.template.pattern: "zeek-*,snort-*,suricata-*,netwatch-*"
setup.template.settings:
  index.number_of_shards: 1
  index.number_of_replicas: 0
setup.ilm.enabled: false

# Après (fix) :
setup.template.enabled: false   # ← Filebeat ne gère plus les templates
setup.ilm.enabled: false        # ← ILM/data-streams désactivés
```

Avec `setup.template.enabled: false`, Filebeat :
- Ne tente plus de créer ou modifier les index templates
- **Ne call plus `putDataStream()`** → plus d'erreur de reconnexion
- Se connecte à ES en un seul attempt, sans retry

Les templates sont désormais gérés exclusivement par `setup-es.sh` (priorité 500).

### 2. ES — Suppression du template catch-all `netwatch [*]`

```bash
curl -X DELETE http://localhost:9200/_index_template/netwatch
```

Remplacé par le template `netwatch [netwatch-*]` (priorité 150) créé lors d'un
restart intermédiaire, qui ne conflicte plus avec les index moteurs.

### 3. `setup-es.sh` — Intégration du pipeline GeoIP

Le script installe maintenant le pipeline avant les templates :
```bash
[1/4] Réplicas → 0 sur les index existants
[2/4] Pipeline netwatch-geoip (création/mise à jour)
[3/4] Index-templates zeek-*, snort-*, suricata-* (priorité 500)
[4/4] Statut cluster
```

Cela garantit que `default_pipeline: netwatch-geoip` est résolvable quand les
nouveaux index sont créés.

### 4. ES — Pipeline `netwatch-geoip` créé

```bash
curl -X PUT http://localhost:9200/_ingest/pipeline/netwatch-geoip \
  -H 'Content-Type: application/json' \
  -d @elasticsearch/pipelines/netwatch-geoip.json
```

---

## Validation end-to-end

Après application des fixes (2026-06-30 09:04:47 UTC) :

```
# Démarrage Filebeat propre (0 erreur) :
info | Connection to backoff(elasticsearch(http://elasticsearch:9200)) established

# Métriques stables (données qui coulent) :
info | Non-zero metrics in the last 30s   ← toutes les 30s

# Index avec données :
zeek-2026.06.30     : 449 docs
snort-2026.06.30    : 4680 docs  (croissant)
suricata-2026.06.30 : 26331 docs (croissant)
```

Templates ES après fix :
| Template          | Pattern       | Priorité | Usage                        |
|-------------------|---------------|----------|------------------------------|
| `netwatch-zeek`   | `zeek-*`      | 500      | Index templates moteur Zeek  |
| `netwatch-snort`  | `snort-*`     | 500      | Index templates moteur Snort |
| `netwatch-suricata`| `suricata-*` | 500      | Index templates moteur Suricata |
| `netwatch`        | `netwatch-*`  | 150      | Fallback (ne conflicte plus) |

---

## Procédure de reproductibilité

En cas de réinitialisation complète (`make clean`) :

```bash
# 1. Démarrer la stack
make start

# 2. Configurer ES (templates + pipeline GeoIP)
make setup-es

# 3. Filebeat démarre sans erreur et indexe automatiquement
docker logs netwatch-filebeat --tail 5
```

L'ordre `make setup-es` → Filebeat indexe est important : les templates moteurs
doivent exister avant la création des index du jour pour que `default_pipeline`
soit appliqué aux nouveaux documents.
