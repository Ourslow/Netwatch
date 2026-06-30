# IOC Composite Risk Scoring — T_014

**Script :** `scripts/security/ioc-score.py`  
**Route API :** `GET /api/ioc-scores` (TTL cache 5 min)  
**Intégration :** `ioc-graph.py` injecte `risk_score` dans les nœuds IP

---

## Formule de score

```
raw_score = nb_alertes × 1
          + severity_sum
          + moteurs_distincts × 15
          + abuse_score / 10       (si cache AbuseIPDB disponible)
          + mitre_ttps_uniques × 8

score = min(raw_score, 100)
```

### Poids de sévérité par moteur

| Moteur    | Valeur champ        | Niveau    | Poids |
|-----------|---------------------|-----------|-------|
| Suricata  | `alert.severity` = 1 | critical  | 10    |
| Suricata  | `alert.severity` = 2 | high      | 5     |
| Suricata  | `alert.severity` = 3 | medium    | 2     |
| Suricata  | `alert.severity` = 4 | low       | 1     |
| Snort     | `priority` = 1       | high      | 5     |
| Snort     | `priority` = 2       | medium    | 2     |
| Snort     | `priority` = 3       | low       | 1     |
| Zeek      | tout événement notice/weird/intel | medium | 2 |

### Bonus moteurs distincts

Chaque moteur distinct parmi Suricata, Snort et Zeek ayant généré au moins une alerte
pour la même IP source ajoute **+15 points**.

- 1 moteur : +15
- 2 moteurs : +30
- 3 moteurs : +45

### Bonus MITRE ATT&CK

Chaque technique MITRE unique observée ajoute **+8 points**.

### Bonus AbuseIPDB (optionnel)

Si le cache `scripts/security/ioc-enrich-cache.json` contient un champ
`abuseConfidenceScore` pour l'IP (renseigné par `ioc-enrich.py` avec une clé AbuseIPDB),
ce score (0–100) contribue : `abuseConfidenceScore / 10`.

---

## Seuils de niveau

| Niveau    | Score  |
|-----------|--------|
| critical  | ≥ 80   |
| high      | ≥ 60   |
| medium    | ≥ 40   |
| low       | < 40   |

---

## Format de sortie JSON

```json
{
  "meta": {
    "generated_at": "2026-06-30T13:38:44Z",
    "source": "elasticsearch:http://localhost:9200",
    "days": 1,
    "threshold": 0,
    "total_ips": 4,
    "total_alerts_processed": 572
  },
  "scores": [
    {
      "ip": "185.220.101.46",
      "score": 80,
      "level": "critical",
      "alerts_count": 4,
      "engines": ["snort", "suricata"],
      "top_rule": "ET TOR Known Tor Exit Node Traffic",
      "enrichment": {
        "source": "ipinfo",
        "country": "DE",
        "org": "AS60729 Stiftung Erneuerbare Freiheit",
        "hostname": "berlin01.tor-exit.artikel10.org"
      },
      "mitre_ttps": ["T1090", "T1573"]
    }
  ]
}
```

Champs par entrée :

| Champ           | Type     | Description                                          |
|-----------------|----------|------------------------------------------------------|
| `ip`            | string   | Adresse IP source                                    |
| `score`         | int      | Score composite 0–100                                |
| `level`         | string   | Niveau de risque : critical / high / medium / low    |
| `alerts_count`  | int      | Nombre total d'alertes pour cette IP sur la période  |
| `engines`       | string[] | Moteurs qui ont détecté cette IP                     |
| `top_rule`      | string   | Règle avec le poids de sévérité le plus élevé        |
| `enrichment`    | object   | Données du cache ioc-enrich-cache.json (si présent)  |
| `mitre_ttps`    | string[] | Techniques MITRE ATT&CK uniques observées            |

La liste est triée par score décroissant.

---

## Utilisation CLI

```bash
# Score sur 24h, toutes les IPs
python3 scripts/security/ioc-score.py

# Score sur 7 jours, export fichier
python3 scripts/security/ioc-score.py --days 7 --output /tmp/scores.json

# Filtrer uniquement les IPs medium et au-dessus (score >= 40)
python3 scripts/security/ioc-score.py --threshold 40

# Données de démonstration (sans ES)
python3 scripts/security/ioc-score.py --demo

# ES distant
python3 scripts/security/ioc-score.py --es-url http://192.168.1.10:9200 --days 3
```

---

## API Portal

```
GET /api/ioc-scores
Authorization: session cookie (login_required)
```

- Exécute `ioc-score.py` et retourne le JSON ci-dessus
- Cache en mémoire + fichier (`scripts/security/ioc-scores-cache.json`) TTL 5 min
- En cas de timeout (60s), retourne le dernier cache disponible

---

## Exemples de scores calculés (données demo)

### IP 185.220.101.46 — score 80 (critical)

| Composant              | Valeur | Points |
|------------------------|--------|--------|
| Alertes                | 4      | +4     |
| Sévérité (2×crit + 2×high) | — | +30   |
| Moteurs (suricata+snort) | 2   | +30    |
| MITRE uniques (T1090, T1573) | 2 | +16  |
| AbuseIPDB              | n/a    | 0      |
| **Total (capé 100)**   |        | **80** |

### IP 10.0.0.55 — score 79 (high)

| Composant              | Valeur | Points |
|------------------------|--------|--------|
| Alertes                | 4      | +4     |
| Sévérité (1×high + 1×med + 1×snort_high + 1×zeek_med) | — | +14 |
| Moteurs (suricata+snort+zeek) | 3 | +45 |
| MITRE uniques (T1595, T1071) | 2  | +16  |
| **Total**              |        | **79** |

---

## Intégration avec ioc-graph.py

`ioc-graph.py` appelle `ioc-score.py` en subprocess après la construction du graphe
et injecte les champs suivants dans chaque nœud `ip_src` / `ip_dst` :

```json
{
  "risk_score": 80,
  "risk_level": "critical",
  "risk_engines": ["snort", "suricata"],
  "risk_top_rule": "ET TOR Known Tor Exit Node Traffic",
  "risk_mitre_ttps": ["T1090", "T1573"]
}
```

Pour désactiver l'enrichissement (ex. depuis ioc-score.py lui-même) :

```bash
python3 scripts/security/ioc-graph.py --no-scores
```

---

## Pipeline complet

```
ioc-graph.py → ioc-graph-output.json
    ↓ (subprocess)
ioc-score.py → scores JSON + injection risk_score dans les nœuds IP
    ↓
ioc-enrich.py → ioc-enrich-cache.json (AbuseIPDB / ipinfo.io)
    ↑ (lu en lecture seule par ioc-score.py)
```
