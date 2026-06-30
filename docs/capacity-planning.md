# Capacity Planning SNMP — NetWatch

Ce document explique la formule de prédiction de saturation des interfaces réseau,
l'interprétation des métriques Prometheus, et comment ajuster la configuration SNMP
pour affiner la précision des prédictions.

---

## 1. Formule : Jours avant saturation

### Définition

La métrique `netwatch:iface_days_to_saturation` répond à la question :
**"Si le trafic continue à croître au même rythme qu'au cours des 7 derniers jours,
dans combien de jours cette interface sera-t-elle saturée ?"**

### Formule PromQL

```yaml
# Recording rule — prometheus/rules/capacity.yml
netwatch:iface_days_to_saturation =
  clamp_min(
    (ifHighSpeed{job="snmp"} * 125000 - rate(ifHCInOctets{job="snmp"}[5m]))
    / clamp_min(deriv(rate(ifHCInOctets{job="snmp"}[5m])[7d:5m]) * 86400, 0.001),
    0)
```

### Décomposition

| Élément | Valeur | Unité | Description |
|---------|--------|-------|-------------|
| `ifHighSpeed * 125000` | capacité max | bytes/s | ifHighSpeed est en Mbps → ×125 000 = bytes/s |
| `rate(ifHCInOctets[5m])` | débit actuel | bytes/s | Compteur 64 bits, fenêtre 5 min |
| numérateur | capacité_restante | bytes/s | Marge disponible avant saturation |
| `deriv(...[7d:5m])` | pente du débit | bytes/s² | Variation linéaire sur 7 jours, step 5 min |
| `* 86400` | croissance/jour | bytes/s/jour | Conversion seconde → jour |
| `clamp_min(..., 0.001)` | protection dénominateur | — | Évite la division par zéro (trafic stable) |
| `clamp_min(result, 0)` | résultat ≥ 0 | jours | Si déjà saturé ou trafic en décroissance → 0 |

### Exemple concret

- Interface GigabitEthernet0/0 : 1 Gbps → capacité = 125 000 000 bytes/s
- Débit actuel : 80 000 000 bytes/s (64 % d'utilisation)
- Croissance constatée (7j) : +500 000 bytes/s par jour
- Capacité restante : 125 000 000 − 80 000 000 = 45 000 000 bytes/s
- **Jours avant saturation : 45 000 000 / 500 000 = 90 jours**

---

## 2. Recording rules intermédiaires

```yaml
# Débit entrant actuel (bytes/s) — fenêtre 5 min
netwatch:iface_bytes_rate = rate(ifHCInOctets{job="snmp"}[5m])

# Taux de croissance sur 7 jours (bytes/s par seconde)
# Valeur positive = trafic en hausse
# Valeur négative = trafic en décroissance
netwatch:iface_growth_rate_7d = deriv(rate(ifHCInOctets{job="snmp"}[5m])[7d:5m])
```

**Pourquoi `deriv` sur un `rate` ?**
`rate()` lisse les pics du compteur brut. `deriv()` calcule la pente linéaire (régression
linéaire simple) sur la fenêtre 7d, ce qui donne une estimation robuste de la tendance
sans être perturbé par la variance quotidienne (heure de pointe vs nuit).

---

## 3. Interprétation des valeurs

### Seuils de criticité (dashboard Grafana)

| Couleur | Jours avant saturation | Action recommandée |
|---------|------------------------|-------------------|
| Rouge | < 7 jours | **Urgent** — commander un uplink ou redistribuer le trafic immédiatement |
| Orange | 7 – 30 jours | **Planifier** — lancer un processus d'augmentation de capacité |
| Vert | > 30 jours | Normal — surveiller l'évolution |

### Cas particuliers

- **Valeur = 0** : interface déjà saturée ou trafic en décroissance (croissance ≤ 0.001 bytes/s/jour)
- **Très grande valeur (> 365j)** : trafic en décroissance ou quasi-stable ; le `clamp_min(0.001)` du dénominateur produit un résultat élevé artificiellement dans ce cas
- **Fluctuations importantes** : normales les premiers 7 jours (fenêtre `deriv` incomplète) — ignorer les alertes pendant la phase d'apprentissage

### Predict_linear vs deriv

Le dashboard affiche aussi `predict_linear(netwatch:iface_bytes_rate[7d], 30*86400)` :
- **predict_linear** : régression linéaire pure sur la fenêtre, extrapolation *t* secondes vers le futur
- **deriv** : dérivée numérique (même base mathématique, mais utilisée dans la formule de saturation)

Les deux convergent vers la même tendance. `predict_linear` est plus lisible visuellement
dans un time series Grafana car il produit une valeur unique (projection à J+30).

---

## 4. Ajuster le SNMP polling interval

### Impact sur la précision

| Polling interval | Fenêtre `rate()` minimale | Précision `deriv()` 7j | Charge SNMP |
|-----------------|--------------------------|----------------------|-------------|
| 30 s | ≥ 2 min | Excellente | Élevée |
| 1 min | ≥ 5 min | Très bonne | Moyenne |
| **5 min (défaut)** | **≥ 5 min** | **Bonne** | **Faible** |
| 15 min | ≥ 15 min | Acceptable | Très faible |

### Modifier le scrape interval SNMP dans Prometheus

```yaml
# prometheus/prometheus.yml
scrape_configs:
  - job_name: snmp
    scrape_interval: 1m    # Réduire de 5m à 1m pour plus de précision
    metrics_path: /snmp
    params:
      module: [ifmib]
    static_configs:
      - targets: ["$SNMP_TARGET_1", "$SNMP_TARGET_2"]
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: netwatch-snmp-exporter:9116
```

**Adapter la fenêtre `rate()` si le scrape interval change :**

Si le scrape interval passe à 1 min, la recording rule peut utiliser une fenêtre plus fine :

```yaml
# Avec scrape_interval: 1m
- record: netwatch:iface_bytes_rate
  expr: rate(ifHCInOctets{job="snmp"}[2m])   # Minimum = 2× l'interval

- record: netwatch:iface_growth_rate_7d
  expr: deriv(rate(ifHCInOctets{job="snmp"}[2m])[7d:1m])   # Step = scrape interval
```

### Recommandations par type d'équipement

| Équipement | Polling recommandé | Raison |
|------------|-------------------|--------|
| Cœur de réseau (>10G) | 1 min | Trafic volatile, alertes rapides critiques |
| Distribution (1G) | 5 min | Équilibre charge/précision — valeur par défaut |
| Accès (100M/1G) | 5–15 min | Trafic stable, moins critique |
| SNMP v1/v2c sur vieux matériel | ≥ 5 min | Certains équipements ne supportent pas les polls fréquents |

### Activation SNMP v3 (recommandé en production)

```yaml
# snmp/snmp.yml — module avec auth v3
modules:
  ifmib_v3:
    walk:
      - 1.3.6.1.2.1.31.1   # ifXTable (64-bit)
      - 1.3.6.1.2.1.2.2    # ifTable
    auth:
      community: ""
      security_level: authPriv
      username: ${SNMP_V3_USER}
      password: ${SNMP_V3_AUTH_PASS}
      auth_protocol: SHA
      priv_protocol: AES
      priv_password: ${SNMP_V3_PRIV_PASS}
```

---

## 5. Fichiers associés

| Fichier | Rôle |
|---------|------|
| `prometheus/rules/capacity.yml` | Recording rules (3 métriques) |
| `prometheus/prometheus.yml` | `rule_files:` + scrape job SNMP |
| `docker-compose.yml` | Volume mount `./prometheus/rules:/etc/prometheus/rules:ro` |
| `grafana/dashboards/capacity-planning.json` | Dashboard dédié capacity planning |
| `grafana/dashboards/snmp-interfaces.json` | Dashboard interfaces + row Capacity Planning |

---

## 6. Vérification

```bash
# Vérifier que Prometheus charge les rules
curl -s http://localhost:9090/api/v1/rules | jq '.data.groups[].name'
# → "capacity_planning"

# Vérifier les métriques disponibles
curl -s 'http://localhost:9090/api/v1/query?query=netwatch:iface_days_to_saturation' | jq .

# Rechargement à chaud (sans restart)
docker exec netwatch-prometheus kill -HUP 1
```
