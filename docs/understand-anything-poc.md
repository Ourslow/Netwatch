# Proof of Concept — IOC Knowledge Graph (T_005)

## Contexte

Ce document documente le PoC de knowledge graph d'IOCs pour NetWatch, réalisé dans le cadre du ticket T_005.

L'objectif initial était d'évaluer la bibliothèque **Understand-Anything** pour construire un graphe de connaissance sur les IOCs détectés. Après vérification, Understand-Anything n'est pas disponible sur PyPI :

```bash
$ pip show understand-anything
WARNING: Package(s) not found: understand-anything
```

**Alternative retenue : NetworkX + elasticsearch-py** — deux librairies éprouvées, disponibles pip, qui couvrent l'intégralité du besoin.

---

## Approche technique

### Stack utilisée

| Composant | Version | Rôle |
|-----------|---------|------|
| `networkx` | 3.6.x | Construction et manipulation du graphe orienté |
| `elasticsearch` | 8.x | Client ES compatible avec ES 8.13 |
| Elasticsearch 8.13 | — | Source des alertes Suricata + Snort |

### Pipeline

```
Elasticsearch 8.13
  ├── suricata-* (72 alertes avec alert.signature)
  └── snort-*    (500 alertes avec msg)
        │
        ▼
  Normalisation des alertes
  (src_ip, dest_ip, signature, category, mitre_tactic, mitre_technique, dns_query)
        │
        ▼
  Construction du graphe NetworkX DiGraph
  ├── Nodes : ip_src, ip_dst, rule, domain, mitre_ttp
  └── Edges : triggered, communicated_with, maps_to_ttp, dns_query, associated_with_rule
        │
        ▼
  Export JSON : ioc-graph-output.json
```

### Types de nœuds

| Type | Description | Couleur |
|------|-------------|---------|
| `ip_src` | IP source d'une alerte | Bleu `#4A90D9` |
| `ip_dst` | IP destination | Vert `#7FBA00` |
| `rule` | Signature de règle IDS (Suricata/Snort) | Orange `#F5A623` |
| `domain` | Domaine DNS observé dans une alerte | Violet `#B86FCE` |
| `mitre_ttp` | Technique MITRE ATT&CK (tactic + technique_id) | Variable selon tactic |

### Types d'arêtes (edges)

| Relation | Source → Cible | Description |
|----------|---------------|-------------|
| `triggered` | `ip_src` → `rule` | L'IP a déclenché cette règle |
| `communicated_with` | `ip_src` → `ip_dst` | Communication réseau observée |
| `maps_to_ttp` | `rule` → `mitre_ttp` | La règle correspond à cette TTP MITRE |
| `dns_query` | `ip_src` → `domain` | L'IP a interrogé ce domaine |
| `associated_with_rule` | `domain` → `rule` | Le domaine est lié à cette règle |

Les edges ont un attribut `weight` = nombre d'occurrences (utile pour la visualisation).

---

## Résultats sur données live ES (2026-06-30)

Exécution sur l'index ES NetWatch du jour :

```
Alertes traitées : 572 (72 Suricata + 500 Snort)
Nodes             : 51
Edges             : 40
```

### Répartition des nœuds

| Type | Nombre |
|------|--------|
| `ip_src` | 10 |
| `ip_dst` | 19 |
| `rule` | 18 |
| `mitre_ttp` | 4 |

### MITRE TTPs détectées

| Technique | Tactic |
|-----------|--------|
| T1071 | Command and Control |
| T1595 | Reconnaissance |
| T1552 | Credential Access |
| T1027 | Defense Evasion |

### Top 5 IPs source (par nombre d'alertes)

| IP | Alertes |
|----|---------|
| 172.31.114.173 | 58 |
| 192.168.1.21 | 3 |
| 117.18.0.55 | 2 |
| 10.10.1.50 | 2 |
| 192.168.1.15 | 2 |

**Observation clé** : `172.31.114.173` représente 80% des alertes Suricata. Cette IP a déclenché la règle `NETWATCH - Large outbound transfer (possible exfiltration)` 33 fois vers `160.79.104.10`. C'est un signal fort de potentielle exfiltration.

---

## Exemple de graphe (données demo)

Extrait du graphe généré avec les données de démo hardcodées (10 alertes) :

```json
{
  "meta": {
    "source": "demo-hardcoded",
    "alert_count_processed": 10,
    "node_count": 30,
    "edge_count": 32,
    "node_types": ["ip_src", "ip_dst", "rule", "domain", "mitre_ttp"]
  },
  "nodes": [
    {
      "id": "ip_src::192.168.1.105",
      "type": "ip_src",
      "label": "192.168.1.105",
      "shape": "circle",
      "color": "#4A90D9",
      "alert_count": 3
    },
    {
      "id": "rule::ET TOR Known Tor Exit Node Traffic",
      "type": "rule",
      "label": "ET TOR Known Tor Exit Node Traffic",
      "category": "Misc Attack",
      "engine": "suricata",
      "shape": "diamond",
      "color": "#F5A623"
    },
    {
      "id": "mitre_ttp::T1090",
      "type": "mitre_ttp",
      "label": "Command and Control (T1090)",
      "tactic": "Command and Control",
      "technique": "T1090",
      "shape": "square",
      "color": "#FF6666"
    },
    {
      "id": "domain::malware-c2.example.com",
      "type": "domain",
      "label": "malware-c2.example.com",
      "shape": "triangle",
      "color": "#B86FCE"
    }
  ],
  "edges": [
    {
      "source": "ip_src::192.168.1.105",
      "target": "rule::ET TOR Known Tor Exit Node Traffic",
      "relation": "triggered",
      "weight": 1
    },
    {
      "source": "ip_src::192.168.1.105",
      "target": "ip_dst::185.220.101.46",
      "relation": "communicated_with",
      "weight": 2
    },
    {
      "source": "rule::ET TOR Known Tor Exit Node Traffic",
      "target": "mitre_ttp::T1090",
      "relation": "maps_to_ttp",
      "weight": 1
    }
  ]
}
```

Ce sous-graphe montre : `192.168.1.105` a communiqué 2 fois avec `185.220.101.46` (nœud Tor connu), déclenchant une règle qui mappe vers la TTP MITRE T1090 (Proxy).

---

## Utilisation du script

```bash
# Sur données ES live (requiert ES opérationnel)
python3 scripts/security/ioc-graph.py

# Avec URL ES personnalisée
python3 scripts/security/ioc-graph.py --es-url http://myhost:9200

# Forcer les données de démo (pas besoin d'ES)
python3 scripts/security/ioc-graph.py --demo

# Spécifier le fichier de sortie
python3 scripts/security/ioc-graph.py --output /tmp/mon-graphe.json

# Limiter le nombre d'alertes ES
python3 scripts/security/ioc-graph.py --max-alerts 1000
```

### Dépendances

```bash
pip install networkx "elasticsearch>=8.0.0,<9.0.0"
```

---

## Livrables

| Fichier | Description |
|---------|-------------|
| `scripts/security/ioc-graph.py` | Script principal — connexion ES, extraction entités, construction graphe, export JSON |
| `scripts/security/ioc-graph-output.json` | Graphe exporté (données ES live du 2026-06-30) |
| `docs/understand-anything-poc.md` | Ce document |

---

## Limitations et pistes d'évolution

### Limitations actuelles
- Pas de déduplication temporelle (même alerte répétée = edge avec weight élevé, pas de timeline)
- Snort ne fournit pas de MITRE TTP dans les logs ES actuels → nodes `mitre_ttp` uniquement depuis Suricata
- Pas de résolution DNS inverse des IPs pour enrichissement géographique
- Le format JSON est adapté à une visualisation type D3.js / Vis.js mais pas encore connecté à une UI

### Pistes d'évolution (v2)
1. **Enrichissement GeoIP** : ajouter latitude/longitude depuis le pipeline GeoIP ES déjà configuré
2. **Timeline** : ajouter l'attribut `timestamp` sur les edges pour filtrage temporel
3. **Interface de visualisation** : intégrer D3.js dans le portail Flask pour afficher le graphe interactif
4. **Corrélation multi-moteurs** : relier les alertes Zeek, Snort, Suricata sur le même flow (via Community ID)
5. **Seuils d'alerte** : déclencher une alerte n8n quand un nœud `ip_src` dépasse N alertes ou atteint une TTP critique
6. **MISP** : exporter les IOCs (IPs, domaines) vers MISP pour partage communautaire
