"""
Client Elasticsearch léger (requêtes REST via requests).
Normalise les alertes Suricata (EVE JSON) et Snort (alert_json)
en un format commun pour le portail.

Structure normalisée :
  {
    "engine":      "suricata" | "snort",
    "timestamp":   str  (ISO 8601),
    "src_ip":      str,
    "dest_ip":     str,
    "signature":   str,
    "category":    str,
    "severity":    int  (1=critique, 2=moyen, 3=faible),
    "mitre_tactic": str | None,
    "mitre_tech":   str | None,
  }
"""

import requests
import config

_TIMEOUT = 5


def _es(path, body=None, method="post"):
    url = config.NETWATCH_ES_URL.rstrip("/") + path
    fn  = getattr(requests, method)
    kw  = {"timeout": _TIMEOUT, "verify": False}
    if body is not None:
        kw["json"] = body
    return fn(url, **kw)


# ------------------------------------------------------------------ #
# Normalisation                                                        #
# ------------------------------------------------------------------ #

def _normalize(hit):
    src    = hit["_source"]
    index  = hit.get("_index", "")
    engine = "suricata" if "suricata" in index else "snort"

    if engine == "suricata":
        alert = src.get("alert", {})
        meta  = alert.get("metadata", {})
        # mitre_tactic_name peut être une liste ou une str
        tactic_raw = meta.get("mitre_tactic_name", [])
        tech_raw   = meta.get("mitre_technique_id", [])
        tactic = (tactic_raw[0] if isinstance(tactic_raw, list) else tactic_raw) or None
        tech   = (tech_raw[0]   if isinstance(tech_raw,   list) else tech_raw)   or None
        return {
            "engine":       "suricata",
            "timestamp":    src.get("@timestamp", ""),
            "src_ip":       src.get("src_ip",  "—"),
            "dest_ip":      src.get("dest_ip", "—"),
            "signature":    alert.get("signature", "—"),
            "category":     alert.get("category",  "—"),
            "severity":     int(alert.get("severity", 3)),
            "mitre_tactic": tactic,
            "mitre_tech":   tech,
        }
    else:  # snort alert_json
        return {
            "engine":       "snort",
            "timestamp":    src.get("@timestamp", src.get("timestamp", "")),
            "src_ip":       src.get("src_addr", "—"),
            "dest_ip":      src.get("dst_addr", "—"),
            "signature":    src.get("msg",   "—"),
            "category":     src.get("class", "—"),
            "severity":     int(src.get("priority", 3)),
            "mitre_tactic": None,
            "mitre_tech":   None,
        }


# ------------------------------------------------------------------ #
# Requêtes                                                             #
# ------------------------------------------------------------------ #

def get_recent_alerts(size=100, engine=None, severity=None, search=None):
    """
    Retourne (alerts: list, error: str|None).
    engine   : "suricata" | "snort" | None
    severity : 1 | 2 | 3 | None
    search   : str libre (signature, IP) | None
    """
    if engine == "suricata":
        index = "suricata-*"
    elif engine == "snort":
        index = "snort-*"
    else:
        index = "suricata-*,snort-*"

    # Filtres obligatoires : garder uniquement les alertes
    # Suricata → event_type = alert
    # Snort    → champ sid présent
    filter_must = [
        {
            "bool": {
                "should": [
                    {"term":   {"event_type": "alert"}},
                    {"exists": {"field": "sid"}},
                ],
                "minimum_should_match": 1,
            }
        }
    ]

    if severity is not None:
        filter_must.append({
            "bool": {
                "should": [
                    {"term": {"alert.severity": severity}},
                    {"term": {"priority":       severity}},
                ],
                "minimum_should_match": 1,
            }
        })

    query = {"bool": {"filter": filter_must}}

    if search:
        query["bool"]["must"] = [{
            "multi_match": {
                "query":  search,
                "fields": [
                    "alert.signature", "alert.category",
                    "msg", "class",
                    "src_ip", "dest_ip", "src_addr", "dst_addr",
                    "alert.metadata.mitre_tactic_name",
                    "alert.metadata.mitre_technique_id",
                ],
            }
        }]

    body = {
        "size": size,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": query,
        "_source": [
            "@timestamp", "timestamp",
            "src_ip", "dest_ip", "src_addr", "dst_addr",
            "alert", "msg", "class", "priority", "sid",
            "event_type",
        ],
    }

    try:
        r = _es(f"/{index}/_search", body)
        r.raise_for_status()
        hits = r.json().get("hits", {}).get("hits", [])
        return [_normalize(h) for h in hits], None
    except requests.exceptions.ConnectionError:
        return [], "Elasticsearch non joignable — vérifier NETWATCH_ES_URL"
    except requests.exceptions.Timeout:
        return [], f"Elasticsearch timeout (> {_TIMEOUT}s)"
    except Exception as e:
        return [], str(e)[:120]


def get_alert_stats():
    """
    Statistiques pour le widget dashboard et le header /alerts.
    Retourne (stats: dict, error: str|None).
    """
    body = {
        "size": 0,
        "query": {
            "bool": {
                "should": [
                    {"term":   {"event_type": "alert"}},
                    {"exists": {"field": "sid"}},
                ],
                "minimum_should_match": 1,
            }
        },
        "aggs": {
            "last_24h": {
                "filter": {"range": {"@timestamp": {"gte": "now-24h"}}},
                "aggs": {
                    "by_severity_24h": {
                        "terms": {"field": "alert.severity", "size": 5, "missing": 3}
                    }
                },
            },
            "by_severity": {
                "terms": {"field": "alert.severity", "size": 5, "missing": 3}
            },
            "by_mitre": {
                "terms": {
                    "field": "alert.metadata.mitre_tactic_name",
                    "size": 5,
                }
            },
        },
    }

    try:
        r = _es("/suricata-*,snort-*/_search", body)
        r.raise_for_status()
        data = r.json()
        aggs  = data.get("aggregations", {})
        total = data.get("hits", {}).get("total", {}).get("value", 0)

        last_24h = aggs.get("last_24h", {}).get("doc_count", 0)

        # Sévérités (priorité = 1 critique)
        sev = {b["key"]: b["doc_count"]
               for b in aggs.get("by_severity", {}).get("buckets", [])}

        # Top MITRE tactics
        mitre = [(b["key"], b["doc_count"])
                 for b in aggs.get("by_mitre", {}).get("buckets", [])]

        return {
            "total":    total,
            "last_24h": last_24h,
            "critical": sev.get(1, 0),
            "medium":   sev.get(2, 0),
            "low":      sev.get(3, 0),
            "mitre":    mitre[:5],
        }, None

    except requests.exceptions.ConnectionError:
        return None, "Elasticsearch non joignable"
    except Exception as e:
        return None, str(e)[:80]
