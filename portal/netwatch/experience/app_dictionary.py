"""
Dictionnaire applicatif SNI/domaine — classe le trafic TLS par application
métier plutôt que par simple port, à la manière du "dictionnaire
applicatif" Riverbed/Netscout (cf.
docs/reports/gaps-vs-editeurs-commerciaux.md). Le mapping s'appuie sur le
SNI TLS (server_name, ssl.log) déjà loggé par Zeek — aucun capteur ni
plugin supplémentaire nécessaire.

Premier volet du pilier "Network Experience Monitoring" (à la Aternity,
sans agent endpoint) du nouvel axe produit LLMOps/DEM.
"""

import json
import os

import requests

from .. import es_client

_CATALOG_PATH = os.path.join(os.path.dirname(__file__), "app_catalog.json")

with open(_CATALOG_PATH, encoding="utf-8") as _f:
    _CATALOG = json.load(_f)["apps"]


def _match(domain):
    """Retourne (app_name, category) pour un domaine/SNI, ou (None, None)."""
    domain = (domain or "").lower().rstrip(".")
    for app in _CATALOG:
        for suffix in app["domains"]:
            suffix = suffix.lower()
            if domain == suffix or domain.endswith("." + suffix):
                return app["name"], app["category"]
    return None, None


def get_app_traffic_stats(days=1, size=200):
    """
    Agrège le trafic SSL (SNI) par application métier sur les `days`
    derniers jours.

    Retourne (apps, unmatched, error) :
      - apps: [{name, category, sessions}] trié par volume décroissant
      - unmatched: [{domain, sessions}] top 20 des SNI non catalogués
        (candidats à ajouter à app_catalog.json)
      - error: str | None
    """
    body = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [{"range": {"@timestamp": {"gte": f"now-{days}d"}}}],
                # should sur les deux discriminants de log : log.file.path (posé par
                # Filebeat en prod) et log_source (posé par simulate-traffic.py) —
                # cf. mémoire project-netwatch-llmops-dem-pitch pour le détail.
                "should": [
                    {"term": {"log.file.path.keyword": "/zeek/logs/ssl.log"}},
                    {"term": {"log_source": "ssl"}},
                ],
                "minimum_should_match": 1,
            }
        },
        "aggs": {"by_sni": {"terms": {"field": "server_name.keyword", "size": size}}},
    }
    try:
        r = es_client._es("/zeek-*/_search", body)
        r.raise_for_status()
        buckets = r.json()["aggregations"]["by_sni"]["buckets"]
    except requests.exceptions.ConnectionError:
        return [], [], "Elasticsearch non joignable"
    except Exception as e:
        return [], [], str(e)[:120]

    app_sessions = {}
    unmatched = []
    for b in buckets:
        domain, count = b["key"], b["doc_count"]
        name, category = _match(domain)
        if name:
            key = (name, category)
            app_sessions[key] = app_sessions.get(key, 0) + count
        else:
            unmatched.append({"domain": domain, "sessions": count})

    apps = sorted(
        ({"name": n, "category": c, "sessions": s} for (n, c), s in app_sessions.items()),
        key=lambda a: -a["sessions"],
    )
    unmatched.sort(key=lambda u: -u["sessions"])
    return apps, unmatched[:20], None
