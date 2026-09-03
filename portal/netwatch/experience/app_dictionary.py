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

import ipaddress
import json
import os

import requests

from .. import es_client
from .. import hostgroups as nw_hostgroups

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


def get_app_traffic_stats(days=1, size=200, hostgroup=None):
    """
    Agrège le trafic SSL (SNI) par application métier sur les `days`
    derniers jours, avec un breakdown par IP source par appli — pour
    répondre à "quel device/hostgroup pèse dans telle catégorie".

    hostgroup : nom d'un hostgroup (cf. netwatch.hostgroups) pour restreindre
    l'agrégation aux IPs de ce groupe uniquement. Filtré côté Python après
    une agrégation plus large (même pattern que filter_items_by_group /
    get_top_talkers ip_ranges ailleurs dans le portail).

    Retourne (apps, unmatched, error) :
      - apps: [{name, category, sessions, top_ips: [{ip, sessions}]}]
        trié par volume décroissant
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
        "aggs": {
            "by_sni": {
                "terms": {"field": "server_name.keyword", "size": size},
                "aggs": {
                    "by_ip": {"terms": {"field": "id.orig_h.keyword", "size": 50}},
                },
            }
        },
    }
    try:
        r = es_client._es("/zeek-*/_search", body)
        r.raise_for_status()
        buckets = r.json()["aggregations"]["by_sni"]["buckets"]
    except requests.exceptions.ConnectionError:
        return [], [], "Elasticsearch non joignable"
    except Exception as e:
        return [], [], str(e)[:120]

    matcher = nw_hostgroups.make_matcher(hostgroup) if hostgroup else None

    app_sessions = {}
    app_ip_counts = {}
    unmatched = []
    for b in buckets:
        domain = b["key"]
        ip_buckets = b.get("by_ip", {}).get("buckets", [])
        if matcher:
            ip_buckets = [ib for ib in ip_buckets if matcher(ib["key"])]
        count = sum(ib["doc_count"] for ib in ip_buckets)
        if count == 0:
            continue

        name, category = _match(domain)
        if name:
            key = (name, category)
            app_sessions[key] = app_sessions.get(key, 0) + count
            ip_counts = app_ip_counts.setdefault(key, {})
            for ib in ip_buckets:
                ip_counts[ib["key"]] = ip_counts.get(ib["key"], 0) + ib["doc_count"]
        else:
            unmatched.append({"domain": domain, "sessions": count})

    apps = []
    for (n, c), s in app_sessions.items():
        top_ips = sorted(
            ({"ip": ip, "sessions": cnt} for ip, cnt in app_ip_counts.get((n, c), {}).items()),
            key=lambda x: -x["sessions"],
        )[:5]
        apps.append({"name": n, "category": c, "sessions": s, "top_ips": top_ips})
    apps.sort(key=lambda a: -a["sessions"])

    unmatched.sort(key=lambda u: -u["sessions"])
    return apps, unmatched[:20], None


def get_app_dependency_map(days=1, hostgroup=None, size=150):
    """
    Carte des dépendances applicatives ("qui parle à qui") — à la Riverbed
    AppResponse. Agrège conn.log par paire (src_ip, dst_ip), labellise les
    IPs destination connues via le dictionnaire applicatif SNI déjà en
    place (ssl.log) — pas de nouveau capteur. Différent de /topology (carte
    physique L2/L3 via SNMP/LLDP) et /graph (graphe sécurité IOC/MITRE) :
    ici c'est le graphe des flux applicatifs eux-mêmes.

    hostgroup : ne garde que les paires impliquant au moins une IP du groupe.

    Retourne (graph: {"nodes": [...], "edges": [...]}, error: str|None).
    """
    matcher = nw_hostgroups.make_matcher(hostgroup) if hostgroup else None

    # 1. dst_ip -> app label, via le SNI déjà résolu par ssl.log — best-effort,
    # une IP non résolue en app connue s'affiche juste sous sa forme brute.
    ip_app = {}
    try:
        r = es_client._es("/zeek-*/_search", {
            "size": 0,
            "query": {
                "bool": {
                    "filter": [{"range": {"@timestamp": {"gte": f"now-{days}d"}}}],
                    "should": [
                        {"term": {"log.file.path.keyword": "/zeek/logs/ssl.log"}},
                        {"term": {"log_source": "ssl"}},
                    ],
                    "minimum_should_match": 1,
                }
            },
            "aggs": {
                "by_ip": {
                    "terms": {"field": "id.resp_h.keyword", "size": 300},
                    "aggs": {"domain": {"terms": {"field": "server_name.keyword", "size": 1}}},
                }
            },
        })
        r.raise_for_status()
        for b in r.json()["aggregations"]["by_ip"]["buckets"]:
            dom_buckets = b.get("domain", {}).get("buckets", [])
            if dom_buckets:
                name, category = _match(dom_buckets[0]["key"])
                if name:
                    ip_app[b["key"]] = {"name": name, "category": category}
    except requests.exceptions.ConnectionError:
        return {"nodes": [], "edges": []}, "Elasticsearch non joignable"
    except Exception:
        pass  # étiquetage par appli = bonus, ne doit pas bloquer le graphe brut

    # 2. Paires (src, dst) agrégées depuis conn.log
    body = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [{"range": {"@timestamp": {"gte": f"now-{days}d"}}}],
                "should": [
                    {"term": {"log.file.path.keyword": "/zeek/logs/conn.log"}},
                    {"term": {"log_source": "conn"}},
                ],
                "minimum_should_match": 1,
            }
        },
        "aggs": {
            "pairs": {
                "multi_terms": {
                    "terms": [{"field": "id.orig_h.keyword"}, {"field": "id.resp_h.keyword"}],
                    "size": size,
                },
                "aggs": {
                    "orig_bytes": {"sum": {"field": "orig_bytes"}},
                    "resp_bytes": {"sum": {"field": "resp_bytes"}},
                },
            }
        },
    }
    try:
        r = es_client._es("/zeek-*/_search", body)
        r.raise_for_status()
        buckets = r.json()["aggregations"]["pairs"]["buckets"]
    except requests.exceptions.ConnectionError:
        return {"nodes": [], "edges": []}, "Elasticsearch non joignable"
    except Exception as e:
        return {"nodes": [], "edges": []}, str(e)[:120]

    def _is_internal(ip):
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    nodes = {}

    def _touch_node(ip):
        if ip not in nodes:
            app = ip_app.get(ip)
            nodes[ip] = {
                "id": ip,
                "label": app["name"] if app else ip,
                "category": app["category"] if app else None,
                "internal": _is_internal(ip),
                "bytes": 0,
            }
        return nodes[ip]

    edges = []
    for b in buckets:
        src, dst = b["key"]
        if matcher and not (matcher(src) or matcher(dst)):
            continue
        total_bytes = (int(b.get("orig_bytes", {}).get("value") or 0)
                       + int(b.get("resp_bytes", {}).get("value") or 0))
        _touch_node(src)["bytes"] += total_bytes
        _touch_node(dst)["bytes"] += total_bytes
        edges.append({
            "source": src, "target": dst,
            "bytes": total_bytes, "count": b["doc_count"],
            "app": ip_app.get(dst, {}).get("name"),
        })

    edges.sort(key=lambda e: -e["bytes"])
    return {"nodes": list(nodes.values()), "edges": edges}, None
