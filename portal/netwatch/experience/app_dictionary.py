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


def _resolve_ip_apps(days, size=300):
    """
    dst_ip -> {"name", "category"} via le SNI déjà résolu par ssl.log —
    partagé entre get_app_dependency_map() et get_app_health_scores() pour
    ne pas dupliquer la même requête ES. Best-effort : une IP non résolue
    n'apparaît simplement pas dans le mapping retourné.
    """
    ip_app = {}
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
                "terms": {"field": "id.resp_h.keyword", "size": size},
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
    return ip_app


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

    try:
        ip_app = _resolve_ip_apps(days)
    except requests.exceptions.ConnectionError:
        return {"nodes": [], "edges": []}, "Elasticsearch non joignable"
    except Exception:
        ip_app = {}  # étiquetage par appli = bonus, ne doit pas bloquer le graphe brut

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


def _penalty(value, warn_at, crit_at, max_penalty):
    """Pénalité 0..max_penalty, interpolée linéairement entre warn_at (0) et
    crit_at (max_penalty) — mêmes seuils que les badges déjà utilisés sur
    /flows (retransmit/zero-window : <1% ok, 1-3% warn, >3% crit)."""
    if value <= warn_at:
        return 0.0
    if value >= crit_at:
        return max_penalty
    return max_penalty * (value - warn_at) / (crit_at - warn_at)


def _grade(score):
    if score >= 90:
        return "excellent", "ok"
    if score >= 75:
        return "bon", "ok"
    if score >= 50:
        return "dégradé", "warn"
    return "critique", "crit"


def get_app_health_scores(days=1, hostgroup=None):
    """
    Score de santé composite par application (0-100), à la manière du
    "Service Health Score" Netscout — combine des indicateurs déjà calculés
    ailleurs dans le portail (zero-window, retransmissions, RTT) mais jamais
    agrégés par application métier plutôt que par IP/service isolément.

    Pour chaque IP serveur résolue en application connue (via le
    dictionnaire SNI, cf. _resolve_ip_apps), agrège les connexions
    conn.log vers cette IP : ratio zero-window, ratio retransmissions,
    RTT moyen. Pénalise le score selon les mêmes seuils que les badges
    déjà affichés sur /flows.

    Retourne (scores: list[{name, category, score, grade, grade_color,
    conns, zero_window_pct, retransmit_pct, avg_rtt_ms}], error: str|None),
    trié du moins bon au meilleur (les problèmes en premier).
    """
    matcher = nw_hostgroups.make_matcher(hostgroup) if hostgroup else None

    try:
        ip_app = _resolve_ip_apps(days)
    except requests.exceptions.ConnectionError:
        return [], "Elasticsearch non joignable"
    except Exception as e:
        return [], str(e)[:120]

    if not ip_app:
        return [], None

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
            "by_ip": {
                "terms": {"field": "id.resp_h.keyword", "size": 300},
                "aggs": {
                    "zero_window": {"filter": {"regexp": {"history.keyword": ".*[Ww].*"}}},
                    "retransmit":  {"filter": {"regexp": {"history.keyword": ".*[Tt].*"}}},
                    "avg_rtt":     {"avg": {"field": "rtt"}},
                },
            }
        },
    }
    try:
        r = es_client._es("/zeek-*/_search", body)
        r.raise_for_status()
        buckets = r.json()["aggregations"]["by_ip"]["buckets"]
    except requests.exceptions.ConnectionError:
        return [], "Elasticsearch non joignable"
    except Exception as e:
        return [], str(e)[:120]

    agg = {}  # (name, category) -> {"conns", "zw", "retrans", "rtt_sum", "rtt_n"}
    for b in buckets:
        ip = b["key"]
        if matcher and not matcher(ip):
            continue
        app = ip_app.get(ip)
        if not app:
            continue
        key = (app["name"], app["category"])
        a = agg.setdefault(key, {"conns": 0, "zw": 0, "retrans": 0, "rtt_sum": 0.0, "rtt_n": 0})
        a["conns"]   += b["doc_count"]
        a["zw"]      += b["zero_window"]["doc_count"]
        a["retrans"] += b["retransmit"]["doc_count"]
        rtt = b.get("avg_rtt", {}).get("value")
        if rtt is not None:
            a["rtt_sum"] += rtt * b["doc_count"]
            a["rtt_n"]   += b["doc_count"]

    scores = []
    for (name, category), a in agg.items():
        conns = a["conns"]
        if conns == 0:
            continue
        zw_pct      = round(a["zw"] / conns * 100, 2)
        retrans_pct = round(a["retrans"] / conns * 100, 2)
        avg_rtt_ms  = round(a["rtt_sum"] / a["rtt_n"] * 1000, 1) if a["rtt_n"] else None

        score = 100.0
        score -= _penalty(zw_pct, 1, 3, 35)
        score -= _penalty(retrans_pct, 1, 3, 35)
        if avg_rtt_ms is not None:
            score -= _penalty(avg_rtt_ms, 50, 150, 30)
        score = round(max(0.0, score))

        grade, grade_color = _grade(score)
        scores.append({
            "name": name, "category": category,
            "score": score, "grade": grade, "grade_color": grade_color,
            "conns": conns, "zero_window_pct": zw_pct,
            "retransmit_pct": retrans_pct, "avg_rtt_ms": avg_rtt_ms,
        })

    scores.sort(key=lambda s: s["score"])
    return scores, None
