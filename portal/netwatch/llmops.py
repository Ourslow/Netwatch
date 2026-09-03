"""
Lecture/agrégation des logs d'appels Ollama journalisés par llm_client.py
dans netwatch-llmops-*. Volet observabilité (LLMOps) du pitch Network
Experience Monitoring — l'IA du portail est on-prem, mais monitorée
elle-même (latence, disponibilité, volume) comme n'importe quel service.
"""

from . import es_client


def get_llmops_stats(days=7):
    """
    Statistiques d'usage de l'assistant IA sur les `days` derniers jours.

    Retourne (stats: dict, error: str|None) avec :
      - total: nb d'appels
      - ok_pct: taux de succès (%)
      - avg_latency_ms / p95_latency_ms
      - by_kind: [{kind, count}] — explain_alert / summarize_alerts / ...
      - recent_errors: [{timestamp, kind, error}] (5 plus récentes)
    """
    empty = {
        "total": 0, "ok_pct": None, "avg_latency_ms": None, "p95_latency_ms": None,
        "by_kind": [], "recent_errors": [],
    }

    body = {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": f"now-{days}d"}}},
        "aggs": {
            "ok_ratio":  {"avg": {"field": "ok"}},
            "avg_lat":   {"avg": {"field": "latency_ms"}},
            "p95_lat":   {"percentiles": {"field": "latency_ms", "percents": [95]}},
            # "kind" est mappé en keyword natif par le template ECS hérité
            # (netwatch-*) — pas de sous-champ ".keyword" comme sur un texte.
            "by_kind":   {"terms": {"field": "kind", "size": 10}},
        },
    }
    try:
        r = es_client._es("/netwatch-llmops-*/_search", body)
        if r.status_code == 404:
            return empty, None  # index pas encore créé — aucun appel IA journalisé
        r.raise_for_status()
        payload = r.json()
    except Exception as e:
        return empty, str(e)[:120]

    total = int(payload.get("hits", {}).get("total", {}).get("value", 0))
    if total == 0:
        return empty, None

    aggs = payload.get("aggregations", {})
    ok_ratio = aggs.get("ok_ratio", {}).get("value")
    avg_lat  = aggs.get("avg_lat", {}).get("value")
    p95_lat  = aggs.get("p95_lat", {}).get("values", {}).get("95.0")
    by_kind  = [
        {"kind": b["key"], "count": b["doc_count"]}
        for b in aggs.get("by_kind", {}).get("buckets", [])
    ]

    recent_errors = []
    try:
        r_err = es_client._es("/netwatch-llmops-*/_search", {
            "size": 5,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "filter": [{"range": {"@timestamp": {"gte": f"now-{days}d"}}}],
                    "must": [{"term": {"ok": False}}],
                }
            },
        })
        if r_err.status_code == 200:
            for h in r_err.json().get("hits", {}).get("hits", []):
                src = h["_source"]
                recent_errors.append({
                    "timestamp": src.get("@timestamp"),
                    "kind":      src.get("kind"),
                    "error":     src.get("error_message"),
                })
    except Exception:
        pass

    return {
        "total":          total,
        "ok_pct":         round(ok_ratio * 100, 1) if ok_ratio is not None else None,
        "avg_latency_ms": round(avg_lat) if avg_lat is not None else None,
        "p95_latency_ms": round(p95_lat) if p95_lat is not None else None,
        "by_kind":        sorted(by_kind, key=lambda b: -b["count"]),
        "recent_errors":  recent_errors,
    }, None
