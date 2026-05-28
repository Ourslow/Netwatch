"""
Vérification de l'état des services NetWatch.
Chaque checker retourne un dict :
  {
    "name":    str,
    "url":     str,
    "status":  "up" | "degraded" | "down",
    "latency": float | None,   # ms
    "detail":  str | None,
  }
"""

import time
import requests

TIMEOUT = 3  # secondes


def _check(name, url, parse_fn=None):
    """Appel HTTP générique avec mesure de latence."""
    t0 = time.monotonic()
    try:
        r = requests.get(url, timeout=TIMEOUT, verify=False)
        latency = round((time.monotonic() - t0) * 1000)
        if r.status_code >= 500:
            return {"name": name, "url": url, "status": "down",
                    "latency": latency, "detail": f"HTTP {r.status_code}"}
        detail = None
        status = "up"
        if parse_fn:
            status, detail = parse_fn(r)
        return {"name": name, "url": url, "status": status,
                "latency": latency, "detail": detail}
    except requests.exceptions.ConnectionError:
        return {"name": name, "url": url, "status": "down",
                "latency": None, "detail": "Connexion refusée"}
    except requests.exceptions.Timeout:
        return {"name": name, "url": url, "status": "down",
                "latency": None, "detail": f"Timeout > {TIMEOUT}s"}
    except Exception as e:
        return {"name": name, "url": url, "status": "down",
                "latency": None, "detail": str(e)[:80]}


def _parse_es(r):
    """Cluster health Elasticsearch : green=up, yellow=degraded, red=down."""
    try:
        data = r.json()
        color = data.get("status", "red")
        indices = data.get("number_of_data_nodes", "?")
        shards  = data.get("active_shards", "?")
        detail  = f"status={color} · data_nodes={indices} · shards={shards}"
        if color == "green":
            return "up", detail
        if color == "yellow":
            return "degraded", detail
        return "down", detail
    except Exception:
        return "degraded", "Réponse non parseable"


def _parse_grafana(r):
    """Grafana /api/health : {"database": "ok"} → up."""
    try:
        data = r.json()
        db = data.get("database", "?")
        commit = data.get("commit", "")[:7]
        detail = f"db={db}" + (f" · commit={commit}" if commit else "")
        return ("up" if db == "ok" else "degraded"), detail
    except Exception:
        return "up", None   # Grafana renvoie parfois du HTML en mode no-auth


def _parse_prometheus(r):
    """Prometheus /-/healthy : "Prometheus Server is Healthy." → up."""
    body = r.text.strip()
    if "Healthy" in body or r.status_code == 200:
        return "up", "Prometheus Healthy"
    return "degraded", body[:60]


def _parse_autoblock(r):
    """AutoBlock Flask : /health ou / → JSON {"status": "ok", "dry_run": bool}."""
    try:
        data = r.json()
        dry = data.get("dry_run", True)
        mode = "DRY_RUN" if dry else "LIVE ⚠️"
        return "up", f"mode={mode}"
    except Exception:
        return "up", None


def check_all(es_url, grafana_url, prometheus_url, autoblock_url):
    services = [
        _check("Elasticsearch",   f"{es_url}/_cluster/health",  _parse_es),
        _check("Grafana",         f"{grafana_url}/api/health",  _parse_grafana),
        _check("Prometheus",      f"{prometheus_url}/-/healthy", _parse_prometheus),
        _check("AutoBlock",       f"{autoblock_url}/health",    _parse_autoblock),
    ]
    # Résumé global
    statuses = [s["status"] for s in services]
    if all(s == "up" for s in statuses):
        global_status = "up"
    elif all(s == "down" for s in statuses):
        global_status = "down"
    else:
        global_status = "degraded"

    return services, global_status
