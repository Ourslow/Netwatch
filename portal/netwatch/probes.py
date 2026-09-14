"""
Sondes actives (Blackbox exporter) lues via l'API Prometheus.

NetWatch est passif par construction (Zeek/Suricata ne voient que le trafic qui
existe). Blackbox mesure DEPUIS la sonde : un service que personne n'appelle,
une passerelle qui ne répond plus, un DNS lent — visibles ici.

Chaque sonde = { name, target, module, group, up, latency_ms, availability_pct }
  - up               : probe_success (instantané)
  - latency_ms       : probe_duration_seconds
  - availability_pct : avg_over_time(probe_success[<plage>]) → SLA actif
"""

import requests

import config
from .es_client import _ttl_cache

_TIMEOUT = 4


def _query(expr):
    """Requête instantanée PromQL → liste de {metric, value}."""
    r = requests.get(
        config.NETWATCH_PROMETHEUS_URL.rstrip("/") + "/api/v1/query",
        params={"query": expr}, timeout=_TIMEOUT,
    )
    r.raise_for_status()
    data = r.json()
    if data.get("status") != "success":
        raise RuntimeError(data.get("error", "réponse Prometheus invalide"))
    return data.get("data", {}).get("result", [])


def _key(m):
    return (m.get("instance", ""), m.get("module", ""))


@_ttl_cache(30)
def get_probes(hours=24):
    """
    Retourne (probes: list, error: str|None), triées : KO d'abord, puis par nom.
    Liste vide + error=None si Blackbox n'est pas configuré dans Prometheus.
    """
    try:
        success = _query('probe_success{job="blackbox"}')
        if not success:
            return [], None
        duration = _query('probe_duration_seconds{job="blackbox"}')
        avail    = _query(f'avg_over_time(probe_success{{job="blackbox"}}[{int(hours)}h])')
    except requests.exceptions.ConnectionError:
        return [], "Prometheus non joignable"
    except Exception as e:
        return [], str(e)[:120]

    dur_by   = {_key(x["metric"]): float(x["value"][1]) for x in duration}
    avail_by = {_key(x["metric"]): float(x["value"][1]) for x in avail}

    probes = []
    for x in success:
        m = x["metric"]
        k = _key(m)
        up = x["value"][1] == "1"
        lat = dur_by.get(k)
        av  = avail_by.get(k)
        probes.append({
            "name":             m.get("name") or m.get("instance", "?"),
            "target":           m.get("instance", ""),
            "module":           m.get("module", ""),
            "group":            m.get("group", ""),
            "up":               up,
            "latency_ms":       round(lat * 1000, 1) if lat is not None else None,
            "availability_pct": round(av * 100, 2) if av is not None else None,
        })
    probes.sort(key=lambda p: (p["up"], p["name"].lower()))
    return probes, None


def summarize(probes):
    """{total, up, down, worst_availability} pour les KPIs / le triage."""
    total = len(probes)
    up = sum(1 for p in probes if p["up"])
    avails = [p["availability_pct"] for p in probes if p["availability_pct"] is not None]
    return {
        "total": total,
        "up": up,
        "down": total - up,
        "worst_availability": min(avails) if avails else None,
    }
