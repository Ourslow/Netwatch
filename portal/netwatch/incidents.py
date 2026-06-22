"""
Regroupement des alertes en incidents par fenêtre temporelle glissante.
Chaque incident = cluster d'alertes dans une fenêtre de N minutes.
"""

from collections import Counter
from datetime import datetime, timedelta, timezone


def _parse_ts(ts_str):
    if not ts_str:
        return None
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except Exception:
        return None


def build_incidents(alerts, window_minutes=5):
    """
    Regroupe une liste d'alertes normalisées en incidents.
    Retourne une liste d'incidents triée du plus récent au plus ancien.
    """
    if not alerts:
        return []

    dated = [(a, _parse_ts(a.get("timestamp"))) for a in alerts]
    dated = [(a, ts) for a, ts in dated if ts is not None]
    dated.sort(key=lambda x: x[1], reverse=True)

    now = datetime.now(timezone.utc)
    window = timedelta(minutes=window_minutes)

    incidents = []
    current = None

    for alert, ts in dated:
        if current is None or (current["_anchor"] - ts) > window:
            if current:
                incidents.append(_finalize(current, now))
            current = {
                "_anchor": ts,
                "_end":    ts,
                "alerts":    [alert],
                "engines":   set(),
                "src_ips":   set(),
                "dest_ips":  set(),
            }
        else:
            current["alerts"].append(alert)
            current["_end"] = ts

        current["engines"].add(alert.get("engine", "?"))
        src = alert.get("src_ip", "")
        dst = alert.get("dest_ip", "")
        if src and src != "—":
            current["src_ips"].add(src)
        if dst and dst != "—":
            current["dest_ips"].add(dst)

    if current:
        incidents.append(_finalize(current, now))

    return incidents


def _finalize(inc, now):
    alerts    = inc["alerts"]
    sevs      = [a.get("severity", 3) for a in alerts]
    critical  = sum(1 for s in sevs if s == 1)
    medium    = sum(1 for s in sevs if s == 2)
    low       = sum(1 for s in sevs if s == 3)
    max_sev   = min(sevs) if sevs else 3

    age = now - inc["_anchor"]
    if age < timedelta(hours=1):
        status, status_color = "nouveau",  "danger"
    elif age < timedelta(hours=24):
        status, status_color = "en cours", "warning"
    else:
        status, status_color = "clôturé",  "secondary"

    top_sig = Counter(a.get("signature", "") for a in alerts).most_common(1)

    return {
        "start":         inc["_anchor"].isoformat(),
        "end":           inc["_end"].isoformat(),
        "count":         len(alerts),
        "critical":      critical,
        "medium":        medium,
        "low":           low,
        "max_severity":  max_sev,
        "engines":       sorted(inc["engines"]),
        "src_ips":       sorted(inc["src_ips"])[:6],
        "dest_ips":      sorted(inc["dest_ips"])[:6],
        "top_signature": top_sig[0][0] if top_sig else "—",
        "status":        status,
        "status_color":  status_color,
        "alerts":        alerts[:10],
    }
