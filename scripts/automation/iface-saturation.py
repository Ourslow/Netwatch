#!/usr/bin/env python3
"""
iface-saturation.py — NetWatch Interface Saturation Monitor

Surveille la saturation des interfaces réseau via Prometheus (métriques SNMP).
Requête Prometheus : rate(ifHCInOctets{job="snmp"}[5m])*8  (bits/s)
Compare au débit nominal de l'interface pour calculer l'utilisation en %.

Seuils :
  > 80 %  → medium
  > 90 %  → high
  > 95 %  → critical

Actions :
  - create-ticket.py (category: capacity)
  - Teams Adaptive Card si severity ≥ high

Anti-doublon : iface-saturation-history.json TTL 15min par clé (iface+seuil)
Fallback      : si Prometheus non joignable → skip gracieusement

Usage :
    python3 iface-saturation.py [--dry-run] [--verbose] [--threshold 80]
                                [--prometheus-url http://localhost:9090]
"""

import argparse
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone, timedelta
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SCRIPT_DIR          = Path(__file__).resolve().parent
REPO_ROOT           = SCRIPT_DIR.parent.parent
HISTORY_FILE        = SCRIPT_DIR / "iface-saturation-history.json"
CREATE_TICKET_SCRIPT = SCRIPT_DIR / "create-ticket.py"

DEFAULT_PROMETHEUS_URL = os.environ.get("PROMETHEUS_URL", "http://localhost:9090")
HISTORY_TTL_MINUTES    = 15

# Thresholds (%)
THRESHOLD_MEDIUM   = 80.0
THRESHOLD_HIGH     = 90.0
THRESHOLD_CRITICAL = 95.0

# Assumed nominal bandwidth per interface (bits/s) — override via env
# If Prometheus exposes ifHighSpeed (Mbps) we use it; otherwise this fallback
DEFAULT_IFACE_SPEED_BPS = int(os.environ.get("IFACE_SPEED_MBPS", "1000")) * 1_000_000

# Query for ingress traffic in bits/s
QUERY_INGRESS = "rate(ifHCInOctets{job=\"snmp\"}[5m])*8"
QUERY_EGRESS  = "rate(ifHCOutOctets{job=\"snmp\"}[5m])*8"
# Query for interface speed in bits/s (ifHighSpeed is in Mbps)
QUERY_SPEED   = "ifHighSpeed{job=\"snmp\"} * 1000000"


# ---------------------------------------------------------------------------
# History / anti-doublon
# ---------------------------------------------------------------------------

def load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def save_json(path: Path, data: dict) -> None:
    try:
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except OSError as e:
        print(f"WARN: cannot write {path.name}: {e}", file=sys.stderr)


def purge_history(history: dict, ttl_minutes: int) -> dict:
    """Supprime les entrées plus vieilles que TTL."""
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=ttl_minutes)
    return {
        k: v for k, v in history.items()
        if datetime.fromisoformat(v.get("fired_at", "1970-01-01T00:00:00+00:00")) > cutoff
    }


def is_in_cooldown(key: str, history: dict) -> bool:
    entry = history.get(key)
    if not entry:
        return False
    try:
        last_ts = datetime.fromisoformat(entry["fired_at"])
        cutoff  = datetime.now(timezone.utc) - timedelta(minutes=HISTORY_TTL_MINUTES)
        return last_ts > cutoff
    except (KeyError, ValueError):
        return False


def record_history(key: str, severity: str, pct: float, history: dict) -> None:
    history[key] = {
        "fired_at": datetime.now(timezone.utc).isoformat(),
        "severity": severity,
        "pct":      round(pct, 2),
    }


# ---------------------------------------------------------------------------
# Prometheus helpers
# ---------------------------------------------------------------------------

def prometheus_query(prom_url: str, query: str, verbose: bool = False) -> list[dict] | None:
    """
    Execute an instant Prometheus query.
    Returns list of result items [{metric:{...}, value:[ts, val]}]
    or None if Prometheus is not reachable (graceful fallback).
    """
    import urllib.parse
    url = prom_url.rstrip("/") + "/api/v1/query?" + urllib.parse.urlencode({"query": query})
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        if data.get("status") != "success":
            if verbose:
                print(f"  [Prometheus] status={data.get('status')} error={data.get('error', '')}", file=sys.stderr)
            return []
        return data.get("data", {}).get("result", [])
    except (urllib.error.URLError, OSError) as e:
        if verbose:
            print(f"  [Prometheus] non joignable: {e}", file=sys.stderr)
        return None  # Signal: Prometheus absent → skip
    except Exception as e:
        if verbose:
            print(f"  [Prometheus] erreur inattendue: {e}", file=sys.stderr)
        return None


def parse_metric_value(result_item: dict) -> float | None:
    """Extract float value from Prometheus result item."""
    try:
        return float(result_item["value"][1])
    except (KeyError, IndexError, ValueError, TypeError):
        return None


def get_iface_label(metric: dict) -> str:
    """Build a human-readable interface label from Prometheus labels."""
    iface   = metric.get("ifDescr") or metric.get("ifAlias") or metric.get("ifIndex", "?")
    instance = metric.get("instance", "")
    job      = metric.get("job", "")
    if instance:
        return f"{instance}/{iface}"
    return f"{job}/{iface}"


# ---------------------------------------------------------------------------
# Interface speed lookup
# ---------------------------------------------------------------------------

def get_iface_speeds(prom_url: str, verbose: bool) -> dict[str, float]:
    """
    Query ifHighSpeed to get nominal speed per interface (bits/s).
    Returns dict: iface_label → speed_bps.
    Falls back to DEFAULT_IFACE_SPEED_BPS for unknown interfaces.
    """
    results = prometheus_query(prom_url, QUERY_SPEED, verbose)
    if not results:
        return {}

    speeds: dict[str, float] = {}
    for item in results:
        label = get_iface_label(item.get("metric", {}))
        val   = parse_metric_value(item)
        if val is not None and val > 0:
            speeds[label] = val

    if verbose:
        print(f"  [speed] {len(speeds)} interfaces avec vitesse nominale connue")
    return speeds


# ---------------------------------------------------------------------------
# Traffic query
# ---------------------------------------------------------------------------

def get_iface_traffic(prom_url: str, query: str, verbose: bool) -> dict[str, float]:
    """
    Query Prometheus for interface traffic in bits/s.
    Returns dict: iface_label → bps.
    Returns None if Prometheus not reachable.
    """
    results = prometheus_query(prom_url, query, verbose)
    if results is None:
        return None  # Prometheus absent

    traffic: dict[str, float] = {}
    for item in results:
        label = get_iface_label(item.get("metric", {}))
        val   = parse_metric_value(item)
        if val is not None:
            traffic[label] = val

    return traffic


# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------

def action_create_ticket(iface: str, direction: str, severity: str,
                          pct: float, bps: float,
                          dry_run: bool, verbose: bool) -> bool:
    """Pipe capacity alert JSON to create-ticket.py."""
    if not CREATE_TICKET_SCRIPT.exists():
        if verbose:
            print(f"  [ticket] SKIP: {CREATE_TICKET_SCRIPT} introuvable", file=sys.stderr)
        return False

    severity_num = {"critical": 1, "high": 2, "medium": 3}.get(severity, 3)
    mbps = bps / 1_000_000
    desc = f"SATURATION {direction.upper()} {iface} = {pct:.1f}% ({mbps:.0f} Mbps)"

    alert_json = json.dumps({
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip":     "network",
        "dest_ip":    "0.0.0.0",
        "alert": {
            "signature": f"IFACE SATURATION — {desc}",
            "severity":  severity_num,
            "category":  "capacity",
        },
        "severity": severity,
        "engine":   "iface-saturation",
        "capacity": {
            "interface": iface,
            "direction": direction,
            "pct":       round(pct, 2),
            "bps":       round(bps, 0),
            "category":  "capacity",
        },
    })

    if dry_run:
        print(f"  [DRY-RUN] create-ticket: {desc} (severity={severity})")
        return True

    try:
        result = subprocess.run(
            [sys.executable, str(CREATE_TICKET_SCRIPT)],
            input=alert_json, capture_output=True, text=True, timeout=30,
        )
        out = (result.stdout or "").strip()
        err = (result.stderr or "").strip()
        if result.returncode == 0:
            if verbose or out:
                print(f"  [ticket] {out or 'OK'}")
            return True
        if "SKIP" in err:
            if verbose:
                print(f"  [ticket] {err}")
            return True
        print(f"  [ticket] ERREUR (exit {result.returncode}): {err}", file=sys.stderr)
        return False
    except (subprocess.TimeoutExpired, OSError) as e:
        print(f"  [ticket] ERREUR subprocess: {e}", file=sys.stderr)
        return False


def action_teams(iface: str, direction: str, severity: str,
                  pct: float, bps: float,
                  dry_run: bool, verbose: bool) -> bool:
    """
    POST Teams Adaptive Card alert.
    Called only when severity ≥ high.
    """
    webhook_url = os.environ.get("TEAMS_WEBHOOK_URL", "").strip()
    if not webhook_url:
        if verbose:
            print("  [teams] TEAMS_WEBHOOK_URL non définie — skip")
        return True

    mbps    = bps / 1_000_000
    emoji   = "\U0001f6a8" if severity == "critical" else "⚠️"
    color   = "Attention" if severity == "critical" else "Warning"

    payload = {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type":    "AdaptiveCard",
                "version": "1.4",
                "body": [
                    {
                        "type":    "TextBlock",
                        "text":    f"{emoji} Saturation Interface [{severity.upper()}] — {iface}",
                        "size":    "Large",
                        "weight":  "Bolder",
                        "color":   color,
                        "wrap":    True,
                    },
                    {
                        "type": "FactSet",
                        "facts": [
                            {"title": "Interface",    "value": iface},
                            {"title": "Direction",    "value": direction.upper()},
                            {"title": "Utilisation",  "value": f"{pct:.1f} %"},
                            {"title": "Débit actuel", "value": f"{mbps:.0f} Mbps"},
                            {"title": "Sévérité",     "value": severity.upper()},
                            {
                                "title": "Horodatage",
                                "value": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                            },
                        ],
                    },
                ],
                "actions": [{
                    "type":  "Action.OpenUrl",
                    "title": "Ouvrir NetWatch",
                    "url":   "http://localhost:5050",
                }],
            },
        }],
    }

    if dry_run:
        print(f"  [DRY-RUN] POST Teams card ({severity}): {iface} {pct:.1f}%")
        return True

    try:
        body = json.dumps(payload).encode()
        req  = urllib.request.Request(
            webhook_url, data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            status = resp.status
        if verbose:
            print(f"  [teams] POST → HTTP {status}")
        return status < 300
    except urllib.error.URLError as e:
        print(f"  [teams] ERREUR: {e}", file=sys.stderr)
        return False


# ---------------------------------------------------------------------------
# Alert evaluation
# ---------------------------------------------------------------------------

def evaluate_interface(
    iface: str, direction: str,
    bps: float, speed_bps: float,
    history: dict, args,
) -> dict | None:
    """
    Compute utilization % and fire alert if above threshold.
    Returns alert dict if fired, else None.
    """
    pct = (bps / speed_bps * 100.0) if speed_bps > 0 else 0.0

    threshold = args.threshold
    if pct < threshold:
        if args.verbose:
            print(f"  OK {iface} {direction}: {pct:.1f}% (< {threshold:.0f}%)")
        return None

    # Determine severity
    if pct >= THRESHOLD_CRITICAL:
        severity = "critical"
    elif pct >= THRESHOLD_HIGH:
        severity = "high"
    else:
        severity = "medium"

    alert_key = f"{iface}|{direction}|{severity}"

    if is_in_cooldown(alert_key, history):
        if args.verbose:
            print(f"  SKIP (cooldown {HISTORY_TTL_MINUTES}min): {alert_key}")
        return None

    mbps = bps / 1_000_000
    print(f"  ALERTE [{severity.upper()}] {iface} {direction}: {pct:.1f}% ({mbps:.0f} Mbps)")

    # Action 1: create ticket (category: capacity)
    action_create_ticket(iface, direction, severity, pct, bps, args.dry_run, args.verbose)

    # Action 2: Teams (only if severity >= high)
    if severity in ("high", "critical"):
        action_teams(iface, direction, severity, pct, bps, args.dry_run, args.verbose)

    # Record in history
    record_history(alert_key, severity, pct, history)

    return {
        "interface": iface,
        "direction": direction,
        "severity":  severity,
        "pct":       round(pct, 1),
        "bps":       round(bps, 0),
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description=(
            "NetWatch Interface Saturation Monitor — surveille la saturation "
            "des interfaces via Prometheus SNMP."
        )
    )
    parser.add_argument("--dry-run", action="store_true",
                        help="Simuler sans créer de tickets ni envoyer vers Teams")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Afficher les détails de chaque étape")
    parser.add_argument("--threshold", type=float, default=THRESHOLD_MEDIUM,
                        help=f"Seuil d'alerte minimum en %% (défaut: {THRESHOLD_MEDIUM:.0f})")
    parser.add_argument("--prometheus-url", default=DEFAULT_PROMETHEUS_URL,
                        help=f"URL Prometheus (défaut: {DEFAULT_PROMETHEUS_URL})")
    parser.add_argument("--history-file", default=str(HISTORY_FILE),
                        help=f"Fichier JSON anti-doublon (défaut: {HISTORY_FILE})")
    args = parser.parse_args()

    history_path = Path(args.history_file)

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    print(
        f"[iface-saturation] {ts} | seuil={args.threshold:.0f}% | "
        f"Prometheus={args.prometheus_url}"
        + (" | DRY-RUN" if args.dry_run else "")
    )

    # Load + purge anti-doublon history
    history = load_json(history_path)
    if not isinstance(history, dict):
        history = {}
    history = purge_history(history, HISTORY_TTL_MINUTES)

    # ------------------------------------------------------------------
    # [1/3] Interface speeds
    # ------------------------------------------------------------------
    print(f"\n[1/3] Récupération vitesses nominales (ifHighSpeed)")
    speeds = get_iface_speeds(args.prometheus_url, args.verbose)
    if speeds is None:
        print("  INFO: Prometheus non joignable — arrêt gracieux")
        save_json(history_path, history)
        return
    print(f"  {len(speeds)} interface(s) avec vitesse connue")

    # ------------------------------------------------------------------
    # [2/3] Ingress traffic
    # ------------------------------------------------------------------
    print(f"\n[2/3] Trafic ingress : {QUERY_INGRESS}")
    ingress_traffic = get_iface_traffic(args.prometheus_url, QUERY_INGRESS, args.verbose)
    if ingress_traffic is None:
        print("  INFO: Prometheus non joignable — arrêt gracieux")
        save_json(history_path, history)
        return

    # [2b/3] Egress traffic
    print(f"\n[2b/3] Trafic egress : {QUERY_EGRESS}")
    egress_traffic = get_iface_traffic(args.prometheus_url, QUERY_EGRESS, args.verbose)
    if egress_traffic is None:
        egress_traffic = {}

    if not ingress_traffic and not egress_traffic:
        print("  INFO: aucune métrique SNMP disponible dans Prometheus — skip")
        save_json(history_path, history)
        return

    print(f"  {len(ingress_traffic)} interfaces ingress | {len(egress_traffic)} interfaces egress")

    # ------------------------------------------------------------------
    # [3/3] Evaluate
    # ------------------------------------------------------------------
    print(f"\n[3/3] Évaluation saturation (seuil={args.threshold:.0f}%)")
    all_alerts: list[dict] = []

    all_ifaces = set(ingress_traffic) | set(egress_traffic)
    for iface in sorted(all_ifaces):
        speed_bps = speeds.get(iface, DEFAULT_IFACE_SPEED_BPS)

        if ingress_traffic.get(iface) is not None:
            bps = ingress_traffic[iface]
            alert = evaluate_interface(iface, "ingress", bps, speed_bps, history, args)
            if alert:
                all_alerts.append(alert)

        if egress_traffic.get(iface) is not None:
            bps = egress_traffic[iface]
            alert = evaluate_interface(iface, "egress", bps, speed_bps, history, args)
            if alert:
                all_alerts.append(alert)

    # ------------------------------------------------------------------
    # Save history
    # ------------------------------------------------------------------
    if not args.dry_run:
        save_json(history_path, history)

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    print(f"\n[iface-saturation] Résumé : {len(all_alerts)} alerte(s) déclenchée(s)")
    if all_alerts:
        for a in all_alerts:
            print(f"  - {a['interface']} {a['direction']} [{a['severity'].upper()}] "
                  f"{a['pct']:.1f}% ({a['bps'] / 1e6:.0f} Mbps)")
    else:
        print("  Toutes les interfaces dans les seuils — aucune alerte.")


if __name__ == "__main__":
    main()
