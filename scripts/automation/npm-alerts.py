#!/usr/bin/env python3
"""
npm-alerts.py — NetWatch NPM Performance Alerting

Monitors RTT, retransmissions and ART HTTP from Elasticsearch (zeek-* conn.log)
and fires alerts when thresholds are exceeded.

Data source: ES zeek-* conn.log
  - conn.rtt              → RTT per connection (seconds, converted to ms)
  - conn.orig_retrans_pkts → retransmitted packets
  - conn.orig_pkts        → total original packets
  - art.log / http.log    → ART HTTP (graceful skip if unavailable)

Thresholds:
  RTT p95 > 150ms  → medium
  RTT p95 > 300ms  → high
  retrans ratio > 3%  → medium
  retrans ratio > 10% → critical
  ART HTTP p95 > 500ms → medium (art.log only, skip if missing)

Actions:
  - create-ticket.py (category: performance)
  - Teams Adaptive Card if severity >= high (TEAMS_WEBHOOK_URL env)

Anti-duplicate: npm-alerts-history.json TTL 1h per metric+threshold key
Alert log:      npm-perf-log.json (30-day rolling, read by daily-npm-report.py)

Usage:
    python3 npm-alerts.py [--dry-run] [--verbose] [--window-minutes 5]
                          [--es-url http://localhost:9200]
                          [--history-file npm-alerts-history.json]
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
SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent.parent
HISTORY_FILE = SCRIPT_DIR / "npm-alerts-history.json"
PERF_LOG_FILE = SCRIPT_DIR / "npm-perf-log.json"
CREATE_TICKET_SCRIPT = SCRIPT_DIR / "create-ticket.py"

DEFAULT_ES_URL = "http://localhost:9200"
DEFAULT_WINDOW_MINUTES = 5
HISTORY_TTL_HOURS = 1
PERF_LOG_RETENTION_DAYS = 30

# Thresholds
RTT_MEDIUM_MS = 150.0
RTT_HIGH_MS = 300.0
RETRANS_MEDIUM_PCT = 3.0
RETRANS_CRITICAL_PCT = 10.0
ART_HTTP_MEDIUM_MS = 500.0


# ---------------------------------------------------------------------------
# History / anti-duplicate management
# ---------------------------------------------------------------------------

def load_json_file(path: Path) -> dict | list:
    if not path.exists():
        return {}
    try:
        raw = path.read_text(encoding="utf-8")
        return json.loads(raw)
    except (json.JSONDecodeError, OSError):
        return {}


def save_json_file(path: Path, data: dict | list) -> None:
    try:
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except OSError as e:
        print(f"WARN: cannot write {path.name}: {e}", file=sys.stderr)


def purge_history(history: dict, ttl_hours: int) -> dict:
    """Remove anti-doublon entries older than TTL."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=ttl_hours)
    return {
        k: v for k, v in history.items()
        if datetime.fromisoformat(v.get("fired_at", "1970-01-01T00:00:00+00:00")) > cutoff
    }


def is_in_cooldown(key: str, history: dict, ttl_hours: int) -> bool:
    entry = history.get(key)
    if not entry:
        return False
    try:
        last_ts = datetime.fromisoformat(entry["fired_at"])
        cutoff = datetime.now(timezone.utc) - timedelta(hours=ttl_hours)
        return last_ts > cutoff
    except (KeyError, ValueError):
        return False


def record_alert_history(key: str, severity: str, value: float, history: dict) -> None:
    history[key] = {
        "fired_at": datetime.now(timezone.utc).isoformat(),
        "severity": severity,
        "value": value,
    }


def append_perf_log(metric: str, severity: str, value: float, description: str) -> None:
    """Append alert to rolling performance log (read by daily-npm-report.py)."""
    log: list = load_json_file(PERF_LOG_FILE) if PERF_LOG_FILE.exists() else []
    if not isinstance(log, list):
        log = []

    log.append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "metric": metric,
        "severity": severity,
        "value": value,
        "description": description,
    })

    # Keep only entries within retention window
    cutoff = datetime.now(timezone.utc) - timedelta(days=PERF_LOG_RETENTION_DAYS)
    log = [
        e for e in log
        if datetime.fromisoformat(e.get("timestamp", "1970-01-01T00:00:00+00:00")) > cutoff
    ]

    save_json_file(PERF_LOG_FILE, log)


# ---------------------------------------------------------------------------
# Elasticsearch helpers
# ---------------------------------------------------------------------------

def es_post(url: str, body: dict, verbose: bool = False) -> dict:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if verbose:
            print(f"DEBUG: ES HTTP {e.code} on {url}: {e.read()[:200]}", file=sys.stderr)
        return {}
    except (urllib.error.URLError, OSError) as e:
        if verbose:
            print(f"DEBUG: ES request error: {e}", file=sys.stderr)
        return {}


def index_has_field(es_url: str, pattern: str, field: str, window_minutes: int,
                    verbose: bool = False) -> bool:
    """Check if any docs exist in pattern with the given field in the window."""
    url = f"{es_url.rstrip('/')}/{pattern}/_count"
    body = {
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": f"now-{window_minutes}m", "lte": "now"}}},
                    {"exists": {"field": field}},
                ]
            }
        }
    }
    resp = es_post(url, body, verbose)
    return resp.get("count", 0) > 0


# ---------------------------------------------------------------------------
# Metric queries
# ---------------------------------------------------------------------------

def query_rtt_p95(es_url: str, window_minutes: int, verbose: bool) -> float | None:
    """
    Query RTT p95 from zeek-* conn.log (field: conn.rtt, in seconds).
    Returns value in milliseconds, or None if no data.
    """
    url = f"{es_url.rstrip('/')}/zeek-*/_search"
    body = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": f"now-{window_minutes}m", "lte": "now"}}},
                    {"exists": {"field": "conn.rtt"}},
                ]
            }
        },
        "aggs": {
            "rtt_p95": {
                "percentiles": {
                    "field": "conn.rtt",
                    "percents": [95],
                    "keyed": True,
                }
            },
        },
    }
    resp = es_post(url, body, verbose)
    hits_total = resp.get("hits", {}).get("total", {}).get("value", 0)
    if not hits_total:
        return None

    val = (
        resp.get("aggregations", {})
        .get("rtt_p95", {})
        .get("values", {})
        .get("95.0")
    )
    if val is None:
        return None
    # conn.rtt is in seconds → convert to ms
    return round(val * 1000.0, 2)


def query_retransmission_ratio(es_url: str, window_minutes: int, verbose: bool) -> float | None:
    """
    Query retransmission ratio from zeek-* conn.log.
    Ratio = sum(conn.orig_retrans_pkts) / sum(conn.orig_pkts) * 100.
    Returns percentage, or None if no packet data.
    """
    url = f"{es_url.rstrip('/')}/zeek-*/_search"
    body = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": f"now-{window_minutes}m", "lte": "now"}}},
                    {"exists": {"field": "conn.orig_pkts"}},
                    {"range": {"conn.orig_pkts": {"gt": 0}}},
                ]
            }
        },
        "aggs": {
            "total_orig_pkts": {"sum": {"field": "conn.orig_pkts"}},
            "total_retrans_pkts": {"sum": {"field": "conn.orig_retrans_pkts"}},
        },
    }
    resp = es_post(url, body, verbose)
    hits_total = resp.get("hits", {}).get("total", {}).get("value", 0)
    if not hits_total:
        return None

    aggs = resp.get("aggregations", {})
    total_pkts = aggs.get("total_orig_pkts", {}).get("value") or 0
    retrans_pkts = aggs.get("total_retrans_pkts", {}).get("value") or 0

    if total_pkts <= 0:
        return None
    return round((retrans_pkts / total_pkts) * 100.0, 3)


def query_art_http_p95(es_url: str, window_minutes: int, verbose: bool) -> float | None:
    """
    Query ART HTTP p95. Tries (in order):
      1. zeek-art-* index with field 'rtt' or 'art.rtt'
      2. zeek-* with field 'http.duration' (Zeek http.log, in seconds)
    Returns value in milliseconds, or None if no art data is available.
    """
    candidates = [
        ("zeek-art-*", "art.rtt"),
        ("zeek-art-*", "rtt"),
        ("zeek-*", "http.duration"),
    ]

    for pattern, field in candidates:
        if not index_has_field(es_url, pattern, field, window_minutes, verbose):
            if verbose:
                print(f"DEBUG: ART — no data in {pattern}/{field}", file=sys.stderr)
            continue

        url = f"{es_url.rstrip('/')}/{pattern}/_search"
        body = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": f"now-{window_minutes}m", "lte": "now"}}},
                        {"exists": {"field": field}},
                        {"range": {field: {"gt": 0}}},
                    ]
                }
            },
            "aggs": {
                "art_p95": {
                    "percentiles": {
                        "field": field,
                        "percents": [95],
                        "keyed": True,
                    }
                }
            },
        }
        resp = es_post(url, body, verbose)
        val = (
            resp.get("aggregations", {})
            .get("art_p95", {})
            .get("values", {})
            .get("95.0")
        )
        if val is None:
            continue

        # Convert to ms if value looks like seconds (< 100)
        val_ms = round(val * 1000.0, 2) if val < 100.0 else round(val, 2)
        if verbose:
            print(f"DEBUG: ART HTTP p95 from {pattern}/{field} = {val_ms}ms", file=sys.stderr)
        return val_ms

    return None


# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------

def action_create_ticket(metric: str, severity: str, value: float, description: str,
                          dry_run: bool, verbose: bool) -> bool:
    """Pipe performance alert JSON to create-ticket.py."""
    if not CREATE_TICKET_SCRIPT.exists():
        print(f"  [ticket] SKIP: {CREATE_TICKET_SCRIPT} introuvable", file=sys.stderr)
        return False

    severity_num = {"critical": 1, "high": 2, "medium": 3, "low": 4}.get(severity, 3)
    alert_json = json.dumps({
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip": "network",
        "dest_ip": "0.0.0.0",
        "alert": {
            "signature": f"NPM PERF — {description}",
            "severity": severity_num,
            "category": "performance",
        },
        "severity": severity,
        "engine": "npm-alerts",
        "npm": {
            "metric": metric,
            "value": value,
            "category": "performance",
        },
    })

    if dry_run:
        print(f"  [DRY-RUN] create-ticket: {description} (severity={severity})")
        if verbose:
            print(f"  [DRY-RUN] json payload ready")
        return True

    try:
        result = subprocess.run(
            [sys.executable, str(CREATE_TICKET_SCRIPT)],
            input=alert_json,
            capture_output=True,
            text=True,
            timeout=30,
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


def action_teams(severity: str, metric: str, description: str,
                  dry_run: bool, verbose: bool) -> bool:
    """
    POST Teams Adaptive Card alert (only called when severity >= high).
    Gracefully skips if TEAMS_WEBHOOK_URL is not set.
    """
    webhook_url = os.environ.get("TEAMS_WEBHOOK_URL", "").strip()
    if not webhook_url:
        if verbose:
            print("  [teams] TEAMS_WEBHOOK_URL non définie — skip")
        return True  # not a failure

    color = "Attention" if severity == "critical" else "Warning"
    emoji = "\U0001f6a8" if severity == "critical" else "⚠️"

    payload = {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": [
                        {
                            "type": "TextBlock",
                            "text": f"{emoji} NPM Alert [{severity.upper()}] — {description}",
                            "size": "Large",
                            "weight": "Bolder",
                            "color": color,
                            "wrap": True,
                        },
                        {
                            "type": "FactSet",
                            "facts": [
                                {"title": "Métrique", "value": metric},
                                {"title": "Sévérité", "value": severity.upper()},
                                {
                                    "title": "Horodatage",
                                    "value": datetime.now(timezone.utc).strftime(
                                        "%Y-%m-%d %H:%M:%S UTC"
                                    ),
                                },
                            ],
                        },
                    ],
                    "actions": [
                        {
                            "type": "Action.OpenUrl",
                            "title": "Ouvrir NetWatch",
                            "url": "http://localhost:5050/alerts",
                        }
                    ],
                },
            }
        ],
    }

    if dry_run:
        print(f"  [DRY-RUN] POST Teams card ({severity}): {description}")
        return True

    try:
        body = json.dumps(payload).encode()
        req = urllib.request.Request(
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

def fire_alert(metric_key: str, severity: str, value: float, description: str,
               history: dict, args) -> bool:
    """
    Check cooldown, fire actions, record in history and perf log.
    Returns True if alert was fired (not in cooldown).
    """
    if is_in_cooldown(metric_key, history, HISTORY_TTL_HOURS):
        if args.verbose:
            print(f"  SKIP (cooldown {HISTORY_TTL_HOURS}h): {metric_key}")
        return False

    print(f"  ALERTE [{severity.upper()}] {description}")

    # Action 1: create ticket
    action_create_ticket(
        metric_key, severity, value, description, args.dry_run, args.verbose
    )

    # Action 2: Teams (only if severity >= high)
    if severity in ("high", "critical"):
        action_teams(severity, metric_key, description, args.dry_run, args.verbose)

    # Record in anti-doublon history
    record_alert_history(metric_key, severity, value, history)

    # Append to rolling performance log (for daily report)
    if not args.dry_run:
        append_perf_log(metric_key, severity, value, description)

    return True


def evaluate_rtt(rtt_ms: float, history: dict, args) -> list[dict]:
    alerts = []
    if rtt_ms > RTT_HIGH_MS:
        desc = f"RTT p95 = {rtt_ms:.1f}ms (seuil high: >{RTT_HIGH_MS:.0f}ms)"
        if fire_alert("rtt_high", "high", rtt_ms, desc, history, args):
            alerts.append({"metric": "rtt", "severity": "high", "value_ms": rtt_ms})
    elif rtt_ms > RTT_MEDIUM_MS:
        desc = f"RTT p95 = {rtt_ms:.1f}ms (seuil medium: >{RTT_MEDIUM_MS:.0f}ms)"
        if fire_alert("rtt_medium", "medium", rtt_ms, desc, history, args):
            alerts.append({"metric": "rtt", "severity": "medium", "value_ms": rtt_ms})
    else:
        if args.verbose:
            print(f"  RTT p95 OK : {rtt_ms:.1f}ms (< {RTT_MEDIUM_MS:.0f}ms)")
    return alerts


def evaluate_retransmissions(ratio_pct: float, history: dict, args) -> list[dict]:
    alerts = []
    if ratio_pct > RETRANS_CRITICAL_PCT:
        desc = f"Retransmissions = {ratio_pct:.2f}% (seuil critical: >{RETRANS_CRITICAL_PCT:.0f}%)"
        if fire_alert("retrans_critical", "critical", ratio_pct, desc, history, args):
            alerts.append({"metric": "retransmissions", "severity": "critical", "value_pct": ratio_pct})
    elif ratio_pct > RETRANS_MEDIUM_PCT:
        desc = f"Retransmissions = {ratio_pct:.2f}% (seuil medium: >{RETRANS_MEDIUM_PCT:.0f}%)"
        if fire_alert("retrans_medium", "medium", ratio_pct, desc, history, args):
            alerts.append({"metric": "retransmissions", "severity": "medium", "value_pct": ratio_pct})
    else:
        if args.verbose:
            print(f"  Retransmissions OK : {ratio_pct:.3f}% (< {RETRANS_MEDIUM_PCT:.0f}%)")
    return alerts


def evaluate_art_http(art_ms: float, history: dict, args) -> list[dict]:
    alerts = []
    if art_ms > ART_HTTP_MEDIUM_MS:
        desc = f"ART HTTP p95 = {art_ms:.1f}ms (seuil: >{ART_HTTP_MEDIUM_MS:.0f}ms)"
        if fire_alert("art_http_medium", "medium", art_ms, desc, history, args):
            alerts.append({"metric": "art_http", "severity": "medium", "value_ms": art_ms})
    else:
        if args.verbose:
            print(f"  ART HTTP p95 OK : {art_ms:.1f}ms (< {ART_HTTP_MEDIUM_MS:.0f}ms)")
    return alerts


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="NetWatch NPM Performance Alerting — surveille RTT, retransmissions et ART."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simuler sans créer de tickets ni envoyer vers Teams",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Afficher les détails de chaque étape",
    )
    parser.add_argument(
        "--window-minutes",
        type=int,
        default=DEFAULT_WINDOW_MINUTES,
        metavar="N",
        help=f"Fenêtre d'analyse en minutes (défaut: {DEFAULT_WINDOW_MINUTES})",
    )
    parser.add_argument(
        "--es-url",
        default=os.environ.get("ES_URL", DEFAULT_ES_URL),
        help=f"URL Elasticsearch (défaut: {DEFAULT_ES_URL})",
    )
    parser.add_argument(
        "--history-file",
        default=str(HISTORY_FILE),
        help=f"Fichier JSON anti-doublon (défaut: {HISTORY_FILE})",
    )
    args = parser.parse_args()

    global HISTORY_FILE
    HISTORY_FILE = Path(args.history_file)

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    print(
        f"[npm-alerts] {ts} | fenêtre={args.window_minutes}min | ES={args.es_url}"
        + (" | DRY-RUN" if args.dry_run else "")
    )

    # Load + purge anti-doublon history
    history = load_json_file(HISTORY_FILE) if isinstance(load_json_file(HISTORY_FILE), dict) else {}
    history = purge_history(history, HISTORY_TTL_HOURS)

    all_alerts: list[dict] = []

    # ------------------------------------------------------------------
    # [1/3] RTT
    # ------------------------------------------------------------------
    print(f"\n[1/3] RTT zeek-*/conn.rtt (fenêtre {args.window_minutes}min)")
    rtt_ms = query_rtt_p95(args.es_url, args.window_minutes, args.verbose)
    if rtt_ms is None:
        print("  WARN: aucune donnée RTT (zeek-* conn.rtt) dans la fenêtre — skip")
    else:
        print(f"  RTT p95 = {rtt_ms:.1f}ms")
        all_alerts.extend(evaluate_rtt(rtt_ms, history, args))

    # ------------------------------------------------------------------
    # [2/3] Retransmissions
    # ------------------------------------------------------------------
    print(f"\n[2/3] Retransmissions zeek-*/conn.orig_retrans_pkts (fenêtre {args.window_minutes}min)")
    retrans_pct = query_retransmission_ratio(args.es_url, args.window_minutes, args.verbose)
    if retrans_pct is None:
        print("  WARN: aucune donnée retransmissions (zeek-* conn.orig_pkts) — skip")
    else:
        print(f"  Ratio retransmissions = {retrans_pct:.3f}%")
        all_alerts.extend(evaluate_retransmissions(retrans_pct, history, args))

    # ------------------------------------------------------------------
    # [3/3] ART HTTP
    # ------------------------------------------------------------------
    print(f"\n[3/3] ART HTTP (art.log ou http.log, fenêtre {args.window_minutes}min)")
    art_ms = query_art_http_p95(args.es_url, args.window_minutes, args.verbose)
    if art_ms is None:
        print("  INFO: ART HTTP non disponible (art.log non indexé) — skip gracieux")
    else:
        print(f"  ART HTTP p95 = {art_ms:.1f}ms")
        all_alerts.extend(evaluate_art_http(art_ms, history, args))

    # ------------------------------------------------------------------
    # Save history
    # ------------------------------------------------------------------
    save_json_file(HISTORY_FILE, history)

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    print(f"\n[npm-alerts] Résumé : {len(all_alerts)} alerte(s) déclenchée(s)")
    if all_alerts:
        for a in all_alerts:
            val_str = (
                f"{a.get('value_ms', a.get('value_pct', '?'))}"
                + ("ms" if "value_ms" in a else "%")
            )
            print(f"  - {a['metric']} [{a['severity'].upper()}] = {val_str}")
    else:
        print("  Toutes les métriques dans les seuils — aucune alerte.")


if __name__ == "__main__":
    main()
