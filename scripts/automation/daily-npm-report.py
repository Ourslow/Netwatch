#!/usr/bin/env python3
"""
daily-npm-report.py — NetWatch Daily NPM Performance Report

Generates a structured daily NPM report from Elasticsearch data.

Data sources (graceful fallback if unavailable):
  - Top 5 talkers  : netflow-* bytes  →  zeek-* conn.orig_bytes (fallback)
  - RTT p95        : zeek-* conn.rtt (seconds → ms)
  - ART HTTP p95   : zeek-art-* rtt  →  zeek-* http.duration (fallback)
  - DNS p95        : zeek-* dns.rtt (seconds → ms)
  - Total bytes    : zeek-* conn.orig_bytes + conn.resp_bytes
  - J-1 comparison : same queries for [days, 2*days] window (best-effort)
  - Perf alerts    : npm-perf-log.json entries in window

Output JSON schema:
  {
    "date": "YYYY-MM-DD",
    "generated_at": "ISO8601",
    "window_hours": int,
    "top_talkers": [{"ip": str, "bytes": int, "source": str}, ...],   # top 5
    "rtt_p95_ms": float | null,
    "art_http_p95_ms": float | null,
    "dns_p95_ms": float | null,
    "total_bytes": int,
    "yesterday_total_bytes": int | null,
    "bytes_variation_pct": float | null,
    "perf_alerts": {"total": int, "critical": int, "high": int, "medium": int},
    "data_sources": {"top_talkers": str, "art_http": str | null}
  }

Usage:
    python3 daily-npm-report.py [--days 1] [--output FILE] [--no-color]
                                [--es-url http://localhost:9200]
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent.parent
PERF_LOG_FILE = SCRIPT_DIR / "npm-perf-log.json"
REPORTS_DIR = REPO_ROOT / "reports"

DEFAULT_ES_URL = "http://localhost:9200"
DEFAULT_DAYS = 1

# ANSI color codes
C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_GREEN = "\033[92m"
C_YELLOW = "\033[93m"
C_RED = "\033[91m"
C_CYAN = "\033[96m"
C_GREY = "\033[90m"


# ---------------------------------------------------------------------------
# Elasticsearch helpers
# ---------------------------------------------------------------------------

def es_post(url: str, body: dict, verbose: bool = False) -> dict:
    import urllib.request
    import urllib.error

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
    except Exception as e:
        if verbose:
            print(f"DEBUG: ES error on {url}: {e}", file=sys.stderr)
        return {}


def index_has_data(es_url: str, pattern: str, gte: str, lte: str,
                   field: str | None = None, verbose: bool = False) -> bool:
    """Check if an index pattern has any docs in the time range."""
    import urllib.request
    url = f"{es_url.rstrip('/')}/{pattern}/_count"
    must_clauses = [{"range": {"@timestamp": {"gte": gte, "lte": lte}}}]
    if field:
        must_clauses.append({"exists": {"field": field}})
    body = {"query": {"bool": {"must": must_clauses}}}
    try:
        data = json.dumps(body).encode()
        req = urllib.request.Request(
            url, data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            result = json.loads(resp.read().decode())
            return result.get("count", 0) > 0
    except Exception as e:
        if verbose:
            print(f"DEBUG: index_has_data({pattern}) error: {e}", file=sys.stderr)
        return False


# ---------------------------------------------------------------------------
# Data queries
# ---------------------------------------------------------------------------

def query_top_talkers(es_url: str, gte: str, lte: str, size: int = 5,
                      verbose: bool = False) -> tuple[list[dict], str]:
    """
    Top N talkers by bytes transferred.
    Tries netflow-* bytes first, falls back to zeek-* conn.orig_bytes.
    Returns (list of {ip, bytes}, source_label).
    """
    sources = [
        ("netflow-*", "src_ip.keyword", "bytes", "netflow"),
        ("zeek-*", "src_ip.keyword", "conn.orig_bytes", "zeek-conn"),
    ]

    for pattern, ip_field, bytes_field, label in sources:
        if not index_has_data(es_url, pattern, gte, lte, bytes_field, verbose):
            if verbose:
                print(f"DEBUG: top_talkers — no data in {pattern}/{bytes_field}", file=sys.stderr)
            continue

        url = f"{es_url.rstrip('/')}/{pattern}/_search"
        body = {
            "size": 0,
            "query": {"bool": {"must": [
                {"range": {"@timestamp": {"gte": gte, "lte": lte}}},
                {"exists": {"field": bytes_field}},
            ]}},
            "aggs": {
                "top_ips": {
                    "terms": {"field": ip_field, "size": size},
                    "aggs": {
                        "total_bytes": {"sum": {"field": bytes_field}},
                    },
                }
            },
        }
        resp = es_post(url, body, verbose)
        buckets = resp.get("aggregations", {}).get("top_ips", {}).get("buckets", [])
        if not buckets:
            continue

        result = [
            {
                "ip": b.get("key", ""),
                "bytes": int(b.get("total_bytes", {}).get("value", 0) or 0),
                "source": label,
            }
            for b in buckets
        ]
        result.sort(key=lambda x: x["bytes"], reverse=True)
        if verbose:
            print(f"DEBUG: top_talkers from {pattern}/{bytes_field} ({len(result)} IPs)", file=sys.stderr)
        return result[:size], label

    return [], "unavailable"


def query_percentile(es_url: str, pattern: str, field: str, gte: str, lte: str,
                     pct: float = 95.0, to_ms: bool = False,
                     verbose: bool = False) -> float | None:
    """
    Generic p95 percentile query. Returns value (optionally converted to ms).
    Returns None if no data.
    """
    if not index_has_data(es_url, pattern, gte, lte, field, verbose):
        return None

    url = f"{es_url.rstrip('/')}/{pattern}/_search"
    body = {
        "size": 0,
        "query": {"bool": {"must": [
            {"range": {"@timestamp": {"gte": gte, "lte": lte}}},
            {"exists": {"field": field}},
            {"range": {field: {"gt": 0}}},
        ]}},
        "aggs": {
            "pct": {
                "percentiles": {
                    "field": field,
                    "percents": [pct],
                    "keyed": True,
                }
            }
        },
    }
    resp = es_post(url, body, verbose)
    val = resp.get("aggregations", {}).get("pct", {}).get("values", {}).get(f"{pct}")
    if val is None:
        return None
    if to_ms:
        # Convert seconds → ms if value looks like seconds (< 100)
        val = val * 1000.0 if val < 100.0 else val
    return round(val, 2)


def query_rtt_p95(es_url: str, gte: str, lte: str, verbose: bool) -> float | None:
    """RTT p95 from zeek-* conn.rtt (seconds → ms)."""
    return query_percentile(es_url, "zeek-*", "conn.rtt", gte, lte,
                            to_ms=True, verbose=verbose)


def query_art_http_p95(es_url: str, gte: str, lte: str,
                       verbose: bool) -> tuple[float | None, str | None]:
    """
    ART HTTP p95. Tries art.log then http.log fallback.
    Returns (value_ms, source_label) or (None, None).
    """
    candidates = [
        ("zeek-art-*", "art.rtt", True),
        ("zeek-art-*", "rtt", True),
        ("zeek-*", "http.duration", True),
    ]
    for pattern, field, to_ms in candidates:
        val = query_percentile(es_url, pattern, field, gte, lte, to_ms=to_ms, verbose=verbose)
        if val is not None:
            label = "art.log" if "art" in pattern else f"http.log ({field})"
            if verbose:
                print(f"DEBUG: ART HTTP p95 from {pattern}/{field} = {val}ms", file=sys.stderr)
            return val, label
    return None, None


def query_dns_p95(es_url: str, gte: str, lte: str, verbose: bool) -> float | None:
    """DNS p95 from zeek-* dns.rtt (seconds → ms)."""
    for field in ("dns.rtt", "rtt"):
        if not index_has_data(es_url, "zeek-*", gte, lte, field, verbose):
            continue
        # Filter to DNS log type if possible
        url = f"{es_url.rstrip('/')}/zeek-*/_search"
        body = {
            "size": 0,
            "query": {"bool": {"must": [
                {"range": {"@timestamp": {"gte": gte, "lte": lte}}},
                {"exists": {"field": field}},
                {"range": {field: {"gt": 0}}},
            ]}},
            "aggs": {
                "dns_pct": {
                    "percentiles": {
                        "field": field,
                        "percents": [95],
                        "keyed": True,
                    }
                }
            },
        }
        resp = es_post(url, body, verbose)
        val = resp.get("aggregations", {}).get("dns_pct", {}).get("values", {}).get("95.0")
        if val is not None:
            val_ms = val * 1000.0 if val < 100.0 else val
            return round(val_ms, 2)
    return None


def query_total_bytes(es_url: str, gte: str, lte: str, verbose: bool) -> int:
    """Total bytes transferred (orig + resp) from zeek-* conn.log."""
    url = f"{es_url.rstrip('/')}/zeek-*/_search"
    body = {
        "size": 0,
        "query": {"bool": {"must": [
            {"range": {"@timestamp": {"gte": gte, "lte": lte}}},
        ]}},
        "aggs": {
            "orig_bytes": {"sum": {"field": "conn.orig_bytes"}},
            "resp_bytes": {"sum": {"field": "conn.resp_bytes"}},
        },
    }
    resp = es_post(url, body, verbose)
    aggs = resp.get("aggregations", {})
    orig = aggs.get("orig_bytes", {}).get("value") or 0
    resp_b = aggs.get("resp_bytes", {}).get("value") or 0

    # Fallback: try netflow-* bytes
    if orig == 0 and resp_b == 0:
        url2 = f"{es_url.rstrip('/')}/netflow-*/_search"
        body2 = {
            "size": 0,
            "query": {"bool": {"must": [
                {"range": {"@timestamp": {"gte": gte, "lte": lte}}}
            ]}},
            "aggs": {"total_bytes": {"sum": {"field": "bytes"}}},
        }
        resp2 = es_post(url2, body2, verbose)
        total = resp2.get("aggregations", {}).get("total_bytes", {}).get("value") or 0
        return int(total)

    return int(orig + resp_b)


# ---------------------------------------------------------------------------
# Performance alert count
# ---------------------------------------------------------------------------

def count_perf_alerts(gte_dt: datetime, verbose: bool = False) -> dict:
    """
    Count performance alerts from npm-perf-log.json within the time window.
    Returns {"total": N, "critical": N, "high": N, "medium": N}.
    """
    counts = {"total": 0, "critical": 0, "high": 0, "medium": 0}

    if not PERF_LOG_FILE.exists():
        if verbose:
            print(f"DEBUG: {PERF_LOG_FILE} not found — alert count = 0", file=sys.stderr)
        return counts

    try:
        raw = PERF_LOG_FILE.read_text(encoding="utf-8")
        log: list = json.loads(raw)
    except (json.JSONDecodeError, OSError) as e:
        if verbose:
            print(f"DEBUG: cannot read perf log: {e}", file=sys.stderr)
        return counts

    if not isinstance(log, list):
        return counts

    for entry in log:
        try:
            ts = datetime.fromisoformat(entry.get("timestamp", "1970-01-01T00:00:00+00:00"))
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            if ts >= gte_dt:
                counts["total"] += 1
                sev = entry.get("severity", "medium")
                if sev in counts:
                    counts[sev] += 1
        except (ValueError, TypeError):
            continue

    return counts


# ---------------------------------------------------------------------------
# Report building
# ---------------------------------------------------------------------------

def build_report(es_url: str, days: int, verbose: bool = False) -> dict:
    now = datetime.now(timezone.utc)
    gte_dt = now - timedelta(days=days)
    gte = gte_dt.isoformat()
    lte = now.isoformat()

    # Yesterday window for J-1 comparison
    gte_prev_dt = now - timedelta(days=days * 2)
    gte_prev = gte_prev_dt.isoformat()
    lte_prev = gte  # end of yesterday = start of today

    # --- Top talkers ---
    top_talkers, talkers_source = query_top_talkers(es_url, gte, lte, size=5, verbose=verbose)

    # --- RTT p95 ---
    rtt_p95 = query_rtt_p95(es_url, gte, lte, verbose)

    # --- ART HTTP p95 ---
    art_http_p95, art_source = query_art_http_p95(es_url, gte, lte, verbose)

    # --- DNS p95 ---
    dns_p95 = query_dns_p95(es_url, gte, lte, verbose)

    # --- Total bytes ---
    total_bytes = query_total_bytes(es_url, gte, lte, verbose)

    # --- J-1 comparison (best-effort) ---
    yesterday_bytes: int | None = None
    bytes_variation_pct: float | None = None
    try:
        y_bytes = query_total_bytes(es_url, gte_prev, lte_prev, verbose)
        if y_bytes > 0:
            yesterday_bytes = y_bytes
            if total_bytes > 0:
                bytes_variation_pct = round(
                    ((total_bytes - y_bytes) / y_bytes) * 100.0, 1
                )
    except Exception as e:
        if verbose:
            print(f"DEBUG: J-1 comparison error: {e}", file=sys.stderr)

    # --- Performance alerts ---
    perf_alerts = count_perf_alerts(gte_dt, verbose)

    return {
        "date": now.strftime("%Y-%m-%d"),
        "generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "window_hours": days * 24,
        "top_talkers": top_talkers,
        "rtt_p95_ms": rtt_p95,
        "art_http_p95_ms": art_http_p95,
        "dns_p95_ms": dns_p95,
        "total_bytes": total_bytes,
        "yesterday_total_bytes": yesterday_bytes,
        "bytes_variation_pct": bytes_variation_pct,
        "perf_alerts": perf_alerts,
        "data_sources": {
            "top_talkers": talkers_source,
            "art_http": art_source,
        },
    }


# ---------------------------------------------------------------------------
# Console output
# ---------------------------------------------------------------------------

def colorize(text: str, color: str, use_color: bool) -> str:
    return f"{color}{text}{C_RESET}" if use_color else text


def fmt_bytes(b: int) -> str:
    """Human-readable byte size."""
    if b >= 1_000_000_000:
        return f"{b / 1_000_000_000:.2f} GB"
    if b >= 1_000_000:
        return f"{b / 1_000_000:.1f} MB"
    if b >= 1_000:
        return f"{b / 1_000:.1f} KB"
    return f"{b} B"


def rtt_icon(val_ms: float | None, use_color: bool) -> str:
    """Return colored status icon for RTT values."""
    if val_ms is None:
        return colorize("N/A", C_GREY, use_color)
    if val_ms > 300:
        return f"{colorize(f'{val_ms:.0f}ms', C_RED, use_color)} {colorize('[✗]', C_RED, use_color)}"
    if val_ms > 150:
        return f"{colorize(f'{val_ms:.0f}ms', C_YELLOW, use_color)} {colorize('[⚠]', C_YELLOW, use_color)}"
    return f"{colorize(f'{val_ms:.0f}ms', C_GREEN, use_color)} {colorize('[✓]', C_GREEN, use_color)}"


def art_icon(val_ms: float | None, use_color: bool) -> str:
    """Return colored status icon for ART values."""
    if val_ms is None:
        return colorize("N/A", C_GREY, use_color)
    if val_ms > 500:
        return f"{colorize(f'{val_ms:.0f}ms', C_YELLOW, use_color)} {colorize('[⚠]', C_YELLOW, use_color)}"
    return f"{colorize(f'{val_ms:.0f}ms', C_GREEN, use_color)} {colorize('[✓]', C_GREEN, use_color)}"


def print_console_summary(report: dict, use_color: bool = True) -> None:
    uc = use_color
    date_str = datetime.strptime(report["date"], "%Y-%m-%d").strftime("%d/%m/%Y")

    print()
    print(colorize(f"{'='*54}", C_CYAN, uc))
    print(colorize(f"  📊 Rapport NPM — {date_str}", C_BOLD, uc))
    print(colorize(f"{'='*54}", C_CYAN, uc))

    # Top talker
    talkers = report.get("top_talkers", [])
    if talkers:
        top = talkers[0]
        ip_str = colorize(top["ip"], C_BOLD, uc)
        bytes_str = colorize(fmt_bytes(top["bytes"]), C_CYAN, uc)
        print(f"  Top talker     : {ip_str} ({bytes_str})")
    else:
        print(f"  Top talker     : {colorize('N/A', C_GREY, uc)}")

    # Total bytes
    total = report.get("total_bytes", 0)
    var_str = ""
    var_pct = report.get("bytes_variation_pct")
    if var_pct is not None:
        sign = "+" if var_pct >= 0 else ""
        var_color = C_RED if var_pct > 20 else C_YELLOW if var_pct > 0 else C_GREEN
        var_str = f"  ({colorize(f'{sign}{var_pct:.1f}% vs J-1', var_color, uc)})"
    print(f"  Volume total   : {colorize(fmt_bytes(total), C_CYAN, uc)}{var_str}")

    # RTT p95
    print(f"  RTT p95        : {rtt_icon(report.get('rtt_p95_ms'), uc)}")

    # ART HTTP p95
    print(f"  ART HTTP p95   : {art_icon(report.get('art_http_p95_ms'), uc)}")

    # DNS p95
    dns = report.get("dns_p95_ms")
    if dns is not None:
        print(f"  DNS p95        : {colorize(f'{dns:.0f}ms', C_CYAN, uc)}")

    # Performance alerts
    pa = report.get("perf_alerts", {})
    total_alerts = pa.get("total", 0)
    crit = pa.get("critical", 0)
    high = pa.get("high", 0)
    med = pa.get("medium", 0)
    alert_color = C_RED if crit > 0 else C_YELLOW if high > 0 else C_GREEN
    detail = f"({crit} critical, {high} high, {med} medium)"
    print(
        f"  Alertes perf   : {colorize(str(total_alerts), alert_color, uc)}"
        + f" {colorize(detail, C_GREY, uc)}"
    )

    print(colorize(f"{'='*54}", C_CYAN, uc))
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="NetWatch Daily NPM Report — agrège les métriques réseau depuis Elasticsearch."
    )
    parser.add_argument(
        "--days",
        type=int,
        default=DEFAULT_DAYS,
        metavar="N",
        help=f"Fenêtre en jours (défaut: {DEFAULT_DAYS})",
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        metavar="FILE",
        help="Fichier JSON de sortie (défaut: reports/npm-YYYY-MM-DD.json)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Désactiver les couleurs ANSI dans la console",
    )
    parser.add_argument(
        "--es-url",
        default=os.environ.get("ES_URL", DEFAULT_ES_URL),
        help=f"URL Elasticsearch (défaut: {DEFAULT_ES_URL})",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Afficher les détails des requêtes ES",
    )
    args = parser.parse_args()

    use_color = not args.no_color and sys.stdout.isatty()

    print(
        f"[daily-npm-report] génération rapport {args.days}j | ES={args.es_url}",
        file=sys.stderr,
    )

    report = build_report(args.es_url, args.days, args.verbose)

    # --- Determine output path ---
    if args.output:
        output_path = Path(args.output)
    else:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        date_str = report["date"]
        output_path = REPORTS_DIR / f"npm-{date_str}.json"

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[daily-npm-report] rapport écrit → {output_path}", file=sys.stderr)

    # --- Console summary ---
    print_console_summary(report, use_color=use_color)

    # --- Stdout JSON (for n8n / piping) ---
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
