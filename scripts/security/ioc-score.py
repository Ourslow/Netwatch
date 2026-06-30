#!/usr/bin/env python3
"""
NetWatch — IOC Composite Risk Scorer
T_014 — Score de risque composite IOC par IP

Queries Elasticsearch for Suricata, Snort and Zeek alerts over the last N days,
computes a 0-100 composite risk score per source IP and outputs sorted JSON.

Score formula:
    raw = nb_alerts*1 + severity_sum + distinct_engines*15 + abuse_score/10 + unique_mitre*8
    score = min(raw, 100)

Severity weights:
    Suricata: severity 1 (critical)=10, 2 (high)=5, 3 (medium)=2, 4 (low)=1
    Snort:    priority 1 (high)=5, 2 (medium)=2, 3 (low)=1
    Zeek:     any alert event = 2 (medium)

Risk levels:
    critical  >= 80
    high      >= 60
    medium    >= 40
    low        < 40

Usage:
    python3 ioc-score.py [--days 1] [--output scores.json] [--threshold 0]
    python3 ioc-score.py --days 7 --output /tmp/scores.json --threshold 40
    python3 ioc-score.py --es-url http://localhost:9200 --days 1
"""

import argparse
import json
import logging
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

try:
    from elasticsearch import Elasticsearch
    ES_AVAILABLE = True
except ImportError:
    ES_AVAILABLE = False

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("ioc-score")

# ---------------------------------------------------------------------------
# Demo data (fallback when ES is empty or unreachable)
# ---------------------------------------------------------------------------
DEMO_HITS = [
    # Suricata — severity 1 (critical)
    {"engine": "suricata", "src_ip": "185.220.101.46", "severity": 1,
     "signature": "ET TOR Known Tor Exit Node Traffic", "mitre": "T1090"},
    {"engine": "suricata", "src_ip": "185.220.101.46", "severity": 1,
     "signature": "ET TOR Known Tor Exit Node Traffic", "mitre": "T1090"},
    {"engine": "suricata", "src_ip": "185.220.101.46", "severity": 2,
     "signature": "ET TROJAN Metasploit Meterpreter", "mitre": "T1573"},
    # Suricata — severity 2 (high)
    {"engine": "suricata", "src_ip": "10.0.0.55", "severity": 2,
     "signature": "ET SCAN Rapid SYN Scan", "mitre": "T1595"},
    {"engine": "suricata", "src_ip": "10.0.0.55", "severity": 3,
     "signature": "ET DNS Query Malware Domain", "mitre": "T1071"},
    # Snort — priority 1 (high)
    {"engine": "snort", "src_ip": "10.0.0.55", "severity": 1,
     "signature": "NETWATCH - ICMP Ping Sweep", "mitre": None},
    {"engine": "snort", "src_ip": "185.220.101.46", "severity": 1,
     "signature": "INDICATOR-SHELLCODE x86 setuid 0", "mitre": None},
    # Zeek — medium
    {"engine": "zeek", "src_ip": "172.16.0.99", "severity": 3,
     "signature": "zeek:notice", "mitre": None},
    {"engine": "zeek", "src_ip": "10.0.0.55", "severity": 3,
     "signature": "zeek:weird", "mitre": None},
    # Low-risk IP
    {"engine": "suricata", "src_ip": "203.0.113.42", "severity": 4,
     "signature": "ET POLICY Cleartext Password", "mitre": "T1552"},
]

# ---------------------------------------------------------------------------
# Scoring constants
# ---------------------------------------------------------------------------
SURICATA_SEVERITY_WEIGHT = {1: 10, 2: 5, 3: 2, 4: 1}
SNORT_PRIORITY_WEIGHT    = {1: 5, 2: 2, 3: 1}
ZEEK_WEIGHT              = 2  # always medium
ENGINE_BONUS             = 15  # per distinct engine


def _sev_weight(engine: str, severity: int) -> int:
    """Return the severity weight for a given engine and severity/priority value."""
    if engine == "suricata":
        return SURICATA_SEVERITY_WEIGHT.get(severity, 1)
    if engine == "snort":
        return SNORT_PRIORITY_WEIGHT.get(severity, 1)
    return ZEEK_WEIGHT  # zeek


def level_from_score(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# Elasticsearch queries
# ---------------------------------------------------------------------------

def _time_filter(days: int) -> dict:
    return {"range": {"@timestamp": {"gte": f"now-{days}d/d", "lte": "now"}}}


def fetch_suricata(es: "Elasticsearch", days: int, size: int = 2000) -> list[dict]:
    """Fetch Suricata alerts from ES."""
    query = {
        "size": size,
        "query": {
            "bool": {
                "filter": [
                    _time_filter(days),
                    {"exists": {"field": "alert.signature"}},
                ]
            }
        },
        "_source": [
            "src_ip",
            "alert.severity",
            "alert.signature",
            "alert.metadata.mitre_technique_id",
            "alert.metadata.mitre_tactic_name",
        ],
    }
    try:
        resp = es.search(index="suricata-*", body=query)
        hits = []
        for h in resp["hits"]["hits"]:
            s = h["_source"]
            alert = s.get("alert", {})
            meta = alert.get("metadata", {})
            tech_raw = meta.get("mitre_technique_id", [])
            technique = (
                tech_raw[0] if isinstance(tech_raw, list) and tech_raw
                else (tech_raw or None)
            )
            hits.append({
                "engine": "suricata",
                "src_ip": s.get("src_ip"),
                "severity": int(alert.get("severity", 3)),
                "signature": alert.get("signature", ""),
                "mitre": technique,
            })
        log.info("Suricata: %d alerts fetched", len(hits))
        return hits
    except Exception as exc:
        log.warning("suricata-* query failed: %s", exc)
        return []


def fetch_snort(es: "Elasticsearch", days: int, size: int = 2000) -> list[dict]:
    """Fetch Snort alerts from ES."""
    query = {
        "size": size,
        "query": {
            "bool": {
                "filter": [
                    _time_filter(days),
                    {"exists": {"field": "msg"}},
                ]
            }
        },
        "_source": ["src_ip", "priority", "msg"],
    }
    try:
        resp = es.search(index="snort-*", body=query)
        hits = []
        for h in resp["hits"]["hits"]:
            s = h["_source"]
            src = s.get("src_ip")
            if not src:
                continue
            hits.append({
                "engine": "snort",
                "src_ip": src,
                "severity": int(s.get("priority", 2)),
                "signature": s.get("msg", ""),
                "mitre": None,
            })
        log.info("Snort: %d alerts fetched", len(hits))
        return hits
    except Exception as exc:
        log.warning("snort-* query failed: %s", exc)
        return []


def fetch_zeek(es: "Elasticsearch", days: int, size: int = 2000) -> list[dict]:
    """Fetch Zeek alert-like events (notice/weird/intel) from ES."""
    query = {
        "size": size,
        "query": {
            "bool": {
                "filter": [
                    _time_filter(days),
                    {"exists": {"field": "id.orig_h"}},
                    {"terms": {"log_type.keyword": ["notice", "weird", "intel"]}},
                ]
            }
        },
        "_source": ["id.orig_h", "log_type", "note", "name", "msg"],
    }
    try:
        resp = es.search(index="zeek-*", body=query)
        hits = []
        for h in resp["hits"]["hits"]:
            s = h["_source"]
            src = s.get("id", {}).get("orig_h") or s.get("id.orig_h")
            if not src:
                continue
            log_type = s.get("log_type", "notice")
            sig = s.get("note") or s.get("name") or s.get("msg") or f"zeek:{log_type}"
            hits.append({
                "engine": "zeek",
                "src_ip": src,
                "severity": 3,   # always medium
                "signature": sig,
                "mitre": None,
            })
        log.info("Zeek: %d alert events fetched", len(hits))
        return hits
    except Exception as exc:
        log.warning("zeek-* query failed: %s", exc)
        return []


def fetch_all_alerts(es_url: str, days: int) -> list[dict]:
    """Connect to ES and fetch all alert events from the three engines."""
    if not ES_AVAILABLE:
        log.warning("elasticsearch-py not installed — skipping ES fetch")
        return []
    try:
        es = Elasticsearch(es_url, request_timeout=10)
        if not es.ping():
            log.warning("ES not reachable at %s", es_url)
            return []
    except Exception as exc:
        log.warning("ES connection error: %s", exc)
        return []

    alerts = []
    alerts.extend(fetch_suricata(es, days))
    alerts.extend(fetch_snort(es, days))
    alerts.extend(fetch_zeek(es, days))
    log.info("Total alerts fetched: %d", len(alerts))
    return alerts


# ---------------------------------------------------------------------------
# Enrichment cache
# ---------------------------------------------------------------------------

def load_enrich_cache(cache_path: str) -> dict:
    """Load the ioc-enrich-cache.json if it exists. Returns {ip: {...}} dict."""
    try:
        with open(cache_path, encoding="utf-8") as f:
            data = json.load(f)
        log.info("Enrichment cache loaded: %d entries from %s", len(data), cache_path)
        return data
    except FileNotFoundError:
        log.info("No enrichment cache found at %s", cache_path)
        return {}
    except Exception as exc:
        log.warning("Could not load enrichment cache: %s", exc)
        return {}


# ---------------------------------------------------------------------------
# Score computation
# ---------------------------------------------------------------------------

def compute_scores(alerts: list[dict], enrich_cache: dict) -> list[dict]:
    """
    Compute composite risk scores for each source IP.

    Returns a list of score records sorted by score descending.
    """
    # Aggregate per IP
    per_ip: dict[str, dict] = defaultdict(lambda: {
        "alerts_count": 0,
        "severity_sum": 0,
        "engines": set(),
        "signatures": [],
        "mitre_ttps": set(),
    })

    for alert in alerts:
        src = alert.get("src_ip")
        if not src:
            continue
        engine = alert.get("engine", "unknown")
        severity = alert.get("severity", 3)
        signature = alert.get("signature") or ""
        mitre = alert.get("mitre")

        rec = per_ip[src]
        rec["alerts_count"] += 1
        rec["severity_sum"] += _sev_weight(engine, severity)
        rec["engines"].add(engine)
        if signature:
            rec["signatures"].append((signature, _sev_weight(engine, severity)))
        if mitre:
            rec["mitre_ttps"].add(mitre)

    results = []
    for ip, rec in per_ip.items():
        n_alerts   = rec["alerts_count"]
        sev_sum    = rec["severity_sum"]
        n_engines  = len(rec["engines"])
        mitre_set  = rec["mitre_ttps"]
        n_mitre    = len(mitre_set)

        # Enrichment
        enrichment = enrich_cache.get(ip, {})
        abuse_score_raw = enrichment.get("abuseConfidenceScore", 0) or 0

        raw = (
            n_alerts * 1
            + sev_sum
            + n_engines * ENGINE_BONUS
            + abuse_score_raw / 10
            + n_mitre * 8
        )
        score = min(int(raw), 100)
        level = level_from_score(score)

        # Top rule = signature with highest severity weight
        top_rule = ""
        if rec["signatures"]:
            top_rule = max(rec["signatures"], key=lambda x: x[1])[0]

        results.append({
            "ip": ip,
            "score": score,
            "level": level,
            "alerts_count": n_alerts,
            "engines": sorted(rec["engines"]),
            "top_rule": top_rule,
            "enrichment": {k: v for k, v in enrichment.items()
                           if k not in ("enriched_at",)},
            "mitre_ttps": sorted(mitre_set),
        })

    # Sort by score descending, then IP for stability
    results.sort(key=lambda x: (-x["score"], x["ip"]))
    return results


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    # Default cache path relative to this script
    _script_dir = Path(__file__).resolve().parent
    default_cache = str(_script_dir / "ioc-enrich-cache.json")

    parser = argparse.ArgumentParser(
        description="NetWatch IOC Composite Risk Scorer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 ioc-score.py
  python3 ioc-score.py --days 7 --output /tmp/scores.json
  python3 ioc-score.py --threshold 60 --output scores.json
  python3 ioc-score.py --demo
""",
    )
    parser.add_argument("--es-url", default="http://localhost:9200",
                        help="Elasticsearch URL (default: http://localhost:9200)")
    parser.add_argument("--days", type=int, default=1,
                        help="Number of days to look back (default: 1)")
    parser.add_argument("--output", default=None,
                        help="Output JSON file path (default: stdout)")
    parser.add_argument("--threshold", type=int, default=0,
                        help="Only output IPs with score >= threshold (default: 0 = all)")
    parser.add_argument("--cache", default=default_cache,
                        help=f"Path to ioc-enrich-cache.json (default: {default_cache})")
    parser.add_argument("--demo", action="store_true",
                        help="Use built-in demo data (skip ES)")
    args = parser.parse_args()

    # --- Fetch alerts ---
    alerts: list[dict] = []
    source = "demo"

    if not args.demo:
        log.info("Querying ES at %s for last %d day(s)...", args.es_url, args.days)
        alerts = fetch_all_alerts(args.es_url, args.days)
        if alerts:
            source = f"elasticsearch:{args.es_url}"

    if not alerts:
        log.info("No alerts from ES — using demo data")
        alerts = DEMO_HITS
        source = "demo-hardcoded"

    log.info("Processing %d alert events...", len(alerts))

    # --- Load enrichment cache ---
    enrich_cache = load_enrich_cache(args.cache)

    # --- Compute scores ---
    scores = compute_scores(alerts, enrich_cache)

    # --- Apply threshold ---
    if args.threshold > 0:
        scores = [s for s in scores if s["score"] >= args.threshold]
        log.info("After threshold %d: %d IPs", args.threshold, len(scores))

    # --- Output ---
    output_data = {
        "meta": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "source": source,
            "days": args.days,
            "threshold": args.threshold,
            "total_ips": len(scores),
            "total_alerts_processed": len(alerts),
        },
        "scores": scores,
    }

    json_str = json.dumps(output_data, indent=2, ensure_ascii=False)

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json_str, encoding="utf-8")
        log.info("Scores written to %s (%d IPs)", args.output, len(scores))
    else:
        print(json_str)

    # Print summary to stderr
    if scores:
        log.info("--- Risk Score Summary ---")
        for rec in scores[:10]:
            log.info(
                "  %-18s  score=%-3d  %-8s  alerts=%-4d  engines=%s  mitre=%s",
                rec["ip"], rec["score"], rec["level"],
                rec["alerts_count"], "+".join(rec["engines"]),
                ",".join(rec["mitre_ttps"]) or "-",
            )


if __name__ == "__main__":
    main()
