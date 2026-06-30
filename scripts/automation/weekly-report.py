#!/usr/bin/env python3
"""
weekly-report.py — NetWatch Weekly Alert Report Generator

Aggregates alerts from Elasticsearch (zeek-*, snort-*, suricata-*) over the last N days
and outputs a structured JSON report.

Usage:
    python3 weekly-report.py [--days N] [--output report.json] [--es-url URL] [--save-docs]

Output JSON schema:
    {
        "period": {"from": "...", "to": "..."},
        "generated_at": "ISO8601",
        "total_alerts": int,
        "by_engine": {"zeek": int, "snort": int, "suricata": int},
        "top_rules": [{"name": str, "count": int}, ...],        # top 10
        "top_src_ips": [{"ip": str, "count": int}, ...],        # top 5
        "severity": {"critical": int, "high": int, "medium": int, "low": int},
        "mitre_ttps": [{"tactic": str, "count": int}, ...]
    }
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone, timedelta
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

ES_URL = "http://localhost:9200"
INDICES = "suricata-*,snort-*,zeek-*"


def es_post(url: str, body: dict) -> dict:
    """POST a JSON body to Elasticsearch and return parsed response."""
    data = json.dumps(body).encode("utf-8")
    req = Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (URLError, HTTPError):
        return {}


def query_total_by_engine(es_url: str, days: int) -> dict:
    """Count total alerts per engine index pattern."""
    results = {}
    engine_indices = {
        "zeek": "zeek-*",
        "snort": "snort-*",
        "suricata": "suricata-*",
    }
    for engine, pattern in engine_indices.items():
        url = f"{es_url}/{pattern}/_count"
        body = {
            "query": {
                "range": {
                    "@timestamp": {"gte": f"now-{days}d", "lte": "now"}
                }
            }
        }
        resp = es_post(url, body)
        results[engine] = resp.get("count", 0)
    return results


def query_top_rules(es_url: str, days: int, size: int = 10) -> list:
    """Aggregate top alert rules across Suricata and Snort."""
    url = f"{es_url}/suricata-*,snort-*/_search"
    body = {
        "size": 0,
        "query": {
            "range": {
                "@timestamp": {"gte": f"now-{days}d", "lte": "now"}
            }
        },
        "aggs": {
            "suricata_rules": {
                "terms": {"field": "alert.signature.keyword", "size": size}
            },
            "snort_rules": {
                "terms": {"field": "msg.keyword", "size": size}
            },
        },
    }
    resp = es_post(url, body)
    aggs = resp.get("aggregations", {})

    rule_counts: dict = {}

    for bucket in aggs.get("suricata_rules", {}).get("buckets", []):
        name = bucket.get("key", "Unknown")
        rule_counts[name] = rule_counts.get(name, 0) + bucket.get("doc_count", 0)

    for bucket in aggs.get("snort_rules", {}).get("buckets", []):
        name = bucket.get("key", "Unknown")
        rule_counts[name] = rule_counts.get(name, 0) + bucket.get("doc_count", 0)

    sorted_rules = sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)
    return [{"name": name, "count": count} for name, count in sorted_rules[:size]]


def query_top_src_ips(es_url: str, days: int, size: int = 5) -> list:
    """Aggregate top source IPs across all engines."""
    url = f"{es_url}/{INDICES}/_search"
    body = {
        "size": 0,
        "query": {
            "range": {
                "@timestamp": {"gte": f"now-{days}d", "lte": "now"}
            }
        },
        "aggs": {
            "top_ips": {
                "terms": {"field": "src_ip.keyword", "size": size}
            }
        },
    }
    resp = es_post(url, body)
    buckets = resp.get("aggregations", {}).get("top_ips", {}).get("buckets", [])
    return [{"ip": b.get("key", ""), "count": b.get("doc_count", 0)} for b in buckets]


def query_severity(es_url: str, days: int) -> dict:
    """Count alerts by severity across Suricata and Snort."""
    url = f"{es_url}/suricata-*,snort-*/_search"
    time_range = {"range": {"@timestamp": {"gte": f"now-{days}d", "lte": "now"}}}

    severity_map = {
        "critical": [
            {"term": {"alert.severity": 1}},
            {"term": {"priority": 1}},
            {"term": {"severity.keyword": "critical"}},
            {"term": {"event.severity_label.keyword": "critical"}},
        ],
        "high": [
            {"term": {"alert.severity": 2}},
            {"term": {"priority": 2}},
            {"term": {"severity.keyword": "high"}},
            {"term": {"event.severity_label.keyword": "high"}},
        ],
        "medium": [
            {"term": {"alert.severity": 3}},
            {"term": {"priority": 3}},
            {"term": {"severity.keyword": "medium"}},
            {"term": {"event.severity_label.keyword": "medium"}},
        ],
        "low": [
            {"term": {"alert.severity": 4}},
            {"term": {"priority": 4}},
            {"term": {"severity.keyword": "low"}},
            {"term": {"event.severity_label.keyword": "low"}},
        ],
    }

    results = {}
    for level, filters in severity_map.items():
        body = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [time_range],
                    "should": filters,
                    "minimum_should_match": 1,
                }
            },
        }
        resp = es_post(url, body)
        results[level] = resp.get("hits", {}).get("total", {}).get("value", 0)
    return results


def query_mitre_ttps(es_url: str, days: int, size: int = 20) -> list:
    """Aggregate MITRE ATT&CK tactics from Suricata metadata."""
    url = f"{es_url}/suricata-*/_search"
    body = {
        "size": 0,
        "query": {
            "range": {
                "@timestamp": {"gte": f"now-{days}d", "lte": "now"}
            }
        },
        "aggs": {
            "mitre_tactics": {
                "terms": {
                    "field": "alert.metadata.mitre_tactic.keyword",
                    "size": size,
                }
            }
        },
    }
    resp = es_post(url, body)
    buckets = (
        resp.get("aggregations", {})
        .get("mitre_tactics", {})
        .get("buckets", [])
    )
    return [
        {"tactic": b.get("key", ""), "count": b.get("doc_count", 0)}
        for b in buckets
    ]


def get_iso_week_label(dt: datetime) -> str:
    """Return ISO week label like 2026-W27."""
    year, week, _ = dt.isocalendar()
    return f"{year}-W{week:02d}"


def build_report(es_url: str, days: int) -> dict:
    """Build the full weekly report by aggregating ES queries."""
    now = datetime.now(timezone.utc)
    period_from = (now - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    period_to = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    by_engine = query_total_by_engine(es_url, days)
    total_alerts = sum(by_engine.values())
    top_rules = query_top_rules(es_url, days)
    top_src_ips = query_top_src_ips(es_url, days)
    severity = query_severity(es_url, days)
    mitre_ttps = query_mitre_ttps(es_url, days)

    return {
        "period": {"from": period_from, "to": period_to},
        "generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total_alerts": total_alerts,
        "by_engine": by_engine,
        "top_rules": top_rules,
        "top_src_ips": top_src_ips,
        "severity": severity,
        "mitre_ttps": mitre_ttps,
    }


def save_to_docs(report: dict, base_dir: str) -> str:
    """Save report to docs/reports/weekly-YYYY-WXX.json and return the path."""
    now_str = report.get("generated_at", datetime.now(timezone.utc).isoformat())
    dt = datetime.fromisoformat(now_str.replace("Z", "+00:00"))
    label = get_iso_week_label(dt)
    reports_dir = os.path.join(base_dir, "docs", "reports")
    os.makedirs(reports_dir, exist_ok=True)
    path = os.path.join(reports_dir, f"weekly-{label}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    return path


def main():
    parser = argparse.ArgumentParser(
        description="NetWatch — Weekly alert report from Elasticsearch"
    )
    parser.add_argument(
        "--days",
        type=int,
        default=7,
        metavar="N",
        help="Number of days to look back (default: 7)",
    )
    parser.add_argument(
        "--output",
        default="report.json",
        metavar="FILE",
        help="Output JSON file path (default: report.json)",
    )
    parser.add_argument(
        "--es-url",
        default=os.environ.get("ES_URL", ES_URL),
        metavar="URL",
        help=f"Elasticsearch URL (default: {ES_URL})",
    )
    parser.add_argument(
        "--save-docs",
        action="store_true",
        help="Also save report to docs/reports/weekly-YYYY-WXX.json",
    )
    parser.add_argument(
        "--netwatch-dir",
        default="/home/ourslow/code/netwatch",
        metavar="DIR",
        help="NetWatch base directory for --save-docs (default: /home/ourslow/code/netwatch)",
    )
    args = parser.parse_args()

    report = build_report(args.es_url, args.days)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f"Report written to: {args.output}", file=sys.stderr)
    print(f"Total alerts ({args.days}d): {report['total_alerts']}", file=sys.stderr)

    if args.save_docs:
        saved_path = save_to_docs(report, args.netwatch_dir)
        print(f"Archived to: {saved_path}", file=sys.stderr)

    # Print JSON to stdout for piping / n8n
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
