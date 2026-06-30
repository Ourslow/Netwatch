#!/usr/bin/env python3
"""
NetWatch — IOC Enrichment Script
T_010 — Enrichissement IOC : réputation IP via AbuseIPDB + ipinfo.io

Reads ioc-graph-output.json, enriches each IP node with reputation data
from AbuseIPDB (if ABUSEIPDB_API_KEY is set) or ipinfo.io (fallback),
and outputs ioc-graph-enriched.json.

Usage:
    python3 ioc-enrich.py [--input FILE] [--output FILE] [--cache FILE]
    python3 ioc-enrich.py --input scripts/security/ioc-graph-output.json

Environment:
    ABUSEIPDB_API_KEY  — optional, enables AbuseIPDB lookups
                         If absent, ipinfo.io is used (no key required)
"""

import json
import argparse
import logging
import os
import sys
import time
import ipaddress
from datetime import datetime, timezone
from pathlib import Path

try:
    import urllib.request
    import urllib.error
except ImportError:
    pass  # stdlib, always present

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("ioc-enrich")

# ---------------------------------------------------------------------------
# RFC 1918 + loopback + link-local private ranges to skip
# ---------------------------------------------------------------------------
PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]


def is_private_ip(ip_str: str) -> bool:
    """Return True if the IP is RFC 1918, loopback or link-local."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in PRIVATE_NETWORKS)
    except ValueError:
        # Not a valid IP (e.g. domain, node ID prefix) — skip
        return False


# ---------------------------------------------------------------------------
# HTTP helper (no external libs required)
# ---------------------------------------------------------------------------

def http_get_json(url: str, headers: dict | None = None, timeout: int = 10) -> dict | None:
    """
    Perform a GET request and parse the JSON response.
    Returns None on any error.
    """
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
            return json.loads(body)
    except urllib.error.HTTPError as exc:
        log.warning("HTTP %s for %s: %s", exc.code, url, exc.reason)
    except urllib.error.URLError as exc:
        log.warning("URL error for %s: %s", url, exc.reason)
    except json.JSONDecodeError as exc:
        log.warning("JSON parse error for %s: %s", url, exc)
    except Exception as exc:
        log.warning("Unexpected error for %s: %s", url, exc)
    return None


# ---------------------------------------------------------------------------
# AbuseIPDB enrichment
# ---------------------------------------------------------------------------

def enrich_abuseipdb(ip: str, api_key: str) -> dict:
    """
    Query AbuseIPDB v2 /check endpoint.
    Returns enrichment dict with source='abuseipdb'.
    """
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
    headers = {
        "Key": api_key,
        "Accept": "application/json",
    }
    data = http_get_json(url, headers=headers)
    if not data or "data" not in data:
        log.warning("AbuseIPDB returned no data for %s", ip)
        return {}

    d = data["data"]
    return {
        "source": "abuseipdb",
        "abuse_score": d.get("abuseConfidenceScore"),
        "country": d.get("countryCode"),
        "isp": d.get("isp"),
        "usage_type": d.get("usageType"),
        "total_reports": d.get("totalReports"),
        "domain": d.get("domain"),
        "is_whitelisted": d.get("isWhitelisted"),
        "enriched_at": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# ipinfo.io enrichment (fallback, no key required)
# ---------------------------------------------------------------------------

def enrich_ipinfo(ip: str, api_token: str | None = None) -> dict:
    """
    Query ipinfo.io for basic IP information.
    Returns enrichment dict with source='ipinfo'.
    Optionally uses an API token for higher rate limits.
    """
    url = f"https://ipinfo.io/{ip}/json"
    headers = {"Accept": "application/json"}
    if api_token:
        headers["Authorization"] = f"Bearer {api_token}"

    data = http_get_json(url, headers=headers)
    if not data:
        log.warning("ipinfo.io returned no data for %s", ip)
        return {}

    return {
        "source": "ipinfo",
        "country": data.get("country"),
        "org": data.get("org"),
        "hostname": data.get("hostname"),
        "city": data.get("city"),
        "region": data.get("region"),
        "enriched_at": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Cache management
# ---------------------------------------------------------------------------

def load_cache(cache_path: str) -> dict:
    """Load the enrichment cache from disk. Returns empty dict if missing."""
    p = Path(cache_path)
    if p.exists():
        try:
            with open(p, "r", encoding="utf-8") as f:
                cache = json.load(f)
            log.info("Cache loaded: %d entries from %s", len(cache), cache_path)
            return cache
        except (json.JSONDecodeError, OSError) as exc:
            log.warning("Cannot load cache %s: %s — starting fresh", cache_path, exc)
    return {}


def save_cache(cache: dict, cache_path: str) -> None:
    """Persist the enrichment cache to disk."""
    try:
        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2, ensure_ascii=False)
        log.info("Cache saved: %d entries to %s", len(cache), cache_path)
    except OSError as exc:
        log.warning("Cannot save cache to %s: %s", cache_path, exc)


# ---------------------------------------------------------------------------
# Core enrichment logic
# ---------------------------------------------------------------------------

def enrich_ip(ip: str, api_key: str | None, cache: dict) -> dict:
    """
    Enrich a single IP address.
    Uses cache to avoid duplicate API calls.
    Falls back from AbuseIPDB → ipinfo.io depending on key availability.
    """
    # Cache hit
    if ip in cache:
        log.debug("Cache hit for %s", ip)
        return cache[ip]

    # Rate limiting — be polite to free-tier APIs
    time.sleep(0.1)

    enrichment: dict = {}

    if api_key:
        log.info("AbuseIPDB lookup: %s", ip)
        enrichment = enrich_abuseipdb(ip, api_key)
        if not enrichment:
            log.info("AbuseIPDB failed for %s — falling back to ipinfo.io", ip)
            enrichment = enrich_ipinfo(ip)
    else:
        log.info("ipinfo.io lookup: %s", ip)
        enrichment = enrich_ipinfo(ip)

    cache[ip] = enrichment
    return enrichment


# ---------------------------------------------------------------------------
# Graph enrichment
# ---------------------------------------------------------------------------

def enrich_graph(graph: dict, api_key: str | None, cache: dict) -> tuple[dict, int]:
    """
    Enrich all IP nodes in the graph.
    Returns (enriched_graph, enriched_count).
    Private IPs are skipped (RFC 1918 + loopback).
    """
    enriched_graph = json.loads(json.dumps(graph))  # deep copy
    enriched_count = 0
    skipped_private = 0
    skipped_other = 0

    for node in enriched_graph.get("nodes", []):
        node_type = node.get("type", "")
        if node_type not in ("ip_src", "ip_dst"):
            continue

        ip = node.get("label", "")
        if not ip:
            # Try to extract from id like "ip_src::1.2.3.4"
            node_id = node.get("id", "")
            ip = node_id.split("::")[-1] if "::" in node_id else ""

        if not ip:
            skipped_other += 1
            continue

        if is_private_ip(ip):
            log.debug("Skipping private IP: %s", ip)
            node["enrichment"] = {"source": "skipped", "reason": "private_ip"}
            skipped_private += 1
            continue

        enrichment = enrich_ip(ip, api_key, cache)
        node["enrichment"] = enrichment
        if enrichment:
            enriched_count += 1

    # Update metadata
    enriched_graph.setdefault("meta", {})
    enriched_graph["meta"]["enriched_at"] = datetime.now(timezone.utc).isoformat()
    enriched_graph["meta"]["enrichment_source"] = "abuseipdb" if api_key else "ipinfo"
    enriched_graph["meta"]["enriched_count"] = enriched_count
    enriched_graph["meta"]["skipped_private"] = skipped_private

    log.info("Enrichment complete: %d IPs enriched, %d private IPs skipped",
             enriched_count, skipped_private)
    return enriched_graph, enriched_count


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    # Resolve default paths relative to this script's directory
    script_dir = Path(__file__).parent

    parser = argparse.ArgumentParser(
        description="NetWatch IOC Enrichment — AbuseIPDB + ipinfo.io"
    )
    parser.add_argument(
        "--input",
        default=str(script_dir / "ioc-graph-output.json"),
        help="Input graph JSON file (default: ioc-graph-output.json)",
    )
    parser.add_argument(
        "--output",
        default=str(script_dir / "ioc-graph-enriched.json"),
        help="Output enriched graph JSON file (default: ioc-graph-enriched.json)",
    )
    parser.add_argument(
        "--cache",
        default=str(script_dir / "ioc-enrich-cache.json"),
        help="Cache file path (default: ioc-enrich-cache.json)",
    )
    args = parser.parse_args()

    # --- API key from .env or environment ---
    api_key = os.environ.get("ABUSEIPDB_API_KEY")
    if not api_key:
        # Try to load from .env in project root (two levels up from scripts/security/)
        env_candidates = [
            Path(__file__).parent.parent.parent / ".env",
            Path(".env"),
        ]
        for env_file in env_candidates:
            if env_file.exists():
                with open(env_file, encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("ABUSEIPDB_API_KEY=") and not line.startswith("#"):
                            api_key = line.split("=", 1)[1].strip().strip('"').strip("'")
                            if api_key:
                                log.info("ABUSEIPDB_API_KEY loaded from %s", env_file)
                                break
                if api_key:
                    break

    if api_key:
        log.info("Using AbuseIPDB for enrichment")
    else:
        log.warning(
            "ABUSEIPDB_API_KEY not set — using ipinfo.io (fallback, no key required). "
            "Set ABUSEIPDB_API_KEY in .env or environment for full reputation data."
        )

    # --- Load input graph ---
    input_path = Path(args.input)
    if not input_path.exists():
        log.error("Input file not found: %s", args.input)
        sys.exit(1)

    with open(input_path, "r", encoding="utf-8") as f:
        graph = json.load(f)

    node_count = len(graph.get("nodes", []))
    ip_count = sum(
        1 for n in graph.get("nodes", []) if n.get("type") in ("ip_src", "ip_dst")
    )
    log.info(
        "Loaded graph: %d total nodes, %d IP nodes from %s",
        node_count, ip_count, args.input,
    )

    # --- Load cache ---
    cache = load_cache(args.cache)

    # --- Enrich ---
    enriched_graph, enriched_count = enrich_graph(graph, api_key, cache)

    # --- Save cache ---
    save_cache(cache, args.cache)

    # --- Write output ---
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(enriched_graph, f, indent=2, ensure_ascii=False)

    log.info(
        "Enriched graph written to %s  (%d nodes, %d enriched)",
        args.output,
        node_count,
        enriched_count,
    )


if __name__ == "__main__":
    main()
