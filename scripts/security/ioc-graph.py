#!/usr/bin/env python3
"""
NetWatch — IOC Knowledge Graph Builder
T_005 — Proof of concept IOC knowledge graph

Connects to Elasticsearch, queries Suricata and Snort alerts,
extracts entities (IPs, domains, rules, MITRE TTPs), builds a
directed graph with NetworkX and exports it to ioc-graph-output.json.

Usage:
    python3 ioc-graph.py [--es-url URL] [--index-pattern PATTERN] [--output FILE]
    python3 ioc-graph.py --demo   # force demo data even if ES is available
"""

import json
import argparse
import logging
import sys
from datetime import datetime, timezone
from collections import defaultdict

try:
    import networkx as nx
    NX_AVAILABLE = True
except ImportError:
    NX_AVAILABLE = False
    print("[WARN] networkx not installed — pip install networkx", file=sys.stderr)

try:
    from elasticsearch import Elasticsearch
    ES_AVAILABLE = True
except ImportError:
    ES_AVAILABLE = False
    print("[WARN] elasticsearch-py not installed — pip install elasticsearch", file=sys.stderr)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("ioc-graph")

# ---------------------------------------------------------------------------
# Demo data (fallback when ES is empty or unavailable)
# ---------------------------------------------------------------------------
DEMO_ALERTS = [
    {
        "engine": "suricata",
        "src_ip": "192.168.1.105",
        "dest_ip": "185.220.101.46",
        "signature": "ET TOR Known Tor Exit Node Traffic",
        "category": "Misc Attack",
        "mitre_tactic": "Command and Control",
        "mitre_technique": "T1090",
        "dns_query": None,
    },
    {
        "engine": "suricata",
        "src_ip": "192.168.1.105",
        "dest_ip": "185.220.101.46",
        "signature": "ET TROJAN Metasploit Meterpreter reverse shell",
        "category": "A Network Trojan was Detected",
        "mitre_tactic": "Command and Control",
        "mitre_technique": "T1573",
        "dns_query": None,
    },
    {
        "engine": "suricata",
        "src_ip": "10.0.0.55",
        "dest_ip": "10.0.0.1",
        "signature": "NETWATCH - ICMP Ping Sweep detected",
        "category": "network-scan",
        "mitre_tactic": "Reconnaissance",
        "mitre_technique": "T1595",
        "dns_query": None,
    },
    {
        "engine": "suricata",
        "src_ip": "10.0.0.55",
        "dest_ip": "8.8.8.8",
        "signature": "ET DNS Query for Known Malware Domain",
        "category": "Potentially Bad Traffic",
        "mitre_tactic": "Command and Control",
        "mitre_technique": "T1071",
        "dns_query": "malware-c2.example.com",
    },
    {
        "engine": "suricata",
        "src_ip": "172.16.0.99",
        "dest_ip": "1.1.1.1",
        "signature": "NETWATCH - Large outbound transfer (possible exfiltration)",
        "category": "Unknown Classtype",
        "mitre_tactic": "Exfiltration",
        "mitre_technique": "T1048",
        "dns_query": None,
    },
    {
        "engine": "suricata",
        "src_ip": "203.0.113.42",
        "dest_ip": "192.168.1.20",
        "signature": "NETWATCH - Cleartext password in HTTP POST",
        "category": "policy-violation",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1552",
        "dns_query": None,
    },
    {
        "engine": "snort",
        "src_ip": "10.0.0.55",
        "dest_ip": "192.168.0.1",
        "signature": "NETWATCH - ICMP Ping Sweep",
        "category": "icmp-event",
        "mitre_tactic": "Reconnaissance",
        "mitre_technique": "T1595",
        "dns_query": None,
    },
    {
        "engine": "snort",
        "src_ip": "192.168.1.105",
        "dest_ip": "10.0.0.1",
        "signature": "INDICATOR-SHELLCODE x86 setuid 0",
        "category": "shellcode-detect",
        "mitre_tactic": "Privilege Escalation",
        "mitre_technique": "T1068",
        "dns_query": None,
    },
    {
        "engine": "suricata",
        "src_ip": "10.0.0.200",
        "dest_ip": "185.220.101.46",
        "signature": "ET TOR Known Tor Exit Node",
        "category": "Misc Attack",
        "mitre_tactic": "Command and Control",
        "mitre_technique": "T1090",
        "dns_query": None,
    },
    {
        "engine": "suricata",
        "src_ip": "10.0.0.200",
        "dest_ip": "185.220.101.46",
        "signature": "ET POLICY Python-urllib User-Agent",
        "category": "policy-violation",
        "mitre_tactic": "Command and Control",
        "mitre_technique": "T1071",
        "dns_query": "update.example-malware.net",
    },
]

# MITRE tactic → color mapping for visualization hints
MITRE_COLORS = {
    "Reconnaissance": "#FF9999",
    "Command and Control": "#FF6666",
    "Exfiltration": "#CC0000",
    "Credential Access": "#FF8C00",
    "Privilege Escalation": "#FF4500",
    "Defense Evasion": "#9370DB",
    "Lateral Movement": "#20B2AA",
    "Discovery": "#87CEEB",
    "Initial Access": "#FFD700",
    "Execution": "#FFA500",
}

# Node type → shape hints
NODE_SHAPES = {
    "ip_src": "circle",
    "ip_dst": "circle",
    "rule": "diamond",
    "domain": "triangle",
    "mitre_ttp": "square",
}


# ---------------------------------------------------------------------------
# Elasticsearch query
# ---------------------------------------------------------------------------

def build_es_query(size: int = 500) -> dict:
    """Build an ES query to fetch alert events from Suricata indices."""
    return {
        "size": size,
        "query": {
            "bool": {
                "filter": [
                    {"exists": {"field": "alert.signature"}},
                ]
            }
        },
        "_source": [
            "src_ip", "dest_ip",
            "alert.signature", "alert.category",
            "alert.metadata.mitre_tactic_name",
            "alert.metadata.mitre_technique_id",
            "dns.query",
        ],
    }


def build_snort_es_query(size: int = 500) -> dict:
    """Build an ES query to fetch Snort alert events."""
    return {
        "size": size,
        "query": {
            "bool": {
                "filter": [
                    {"exists": {"field": "msg"}},
                    {"terms": {"engine.keyword": ["snort"]}},
                ]
            }
        },
        "_source": [
            "src_ip", "dst_ip",
            "msg", "classtype",
        ],
    }


def fetch_alerts_from_es(es_url: str) -> list[dict]:
    """Fetch alerts from Elasticsearch. Returns a list of normalized alert dicts."""
    if not ES_AVAILABLE:
        log.warning("elasticsearch-py not available — skipping ES fetch")
        return []

    try:
        es = Elasticsearch(es_url, request_timeout=5)
        if not es.ping():
            log.warning("ES ping failed at %s", es_url)
            return []
    except Exception as exc:
        log.warning("Cannot connect to ES: %s", exc)
        return []

    alerts = []

    # --- Suricata alerts ---
    try:
        resp = es.search(index="suricata-*", body=build_es_query(size=500))
        for hit in resp["hits"]["hits"]:
            src = hit["_source"]
            alert = src.get("alert", {})
            meta = alert.get("metadata", {})
            # Handle list or string for tactic/technique
            tactic_raw = meta.get("mitre_tactic_name", [])
            technique_raw = meta.get("mitre_technique_id", [])
            tactic = tactic_raw[0] if isinstance(tactic_raw, list) and tactic_raw else (tactic_raw or None)
            technique = technique_raw[0] if isinstance(technique_raw, list) and technique_raw else (technique_raw or None)
            dns_info = src.get("dns", {})
            dns_query = dns_info.get("query") if dns_info else None
            if isinstance(dns_query, list):
                dns_query = dns_query[0] if dns_query else None

            alerts.append({
                "engine": "suricata",
                "src_ip": src.get("src_ip"),
                "dest_ip": src.get("dest_ip"),
                "signature": alert.get("signature"),
                "category": alert.get("category"),
                "mitre_tactic": tactic,
                "mitre_technique": technique,
                "dns_query": dns_query,
            })
        log.info("Fetched %d Suricata alerts from ES", len(alerts))
    except Exception as exc:
        log.warning("Error querying suricata-*: %s", exc)

    # --- Snort alerts ---
    snort_count = 0
    try:
        resp = es.search(index="snort-*", body=build_snort_es_query(size=500))
        for hit in resp["hits"]["hits"]:
            src = hit["_source"]
            msg = src.get("msg")
            if not msg:
                continue
            alerts.append({
                "engine": "snort",
                "src_ip": src.get("src_ip"),
                "dest_ip": src.get("dst_ip"),
                "signature": msg,
                "category": src.get("classtype"),
                "mitre_tactic": None,
                "mitre_technique": None,
                "dns_query": None,
            })
            snort_count += 1
        log.info("Fetched %d Snort alerts from ES", snort_count)
    except Exception as exc:
        log.warning("Error querying snort-*: %s", exc)

    return alerts


# ---------------------------------------------------------------------------
# Graph building
# ---------------------------------------------------------------------------

def make_node_id(node_type: str, value: str) -> str:
    """Build a deterministic node ID from type and value."""
    return f"{node_type}::{value}"


def build_graph(alerts: list[dict]) -> "nx.DiGraph":
    """
    Build a directed graph from alert records.

    Node types:
      - ip_src  : source IP address
      - ip_dst  : destination IP address
      - rule    : alert signature / rule name
      - domain  : DNS query domain
      - mitre_ttp : MITRE ATT&CK technique (tactic + technique_id)

    Edges:
      - ip_src → rule       (source IP triggered this rule)
      - ip_src → ip_dst     (source communicated with destination)
      - rule   → mitre_ttp  (rule maps to MITRE TTP)
      - ip_src → domain     (source queried this domain)
      - domain → rule       (domain associated with rule alert)
    """
    G = nx.DiGraph()

    # Track edge weights (how many times the same edge appears)
    edge_counts: dict = defaultdict(int)

    for alert in alerts:
        src_ip = alert.get("src_ip")
        dest_ip = alert.get("dest_ip")
        signature = alert.get("signature")
        category = alert.get("category") or "unknown"
        mitre_tactic = alert.get("mitre_tactic")
        mitre_technique = alert.get("mitre_technique")
        dns_query = alert.get("dns_query")
        engine = alert.get("engine", "unknown")

        # --- Nodes ---
        if src_ip:
            nid = make_node_id("ip_src", src_ip)
            if not G.has_node(nid):
                G.add_node(nid, type="ip_src", label=src_ip, shape=NODE_SHAPES["ip_src"],
                           color="#4A90D9", alert_count=0)
            G.nodes[nid]["alert_count"] = G.nodes[nid].get("alert_count", 0) + 1

        if dest_ip:
            nid_dst = make_node_id("ip_dst", dest_ip)
            if not G.has_node(nid_dst):
                G.add_node(nid_dst, type="ip_dst", label=dest_ip, shape=NODE_SHAPES["ip_dst"],
                           color="#7FBA00", alert_count=0)

        if signature:
            nid_rule = make_node_id("rule", signature)
            if not G.has_node(nid_rule):
                G.add_node(nid_rule, type="rule", label=signature, shape=NODE_SHAPES["rule"],
                           category=category, engine=engine, color="#F5A623")

        if mitre_tactic and mitre_technique:
            ttp_label = f"{mitre_tactic} ({mitre_technique})"
            nid_ttp = make_node_id("mitre_ttp", mitre_technique)
            if not G.has_node(nid_ttp):
                G.add_node(nid_ttp, type="mitre_ttp", label=ttp_label,
                           tactic=mitre_tactic, technique=mitre_technique,
                           shape=NODE_SHAPES["mitre_ttp"],
                           color=MITRE_COLORS.get(mitre_tactic, "#AAAAAA"))

        if dns_query:
            nid_domain = make_node_id("domain", dns_query)
            if not G.has_node(nid_domain):
                G.add_node(nid_domain, type="domain", label=dns_query,
                           shape=NODE_SHAPES["domain"], color="#B86FCE")

        # --- Edges ---
        if src_ip and signature:
            e = (make_node_id("ip_src", src_ip), make_node_id("rule", signature))
            edge_counts[e] += 1
            if not G.has_edge(*e):
                G.add_edge(*e, relation="triggered", weight=1)
            G.edges[e]["weight"] = edge_counts[e]

        if src_ip and dest_ip:
            e = (make_node_id("ip_src", src_ip), make_node_id("ip_dst", dest_ip))
            edge_counts[e] += 1
            if not G.has_edge(*e):
                G.add_edge(*e, relation="communicated_with", weight=1)
            G.edges[e]["weight"] = edge_counts[e]

        if signature and mitre_tactic and mitre_technique:
            e = (make_node_id("rule", signature), make_node_id("mitre_ttp", mitre_technique))
            edge_counts[e] += 1
            if not G.has_edge(*e):
                G.add_edge(*e, relation="maps_to_ttp", weight=1)
            G.edges[e]["weight"] = edge_counts[e]

        if src_ip and dns_query:
            e = (make_node_id("ip_src", src_ip), make_node_id("domain", dns_query))
            edge_counts[e] += 1
            if not G.has_edge(*e):
                G.add_edge(*e, relation="dns_query", weight=1)
            G.edges[e]["weight"] = edge_counts[e]

        if dns_query and signature:
            e = (make_node_id("domain", dns_query), make_node_id("rule", signature))
            edge_counts[e] += 1
            if not G.has_edge(*e):
                G.add_edge(*e, relation="associated_with_rule", weight=1)
            G.edges[e]["weight"] = edge_counts[e]

    return G


def graph_to_json(G: "nx.DiGraph", source: str, alert_count: int) -> dict:
    """Serialize NetworkX graph to the export JSON format."""
    nodes = []
    for node_id, attrs in G.nodes(data=True):
        nodes.append({
            "id": node_id,
            **attrs,
        })

    edges = []
    for src, dst, attrs in G.edges(data=True):
        edges.append({
            "source": src,
            "target": dst,
            **attrs,
        })

    return {
        "meta": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "source": source,
            "alert_count_processed": alert_count,
            "node_count": G.number_of_nodes(),
            "edge_count": G.number_of_edges(),
            "node_types": list({attrs.get("type") for _, attrs in G.nodes(data=True)}),
        },
        "nodes": nodes,
        "edges": edges,
    }


def print_graph_stats(G: "nx.DiGraph") -> None:
    """Print a human-readable summary of the graph."""
    log.info("--- Graph Statistics ---")
    log.info("  Nodes : %d", G.number_of_nodes())
    log.info("  Edges : %d", G.number_of_edges())

    type_counts: dict = defaultdict(int)
    for _, attrs in G.nodes(data=True):
        type_counts[attrs.get("type", "unknown")] += 1

    for ntype, count in sorted(type_counts.items()):
        log.info("    %s : %d", ntype, count)

    # Top IPs by alert count
    ip_nodes = [
        (nid, attrs.get("alert_count", 0))
        for nid, attrs in G.nodes(data=True)
        if attrs.get("type") == "ip_src"
    ]
    ip_nodes.sort(key=lambda x: x[1], reverse=True)
    if ip_nodes:
        log.info("  Top source IPs by alert count:")
        for nid, cnt in ip_nodes[:5]:
            log.info("    %s  [%d alerts]", nid.split("::")[-1], cnt)

    # MITRE TTPs seen
    ttp_nodes = [
        attrs.get("label")
        for _, attrs in G.nodes(data=True)
        if attrs.get("type") == "mitre_ttp"
    ]
    if ttp_nodes:
        log.info("  MITRE TTPs detected:")
        for ttp in sorted(set(ttp_nodes)):
            log.info("    %s", ttp)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="NetWatch IOC Knowledge Graph Builder")
    parser.add_argument("--es-url", default="http://localhost:9200",
                        help="Elasticsearch URL (default: http://localhost:9200)")
    parser.add_argument("--output", default="scripts/security/ioc-graph-output.json",
                        help="Output JSON file path")
    parser.add_argument("--demo", action="store_true",
                        help="Force use of demo data even if ES is available")
    parser.add_argument("--max-alerts", type=int, default=500,
                        help="Max alerts to fetch from ES (default: 500)")
    args = parser.parse_args()

    if not NX_AVAILABLE:
        log.error("networkx is required: pip install networkx")
        sys.exit(1)

    # --- Fetch alerts ---
    alerts = []
    source = "demo"

    if not args.demo:
        log.info("Connecting to Elasticsearch at %s ...", args.es_url)
        alerts = fetch_alerts_from_es(args.es_url)
        if alerts:
            source = f"elasticsearch:{args.es_url}"
            log.info("Loaded %d alerts from Elasticsearch", len(alerts))

    if not alerts:
        log.info("No alerts from ES (empty index or connection failed) — using demo data")
        alerts = DEMO_ALERTS
        source = "demo-hardcoded"

    # --- Build graph ---
    log.info("Building IOC knowledge graph from %d alerts ...", len(alerts))
    G = build_graph(alerts)
    print_graph_stats(G)

    # --- Export JSON ---
    output = graph_to_json(G, source=source, alert_count=len(alerts))

    output_path = args.output
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    log.info("Graph exported to %s  (%d nodes, %d edges)",
             output_path, G.number_of_nodes(), G.number_of_edges())


if __name__ == "__main__":
    main()
