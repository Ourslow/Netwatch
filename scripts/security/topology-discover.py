#!/usr/bin/env python3
"""
NetWatch — Network Topology Discovery
T_022 — Découverte topologie réseau : SNMP CDP/LLDP + ARP Zeek → topology.json

Discovers L2/L3 topology using:
  - SNMP LLDP-MIB (via snmpwalk subprocess)
  - ARP table via SNMP (ipNetToMediaPhysAddress)
  - Zeek ARP logs from Elasticsearch

Output: topology.json with devices, links, and stats.

Usage:
    python3 topology-discover.py [--targets IP1,IP2] [--community public]
                                  [--output topology.json] [--demo] [--verbose]
"""

import argparse
import json
import logging
import re
import subprocess
import sys
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
log = logging.getLogger("topology-discover")

# ---------------------------------------------------------------------------
# SNMP OIDs (LLDP-MIB + standard MIBs)
# ---------------------------------------------------------------------------
OID_SYS_NAME         = "1.3.6.1.2.1.1.5.0"
OID_SYS_DESCR        = "1.3.6.1.2.1.1.1.0"
OID_IF_DESCR         = "1.3.6.1.2.1.2.2.1.2"
OID_ARP_TABLE        = "1.3.6.1.2.1.4.22.1.2"
OID_LLDP_REM_SYS    = "1.0.8802.1.1.2.1.4.1.1.9"
OID_LLDP_REM_PORT   = "1.0.8802.1.1.2.1.4.1.1.8"
OID_LLDP_LOC_PORT   = "1.0.8802.1.1.2.1.3.7.1.3"
OID_LLDP_REM_CHASSIS = "1.0.8802.1.1.2.1.4.1.1.5"

# ---------------------------------------------------------------------------
# OUI → Vendor lookup table (≥50 entries)
# Covers Cisco, HP/Aruba, Juniper, Dell, VMware, Aruba, Fortinet, Palo Alto
# and many other common manufacturers.
# ---------------------------------------------------------------------------
OUI_VENDOR: dict[str, str] = {
    # Cisco Systems
    "00:00:0c": "Cisco",
    "00:01:42": "Cisco",
    "00:01:43": "Cisco",
    "00:01:63": "Cisco",
    "00:01:64": "Cisco",
    "00:01:96": "Cisco",
    "00:01:97": "Cisco",
    "00:02:16": "Cisco",
    "00:02:17": "Cisco",
    "00:0a:41": "Cisco",
    "00:0a:b8": "Cisco",
    "00:0b:45": "Cisco",
    "00:0c:ce": "Cisco",
    "00:1a:2b": "Cisco",
    "00:1b:0c": "Cisco",
    "00:1c:b0": "Cisco",
    "00:1d:45": "Cisco",
    "00:1e:13": "Cisco",
    "00:1f:9e": "Cisco",
    "00:21:1b": "Cisco",
    "00:22:bd": "Cisco",
    "00:23:ac": "Cisco",
    "00:24:14": "Cisco",
    "00:25:45": "Cisco",
    "00:26:0b": "Cisco",
    "58:ac:78": "Cisco",
    "70:81:05": "Cisco",
    "a4:93:4c": "Cisco",
    "cc:46:d6": "Cisco",
    # HP / Hewlett-Packard
    "00:01:e6": "HP",
    "00:0f:61": "HP",
    "00:11:0a": "HP",
    "00:13:21": "HP",
    "00:14:38": "HP",
    "00:17:08": "HP",
    "00:18:71": "HP",
    "00:19:bb": "HP",
    "00:1a:4b": "HP",
    "00:1b:78": "HP",
    "00:1c:c4": "HP",
    "00:21:5a": "HP",
    "00:23:7d": "HP",
    "00:24:81": "HP",
    "3c:d9:2b": "HP",
    "fc:15:b4": "HP",
    # Aruba Networks (HPE)
    "00:0b:86": "Aruba",
    "00:1a:1e": "Aruba",
    "24:de:c6": "Aruba",
    "40:e3:d6": "Aruba",
    "6c:f3:7f": "Aruba",
    "84:d4:7e": "Aruba",
    "94:b4:0f": "Aruba",
    "d8:c7:c8": "Aruba",
    # Juniper Networks
    "00:05:85": "Juniper",
    "00:10:db": "Juniper",
    "00:12:1e": "Juniper",
    "00:19:e2": "Juniper",
    "00:1f:12": "Juniper",
    "00:21:59": "Juniper",
    "00:23:9c": "Juniper",
    "00:25:c4": "Juniper",
    "2c:6b:f5": "Juniper",
    "40:b4:f0": "Juniper",
    # Dell Technologies
    "00:06:5b": "Dell",
    "00:08:74": "Dell",
    "00:0d:56": "Dell",
    "00:0f:1f": "Dell",
    "00:11:43": "Dell",
    "00:12:3f": "Dell",
    "00:13:72": "Dell",
    "00:14:22": "Dell",
    "00:15:c5": "Dell",
    "00:16:f0": "Dell",
    "00:18:8b": "Dell",
    "00:1a:a0": "Dell",
    "00:1c:23": "Dell",
    "00:1d:09": "Dell",
    "00:1e:4f": "Dell",
    "14:18:77": "Dell",
    "44:a8:42": "Dell",
    "b0:83:fe": "Dell",
    # VMware
    "00:0c:29": "VMware",
    "00:50:56": "VMware",
    "00:05:69": "VMware",
    "00:1c:14": "VMware",
    # Fortinet
    "00:09:0f": "Fortinet",
    "00:0c:e6": "Fortinet",
    "00:11:6b": "Fortinet",
    "08:5b:0e": "Fortinet",
    "70:4c:a5": "Fortinet",
    "90:6c:ac": "Fortinet",
    "b4:fb:e4": "Fortinet",
    # Palo Alto Networks
    "00:1b:17": "Palo Alto",
    "44:38:39": "Palo Alto",
    "d4:f4:be": "Palo Alto",
    # F5 Networks
    "00:01:d7": "F5 Networks",
    "00:0b:09": "F5 Networks",
    # Pfsense / Netgate
    "00:08:a2": "Netgate",
    # Extreme Networks
    "00:01:30": "Extreme",
    "00:04:96": "Extreme",
    # Check Point
    "00:1c:7f": "Check Point",
    "44:03:a7": "Check Point",
    # Ubiquiti
    "00:15:6d": "Ubiquiti",
    "00:27:22": "Ubiquiti",
    "04:18:d6": "Ubiquiti",
    "24:a4:3c": "Ubiquiti",
    "44:d9:e7": "Ubiquiti",
    "68:72:51": "Ubiquiti",
    "78:8a:20": "Ubiquiti",
    "80:2a:a8": "Ubiquiti",
    "dc:9f:db": "Ubiquiti",
    # MikroTik
    "00:0c:42": "MikroTik",
    "2c:c8:1b": "MikroTik",
    "48:8f:5a": "MikroTik",
    "6c:3b:6b": "MikroTik",
    "b8:69:f4": "MikroTik",
    "d4:ca:6d": "MikroTik",
    # Netscout / IXIA
    "00:10:92": "Netscout",
    "00:1c:d5": "Netscout",
}


def lookup_vendor(mac: str) -> str:
    """Return vendor name from OUI lookup, 'Unknown' if not found."""
    if not mac:
        return "Unknown"
    # Normalize mac to lower colon-separated
    normalized = mac.lower().replace("-", ":").replace(".", ":")
    # Try progressively shorter OUI prefixes (6-char, then 3-byte)
    parts = normalized.split(":")
    if len(parts) >= 3:
        oui = ":".join(parts[:3])
        vendor = OUI_VENDOR.get(oui)
        if vendor:
            return vendor
    return "Unknown"


def infer_device_type(sys_descr: str, ip_count: int = 0) -> str:
    """Infer device type from sysDescr string and number of IP interfaces."""
    desc_lower = sys_descr.lower() if sys_descr else ""
    if any(kw in desc_lower for kw in ("asa", "fortigate", "pan-os", "panos", "firewall")):
        return "firewall"
    if any(kw in desc_lower for kw in ("switch", "catalyst", "procurve", "powerconnect", "nexus")):
        return "switch"
    if any(kw in desc_lower for kw in ("router", "ios", "junos", "routeros")):
        return "router"
    if ip_count > 2:
        return "router"
    return "host"


# ---------------------------------------------------------------------------
# SNMP helpers
# ---------------------------------------------------------------------------

def _snmpwalk_available() -> bool:
    """Check if snmpwalk binary is available."""
    try:
        result = subprocess.run(
            ["snmpwalk", "--version"],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0 or b"SNMP" in result.stderr + result.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def snmpwalk(target: str, community: str, oid: str, timeout: int = 10) -> dict[str, str]:
    """
    Run snmpwalk and parse output into {oid_suffix: value} dict.
    Returns empty dict on failure or if snmpwalk is unavailable.
    """
    cmd = ["snmpwalk", "-v2c", "-c", community, "-Oq", "-Oe", target, oid]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        log.warning("snmpwalk not found — SNMP discovery skipped")
        return {}
    except subprocess.TimeoutExpired:
        log.warning("snmpwalk timeout for %s OID %s", target, oid)
        return {}

    if result.returncode != 0:
        log.debug("snmpwalk returned %d for %s: %s", result.returncode, oid, result.stderr.strip())
        return {}

    parsed: dict[str, str] = {}
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        # Format: OID VALUE  (with -Oq flag, one field each)
        # e.g.: .1.3.6.1.2.1.1.5.0 "my-switch"
        #       1.3.6.1.2.1.2.2.1.2.1 "GigabitEthernet0/1"
        parts = line.split(None, 1)
        if len(parts) == 2:
            key, val = parts
            # Strip surrounding quotes if present
            val = val.strip().strip('"')
            parsed[key] = val

    return parsed


def snmpget_scalar(target: str, community: str, oid: str) -> str:
    """Get a single scalar OID value. Returns '' on failure."""
    result = snmpwalk(target, community, oid)
    # scalar OID may come back with the full OID or just the leaf
    for v in result.values():
        return v
    return ""


def discover_device_snmp(target: str, community: str, verbose: bool = False) -> dict:
    """
    Perform full SNMP discovery on a single target IP.
    Returns a device dict (partial, to be merged later).
    """
    if verbose:
        log.info("SNMP discovery: %s (community=%s)", target, community)

    device: dict = {
        "ip": target,
        "mac": "",
        "name": target,
        "sys_descr": "",
        "interfaces": [],
        "lldp_neighbors": [],
        "arp_entries": [],
    }

    # --- sysName ---
    sys_name = snmpget_scalar(target, community, OID_SYS_NAME)
    if sys_name:
        device["name"] = sys_name
        if verbose:
            log.info("  sysName: %s", sys_name)

    # --- sysDescr ---
    sys_descr = snmpget_scalar(target, community, OID_SYS_DESCR)
    if sys_descr:
        device["sys_descr"] = sys_descr
        if verbose:
            log.info("  sysDescr: %s", sys_descr[:80])

    # --- ifDescr table ---
    if_table = snmpwalk(target, community, OID_IF_DESCR)
    for oid_key, if_name in if_table.items():
        # Extract interface index from OID suffix
        idx = oid_key.rsplit(".", 1)[-1]
        device["interfaces"].append({"index": idx, "port": if_name, "speed": None, "neighbor": None})
    if verbose:
        log.info("  interfaces found: %d", len(device["interfaces"]))

    # --- ARP table ---
    arp_table = snmpwalk(target, community, OID_ARP_TABLE)
    for oid_key, mac_hex in arp_table.items():
        # OID suffix is ifIndex.ipAddr components → extract IP from suffix
        # .ifIndex.A.B.C.D → last 4 digits are the IP
        parts = oid_key.rsplit(".", 5)
        if len(parts) >= 5:
            ip_addr = ".".join(parts[-4:])
            mac = _normalize_mac_hex(mac_hex)
            device["arp_entries"].append({"ip": ip_addr, "mac": mac})
    if verbose:
        log.info("  ARP entries: %d", len(device["arp_entries"]))

    # --- LLDP remote systems ---
    lldp_sys = snmpwalk(target, community, OID_LLDP_REM_SYS)
    lldp_port = snmpwalk(target, community, OID_LLDP_REM_PORT)
    lldp_chassis = snmpwalk(target, community, OID_LLDP_REM_CHASSIS)
    lldp_loc_port = snmpwalk(target, community, OID_LLDP_LOC_PORT)

    # Build neighbors keyed by (localPortNum, remoteIdx) from OID suffix
    neighbors: dict[str, dict] = {}
    for oid_key, rem_name in lldp_sys.items():
        key = _lldp_neighbor_key(oid_key)
        neighbors.setdefault(key, {})["remote_name"] = rem_name
    for oid_key, rem_port in lldp_port.items():
        key = _lldp_neighbor_key(oid_key)
        neighbors.setdefault(key, {})["remote_port"] = rem_port
    for oid_key, chassis_id in lldp_chassis.items():
        key = _lldp_neighbor_key(oid_key)
        neighbors.setdefault(key, {})["chassis_id"] = chassis_id

    # Resolve local port names
    for nbr in neighbors.values():
        if "local_port_idx" in nbr:
            idx = nbr["local_port_idx"]
            for oid_key, port_name in lldp_loc_port.items():
                if oid_key.endswith(f".{idx}"):
                    nbr["local_port"] = port_name
                    break

    device["lldp_neighbors"] = list(neighbors.values())
    if verbose:
        log.info("  LLDP neighbors: %d", len(device["lldp_neighbors"]))

    return device


def _lldp_neighbor_key(oid_suffix: str) -> str:
    """Extract a stable key from an LLDP OID suffix (last two numeric components)."""
    parts = oid_suffix.rsplit(".", 2)
    return ".".join(parts[-2:]) if len(parts) >= 2 else oid_suffix


def _normalize_mac_hex(raw: str) -> str:
    """Convert snmpwalk hex MAC (e.g. '0 1 a 2 b 3') or 'Hex-STRING: ...' to xx:xx:xx:xx:xx:xx."""
    # Strip 'Hex-STRING:' prefix if present
    raw = re.sub(r"(?i)hex-string:\s*", "", raw).strip()
    # Remove spaces, colons, dashes → raw hex
    hex_only = re.sub(r"[:\-\s]", "", raw)
    if len(hex_only) == 12:
        pairs = [hex_only[i:i+2] for i in range(0, 12, 2)]
        return ":".join(pairs).lower()
    return raw.lower()


# ---------------------------------------------------------------------------
# Elasticsearch ARP source
# ---------------------------------------------------------------------------

def fetch_arp_from_es(es_url: str, verbose: bool = False) -> list[dict]:
    """
    Query Elasticsearch zeek-* for ARP log entries.
    Returns list of {src_ip, src_mac, dst_ip} dicts.
    """
    query = {
        "size": 5000,
        "_source": [
            "@timestamp",
            "src_ip", "src_mac", "dst_ip",
            "source.ip", "source.mac", "destination.ip",
            "zeek.arp.src_mac", "zeek.arp.src_ip", "zeek.arp.dst_ip",
        ],
        "query": {
            "bool": {
                "should": [
                    {"term": {"network.protocol": "arp"}},
                    {"term": {"log_type": "arp"}},
                    {"term": {"_index": "zeek-arp"}},
                ],
                "minimum_should_match": 1,
            }
        },
    }

    url = f"{es_url}/zeek-*/_search"
    body = json.dumps(query).encode()

    try:
        req = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
    except Exception as exc:
        if verbose:
            log.warning("ES ARP query failed: %s", exc)
        return []

    entries = []
    for hit in data.get("hits", {}).get("hits", []):
        src = hit.get("_source", {})
        # Try several field naming conventions
        src_ip  = (src.get("src_ip")
                   or src.get("source.ip")
                   or src.get("zeek.arp.src_ip", ""))
        src_mac = (src.get("src_mac")
                   or src.get("source.mac")
                   or src.get("zeek.arp.src_mac", ""))
        dst_ip  = (src.get("dst_ip")
                   or src.get("destination.ip")
                   or src.get("zeek.arp.dst_ip", ""))
        if src_ip or src_mac:
            entries.append({"src_ip": src_ip, "src_mac": src_mac, "dst_ip": dst_ip})

    if verbose:
        log.info("ES ARP: %d entries retrieved", len(entries))
    return entries


# ---------------------------------------------------------------------------
# Topology builder
# ---------------------------------------------------------------------------

def build_topology(
    snmp_devices: list[dict],
    arp_entries: list[dict],
    verbose: bool = False,
) -> dict:
    """
    Merge SNMP device data and ARP entries into topology.json structure.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # ── device registry keyed by IP ──────────────────────────────────────────
    device_map: dict[str, dict] = {}

    for dev in snmp_devices:
        ip = dev["ip"]
        vendor = lookup_vendor(dev.get("mac", ""))
        # If vendor still unknown, try LLDP chassis ID
        if vendor == "Unknown":
            chassis = ""
            for nbr in dev.get("lldp_neighbors", []):
                chassis = nbr.get("chassis_id", "")
                if chassis:
                    break
            if chassis:
                vendor = lookup_vendor(chassis)

        dtype = infer_device_type(dev.get("sys_descr", ""))
        dev_id = _make_id(dev.get("name", ip))

        device_map[ip] = {
            "id": dev_id,
            "name": dev.get("name", ip),
            "ip": ip,
            "mac": dev.get("mac", ""),
            "type": dtype,
            "vendor": vendor,
            "interfaces": [
                {"port": iface["port"], "speed": iface.get("speed"), "neighbor": iface.get("neighbor")}
                for iface in dev.get("interfaces", [])
            ],
            "_lldp_neighbors": dev.get("lldp_neighbors", []),
            "_arp_from_device": dev.get("arp_entries", []),
        }

    # ── enrich from ARP (Zeek ES + SNMP ARP table) ──────────────────────────
    all_arp = list(arp_entries)
    for dev in snmp_devices:
        for ae in dev.get("arp_entries", []):
            all_arp.append({"src_ip": ae["ip"], "src_mac": ae["mac"], "dst_ip": dev["ip"]})

    for ae in all_arp:
        src_ip  = ae.get("src_ip", "")
        src_mac = ae.get("src_mac", "")
        if src_ip and src_ip not in device_map:
            vendor = lookup_vendor(src_mac)
            device_map[src_ip] = {
                "id": _make_id(src_ip),
                "name": src_ip,
                "ip": src_ip,
                "mac": src_mac,
                "type": "host",
                "vendor": vendor,
                "interfaces": [],
                "_lldp_neighbors": [],
                "_arp_from_device": [],
            }
        elif src_ip and not device_map[src_ip]["mac"] and src_mac:
            device_map[src_ip]["mac"] = src_mac
            if device_map[src_ip]["vendor"] == "Unknown":
                device_map[src_ip]["vendor"] = lookup_vendor(src_mac)

    # ── build links from LLDP neighbors ──────────────────────────────────────
    links = []
    seen_links: set[frozenset] = set()

    for src_ip, dev in device_map.items():
        for nbr in dev.get("_lldp_neighbors", []):
            rem_name = nbr.get("remote_name", "")
            rem_port = nbr.get("remote_port", "")
            local_port = nbr.get("local_port", "")

            # Find destination device by name
            dst_dev = _find_device_by_name(device_map, rem_name)
            if dst_dev is None:
                # Create a stub for the neighbor
                stub_id = _make_id(rem_name or "unknown")
                dst_dev = {
                    "id": stub_id,
                    "name": rem_name,
                    "ip": "",
                    "mac": nbr.get("chassis_id", ""),
                    "type": "unknown",
                    "vendor": lookup_vendor(nbr.get("chassis_id", "")),
                    "interfaces": [],
                    "_lldp_neighbors": [],
                    "_arp_from_device": [],
                }
                device_map[f"__stub_{stub_id}"] = dst_dev

            src_id = dev["id"]
            dst_id = dst_dev["id"]
            link_key = frozenset([f"{src_id}:{local_port}", f"{dst_id}:{rem_port}"])
            if link_key not in seen_links:
                seen_links.add(link_key)
                links.append({
                    "src": src_id,
                    "src_port": local_port or "unknown",
                    "dst": dst_id,
                    "dst_port": rem_port or "unknown",
                    "speed": None,
                })

    # ── clean up internal fields before output ────────────────────────────────
    devices_out = []
    for dev in device_map.values():
        d = {k: v for k, v in dev.items() if not k.startswith("_")}
        devices_out.append(d)

    # Determine source label
    sources = []
    if snmp_devices:
        sources.append("lldp")
    if arp_entries:
        sources.append("arp")
    source_label = "+".join(sources) if sources else "none"

    return {
        "devices": devices_out,
        "links": links,
        "stats": {
            "devices": len(devices_out),
            "links": len(links),
            "discovered_at": now,
            "source": source_label,
        },
    }


def _make_id(name: str) -> str:
    """Convert a device name/IP to a safe topology ID."""
    s = name.lower()
    s = re.sub(r"[^a-z0-9]", "-", s)
    s = re.sub(r"-+", "-", s).strip("-")
    return s or "device"


def _find_device_by_name(device_map: dict, name: str) -> dict | None:
    """Find a device in the map by its name field (case-insensitive)."""
    name_lower = name.lower()
    for dev in device_map.values():
        if dev.get("name", "").lower() == name_lower:
            return dev
    return None


# ---------------------------------------------------------------------------
# Demo mode
# ---------------------------------------------------------------------------

def build_demo_topology() -> dict:
    """
    Generate a synthetic topology: 1 router, 2 switches, 5 hosts.
    Does not require SNMP or Elasticsearch.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    devices = [
        {
            "id": "rtr-core",
            "name": "router-core-01",
            "ip": "192.168.1.1",
            "mac": "cc:46:d6:01:00:01",
            "type": "router",
            "vendor": "Cisco",
            "interfaces": [
                {"port": "Gi0/0", "speed": 1000, "neighbor": "sw-core-01"},
                {"port": "Gi0/1", "speed": 1000, "neighbor": "sw-access-01"},
                {"port": "Gi0/2", "speed": 1000, "neighbor": None},
            ],
        },
        {
            "id": "sw-core-01",
            "name": "switch-core-01",
            "ip": "192.168.1.2",
            "mac": "00:1a:2b:3c:4d:5e",
            "type": "switch",
            "vendor": "Cisco",
            "interfaces": [
                {"port": "Gi0/1", "speed": 1000, "neighbor": "router-core-01"},
                {"port": "Gi0/2", "speed": 1000, "neighbor": "switch-access-01"},
                {"port": "Gi0/3", "speed": 100,  "neighbor": "host-fin-01"},
                {"port": "Gi0/4", "speed": 100,  "neighbor": "host-srv-01"},
            ],
        },
        {
            "id": "sw-access-01",
            "name": "switch-access-01",
            "ip": "192.168.1.3",
            "mac": "00:0b:86:ab:cd:ef",
            "type": "switch",
            "vendor": "Aruba",
            "interfaces": [
                {"port": "Gi0/1", "speed": 1000, "neighbor": "router-core-01"},
                {"port": "Fa0/1", "speed": 100,  "neighbor": "host-pc-01"},
                {"port": "Fa0/2", "speed": 100,  "neighbor": "host-pc-02"},
                {"port": "Fa0/3", "speed": 100,  "neighbor": "host-pc-03"},
            ],
        },
        {
            "id": "host-fin-01",
            "name": "host-fin-01",
            "ip": "192.168.1.10",
            "mac": "44:a8:42:10:00:01",
            "type": "host",
            "vendor": "Dell",
            "interfaces": [{"port": "eth0", "speed": 100, "neighbor": "switch-core-01"}],
        },
        {
            "id": "host-srv-01",
            "name": "host-srv-01",
            "ip": "192.168.1.11",
            "mac": "00:50:56:11:22:33",
            "type": "host",
            "vendor": "VMware",
            "interfaces": [{"port": "eth0", "speed": 1000, "neighbor": "switch-core-01"}],
        },
        {
            "id": "host-pc-01",
            "name": "host-pc-01",
            "ip": "192.168.2.10",
            "mac": "b0:83:fe:20:00:01",
            "type": "host",
            "vendor": "Dell",
            "interfaces": [{"port": "eth0", "speed": 100, "neighbor": "switch-access-01"}],
        },
        {
            "id": "host-pc-02",
            "name": "host-pc-02",
            "ip": "192.168.2.11",
            "mac": "00:17:08:30:00:02",
            "type": "host",
            "vendor": "HP",
            "interfaces": [{"port": "eth0", "speed": 100, "neighbor": "switch-access-01"}],
        },
        {
            "id": "host-pc-03",
            "name": "host-pc-03",
            "ip": "192.168.2.12",
            "mac": "fc:15:b4:40:00:03",
            "type": "host",
            "vendor": "HP",
            "interfaces": [{"port": "eth0", "speed": 100, "neighbor": "switch-access-01"}],
        },
    ]

    links = [
        {"src": "rtr-core",    "src_port": "Gi0/0", "dst": "sw-core-01",   "dst_port": "Gi0/1", "speed": 1000},
        {"src": "rtr-core",    "src_port": "Gi0/1", "dst": "sw-access-01", "dst_port": "Gi0/1", "speed": 1000},
        {"src": "sw-core-01",  "src_port": "Gi0/3", "dst": "host-fin-01",  "dst_port": "eth0",  "speed": 100},
        {"src": "sw-core-01",  "src_port": "Gi0/4", "dst": "host-srv-01",  "dst_port": "eth0",  "speed": 1000},
        {"src": "sw-access-01","src_port": "Fa0/1", "dst": "host-pc-01",   "dst_port": "eth0",  "speed": 100},
        {"src": "sw-access-01","src_port": "Fa0/2", "dst": "host-pc-02",   "dst_port": "eth0",  "speed": 100},
        {"src": "sw-access-01","src_port": "Fa0/3", "dst": "host-pc-03",   "dst_port": "eth0",  "speed": 100},
        {"src": "sw-core-01",  "src_port": "Gi0/2", "dst": "sw-access-01", "dst_port": "Gi0/2", "speed": 1000},
    ]

    return {
        "devices": devices,
        "links": links,
        "stats": {
            "devices": len(devices),
            "links": len(links),
            "discovered_at": now,
            "source": "demo",
        },
    }


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="NetWatch topology discovery (SNMP LLDP + ARP Zeek)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Demo mode (no SNMP/ES required)
  python3 topology-discover.py --demo

  # Discover from specific targets
  python3 topology-discover.py --targets 192.168.1.1,192.168.1.2 --community public

  # Custom output path
  python3 topology-discover.py --demo --output /tmp/topology.json --verbose
""",
    )
    parser.add_argument(
        "--targets", "-t",
        default="",
        help="Comma-separated list of target IPs for SNMP discovery",
    )
    parser.add_argument(
        "--community", "-c",
        default="public",
        help="SNMP v2c community string (default: public)",
    )
    parser.add_argument(
        "--output", "-o",
        default="scripts/security/topology.json",
        help="Output JSON file (default: scripts/security/topology.json)",
    )
    parser.add_argument(
        "--es-url",
        default="http://localhost:9200",
        help="Elasticsearch URL (default: http://localhost:9200)",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Generate demo topology without SNMP or Elasticsearch",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose/debug logging",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        log.setLevel(logging.DEBUG)

    # ── Demo mode ─────────────────────────────────────────────────────────────
    if args.demo:
        log.info("Demo mode: generating synthetic topology")
        topology = build_demo_topology()
        _write_output(topology, args.output)
        _print_summary(topology)
        return 0

    # ── Live mode ─────────────────────────────────────────────────────────────
    targets: list[str] = [t.strip() for t in args.targets.split(",") if t.strip()]

    # Check SNMP availability
    snmp_ok = _snmpwalk_available()
    if not snmp_ok:
        log.warning("snmpwalk binary not found — SNMP discovery disabled")
        log.warning("Install net-snmp-utils (dnf) or snmp (apt) to enable SNMP")

    # SNMP discovery
    snmp_devices: list[dict] = []
    if snmp_ok and targets:
        for target_ip in targets:
            try:
                dev = discover_device_snmp(target_ip, args.community, verbose=args.verbose)
                snmp_devices.append(dev)
            except Exception as exc:
                log.error("SNMP discovery failed for %s: %s", target_ip, exc)
    elif targets and not snmp_ok:
        # Create minimal stubs for each target so ARP data can still be attached
        for ip in targets:
            snmp_devices.append({
                "ip": ip, "mac": "", "name": ip,
                "sys_descr": "", "interfaces": [],
                "lldp_neighbors": [], "arp_entries": [],
            })

    # ARP from Elasticsearch (Zeek)
    arp_entries = fetch_arp_from_es(args.es_url, verbose=args.verbose)
    if not arp_entries and args.verbose:
        log.info("No ARP data from ES (ES may be unavailable or index empty)")

    if not snmp_devices and not arp_entries:
        log.warning("No data sources available. Use --demo for synthetic output.")
        log.warning("Specify --targets for SNMP, or ensure Elasticsearch is running.")
        # Write an empty topology rather than failing
        topology = {
            "devices": [],
            "links": [],
            "stats": {
                "devices": 0,
                "links": 0,
                "discovered_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "source": "none",
            },
        }
        _write_output(topology, args.output)
        return 1

    topology = build_topology(snmp_devices, arp_entries, verbose=args.verbose)
    _write_output(topology, args.output)
    _print_summary(topology)
    return 0


def _write_output(topology: dict, output_path: str) -> None:
    """Write topology JSON to file, creating parent directories as needed."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(topology, fh, indent=2, ensure_ascii=False)
    log.info("Topology written to %s", path)


def _print_summary(topology: dict) -> None:
    """Print a human-readable summary to stdout."""
    stats = topology.get("stats", {})
    print(f"\n=== NetWatch Topology Discovery ===")
    print(f"  Devices   : {stats.get('devices', 0)}")
    print(f"  Links     : {stats.get('links', 0)}")
    print(f"  Source    : {stats.get('source', 'unknown')}")
    print(f"  Timestamp : {stats.get('discovered_at', 'N/A')}")
    print()

    devices = topology.get("devices", [])
    if devices:
        print("Devices:")
        for dev in sorted(devices, key=lambda d: d.get("type", "")):
            print(
                f"  [{dev.get('type','?'):8s}] {dev.get('name','?'):25s}  "
                f"IP:{dev.get('ip','?'):18s}  "
                f"MAC:{dev.get('mac','?'):19s}  "
                f"Vendor:{dev.get('vendor','?')}"
            )

    links = topology.get("links", [])
    if links:
        print("\nLinks:")
        for link in links:
            speed_str = f" ({link['speed']}M)" if link.get("speed") else ""
            print(
                f"  {link.get('src','?')}:{link.get('src_port','?')}"
                f" ↔ {link.get('dst','?')}:{link.get('dst_port','?')}"
                f"{speed_str}"
            )
    print()


if __name__ == "__main__":
    sys.exit(main())
