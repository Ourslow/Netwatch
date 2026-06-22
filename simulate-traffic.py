#!/usr/bin/env python3
"""
NetWatch — Simulateur de trafic réseau
Injecte des logs simulés dans Elasticsearch pour alimenter tous les dashboards.
Usage : python3 simulate-traffic.py [--hours 24] [--es http://localhost:9200] [--attack] [--intensity low|medium|high]
"""

import json
import random
import string
import time
import argparse
import sys
from datetime import datetime, timedelta, timezone
from urllib.request import Request, urlopen
from urllib.error import URLError

# ============================================================
# Configuration
# ============================================================

# IPs internes simulées
INTERNAL_IPS = [
    "10.10.7.221", "10.10.7.45", "10.10.7.102", "10.10.7.88",
    "10.10.7.33", "10.10.7.150", "10.10.7.200", "10.10.7.15",
    "172.31.250.188", "172.31.250.50", "172.31.250.100"
]

# IPs externes simulées — trafic légitime (CDN, DNS publics)
EXTERNAL_IPS = [
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
    "104.18.27.120", "151.101.1.140", "140.82.121.4",
    "172.217.22.110", "93.184.216.34", "13.107.42.14",
    "34.120.177.193", "52.85.132.99", "54.230.10.42",
    "23.45.67.89", "185.199.108.153", "199.232.69.194",
    "157.240.1.35", "31.13.65.36", "69.171.250.35",
]

# IPs sources d'attaque avec coordonnées GeoIP embarquées
# Format : ip -> {lat, lon, country_name, country_iso_code, city_name}
ATTACK_GEO = {
    # Russie
    "5.8.8.180":       {"lat": 55.75, "lon": 37.62, "country_name": "Russia",       "country_iso_code": "RU", "city_name": "Moscow"},
    "5.45.208.10":     {"lat": 59.89, "lon": 30.32, "country_name": "Russia",       "country_iso_code": "RU", "city_name": "Saint Petersburg"},
    "194.165.16.42":   {"lat": 55.75, "lon": 37.62, "country_name": "Russia",       "country_iso_code": "RU", "city_name": "Moscow"},
    "91.108.4.15":     {"lat": 55.75, "lon": 37.62, "country_name": "Russia",       "country_iso_code": "RU", "city_name": "Moscow"},
    # Chine
    "1.180.0.12":      {"lat": 39.93, "lon": 116.39, "country_name": "China",       "country_iso_code": "CN", "city_name": "Beijing"},
    "58.30.8.21":      {"lat": 31.22, "lon": 121.46, "country_name": "China",       "country_iso_code": "CN", "city_name": "Shanghai"},
    "114.114.114.114": {"lat": 32.06, "lon": 118.77, "country_name": "China",       "country_iso_code": "CN", "city_name": "Nanjing"},
    "219.76.15.8":     {"lat": 22.27, "lon": 114.17, "country_name": "Hong Kong",   "country_iso_code": "HK", "city_name": "Hong Kong"},
    # Corée du Nord
    "175.45.176.5":    {"lat": 39.03, "lon": 125.75, "country_name": "North Korea", "country_iso_code": "KP", "city_name": "Pyongyang"},
    "175.45.179.12":   {"lat": 39.03, "lon": 125.75, "country_name": "North Korea", "country_iso_code": "KP", "city_name": "Pyongyang"},
    # Iran
    "5.160.0.48":      {"lat": 35.69, "lon": 51.42, "country_name": "Iran",         "country_iso_code": "IR", "city_name": "Tehran"},
    "78.38.30.7":      {"lat": 35.69, "lon": 51.42, "country_name": "Iran",         "country_iso_code": "IR", "city_name": "Tehran"},
    "94.182.195.3":    {"lat": 35.69, "lon": 51.42, "country_name": "Iran",         "country_iso_code": "IR", "city_name": "Tehran"},
    # Roumanie
    "79.112.0.60":     {"lat": 44.43, "lon": 26.10, "country_name": "Romania",      "country_iso_code": "RO", "city_name": "Bucharest"},
    "79.115.12.88":    {"lat": 44.43, "lon": 26.10, "country_name": "Romania",      "country_iso_code": "RO", "city_name": "Bucharest"},
    # Pays-Bas
    "31.3.96.45":      {"lat": 52.37, "lon": 4.90,  "country_name": "Netherlands",  "country_iso_code": "NL", "city_name": "Amsterdam"},
    "188.165.200.12":  {"lat": 52.37, "lon": 4.90,  "country_name": "Netherlands",  "country_iso_code": "NL", "city_name": "Amsterdam"},
    "185.220.101.5":   {"lat": 52.37, "lon": 4.90,  "country_name": "Netherlands",  "country_iso_code": "NL", "city_name": "Amsterdam"},
    # Brésil
    "177.71.0.82":     {"lat": -23.55, "lon": -46.63, "country_name": "Brazil",     "country_iso_code": "BR", "city_name": "Sao Paulo"},
    "200.147.55.3":    {"lat": -22.90, "lon": -43.17, "country_name": "Brazil",     "country_iso_code": "BR", "city_name": "Rio de Janeiro"},
    # Inde
    "117.18.0.55":     {"lat": 28.61, "lon": 77.21, "country_name": "India",        "country_iso_code": "IN", "city_name": "New Delhi"},
    "49.206.12.8":     {"lat": 19.08, "lon": 72.88, "country_name": "India",        "country_iso_code": "IN", "city_name": "Mumbai"},
    # Allemagne
    "46.23.0.82":      {"lat": 52.52, "lon": 13.40, "country_name": "Germany",      "country_iso_code": "DE", "city_name": "Berlin"},
    "85.214.55.3":     {"lat": 53.57, "lon": 10.02, "country_name": "Germany",      "country_iso_code": "DE", "city_name": "Hamburg"},
    # France
    "217.70.184.38":   {"lat": 48.86, "lon": 2.35,  "country_name": "France",       "country_iso_code": "FR", "city_name": "Paris"},
    "88.190.16.12":    {"lat": 48.86, "lon": 2.35,  "country_name": "France",       "country_iso_code": "FR", "city_name": "Paris"},
    # États-Unis
    "23.45.67.89":     {"lat": 37.39, "lon": -122.08, "country_name": "United States", "country_iso_code": "US", "city_name": "Mountain View"},
    "104.21.48.3":     {"lat": 37.78, "lon": -122.41, "country_name": "United States", "country_iso_code": "US", "city_name": "San Francisco"},
    "198.199.64.12":   {"lat": 40.71, "lon": -74.01,  "country_name": "United States", "country_iso_code": "US", "city_name": "New York"},
}
ATTACK_IPS = list(ATTACK_GEO.keys())


def attack_geo(ip):
    """Retourne le bloc source.geo pour une IP d'attaque."""
    g = ATTACK_GEO.get(ip, {})
    if not g:
        return {}
    return {
        "location":          {"lat": g["lat"], "lon": g["lon"]},
        "country_name":      g["country_name"],
        "country_iso_code":  g["country_iso_code"],
        "city_name":         g["city_name"],
    }

# Domaines normaux
NORMAL_DOMAINS = [
    "google.com", "github.com", "wikipedia.org", "stackoverflow.com",
    "cloudflare.com", "amazon.com", "microsoft.com", "apple.com",
    "netflix.com", "twitter.com", "facebook.com", "linkedin.com",
    "reddit.com", "youtube.com", "mozilla.org", "debian.org",
    "ubuntu.com", "docker.com", "elastic.co", "grafana.com",
    "office365.com", "outlook.com", "teams.microsoft.com",
    "slack.com", "zoom.us", "dropbox.com", "drive.google.com"
]

# Domaines suspects (haute entropie, type DGA)
DGA_DOMAINS = [
    "xkjhqpwmzr.com", "vjkqplxnbt.net", "rnmxqjzpvl.org",
    "hqzwxpnrjm.com", "bvnxkqzprl.net", "qwzxnkprlm.org",
    "tmhkqxjnvr.com", "plwqxzrnbk.net", "jnxqzwprkm.info",
    "xvnqkzjpmr.biz"
]

# Protocoles et ports
COMMON_PORTS = {
    22: "ssh", 53: "dns", 80: "http", 443: "ssl",
    8080: "http-alt", 3306: "mysql", 5432: "postgresql",
    25: "smtp", 110: "pop3", 143: "imap", 993: "imaps",
    3389: "rdp", 8443: "https-alt", 9200: "elasticsearch"
}

HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"]
HTTP_STATUS_CODES = [200, 200, 200, 200, 200, 301, 302, 304, 400, 401, 403, 404, 500, 502, 503]
HTTP_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "curl/8.5.0",
    "python-requests/2.31.0",
    "Go-http-client/2.0",
    "Wget/1.21"
]

TLS_VERSIONS = ["TLSv13", "TLSv13", "TLSv13", "TLSv12", "TLSv12", "TLSv11", "TLSv10"]
TLS_ISSUERS = [
    "CN=R3,O=Let's Encrypt,C=US",
    "CN=DigiCert Global G2,O=DigiCert Inc,C=US",
    "CN=GTS CA 1C3,O=Google Trust Services LLC,C=US",
    "CN=Amazon RSA 2048 M02,O=Amazon,C=US",
    "CN=Cloudflare Inc ECC CA-3,O=Cloudflare Inc,C=US"
]

# JA3 fingerprints (MD5 des paramètres TLS client)
JA3_NORMAL = [
    "a0e9f5d64349fb13191bc781f81f42e1",  # Firefox
    "8a59ba96178c6a56a8de86a4fc93e9ee",  # Chrome
    "c35a0a51fdfc86fa5e3da6cbf7b5a4bd",  # curl
    "29f97c2e4e15e8edd3f08768fff3fd42",  # Python requests
    "dadae1b59d788f0c854b5e1a94b8ee6f",  # Safari
]
JA3_MALICIOUS = [
    "e7d705a3286e19ea42f587b6d7f83a35",  # Emotet
    "6734f37431670b3ab4292b8f60f29984",  # Trickbot
    "26caf660a5c9fc71f2f88ca1b0d3d2e3",  # CobaltStrike default
    "b386946a5a44d1ddcc843bc75336dfce",  # Metasploit
]
JA3S_VALUES = [
    "9d93b2d1c78f31563ea0bd51a6e78e93",
    "f4febc55ea12b31ae17cfb7e614afda8",
    "15af977ce25de452b96affa2addb1036",
]

# HASSH fingerprints SSH (MD5 des algorithmes négociés)
HASSH_NORMAL = [
    "92674389fa1e47a27ddd8d9b63ecd42b",  # OpenSSH client typique
    "5c78543a9a0c66c56558ffd38bdf7905",  # PuTTY
    "b12a2d992d9e63bc0cb1e1e0db57e0d6",  # Paramiko (Python)
]
HASSH_MALICIOUS = [
    "3f0099d323fed57a7c00e89a4e3d8e23",  # Impacket
    "b8c7b947e4c0b94bb3d3a0e1b00b9e4c",  # Cobalt Strike SSH
]
HASSH_SERVER = [
    "b12a2d992d9e63bc0cb1e1e0db57e0d6",
    "2dd9e3f4a61a9bb50d0fdb7c39e06e51",
    "8a4b3e5f6c7d8e9a0b1c2d3e4f5a6b7c",
]

# Domaines pour DNS tunneling (sous-domaines très longs)
DNS_TUNNEL_DOMAINS = [
    "dGhpcyBpcyBleGZpbHRyYXRlZCBkYXRh.evil-c2.net",
    "aGVsbG93b3JsZHRlc3RkYXRhYmFzZTY0ZW5jb2RlZA.badactor.xyz",
    "bG9uZ3N1YmRvbWFpbnRlc3RmZm9yZG5zdHVubmVsaW5n.c2tunnel.top",
    "dGVzdGV4ZmlsdHJhdGlvbmRhdGE.exfil.info",
    "aGVsbG93b3JsZGZyb21iZWFjb24.beacon-c2.biz",
]

# Signatures Suricata avec MITRE ATT&CK
SURICATA_SIGS_MITRE = [
    (2000001, "NETWATCH - ICMP Ping Sweep detected",         "network-scan",         2, "Reconnaissance",      "T1595"),
    (2000002, "NETWATCH - SSH Brute Force Attempt",          "attempted-admin",       1, "Credential Access",   "T1110"),
    (2000004, "NETWATCH - Obsolete TLS version (TLSv1.0)",   "policy-violation",      3, "Defense Evasion",     "T1027"),
    (2000006, "NETWATCH - Cleartext password in HTTP POST",  "policy-violation",      2, "Credential Access",   "T1552"),
    (2000007, "NETWATCH - Large outbound transfer",          "policy-violation",      1, "Exfiltration",        "T1048"),
    (2013028, "ET POLICY curl User-Agent Outbound",          "policy-violation",      3, "Command and Control", "T1071"),
    (2001219, "ET SCAN Potential SSH Scan",                  "network-scan",          2, "Reconnaissance",      "T1046"),
    (2008578, "ET EXPLOIT Metasploit Framework User-Agent",  "web-application-attack",1, "Execution",           "T1203"),
    (2019714, "ET DNS Query for .xyz TLD",                   "bad-unknown",           3, "Command and Control", "T1568"),
    (2021376, "ET POLICY Python-urllib User-Agent",          "policy-violation",      3, "Command and Control", "T1071"),
    (2022973, "ET SCAN Possible Nmap User-Agent Observed",   "network-scan",          2, "Reconnaissance",      "T1595"),
    (2010935, "ET POLICY Dropbox Offsite Backup In Use",     "policy-violation",      3, "Exfiltration",        "T1567"),
]

# IPs malveillantes (Feodo Tracker simulé) pour Intel hits
MALICIOUS_IPS = [
    "185.220.101.45", "194.165.16.11", "91.219.236.166",
    "45.153.160.2",   "62.233.50.246",  "77.73.133.84",
]
MALICIOUS_DOMAINS = [
    "emotet-c2.xyz", "qakbot-panel.top", "cobalt-strike.info",
    "dridex-loader.net", "trickbot-c2.biz",
]

CONN_STATES = ["SF", "SF", "SF", "SF", "S0", "S1", "REJ", "RSTO", "RSTR", "OTH"]
NOTICE_TYPES = [
    "PortScan::Port_Scan_Detected",
    "DNSEntropy::High_Entropy_DNS",
    "SSL::Certificate_Expired",
    "SSL::Certificate_Not_Valid_Yet"
]

# Signatures Snort 3 (règles custom + community)
SNORT_SIGS = [
    ("NETWATCH - ICMP Ping Sweep", "network-scan", 2, "icmp"),
    ("NETWATCH - SSH Brute Force Attempt", "attempted-admin", 1, "tcp"),
    ("NETWATCH - DNS Query to suspicious TLD", "bad-unknown", 3, "udp"),
    ("NETWATCH - Cleartext credentials over HTTP", "policy-violation", 2, "tcp"),
    ("NETWATCH - Possible data exfiltration (large upload)", "policy-violation", 1, "tcp"),
    ("NETWATCH - Connection to non-standard port", "bad-unknown", 3, "tcp"),
    ("NETWATCH - Suspicious User-Agent (curl)", "bad-unknown", 3, "tcp"),
    ("ET SCAN Nmap Scripting Engine User-Agent", "network-scan", 2, "tcp"),
    ("GPL ICMP_INFO PING", "misc-activity", 3, "icmp"),
    ("ET POLICY External IP Lookup", "policy-violation", 3, "tcp"),
    ("ET SCAN Potential SSH Scan OUTBOUND", "network-scan", 2, "tcp"),
    ("ET POLICY Cleartext Password Detected", "policy-violation", 2, "tcp"),
]

# ============================================================
# Générateurs de logs
# ============================================================

def random_uid():
    chars = string.ascii_letters + string.digits
    return "C" + "".join(random.choices(chars, k=17))

def random_ts(base_time, jitter_seconds=300):
    offset = random.randint(-jitter_seconds, jitter_seconds)
    ts = base_time + timedelta(seconds=offset)
    return ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

def gen_conn_log(ts):
    src = random.choice(INTERNAL_IPS)
    dst = random.choice(EXTERNAL_IPS + INTERNAL_IPS)
    proto = random.choices(["tcp", "udp", "icmp"], weights=[70, 25, 5])[0]
    dst_port = random.choice(list(COMMON_PORTS.keys())) if proto != "icmp" else 0
    src_port = random.randint(1024, 65535)
    duration = round(random.uniform(0.001, 30.0), 6)
    orig_bytes = random.randint(40, 50000)
    resp_bytes = random.randint(40, 500000)
    state = random.choice(CONN_STATES)

    return {
        "ts": ts,
        "@timestamp": ts,
        "uid": random_uid(),
        "id.orig_h": src,
        "id.orig_p": src_port,
        "id.resp_h": dst,
        "id.resp_p": dst_port,
        "proto": proto,
        "duration": duration,
        "orig_bytes": orig_bytes,
        "resp_bytes": resp_bytes,
        "conn_state": state,
        "missed_bytes": 0,
        "orig_pkts": random.randint(1, 200),
        "orig_ip_bytes": orig_bytes + random.randint(20, 100),
        "resp_pkts": random.randint(1, 500),
        "resp_ip_bytes": resp_bytes + random.randint(20, 100),
        "log_type": "zeek",
        "log_source": "conn"
    }

def gen_dns_log(ts, suspicious=False):
    src = random.choice(INTERNAL_IPS)
    dns_server = random.choice(["8.8.8.8", "8.8.4.4", "1.1.1.1", "172.16.1.140"])

    if suspicious:
        domain = random.choice(DGA_DOMAINS)
        rcode = random.choice([0, 3, 3, 3])  # plus de NXDOMAIN pour DGA
    else:
        domain = random.choice(NORMAL_DOMAINS)
        rcode = random.choices([0, 0, 0, 0, 3], weights=[80, 5, 5, 5, 5])[0]

    qtype = random.choices([1, 28, 15, 2, 5], weights=[60, 15, 10, 10, 5])[0]
    qtype_names = {1: "A", 28: "AAAA", 15: "MX", 2: "NS", 5: "CNAME"}
    rcode_names = {0: "NOERROR", 3: "NXDOMAIN", 2: "SERVFAIL", 5: "REFUSED"}

    answers = []
    if rcode == 0 and qtype == 1:
        answers = [f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"]

    return {
        "ts": ts,
        "@timestamp": ts,
        "uid": random_uid(),
        "id.orig_h": src,
        "id.orig_p": random.randint(1024, 65535),
        "id.resp_h": dns_server,
        "id.resp_p": 53,
        "proto": "udp",
        "query": domain,
        "qtype": qtype,
        "qtype_name": qtype_names.get(qtype, "A"),
        "qclass": 1,
        "qclass_name": "C_INTERNET",
        "rcode": rcode,
        "rcode_name": rcode_names.get(rcode, "NOERROR"),
        "AA": False,
        "TC": False,
        "RD": True,
        "RA": True,
        "answers": answers,
        "rtt": round(random.uniform(0.001, 0.5), 6) if rcode == 0 else None,
        "log_type": "zeek",
        "log_source": "dns"
    }

def gen_http_log(ts):
    src = random.choice(INTERNAL_IPS)
    host = random.choice(NORMAL_DOMAINS)
    dst = random.choice(EXTERNAL_IPS)
    method = random.choices(HTTP_METHODS, weights=[60, 20, 5, 2, 8, 5])[0]
    status = random.choice(HTTP_STATUS_CODES)
    uris = ["/", "/index.html", "/api/v1/data", "/login", "/search?q=test",
            "/assets/style.css", "/images/logo.png", "/api/users", "/health",
            "/dashboard", "/api/v2/metrics", "/favicon.ico"]

    return {
        "ts": ts,
        "@timestamp": ts,
        "uid": random_uid(),
        "id.orig_h": src,
        "id.orig_p": random.randint(1024, 65535),
        "id.resp_h": dst,
        "id.resp_p": 80,
        "method": method,
        "host": host,
        "uri": random.choice(uris),
        "status_code": status,
        "request_body_len": random.randint(0, 5000),
        "response_body_len": random.randint(100, 500000),
        "user_agent": random.choice(HTTP_USER_AGENTS),
        "log_type": "zeek",
        "log_source": "http"
    }

def gen_ssl_log(ts, malicious=False):
    src = random.choice(INTERNAL_IPS)
    dst = random.choice(EXTERNAL_IPS)
    server = random.choice(NORMAL_DOMAINS)
    version = random.choice(TLS_VERSIONS)
    ja3 = random.choice(JA3_MALICIOUS if malicious else JA3_NORMAL)
    ja3s = random.choice(JA3S_VALUES)

    return {
        "ts": ts,
        "@timestamp": ts,
        "uid": random_uid(),
        "id.orig_h": src,
        "id.orig_p": random.randint(1024, 65535),
        "id.resp_h": dst,
        "id.resp_p": 443,
        "version": version,
        "server_name": server,
        "subject": f"CN={server}",
        "issuer": random.choice(TLS_ISSUERS),
        "established": True,
        "ja3": ja3,
        "ja3s": ja3s,
        "log_type": "zeek",
        "log_source": "ssl"
    }

def gen_ssh_log(ts, malicious=False):
    src = random.choice(INTERNAL_IPS)
    dst = random.choice(EXTERNAL_IPS + INTERNAL_IPS)
    hassh = random.choice(HASSH_MALICIOUS if malicious else HASSH_NORMAL)

    return {
        "ts": ts,
        "@timestamp": ts,
        "uid": random_uid(),
        "id.orig_h": src,
        "id.orig_p": random.randint(1024, 65535),
        "id.resp_h": dst,
        "id.resp_p": 22,
        "version": random.choice([1, 2]),
        "auth_success": not malicious,
        "auth_attempts": random.randint(1, 3) if not malicious else random.randint(5, 20),
        "direction": "OUTBOUND",
        "client": random.choice(["OpenSSH_8.9", "OpenSSH_9.3", "PuTTY_0.79"]),
        "server": "OpenSSH_8.9",
        "hassh": hassh,
        "hassh_server": random.choice(HASSH_SERVER),
        "log_type": "zeek",
        "log_source": "ssh"
    }

def gen_intel_log(ts):
    src = random.choice(INTERNAL_IPS)
    hit_type = random.choice(["Intel::ADDR", "Intel::DOMAIN"])
    if hit_type == "Intel::ADDR":
        indicator = random.choice(MALICIOUS_IPS)
        where = random.choice(["Conn::IN_ORIG", "Conn::IN_RESP"])
    else:
        indicator = random.choice(MALICIOUS_DOMAINS)
        where = "DNS::IN_REQUEST"

    return {
        "ts": ts,
        "@timestamp": ts,
        "uid": random_uid(),
        "id.orig_h": src,
        "id.orig_p": random.randint(1024, 65535),
        "id.resp_h": indicator if hit_type == "Intel::ADDR" else random.choice(EXTERNAL_IPS),
        "id.resp_p": random.choice([80, 443, 53]),
        "seen.indicator": indicator,
        "seen.indicator_type": hit_type,
        "seen.where": where,
        "seen.node": "netwatch-zeek",
        "sources": ["Feodo Tracker" if hit_type == "Intel::ADDR" else "URLhaus"],
        "log_type": "zeek",
        "log_source": "intel"
    }

def gen_notice_log(ts, notice_type=None):
    src = random.choice(INTERNAL_IPS)
    dst = random.choice(EXTERNAL_IPS)
    note = notice_type or random.choice(NOTICE_TYPES)

    messages = {
        "PortScan::Port_Scan_Detected": f"Port scan depuis {src} : {random.randint(51, 200)} ports en 60sec",
        "DNSEntropy::High_Entropy_DNS": f"Domaine suspect (entropie={round(random.uniform(3.6, 4.5), 2)}) : {random.choice(DGA_DOMAINS)}",
        "SSL::Certificate_Expired": f"Certificat expire pour {random.choice(NORMAL_DOMAINS)}",
        "SSL::Certificate_Not_Valid_Yet": f"Certificat pas encore valide pour {random.choice(NORMAL_DOMAINS)}"
    }

    return {
        "ts": ts,
        "@timestamp": ts,
        "uid": random_uid(),
        "note": note,
        "msg": messages.get(note, "Unknown notice"),
        "src": src,
        "dst": dst,
        "p": random.choice([22, 53, 80, 443]),
        "actions": ["Notice::ACTION_LOG"],
        "log_type": "zeek",
        "log_source": "notice"
    }

def gen_snort_alert(ts):
    sig_msg, classtype, priority, proto = random.choice(SNORT_SIGS)
    src = random.choice(ATTACK_IPS)   # attaque toujours depuis une IP externe géolocalisable
    dst = random.choice(INTERNAL_IPS)
    if proto == "icmp":
        src_port, dst_port, service = 0, 0, "unknown"
    elif proto == "udp":
        src_port, dst_port, service = random.randint(1024, 65535), 53, "dns"
    else:
        dst_port = random.choice([22, 80, 443, 8080, 3389])
        src_port = random.randint(1024, 65535)
        service = {22: "ssh", 80: "http", 443: "ssl", 8080: "http", 3389: "netbios"}.get(dst_port, "unknown")
    return {
        "@timestamp": ts, "timestamp": ts,
        "pkt_num": random.randint(1000, 999999),
        "proto": proto.upper(), "pkt_gen": "raw",
        "pkt_len": random.randint(40, 1500), "dir": "C2S",
        "src_addr": src, "src_port": src_port,
        "dst_addr": dst, "dst_port": dst_port,
        "service": service,
        "rule": f"1:{random.randint(1000001, 1000999)}:1",
        "action": "alert", "msg": sig_msg,
        "priority": priority, "class_desc": classtype,
        "log_type": "snort", "engine": "snort",
        "source": {"geo": attack_geo(src)},
    }

def gen_suricata_alert(ts):
    sid, sig_msg, category, severity, mitre_tactic, mitre_technique = random.choice(SURICATA_SIGS_MITRE)
    src = random.choice(ATTACK_IPS)   # attaque toujours depuis une IP externe géolocalisable
    dst = random.choice(INTERNAL_IPS)
    proto = random.choices(["TCP", "UDP", "ICMP"], weights=[60, 30, 10])[0]
    dst_port = random.choice([22, 53, 80, 443, 8080, 3389]) if proto != "ICMP" else 0
    src_port = random.randint(1024, 65535) if proto != "ICMP" else 0
    return {
        "@timestamp": ts, "timestamp": ts,
        "flow_id": random.randint(100000000, 999999999),
        "in_iface": "eth0", "event_type": "alert",
        "src_ip": src, "src_port": src_port,
        "dest_ip": dst, "dest_port": dst_port,
        "proto": proto,
        "community_id": f"1:{random_uid()[:8]}==",
        "alert": {
            "action": "allowed", "gid": 1,
            "signature_id": sid, "rev": 1,
            "signature": sig_msg, "category": category, "severity": severity,
            "metadata": {
                "mitre_tactic_name": [mitre_tactic],
                "mitre_technique_id": [mitre_technique]
            }
        },
        "log_type": "suricata", "engine": "suricata",
        "source": {"geo": attack_geo(src)},
    }

def gen_long_connection(ts, src=None, dst=None):
    """Connexion longue (> 1h) — détectée par beacon-detect comme tunnel potentiel"""
    src = src or random.choice(INTERNAL_IPS)
    dst = dst or random.choice(EXTERNAL_IPS)
    duration_s = random.uniform(3600, 28800)  # 1h à 8h
    return {
        "ts": ts,
        "@timestamp": ts,
        "uid": random_uid(),
        "id.orig_h": src,
        "id.orig_p": random.randint(1024, 65535),
        "id.resp_h": dst,
        "id.resp_p": random.choice([443, 80, 22, 8443, 4444]),
        "proto": "tcp",
        "duration": round(duration_s, 3),
        "orig_bytes": random.randint(10000, 5000000),
        "resp_bytes": random.randint(10000, 2000000),
        "conn_state": "SF",
        "missed_bytes": 0,
        "orig_pkts": random.randint(1000, 50000),
        "resp_pkts": random.randint(1000, 50000),
        "orig_ip_bytes": random.randint(10000, 5000000),
        "resp_ip_bytes": random.randint(10000, 2000000),
        "log_type": "zeek",
        "log_source": "conn"
    }

def gen_beaconing_batch(base_time, interval_s=60, count=30, jitter_pct=0.05):
    """Génère une série de connexions régulières (beacon C2) — CV < 0.25"""
    src = random.choice(INTERNAL_IPS)
    dst = random.choice(EXTERNAL_IPS)
    port = random.choice([80, 443, 8080, 4444])
    docs = []
    ts = base_time
    for _ in range(count):
        jitter = random.uniform(-interval_s * jitter_pct, interval_s * jitter_pct)
        ts = ts + timedelta(seconds=interval_s + jitter)
        if ts.replace(tzinfo=None) > datetime.utcnow():
            break
        ts_str = ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        docs.append({
            "ts": ts_str,
            "@timestamp": ts_str,
            "uid": random_uid(),
            "id.orig_h": src,
            "id.orig_p": random.randint(1024, 65535),
            "id.resp_h": dst,
            "id.resp_p": port,
            "proto": "tcp",
            "duration": round(random.uniform(0.1, 2.0), 3),
            "orig_bytes": random.randint(200, 800),
            "resp_bytes": random.randint(200, 1200),
            "conn_state": "SF",
            "missed_bytes": 0,
            "orig_pkts": random.randint(3, 8),
            "resp_pkts": random.randint(3, 8),
            "orig_ip_bytes": random.randint(200, 900),
            "resp_ip_bytes": random.randint(200, 1400),
            "log_type": "zeek",
            "log_source": "conn"
        })
    return docs

def gen_dns_tunnel(ts):
    """Requête DNS avec sous-domaine très long (> 40 chars) — indicateur de tunneling"""
    src = random.choice(INTERNAL_IPS)
    domain = random.choice(DNS_TUNNEL_DOMAINS)
    return {
        "ts": ts,
        "@timestamp": ts,
        "uid": random_uid(),
        "id.orig_h": src,
        "id.orig_p": random.randint(1024, 65535),
        "id.resp_h": "8.8.8.8",
        "id.resp_p": 53,
        "proto": "udp",
        "query": domain,
        "qtype": 16,
        "qtype_name": "TXT",
        "qclass": 1,
        "qclass_name": "C_INTERNET",
        "rcode": 0,
        "rcode_name": "NOERROR",
        "AA": False, "TC": False, "RD": True, "RA": True,
        "answers": [],
        "rtt": round(random.uniform(0.05, 0.3), 6),
        "log_type": "zeek",
        "log_source": "dns"
    }

# ============================================================
# Profils de trafic par heure
# ============================================================

def traffic_multiplier(hour):
    """Simule un profil jour/nuit réaliste"""
    profiles = {
        0: 0.2, 1: 0.1, 2: 0.1, 3: 0.1, 4: 0.1, 5: 0.15,
        6: 0.3, 7: 0.5, 8: 0.8, 9: 1.0, 10: 1.0, 11: 0.95,
        12: 0.7, 13: 0.85, 14: 1.0, 15: 0.95, 16: 0.9, 17: 0.7,
        18: 0.5, 19: 0.4, 20: 0.35, 21: 0.3, 22: 0.25, 23: 0.2
    }
    return profiles.get(hour, 0.5)

# ============================================================
# Injection Elasticsearch
# ============================================================

def bulk_index(es_url, docs, index_name):
    """Envoie un batch de documents via l'API Bulk"""
    bulk_body = ""
    for doc in docs:
        action = json.dumps({"index": {"_index": index_name}})
        body = json.dumps(doc)
        bulk_body += action + "\n" + body + "\n"

    req = Request(
        f"{es_url}/_bulk",
        data=bulk_body.encode("utf-8"),
        headers={"Content-Type": "application/x-ndjson"},
        method="POST"
    )
    try:
        resp = urlopen(req)
        result = json.loads(resp.read())
        if result.get("errors"):
            print(f"  [!] Quelques erreurs dans le batch")
        return len(docs)
    except URLError as e:
        print(f"  [ERREUR] {e}")
        return 0

# ============================================================
# Main
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="NetWatch Traffic Simulator")
    parser.add_argument("--hours", type=int, default=24, help="Nombre d'heures a simuler (defaut: 24)")
    parser.add_argument("--es", type=str, default="http://localhost:9200", help="URL Elasticsearch")
    parser.add_argument("--intensity", type=str, default="medium",
                        choices=["low", "medium", "high"],
                        help="Intensite du trafic (low/medium/high)")
    parser.add_argument("--attack", action="store_true", help="Inclure des scenarios d'attaque")
    args = parser.parse_args()

    intensity_base = {"low": 20, "medium": 50, "high": 150}
    base_events = intensity_base[args.intensity]

    # Vérifier la connexion ES
    try:
        resp = urlopen(f"{args.es}/_cluster/health")
        health = json.loads(resp.read())
        print(f"[+] Elasticsearch connecte ({health['cluster_name']}, status: {health['status']})")
    except Exception as e:
        print(f"[ERREUR] Impossible de se connecter a Elasticsearch: {e}")
        sys.exit(1)

    now = datetime.now(timezone.utc)
    start_time = now - timedelta(hours=args.hours)
    total_docs = 0

    print(f"[+] Simulation de {args.hours}h de trafic (intensite: {args.intensity})")
    print(f"[+] Periode : {start_time.strftime('%Y-%m-%d %H:%M')} -> {now.strftime('%Y-%m-%d %H:%M')}")
    if args.attack:
        print("[+] Mode attaque active : inclusion de scans, DGA, et anomalies")
    print()

    # Générer par tranches de 10 minutes
    current_time = start_time
    batch = []
    snort_batch = []
    suricata_batch = []
    batch_size = 500

    while current_time < now:
        hour = current_time.hour
        multiplier = traffic_multiplier(hour)
        events_count = int(base_events * multiplier * random.uniform(0.7, 1.3))

        # --- Connexions (40% du trafic) ---
        for _ in range(int(events_count * 0.4)):
            ts = random_ts(current_time, 300)
            batch.append(gen_conn_log(ts))

        # --- DNS (30% du trafic) ---
        for _ in range(int(events_count * 0.3)):
            ts = random_ts(current_time, 300)
            suspicious = random.random() < 0.03  # 3% suspect
            batch.append(gen_dns_log(ts, suspicious))

        # --- HTTP (15% du trafic) ---
        for _ in range(int(events_count * 0.15)):
            ts = random_ts(current_time, 300)
            batch.append(gen_http_log(ts))

        # --- TLS/SSL avec JA3/JA3S (15% du trafic) ---
        for _ in range(int(events_count * 0.15)):
            ts = random_ts(current_time, 300)
            batch.append(gen_ssl_log(ts))

        # --- SSH avec HASSH (5% du trafic) ---
        for _ in range(max(1, int(events_count * 0.05))):
            ts = random_ts(current_time, 300)
            batch.append(gen_ssh_log(ts))

        # --- IDS alertes baseline (trafic normal) ---
        ids_count = max(1, int(events_count * 0.03))
        for _ in range(random.randint(0, ids_count)):
            snort_batch.append(gen_snort_alert(random_ts(current_time, 300)))
        for _ in range(random.randint(0, ids_count)):
            suricata_batch.append(gen_suricata_alert(random_ts(current_time, 300)))

        # --- Attaques simulées ---
        if args.attack:
            # Port scan toutes les ~2h
            if random.random() < 0.08:
                ts = random_ts(current_time, 300)
                batch.append(gen_notice_log(ts, "PortScan::Port_Scan_Detected"))
                scanner_ip = random.choice(INTERNAL_IPS)
                target_ip = random.choice(EXTERNAL_IPS)
                for port in random.sample(range(1, 1024), random.randint(50, 200)):
                    scan_ts = random_ts(current_time, 60)
                    batch.append({
                        "ts": scan_ts, "@timestamp": scan_ts,
                        "uid": random_uid(),
                        "id.orig_h": scanner_ip, "id.orig_p": random.randint(1024, 65535),
                        "id.resp_h": target_ip, "id.resp_p": port,
                        "proto": "tcp", "duration": round(random.uniform(0.0, 0.01), 6),
                        "orig_bytes": 0, "resp_bytes": 0,
                        "conn_state": random.choice(["REJ", "S0", "RSTO"]),
                        "missed_bytes": 0, "orig_pkts": 1, "resp_pkts": 1,
                        "orig_ip_bytes": 40, "resp_ip_bytes": 40,
                        "log_type": "zeek", "log_source": "conn"
                    })
                for _ in range(random.randint(5, 20)):
                    snort_batch.append(gen_snort_alert(random_ts(current_time, 60)))
                    suricata_batch.append(gen_suricata_alert(random_ts(current_time, 60)))

            # DGA burst toutes les ~3h
            if random.random() < 0.05:
                for _ in range(random.randint(5, 20)):
                    ts = random_ts(current_time, 120)
                    batch.append(gen_dns_log(ts, suspicious=True))
                    batch.append(gen_notice_log(ts, "DNSEntropy::High_Entropy_DNS"))
                    suricata_batch.append(gen_suricata_alert(random_ts(current_time, 120)))

            # DNS tunneling (sous-domaines > 40 chars)
            if random.random() < 0.04:
                for _ in range(random.randint(20, 80)):
                    ts = random_ts(current_time, 120)
                    batch.append(gen_dns_tunnel(ts))

            # Beaconing C2 (connexions régulières à intervalle fixe)
            if random.random() < 0.03:
                beacon_docs = gen_beaconing_batch(
                    current_time,
                    interval_s=random.choice([60, 120, 300]),
                    count=random.randint(10, 40),
                    jitter_pct=random.uniform(0.02, 0.08)
                )
                batch.extend(beacon_docs)

            # Longue connexion (tunnel potentiel)
            if random.random() < 0.02:
                ts = random_ts(current_time, 60)
                batch.append(gen_long_connection(ts))

            # Intel hit (IP/domaine malveillant connu)
            if random.random() < 0.04:
                ts = random_ts(current_time, 120)
                batch.append(gen_intel_log(ts))

            # JA3 malveillant (fingerprint C2 connu)
            if random.random() < 0.04:
                ts = random_ts(current_time, 120)
                batch.append(gen_ssl_log(ts, malicious=True))
                batch.append(gen_ssh_log(ts, malicious=True))

            # Pic de trafic (exfiltration) rare
            if random.random() < 0.02:
                exfil_ip = random.choice(INTERNAL_IPS)
                for _ in range(random.randint(30, 80)):
                    ts = random_ts(current_time, 60)
                    doc = gen_conn_log(ts)
                    doc["id.orig_h"] = exfil_ip
                    doc["orig_bytes"] = random.randint(100000, 5000000)
                    batch.append(doc)
                snort_batch.append(gen_snort_alert(random_ts(current_time, 60)))
                suricata_batch.append(gen_suricata_alert(random_ts(current_time, 60)))

        # Envoyer les batches si assez gros
        if len(batch) >= batch_size:
            date_str = current_time.strftime("%Y.%m.%d")
            sent_z = bulk_index(args.es, batch, f"zeek-{date_str}")
            sent_s = bulk_index(args.es, snort_batch, f"snort-{date_str}") if snort_batch else 0
            sent_u = bulk_index(args.es, suricata_batch, f"suricata-{date_str}") if suricata_batch else 0
            total_docs += sent_z + sent_s + sent_u
            print(f"  [{current_time.strftime('%Y-%m-%d %H:%M')}] zeek:{sent_z} snort:{sent_s} suricata:{sent_u} (total: {total_docs})")
            batch = []
            snort_batch = []
            suricata_batch = []

        current_time += timedelta(minutes=10)

    # Envoyer le reste
    if batch or snort_batch or suricata_batch:
        date_str = current_time.strftime("%Y.%m.%d")
        if batch:
            total_docs += bulk_index(args.es, batch, f"zeek-{date_str}")
        if snort_batch:
            total_docs += bulk_index(args.es, snort_batch, f"snort-{date_str}")
        if suricata_batch:
            total_docs += bulk_index(args.es, suricata_batch, f"suricata-{date_str}")

    print(f"\n[+] Simulation terminee ! {total_docs} documents indexes au total.")
    print(f"[+] Verifiez Zeek      : curl '{args.es}/zeek-*/_count?pretty'")
    print(f"[+] Verifiez Snort     : curl '{args.es}/snort-*/_count?pretty'")
    print(f"[+] Verifiez Suricata  : curl '{args.es}/suricata-*/_count?pretty'")
    print(f"[+] Ouvrez Grafana et selectionnez 'Last {args.hours} hours'")

if __name__ == "__main__":
    main()


