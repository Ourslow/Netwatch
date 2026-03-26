#!/usr/bin/env python3
"""
NetWatch — Simulateur de trafic réseau
Injecte des logs Zeek simulés dans Elasticsearch pour alimenter les dashboards.
Usage : python3 simulate-traffic.py [--hours 24] [--es http://localhost:9200]
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

# IPs externes simulées
EXTERNAL_IPS = [
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
    "104.18.27.120", "151.101.1.140", "140.82.121.4",
    "172.217.22.110", "93.184.216.34", "13.107.42.14",
    "34.120.177.193", "52.85.132.99", "54.230.10.42",
    "23.45.67.89", "185.199.108.153", "199.232.69.194",
    "157.240.1.35", "31.13.65.36", "69.171.250.35"
]

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

CONN_STATES = ["SF", "SF", "SF", "SF", "S0", "S1", "REJ", "RSTO", "RSTR", "OTH"]
NOTICE_TYPES = [
    "PortScan::Port_Scan_Detected",
    "DNSEntropy::High_Entropy_DNS",
    "SSL::Certificate_Expired",
    "SSL::Certificate_Not_Valid_Yet"
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

def gen_ssl_log(ts):
    src = random.choice(INTERNAL_IPS)
    dst = random.choice(EXTERNAL_IPS)
    server = random.choice(NORMAL_DOMAINS)
    version = random.choice(TLS_VERSIONS)

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
        "log_type": "zeek",
        "log_source": "ssl"
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

        # --- TLS/SSL (15% du trafic) ---
        for _ in range(int(events_count * 0.15)):
            ts = random_ts(current_time, 300)
            batch.append(gen_ssl_log(ts))

        # --- Attaques simulées ---
        if args.attack:
            # Port scan toutes les ~2h
            if random.random() < 0.08:
                ts = random_ts(current_time, 300)
                batch.append(gen_notice_log(ts, "PortScan::Port_Scan_Detected"))
                # Ajouter les connexions du scan
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

            # DGA burst toutes les ~3h
            if random.random() < 0.05:
                for _ in range(random.randint(5, 20)):
                    ts = random_ts(current_time, 120)
                    batch.append(gen_dns_log(ts, suspicious=True))
                    batch.append(gen_notice_log(ts, "DNSEntropy::High_Entropy_DNS"))

            # Pic de trafic (exfiltration) rare
            if random.random() < 0.02:
                exfil_ip = random.choice(INTERNAL_IPS)
                for _ in range(random.randint(30, 80)):
                    ts = random_ts(current_time, 60)
                    doc = gen_conn_log(ts)
                    doc["id.orig_h"] = exfil_ip
                    doc["orig_bytes"] = random.randint(100000, 5000000)
                    batch.append(doc)

        # Envoyer le batch si assez gros
        if len(batch) >= batch_size:
            date_str = current_time.strftime("%Y.%m.%d")
            index_name = f"zeek-zeek-{date_str}"
            sent = bulk_index(args.es, batch, index_name)
            total_docs += sent
            print(f"  [{current_time.strftime('%Y-%m-%d %H:%M')}] {sent} docs indexes (total: {total_docs})")
            batch = []

        current_time += timedelta(minutes=10)

    # Envoyer le reste
    if batch:
        date_str = current_time.strftime("%Y.%m.%d")
        index_name = f"zeek-zeek-{date_str}"
        sent = bulk_index(args.es, batch, index_name)
        total_docs += sent

    print(f"\n[+] Simulation terminee ! {total_docs} documents indexes au total.")
    print(f"[+] Verifiez : curl '{args.es}/zeek-*/_count?pretty'")
    print(f"[+] Ouvrez Grafana et selectionnez 'Last {args.hours} hours'")

if __name__ == "__main__":
    main()


