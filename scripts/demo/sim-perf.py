"""Simulation « site sain » 7 jours pour le portail : conn.log (RTT, ART HTTP/TLS via service+duration, history),
dns.log (rtt), http.log (duration, SLA), ssl.log (SNI → dictionnaire applicatif). Index zeek-<date>-sim (pattern zeek-*).
Dense sur les dernières 24 h pour que les percentiles ne soient pas dominés par les scénarios d'attaque du simulateur."""
import json, random, sys, urllib.request, uuid
from datetime import datetime, timedelta, timezone

ES = "http://localhost:9200"; random.seed(7); now = datetime.now(timezone.utc)
DAYS = int(sys.argv[1]) if len(sys.argv) > 1 else 7

def req(method, path, body=None, ctype="application/json"):
    data = body.encode() if isinstance(body, str) else (json.dumps(body).encode() if body is not None else None)
    r = urllib.request.Request(ES + path, data=data, method=method, headers={"Content-Type": ctype})
    try:
        with urllib.request.urlopen(r, timeout=180) as resp: return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e: return e.code, e.read().decode()

USERS = [f"10.0.20.{i}" for i in range(10, 90)] + [f"10.0.21.{i}" for i in range(10, 60)]
SRV = {"10.0.3.14": ("srv-erp-01", 443, "ssl", "erp.netwatch.local"), "10.0.3.11": ("srv-web-01", 80, "http", "intranet.netwatch.local"),
       "10.0.3.20": ("srv-ad-01", 445, None, None), "10.0.3.12": ("srv-db-01", 1433, None, None), "10.0.3.30": ("srv-file-01", 445, None, None)}
SAAS = [("outlook.office365.com", "52.97.149.34"), ("teams.microsoft.com", "52.113.194.132"), ("login.microsoftonline.com", "40.126.31.6"),
        ("www.google.com", "142.250.74.78"), ("github.com", "140.82.121.4"), ("salesforce.com", "13.110.54.106"),
        ("api.sap.com", "155.56.53.10"), ("zoom.us", "170.114.52.2"), ("www.linkedin.com", "13.107.42.14"), ("cdn.jsdelivr.net", "104.16.132.229")]
DOMAINS = [d for d, _ in SAAS] + ["erp.netwatch.local", "intranet.netwatch.local", "srv-ad-01.netwatch.local", "wpad.netwatch.local", "ntp.ubuntu.com"]
DNS_SRV = "10.0.3.20"

def diurnal(t):
    lh = (t.hour + 2) % 24; wd = t.weekday()
    base = 1.0 if 8 <= lh < 12 else 0.6 if 12 <= lh < 14 else 0.95 if 14 <= lh < 18 else 0.35 if 18 <= lh < 20 else 0.18
    return base * (0.3 if wd >= 5 else 1.0)

def ts(t): return t.strftime("%Y-%m-%dT%H:%M:%S.000Z")
def uid(): return "C" + uuid.uuid4().hex[:17]
def base(t, src, dst, sp, dp, proto, ls):
    return {"ts": ts(t), "@timestamp": ts(t), "uid": uid(), "id.orig_h": src, "id.orig_p": sp, "id.resp_h": dst, "id.resp_p": dp,
            "proto": proto, "log_type": "zeek", "log_source": ls, "sim": True}

def history():
    r = random.random()
    if r < 0.012: return "ShADadTFf"      # retransmission
    if r < 0.015: return "ShADadwFf"      # zero-window côté serveur
    return random.choice(["ShADadFf", "ShADadfF", "ShADadFf", "ShADadFR"])

def conn(t, kind):
    src = random.choice(USERS)
    if kind == "http":
        dst, dp, svc = "10.0.3.11", 80, "http"; dur = random.lognormvariate(-2.6, 0.42)      # ≈ 90 ms médian, p95 ≈ 190 ms
    elif kind == "ssl":
        if random.random() < 0.55: dst, dp = "10.0.3.14", 443
        else: dst = random.choice(SAAS)[1]; dp = 443
        svc = "ssl"; dur = random.lognormvariate(-2.1, 0.5)                                    # ≈ 120 ms médian
    else:
        dst = random.choice(list(SRV)); dp = SRV[dst][1]; svc = None; dur = random.lognormvariate(0.5, 1.2)
    d = base(t, src, dst, random.randint(1024, 65535), dp, "tcp", "conn")
    ob, rb = int(random.lognormvariate(7.5, 1.0)), int(random.lognormvariate(9.5, 1.3))
    d.update({"duration": round(dur, 5), "orig_bytes": ob, "resp_bytes": rb, "conn_state": "SF", "missed_bytes": 0,
              "orig_pkts": max(2, ob // 700), "orig_ip_bytes": ob + 200, "resp_pkts": max(2, rb // 1200), "resp_ip_bytes": rb + 300,
              "history": history(), "rtt": round(random.lognormvariate(-4.4, 0.45), 4)})     # ≈ 12 ms médian, p95 ≈ 25 ms
    if svc: d["service"] = svc
    return d

def dns(t):
    src = random.choice(USERS); q = random.choice(DOMAINS)
    d = base(t, src, DNS_SRV, random.randint(1024, 65535), 53, "udp", "dns")
    d.update({"query": q, "qtype": 1, "qtype_name": "A", "qclass": 1, "qclass_name": "C_INTERNET", "rcode": 0, "rcode_name": "NOERROR",
              "AA": False, "TC": False, "RD": True, "RA": True, "answers": ["10.0.3.14" if "erp" in q else "142.250.74.78"],
              "rtt": round(random.lognormvariate(-4.6, 0.4), 4)})                              # ≈ 10 ms médian
    return d

def http(t):
    src = random.choice(USERS)
    d = base(t, src, "10.0.3.11", random.randint(1024, 65535), 80, "tcp", "http")
    d.update({"method": random.choice(["GET", "GET", "GET", "POST"]), "http_host": "intranet.netwatch.local",
              "uri": random.choice(["/", "/api/v1/items", "/login", "/static/app.js", "/reports/daily", "/search?q=facture"]),
              "status_code": random.choice([200, 200, 200, 200, 304, 302, 404]), "request_body_len": random.randint(0, 900),
              "response_body_len": int(random.lognormvariate(8.5, 1.2)), "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
              "duration": round(random.lognormvariate(-2.6, 0.42), 5)})
    return d

def ssl(t):
    src = random.choice(USERS)
    if random.random() < 0.45: sni, dst = "erp.netwatch.local", "10.0.3.14"
    else: sni, dst = random.choice(SAAS)
    d = base(t, src, dst, random.randint(1024, 65535), 443, "tcp", "ssl")
    d.update({"version": "TLSv13", "server_name": sni, "subject": f"CN={sni}", "issuer": "CN=DigiCert TLS RSA SHA256 2020 CA1,O=DigiCert Inc,C=US",
              "established": True, "cipher": "TLS_AES_256_GCM_SHA384", "validation_status": "ok",
              "ja3": random.choice(["cd08e31494f9531f560d64c695473da9", "b32309a26951912be7dba376398abc3b", "3b5074b1b5d032e5620f69f9f700ff0e"])})
    return d

index = f"zeek-{now.strftime('%Y.%m.%d')}-sim"
req("DELETE", f"/{index}")
st, body = req("PUT", f"/{index}", {"settings": {"number_of_shards": 1, "number_of_replicas": 0, "refresh_interval": "30s"},
                                    "mappings": {"properties": {"@timestamp": {"type": "date"}, "ts": {"type": "date"},
                                                                "duration": {"type": "float"}, "rtt": {"type": "float"}}}})
print("index", index, st)

total = 0; lines = []
def flush():
    global lines, total
    if not lines: return
    st, body = req("POST", "/_bulk", "\n".join(lines) + "\n", "application/x-ndjson"); d = json.loads(body)
    if d.get("errors"): print("ERREUR bulk :", body[:300]); sys.exit(1)
    total += len(d["items"]); lines = []

for h in range(DAYS * 24, 0, -1):
    t0 = now - timedelta(hours=h); f = diurnal(t0); dense = 6.0 if h <= 24 else 1.5
    counts = {"conn_http": int(180 * f * dense), "conn_ssl": int(240 * f * dense), "conn_other": int(120 * f * dense),
              "dns": int(600 * f * dense), "http": int(180 * f * dense), "ssl": int(160 * f * dense)}
    for kind, n in counts.items():
        for _ in range(max(6, n)):
            t = t0 + timedelta(seconds=random.randint(0, 3599))
            doc = conn(t, kind.split("_")[1]) if kind.startswith("conn") else {"dns": dns, "http": http, "ssl": ssl}[kind](t)
            lines.append(json.dumps({"index": {"_index": index}})); lines.append(json.dumps(doc))
            if len(lines) >= 8000: flush()
flush(); req("POST", f"/{index}/_refresh")
print("docs indexés :", total)
st, body = req("GET", "/zeek-*/_search", {"size": 0, "query": {"bool": {"filter": [{"range": {"@timestamp": {"gte": "now-24h"}}}, {"term": {"log_source": "conn"}}, {"term": {"service": "http"}}]}},
    "aggs": {"p": {"percentiles": {"field": "duration", "percents": [50, 95, 99]}}, "n": {"value_count": {"field": "duration"}}}})
a = json.loads(body)["aggregations"]; print("ART HTTP 24h (ms) :", {k: round(v * 1000) for k, v in a["p"]["values"].items()}, "| n =", a["n"]["value"])
st, body = req("GET", "/zeek-*/_search", {"size": 0, "query": {"bool": {"filter": [{"range": {"@timestamp": {"gte": "now-24h"}}}, {"term": {"log_source": "conn"}}, {"exists": {"field": "rtt"}}]}},
    "aggs": {"p": {"percentiles": {"field": "rtt", "percents": [50, 95]}}}})
print("RTT TCP 24h (ms) :", {k: round(v * 1000, 1) for k, v in json.loads(body)["aggregations"]["p"]["values"].items()})
