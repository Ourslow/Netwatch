"""Simulation NetFlow 24 h → index netflow-<date>-sim (pattern netflow-* du portail).
Mapping aligné sur es_client.get_flows_stats : src_addr/dst_addr/proto text+keyword, in_bytes long.
Trafic « site » cohérent avec la démo NetBox : serveurs 10.0.3.x, postes 10.0.20.x, passerelle 192.168.1.1."""
import json, random, sys, urllib.request
from datetime import datetime, timedelta, timezone

ES = "http://localhost:9200"
HOURS = int(sys.argv[1]) if len(sys.argv) > 1 else 24
random.seed(42)
now = datetime.now(timezone.utc)

def req(method, path, body=None, ctype="application/json"):
    data = body.encode() if isinstance(body, str) else (json.dumps(body).encode() if body is not None else None)
    r = urllib.request.Request(ES + path, data=data, method=method, headers={"Content-Type": ctype})
    try:
        with urllib.request.urlopen(r, timeout=120) as resp: return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e: return e.code, e.read().decode()

SERVERS = {"10.0.3.14": "srv-erp-01", "10.0.3.20": "srv-ad-01", "10.0.3.11": "srv-web-01", "10.0.3.12": "srv-db-01",
           "10.0.3.30": "srv-file-01", "10.0.3.40": "srv-voip-01"}
USERS = [f"10.0.20.{i}" for i in range(10, 90)] + [f"10.0.21.{i}" for i in range(10, 60)]
EXT = {"142.250.74.78": 443, "13.107.42.14": 443, "52.97.149.34": 443, "185.199.108.153": 443, "104.16.132.229": 443,
       "1.1.1.1": 53, "8.8.8.8": 53, "151.101.1.69": 443, "23.62.161.7": 443, "40.99.213.2": 443}
GW = "192.168.1.1"

def diurnal(h):            # facteur de charge selon l'heure locale (UTC+2)
    lh = (h + 2) % 24
    if 8 <= lh < 12: return 1.0
    if 12 <= lh < 14: return 0.6
    if 14 <= lh < 18: return 0.95
    if 18 <= lh < 20: return 0.35
    return 0.08

def flow(ts):
    r = random.random()
    if r < 0.42:   # poste → SaaS/Internet (HTTPS/DNS)
        src, dst = random.choice(USERS), random.choice(list(EXT)); dport = EXT[dst]
        proto = "UDP" if dport == 53 else "TCP"; b = random.randint(200, 900) if dport == 53 else int(random.lognormvariate(10.5, 1.1))
    elif r < 0.62: # poste → serveurs internes (ERP 443, AD 445/389/88, fichiers 445, web 80)
        src = random.choice(USERS); dst = random.choice(list(SERVERS))
        dport = {"10.0.3.14": 443, "10.0.3.20": random.choice([445, 389, 88, 53]), "10.0.3.11": 80, "10.0.3.12": 1433,
                 "10.0.3.30": 445, "10.0.3.40": random.choice([5060, 5060, 10000])}[dst]
        proto = "UDP" if dport in (53, 88, 10000) else "TCP"; b = int(random.lognormvariate(11.2, 1.3))
    elif r < 0.78: # serveur → serveur (ERP ↔ DB, AD réplication, sauvegardes)
        src, dst = random.sample(list(SERVERS), 2); dport = 1433 if dst == "10.0.3.12" else random.choice([443, 445, 3306, 22])
        proto = "TCP"; b = int(random.lognormvariate(12.5, 1.2))
    elif r < 0.9:  # serveur → Internet (mises à jour, API)
        src, dst = random.choice(list(SERVERS)), random.choice(list(EXT)); dport = EXT[dst]
        proto = "UDP" if dport == 53 else "TCP"; b = int(random.lognormvariate(11.0, 1.0))
    else:          # admin / divers : SSH, RDP, NTP, ICMP
        src = random.choice(USERS[:8]); dst = random.choice(list(SERVERS)); dport = random.choice([22, 3389, 123, 161])
        proto = "UDP" if dport in (123, 161) else "TCP"; b = int(random.lognormvariate(9.5, 1.0))
    pkts = max(1, b // random.randint(400, 1400))
    return {"@timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.000Z"), "type": "NETFLOW_V9", "sampler_addr": GW,
            "src_addr": src, "dst_addr": dst, "src_port": random.randint(1024, 65535), "dst_port": dport, "proto": proto,
            "in_bytes": b, "in_pkts": pkts, "etype": "IPv4", "log_type": "netflow", "engine": "netflow", "sim": True}

index = f"netflow-{now.strftime('%Y.%m.%d')}-sim"
mapping = {"settings": {"number_of_shards": 1, "number_of_replicas": 0},
           "mappings": {"properties": {
               "@timestamp": {"type": "date"}, "type": {"type": "keyword"}, "etype": {"type": "keyword"},
               "sampler_addr": {"type": "keyword"}, "log_type": {"type": "keyword"}, "engine": {"type": "keyword"}, "sim": {"type": "boolean"},
               "src_addr": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
               "dst_addr": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
               "proto":    {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
               "src_port": {"type": "integer"}, "dst_port": {"type": "integer"},
               "in_bytes": {"type": "long"}, "in_pkts": {"type": "long"}}}}
req("DELETE", f"/{index}")
st, body = req("PUT", f"/{index}", mapping); print("index", index, st, body[:80])

total = 0
for h in range(HOURS, 0, -1):
    base = now - timedelta(hours=h)
    n = int(1400 * diurnal(base.hour) + random.randint(-60, 60))
    lines = []
    for _ in range(max(40, n)):
        ts = base + timedelta(seconds=random.randint(0, 3599))
        lines.append(json.dumps({"index": {"_index": index}})); lines.append(json.dumps(flow(ts)))
    st, body = req("POST", "/_bulk", "\n".join(lines) + "\n", "application/x-ndjson")
    d = json.loads(body); total += len(d.get("items", [])); err = d.get("errors")
    if err: print("erreurs bulk heure", h, body[:200]); break
req("POST", f"/{index}/_refresh")
st, body = req("GET", f"/{index}/_count"); print("docs indexés :", total, "| count :", json.loads(body).get("count"))
st, body = req("GET", "/netflow-*/_search", {"size": 0, "query": {"range": {"@timestamp": {"gte": "now-24h"}}},
    "aggs": {"top": {"terms": {"field": "src_addr.keyword", "size": 5}, "aggs": {"b": {"sum": {"field": "in_bytes"}}}}}})
for bk in json.loads(body)["aggregations"]["top"]["buckets"]:
    print(f"  {bk['key']:14s} {bk['b']['value']/1e9:6.2f} GB  {bk['doc_count']} flux")
