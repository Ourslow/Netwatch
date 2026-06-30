#!/usr/bin/env python3
"""
NetWatch — Beacon Detector (RITA-lite)
Detecte les patterns C2 dans les logs Zeek stockes dans Elasticsearch.

Detections :
  - Beaconing      : connexions regulieres vers une meme destination (C2 check-in)
  - Long connection : connexion ouverte > 1h (tunnel C2, exfiltration lente)
  - DNS tunneling  : sous-domaines tres longs ou frequence DNS anormale

Tourne en boucle toutes les SCAN_INTERVAL_MIN minutes.
Ecrit les resultats dans l'index netwatch-beacons-YYYY.MM.DD.
"""

import os
import time
import logging
import statistics
from datetime import datetime, timezone, timedelta

from elasticsearch import Elasticsearch, helpers

# ─── Config ───────────────────────────────────────────────────────────────────
ES_URL               = os.environ.get("ES_URL", "http://elasticsearch:9200")
SCAN_INTERVAL_MIN    = int(os.environ.get("SCAN_INTERVAL_MIN", "15"))
LOOKBACK_HOURS       = int(os.environ.get("LOOKBACK_HOURS", "2"))
MIN_CONNECTIONS      = int(os.environ.get("MIN_CONNECTIONS", "8"))
BEACON_CV_THRESHOLD  = float(os.environ.get("BEACON_CV_THRESHOLD", "0.25"))
MAX_INTERVAL_SEC     = 3600   # intervalles > 1h ne sont pas du beaconing
LONG_CONN_THRESHOLD  = 3600   # connexion > 1h = suspecte
DNS_SUBDOMAIN_LEN    = 40     # sous-domaine > 40 chars = suspect
DNS_FREQ_THRESHOLD   = 100    # > 100 requetes meme domaine = suspect

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger("beacon-detect")


# ─── Elasticsearch ────────────────────────────────────────────────────────────
def get_es():
    return Elasticsearch(ES_URL, request_timeout=30)


def wait_for_es(es):
    while True:
        try:
            es.cluster.health(wait_for_status="yellow", timeout="5s")
            log.info("Elasticsearch pret.")
            return
        except Exception:
            log.info("Attente Elasticsearch...")
            time.sleep(10)


def index_detections(es, detections):
    if not detections:
        return
    today = datetime.now(timezone.utc).strftime("%Y.%m.%d")
    index  = f"netwatch-beacons-{today}"
    actions = [{"_index": index, "_source": d} for d in detections]
    ok, errors = helpers.bulk(es, actions, raise_on_error=False)
    if errors:
        log.warning("%d erreurs d'indexation", len(errors))
    log.info("Indexe %d detections dans %s", ok, index)


# ─── Detection 1 : Beaconing ──────────────────────────────────────────────────
def detect_beacons(es, since: datetime) -> list:
    """
    Cherche les paires (src, dst, port) avec des intervalles tres reguliers
    => indicateur d'un agent C2 qui fait des check-ins periodiques.
    Score = 1 - coefficient_de_variation (plus c'est regulier, plus le score est eleve).
    """
    log.info("Detection beaconing depuis %s...", since.isoformat())

    query = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"exists": {"field": "orig_bytes"}},
                    {"range": {"@timestamp": {"gte": since.isoformat()}}}
                ]
            }
        },
        "aggs": {
            "sources": {
                "terms": {"field": "id.orig_h.keyword", "size": 300},
                "aggs": {
                    "destinations": {
                        "terms": {"field": "id.resp_h.keyword", "size": 20},
                        "aggs": {
                            "ports": {
                                "terms": {"field": "id.resp_p", "size": 5},
                                "aggs": {
                                    "hits": {
                                        "top_hits": {
                                            "size": 200,
                                            "_source": ["@timestamp"],
                                            "sort": [{"@timestamp": "asc"}]
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    try:
        resp = es.search(index="zeek-*", **query)
    except Exception as e:
        log.error("Erreur ES beaconing : %s", e)
        return []

    detections = []
    now_iso = datetime.now(timezone.utc).isoformat()

    for src_b in resp["aggregations"]["sources"]["buckets"]:
        src_ip = src_b["key"]
        for dst_b in src_b["destinations"]["buckets"]:
            dst_ip = dst_b["key"]
            for port_b in dst_b["ports"]["buckets"]:
                dst_port = port_b["key"]
                hits     = port_b["hits"]["hits"]["hits"]

                if len(hits) < MIN_CONNECTIONS:
                    continue

                # Extraire les timestamps en secondes epoch
                ts_list = []
                for h in hits:
                    raw = h["_source"].get("@timestamp", "")
                    try:
                        ts_list.append(
                            datetime.fromisoformat(
                                raw.replace("Z", "+00:00")
                            ).timestamp()
                        )
                    except Exception:
                        pass

                if len(ts_list) < MIN_CONNECTIONS:
                    continue

                ts_list.sort()
                intervals = [b - a for a, b in zip(ts_list, ts_list[1:])]
                mean_iv   = statistics.mean(intervals)

                if mean_iv == 0 or mean_iv > MAX_INTERVAL_SEC:
                    continue

                try:
                    std_iv = statistics.stdev(intervals)
                except statistics.StatisticsError:
                    continue

                cv    = std_iv / mean_iv
                score = round(1 - cv, 3)

                if cv < BEACON_CV_THRESHOLD:
                    detections.append({
                        "@timestamp":       now_iso,
                        "detection_type":   "beaconing",
                        "src_ip":           src_ip,
                        "dst_ip":           dst_ip,
                        "dst_port":         dst_port,
                        "connection_count": len(ts_list),
                        "mean_interval_s":  round(mean_iv, 1),
                        "std_interval_s":   round(std_iv, 1),
                        "cv":               round(cv, 3),
                        "beacon_score":     score,
                        "severity":         "high" if score > 0.85 else "medium",
                        "description": (
                            f"{src_ip} -> {dst_ip}:{dst_port} | "
                            f"{len(ts_list)} connexions, "
                            f"intervalle moyen {mean_iv:.0f}s (CV={cv:.3f})"
                        )
                    })

    log.info("Beaconing : %d detections", len(detections))
    return detections


# ─── Detection 2 : Longues connexions ─────────────────────────────────────────
def detect_long_connections(es, since: datetime) -> list:
    """
    Connexions ouvertes > LONG_CONN_THRESHOLD secondes.
    Peut indiquer un tunnel C2, une session de reverse-shell ou exfiltration lente.
    """
    log.info("Detection longues connexions...")

    query = {
        "size": 100,
        "query": {
            "bool": {
                "filter": [
                    {"exists": {"field": "duration"}},
                    {"range": {"@timestamp": {"gte": since.isoformat()}}},
                    {"range": {"duration": {"gte": LONG_CONN_THRESHOLD}}}
                ]
            }
        },
        "_source": [
            "@timestamp", "id.orig_h", "id.resp_h", "id.resp_p",
            "duration", "orig_bytes", "resp_bytes", "proto", "service"
        ]
    }

    try:
        resp = es.search(index="zeek-*", **query)
    except Exception as e:
        log.error("Erreur ES long_conn : %s", e)
        return []

    now_iso    = datetime.now(timezone.utc).isoformat()
    detections = []

    for hit in resp["hits"]["hits"]:
        s        = hit["_source"]
        duration = s.get("duration", 0)
        score    = min(duration / 86400.0, 1.0)   # normalise sur 24h

        detections.append({
            "@timestamp":       now_iso,
            "detection_type":   "long_connection",
            "src_ip":           s.get("id", {}).get("orig_h", s.get("id.orig_h", "unknown")),
            "dst_ip":           s.get("id", {}).get("resp_h", s.get("id.resp_h", "unknown")),
            "dst_port":         s.get("id.resp_p", 0),
            "duration_s":       round(duration, 1),
            "duration_h":       round(duration / 3600, 2),
            "orig_bytes":       s.get("orig_bytes", 0),
            "resp_bytes":       s.get("resp_bytes", 0),
            "proto":            s.get("proto", "unknown"),
            "service":          s.get("service", "unknown"),
            "beacon_score":     round(score, 3),
            "severity":         "high" if duration > 7200 else "medium",
            "description": (
                f"{s.get('id.orig_h')} -> {s.get('id.resp_h')}:{s.get('id.resp_p')} | "
                f"duree {duration/3600:.1f}h"
            )
        })

    log.info("Longues connexions : %d detections", len(detections))
    return detections


# ─── Detection 3 : DNS Tunneling ─────────────────────────────────────────────
def detect_dns_tunneling(es, since: datetime) -> list:
    """
    Indicateurs de DNS tunneling :
    - Sous-domaine > DNS_SUBDOMAIN_LEN caracteres (encodage binaire en DNS)
    - > DNS_FREQ_THRESHOLD requetes vers le meme domaine (data exfil via DNS)
    """
    log.info("Detection DNS tunneling...")

    query = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"exists": {"field": "qtype_name"}},
                    {"range": {"@timestamp": {"gte": since.isoformat()}}}
                ]
            }
        },
        "aggs": {
            "sources": {
                "terms": {"field": "id.orig_h.keyword", "size": 200},
                "aggs": {
                    "queries": {
                        "terms": {"field": "query.keyword", "size": 20},
                    }
                }
            }
        }
    }

    try:
        resp = es.search(index="zeek-*", **query)
    except Exception as e:
        log.error("Erreur ES dns_tunnel : %s", e)
        return []

    now_iso    = datetime.now(timezone.utc).isoformat()
    detections = []

    for src_b in resp["aggregations"]["sources"]["buckets"]:
        src_ip = src_b["key"]
        for q_b in src_b["queries"]["buckets"]:
            fqdn  = q_b["key"]
            count = q_b["doc_count"]

            parts      = fqdn.split(".")
            subdomain  = parts[0] if len(parts) > 1 else fqdn
            is_long    = len(subdomain) > DNS_SUBDOMAIN_LEN
            is_frequent = count > DNS_FREQ_THRESHOLD

            if not (is_long or is_frequent):
                continue

            score = 0.0
            if is_long:
                score += min(len(subdomain) / 60.0, 0.5)
            if is_frequent:
                score += min(count / 500.0, 0.5)
            score = round(min(score, 1.0), 3)

            detections.append({
                "@timestamp":       now_iso,
                "detection_type":   "dns_tunneling",
                "src_ip":           src_ip,
                "query":            fqdn,
                "subdomain":        subdomain,
                "subdomain_length": len(subdomain),
                "query_count":      count,
                "beacon_score":     score,
                "severity":         "high" if score > 0.7 else "medium",
                "indicators": {
                    "long_subdomain": is_long,
                    "high_frequency": is_frequent
                },
                "description": (
                    f"{src_ip} -> DNS:{fqdn} | "
                    f"subdomain={len(subdomain)} chars, {count} requetes"
                )
            })

    log.info("DNS tunneling : %d detections", len(detections))
    return detections


# ─── Boucle principale ────────────────────────────────────────────────────────
def run_once(es):
    since = datetime.now(timezone.utc) - timedelta(hours=LOOKBACK_HOURS)
    all_detections = []

    all_detections.extend(detect_beacons(es, since))
    all_detections.extend(detect_long_connections(es, since))
    all_detections.extend(detect_dns_tunneling(es, since))

    index_detections(es, all_detections)

    counts = {}
    for d in all_detections:
        t = d["detection_type"]
        counts[t] = counts.get(t, 0) + 1
    log.info("Scan termine : %s | total=%d", counts, len(all_detections))


def main():
    log.info("NetWatch Beacon Detector demarre (interval=%dmin, lookback=%dh)",
             SCAN_INTERVAL_MIN, LOOKBACK_HOURS)
    es = get_es()
    wait_for_es(es)

    while True:
        try:
            run_once(es)
        except Exception as e:
            log.error("Erreur scan : %s", e)
        log.info("Prochain scan dans %d minutes.", SCAN_INTERVAL_MIN)
        time.sleep(SCAN_INTERVAL_MIN * 60)


if __name__ == "__main__":
    main()
