"""
Client Elasticsearch léger (requêtes REST via requests).
Normalise les alertes Suricata (EVE JSON) et Snort (alert_json)
en un format commun pour le portail.

Structure normalisée :
  {
    "engine":      "suricata" | "snort",
    "timestamp":   str  (ISO 8601),
    "src_ip":      str,
    "dest_ip":     str,
    "signature":   str,
    "category":    str,
    "severity":    int  (1=critique, 2=moyen, 3=faible),
    "mitre_tactic": str | None,
    "mitre_tech":   str | None,
  }
"""

import re
import requests
from datetime import datetime, timezone

import config

_TIMEOUT = 5


def _es(path, body=None, method="post"):
    url = config.NETWATCH_ES_URL.rstrip("/") + path
    fn  = getattr(requests, method)
    kw  = {"timeout": _TIMEOUT, "verify": False}
    if body is not None:
        kw["json"] = body
    return fn(url, **kw)


# ------------------------------------------------------------------ #
# Normalisation                                                        #
# ------------------------------------------------------------------ #

def _first(v):
    """Premier élément si liste (vide → None), sinon la valeur telle quelle.
    Robuste aux alertes réelles (ET/GPL) dont les champs MITRE sont absents/vides."""
    if isinstance(v, list):
        return v[0] if v else None
    return v or None


def _normalize(hit):
    src    = hit["_source"]
    index  = hit.get("_index", "")
    engine = "suricata" if "suricata" in index else "snort"

    if engine == "suricata":
        alert = src.get("alert", {})
        meta  = alert.get("metadata", {})
        # mitre_tactic_name / technique_id : liste, str, ou absent selon la règle
        tactic = _first(meta.get("mitre_tactic_name"))
        tech   = _first(meta.get("mitre_technique_id"))
        return {
            "engine":       "suricata",
            "timestamp":    src.get("@timestamp", ""),
            "src_ip":       src.get("src_ip",  "—"),
            "dest_ip":      src.get("dest_ip", "—"),
            "signature":    alert.get("signature", "—"),
            "category":     alert.get("category",  "—"),
            "severity":     int(alert.get("severity", 3)),
            "mitre_tactic": tactic,
            "mitre_tech":   tech,
            "community_id": src.get("community_id"),
        }
    else:  # snort alert_json
        return {
            "engine":       "snort",
            "timestamp":    src.get("@timestamp", src.get("timestamp", "")),
            "src_ip":       src.get("src_addr", "—"),
            "dest_ip":      src.get("dst_addr", "—"),
            "signature":    src.get("msg",   "—"),
            "category":     src.get("class", "—"),
            "severity":     int(src.get("priority", 3)),
            "mitre_tactic": None,
            "mitre_tech":   None,
            "community_id": None,
        }


# ------------------------------------------------------------------ #
# Requêtes                                                             #
# ------------------------------------------------------------------ #

def get_recent_alerts(size=100, engine=None, severity=None, search=None):
    """
    Retourne (alerts: list, error: str|None).
    engine   : "suricata" | "snort" | None
    severity : 1 | 2 | 3 | None
    search   : str libre (signature, IP) | None
    """
    if engine == "suricata":
        index = "suricata-*"
    elif engine == "snort":
        index = "snort-*"
    else:
        index = "suricata-*,snort-*"

    # Filtres obligatoires : garder uniquement les alertes
    # Suricata → event_type = alert
    # Snort    → champ rule présent (gid:sid:rev ; ni le simulateur ni Snort 3
    #            n'écrivent un champ "sid" isolé)
    filter_must = [
        {
            "bool": {
                "should": [
                    {"term":   {"event_type": "alert"}},
                    {"exists": {"field": "rule"}},
                ],
                "minimum_should_match": 1,
            }
        }
    ]

    if severity is not None:
        filter_must.append({
            "bool": {
                "should": [
                    {"term": {"alert.severity": severity}},
                    {"term": {"priority":       severity}},
                ],
                "minimum_should_match": 1,
            }
        })

    query = {"bool": {"filter": filter_must}}

    if search:
        query["bool"]["must"] = [{
            "multi_match": {
                "query":  search,
                "fields": [
                    "alert.signature", "alert.category",
                    "msg", "class",
                    "src_ip", "dest_ip", "src_addr", "dst_addr",
                    "alert.metadata.mitre_tactic_name",
                    "alert.metadata.mitre_technique_id",
                ],
            }
        }]

    body = {
        "size": size,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": query,
        "_source": [
            "@timestamp", "timestamp",
            "src_ip", "dest_ip", "src_addr", "dst_addr",
            "alert", "msg", "class", "priority", "sid",
            "event_type", "community_id",
        ],
    }

    try:
        r = _es(f"/{index}/_search", body)
        r.raise_for_status()
        hits = r.json().get("hits", {}).get("hits", [])
        return [_normalize(h) for h in hits], None
    except requests.exceptions.ConnectionError:
        return [], "Elasticsearch non joignable — vérifier NETWATCH_ES_URL"
    except requests.exceptions.Timeout:
        return [], f"Elasticsearch timeout (> {_TIMEOUT}s)"
    except Exception as e:
        return [], str(e)[:120]


def get_zeek_flow_by_community_id(community_id):
    """
    Retourne le flux Zeek conn.log correspondant à un Community ID.
    Retourne (flow: dict|None, error: str|None).
    """
    body = {
        "size": 1,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"term": {"community_id": community_id}},
        "_source": [
            "@timestamp", "ts", "id",
            "proto", "service", "duration",
            "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts",
            "conn_state",
        ],
    }
    try:
        r = _es("/zeek-*/_search", body)
        r.raise_for_status()
        hits = r.json().get("hits", {}).get("hits", [])
        if not hits:
            return None, None
        src = hits[0]["_source"]
        id_ = src.get("id", {})
        return {
            "timestamp":  src.get("@timestamp", src.get("ts", "")),
            "src_ip":     id_.get("orig_h", "—"),
            "src_port":   id_.get("orig_p", "—"),
            "dst_ip":     id_.get("resp_h", "—"),
            "dst_port":   id_.get("resp_p", "—"),
            "proto":      src.get("proto", "—"),
            "service":    src.get("service") or "—",
            "duration":   src.get("duration"),
            "orig_bytes": src.get("orig_bytes", 0),
            "resp_bytes": src.get("resp_bytes", 0),
            "orig_pkts":  src.get("orig_pkts", 0),
            "resp_pkts":  src.get("resp_pkts", 0),
            "conn_state": src.get("conn_state", "—"),
        }, None
    except requests.exceptions.ConnectionError:
        return None, "Elasticsearch non joignable"
    except Exception as e:
        return None, str(e)[:120]


def get_alerts_by_community_id(community_id):
    """
    Retourne toutes les alertes IDS (Suricata + Snort) partageant ce Community ID.
    Retourne (alerts: list, error: str|None).
    """
    body = {
        "size": 10,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "must": [{"term": {"community_id": community_id}}],
                "should": [
                    {"term": {"event_type": "alert"}},
                    {"exists": {"field": "rule"}},
                ],
                "minimum_should_match": 1,
            }
        },
        "_source": [
            "@timestamp", "src_ip", "dest_ip",
            "alert", "msg", "class", "priority",
            "event_type", "community_id",
        ],
    }
    try:
        r = _es("/suricata-*,snort-*/_search", body)
        r.raise_for_status()
        hits = r.json().get("hits", {}).get("hits", [])
        return [_normalize(h) for h in hits], None
    except Exception as e:
        return [], str(e)[:120]


def get_alert_timeseries(hours=24, interval="1h"):
    """
    Série temporelle des alertes pour les sparklines (volume horaire sur 24h).
    Retourne (series: list[{"t", "total", "critical"}], error: str|None).
    """
    body = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [{"range": {"@timestamp": {"gte": f"now-{hours}h"}}}],
                "should": [
                    {"term":   {"event_type": "alert"}},
                    {"exists": {"field": "rule"}},
                ],
                "minimum_should_match": 1,
            }
        },
        "aggs": {
            "per_bucket": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": interval,
                    "min_doc_count": 0,
                    "extended_bounds": {"min": f"now-{hours}h", "max": "now"},
                },
                "aggs": {
                    # Critiques = severity Suricata 1 OU priority Snort 1
                    "critical": {
                        "filter": {
                            "bool": {
                                "should": [
                                    {"term": {"alert.severity": 1}},
                                    {"term": {"priority":       1}},
                                ],
                                "minimum_should_match": 1,
                            }
                        }
                    }
                },
            }
        },
    }

    try:
        r = _es("/suricata-*,snort-*/_search", body)
        r.raise_for_status()
        buckets = (r.json().get("aggregations", {})
                          .get("per_bucket", {})
                          .get("buckets", []))
        series = [
            {
                "t":        b.get("key_as_string", ""),
                "total":    b.get("doc_count", 0),
                "critical": b.get("critical", {}).get("doc_count", 0),
            }
            for b in buckets
        ]
        return series, None
    except requests.exceptions.ConnectionError:
        return [], "Elasticsearch non joignable"
    except Exception as e:
        return [], str(e)[:80]


def get_geo_data():
    """
    Agrège tous les événements géolocalisés (alertes + Zeek) par pays.
    Retourne (countries: list, total_geolocated: int, error: str|None).
    """
    body = {
        "size": 0,
        "query": {"exists": {"field": "source.geo.country_name"}},
        "aggs": {
            "total_geo": {
                "value_count": {"field": "source.geo.country_name.keyword"}
            },
            "by_country": {
                "terms": {
                    "field": "source.geo.country_name.keyword",
                    "size": 100,
                },
                "aggs": {
                    "sample": {
                        "top_hits": {
                            "size": 1,
                            "_source": [
                                "source.geo.location",
                                "source.geo.country_iso_code",
                            ],
                        }
                    },
                    "critical": {
                        "filter": {
                            "bool": {
                                "should": [
                                    {"term": {"alert.severity": 1}},
                                    {"term": {"priority": 1}},
                                ],
                                "minimum_should_match": 1,
                            }
                        }
                    },
                    "medium": {
                        "filter": {
                            "bool": {
                                "should": [
                                    {"term": {"alert.severity": 2}},
                                    {"term": {"priority": 2}},
                                ],
                                "minimum_should_match": 1,
                            }
                        }
                    },
                },
            },
        },
    }

    try:
        r = _es("/zeek-*,suricata-*,snort-*/_search", body)
        r.raise_for_status()
        data = r.json()
        aggs  = data.get("aggregations", {})
        total = int(aggs.get("total_geo", {}).get("value", 0))

        countries = []
        for b in aggs.get("by_country", {}).get("buckets", []):
            # Extraire lat/lon depuis un doc sample (top_hits)
            hits   = b.get("sample", {}).get("hits", {}).get("hits", [])
            geo    = (hits[0].get("_source", {})
                              .get("source", {})
                              .get("geo", {}) if hits else {})
            loc    = geo.get("location", {})
            # location peut être {"lat":x,"lon":y} ou "lat,lon" string
            if isinstance(loc, dict):
                lat = float(loc.get("lat", 0))
                lon = float(loc.get("lon", 0))
            elif isinstance(loc, str) and "," in loc:
                parts = loc.split(",")
                lat, lon = float(parts[0]), float(parts[1])
            else:
                lat, lon = 0.0, 0.0

            iso      = geo.get("country_iso_code", "")
            critical = b.get("critical", {}).get("doc_count", 0)
            medium   = b.get("medium",   {}).get("doc_count", 0)
            count    = b.get("doc_count", 0)
            countries.append({
                "country":  b["key"],
                "iso":      iso,
                "lat":      lat,
                "lon":      lon,
                "count":    count,
                "critical": critical,
                "medium":   medium,
                "low":      max(0, count - critical - medium),
            })

        countries.sort(key=lambda x: x["count"], reverse=True)
        return countries, total, None

    except requests.exceptions.ConnectionError:
        return [], 0, "Elasticsearch non joignable"
    except Exception as e:
        return [], 0, str(e)[:80]


def get_ip_events(ip, size=200):
    """
    Agrège toutes les alertes + stats Zeek pour une IP donnée.
    Retourne (alerts: list, conn_stats: dict, error: str|None).
    """
    ip_filter = {
        "bool": {
            "should": [
                {"term": {"src_ip":   ip}},
                {"term": {"dest_ip":  ip}},
                {"term": {"src_addr": ip}},
                {"term": {"dst_addr": ip}},
            ],
            "minimum_should_match": 1,
        }
    }

    alert_body = {
        "size": size,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "filter": [
                    {"bool": {
                        "should": [
                            {"term":   {"event_type": "alert"}},
                            {"exists": {"field": "rule"}},
                        ],
                        "minimum_should_match": 1,
                    }},
                    ip_filter,
                ]
            }
        },
    }

    alerts, error = [], None
    try:
        r = _es("/suricata-*,snort-*/_search", alert_body)
        r.raise_for_status()
        alerts = [_normalize(h) for h in r.json().get("hits", {}).get("hits", [])]
    except Exception as e:
        error = str(e)[:80]

    zeek_body = {
        "size": 0,
        "query": {
            "bool": {
                "should": [
                    {"term": {"id.orig_h": ip}},
                    {"term": {"id.resp_h": ip}},
                ],
                "minimum_should_match": 1,
            }
        },
        "aggs": {
            "top_ports":   {"terms": {"field": "id.resp_p", "size": 10}},
            "total_bytes": {"sum":   {"field": "orig_bytes"}},
            "first_seen":  {"min":   {"field": "@timestamp"}},
            "last_seen":   {"max":   {"field": "@timestamp"}},
            "proto":       {"terms": {"field": "proto",     "size": 5}},
        },
    }

    conn_stats = {}
    try:
        r = _es("/zeek-*/_search", zeek_body)
        r.raise_for_status()
        data = r.json()
        aggs = data.get("aggregations", {})
        conn_stats = {
            "total_conns":  data.get("hits", {}).get("total", {}).get("value", 0),
            "top_ports":    [(b["key"], b["doc_count"])
                             for b in aggs.get("top_ports", {}).get("buckets", [])],
            "total_bytes":  int(aggs.get("total_bytes", {}).get("value") or 0),
            "first_seen":   aggs.get("first_seen", {}).get("value_as_string", ""),
            "last_seen":    aggs.get("last_seen",  {}).get("value_as_string", ""),
            "protocols":    [b["key"] for b in aggs.get("proto", {}).get("buckets", [])],
        }
    except Exception:
        pass

    return alerts, conn_stats, error


def get_alert_stats():
    """
    Statistiques pour le widget dashboard et le header /alerts.
    Retourne (stats: dict, error: str|None).
    """
    body = {
        "size": 0,
        "query": {
            "bool": {
                "should": [
                    {"term":   {"event_type": "alert"}},
                    {"exists": {"field": "rule"}},
                ],
                "minimum_should_match": 1,
            }
        },
        "aggs": {
            "last_24h": {
                "filter": {"range": {"@timestamp": {"gte": "now-24h"}}},
                "aggs": {
                    "by_severity_24h": {
                        "terms": {"field": "alert.severity", "size": 5, "missing": 3}
                    }
                },
            },
            "by_severity": {
                "terms": {"field": "alert.severity", "size": 5, "missing": 3}
            },
            "by_mitre": {
                "terms": {
                    "field": "alert.metadata.mitre_tactic_name.keyword",
                    "size": 5,
                }
            },
        },
    }

    try:
        r = _es("/suricata-*,snort-*/_search", body)
        r.raise_for_status()
        data = r.json()
        aggs  = data.get("aggregations", {})
        total = data.get("hits", {}).get("total", {}).get("value", 0)

        last_24h = aggs.get("last_24h", {}).get("doc_count", 0)

        # Sévérités (priorité = 1 critique)
        sev = {b["key"]: b["doc_count"]
               for b in aggs.get("by_severity", {}).get("buckets", [])}

        # Top MITRE tactics
        mitre = [(b["key"], b["doc_count"])
                 for b in aggs.get("by_mitre", {}).get("buckets", [])]

        return {
            "total":    total,
            "last_24h": last_24h,
            "critical": sev.get(1, 0),
            "medium":   sev.get(2, 0),
            "low":      sev.get(3, 0),
            "mitre":    mitre[:5],
        }, None

    except requests.exceptions.ConnectionError:
        return None, "Elasticsearch non joignable"
    except Exception as e:
        return None, str(e)[:80]


# ------------------------------------------------------------------ #
# Zeek logs enrichis — weird / files / x509                           #
# ------------------------------------------------------------------ #

_SUSPICIOUS_MIMES = {
    "application/x-dosexec":       "Exécutable Windows",
    "application/x-msdownload":    "Exécutable Windows",
    "application/x-msdos-program": "Exécutable DOS/Windows",
    "application/x-executable":    "Exécutable Linux",
    "application/x-elf":           "Binaire ELF Linux",
    "application/x-sh":            "Script Shell",
    "application/x-shellscript":   "Script Shell",
    "text/x-shellscript":          "Script Shell",
    "application/javascript":      "Script JavaScript",
    "application/x-javascript":    "Script JavaScript",
    "application/x-python":        "Script Python",
    "application/x-perl":          "Script Perl",
}


def get_tls_certs(size=50):
    """
    Certificats TLS vus sur le réseau (x509.log Zeek).
    Retourne (certs: list, error: str|None).
    """
    body = {
        "size": size,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"term": {"_path": "x509"}},
        "_source": [
            "@timestamp", "certificate",
        ],
    }
    try:
        r = _es("/zeek-*/_search", body)
        r.raise_for_status()
        hits = r.json().get("hits", {}).get("hits", [])
        now  = datetime.now(timezone.utc)
        results = []
        for h in hits:
            src  = h["_source"]
            cert = src.get("certificate", {})
            subject  = cert.get("subject", "")
            issuer   = cert.get("issuer",  "")
            not_after_raw = cert.get("not_valid_after")

            cn_m = re.search(r"CN=([^,/]+)", subject)
            cn   = cn_m.group(1) if cn_m else subject[:50] or "—"

            expiry_str = None
            expired = expiring_soon = False
            if not_after_raw:
                try:
                    expiry = datetime.fromtimestamp(float(not_after_raw), tz=timezone.utc)
                    expiry_str = expiry.strftime("%Y-%m-%d")
                    delta = (expiry - now).days
                    expired      = delta < 0
                    expiring_soon = 0 <= delta < 30
                except (ValueError, OSError):
                    pass

            results.append({
                "timestamp":    src.get("@timestamp", ""),
                "cn":           cn,
                "subject":      subject,
                "issuer":       issuer,
                "not_after":    expiry_str,
                "key_type":     cert.get("key_type", "—"),
                "key_length":   cert.get("key_length"),
                "self_signed":  bool(subject and subject == issuer),
                "expired":      expired,
                "expiring_soon": expiring_soon,
            })
        return results, None
    except requests.exceptions.ConnectionError:
        return [], "Elasticsearch non joignable"
    except Exception as e:
        return [], str(e)[:120]


def get_suspicious_files(size=50):
    """
    Fichiers aux MIME types suspects transférés sur le réseau (files.log Zeek).
    Retourne (files: list, error: str|None).
    """
    body = {
        "size": size,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "must": [{"term": {"_path": "files"}}],
                "should": [{"term": {"mime_type": m}} for m in _SUSPICIOUS_MIMES],
                "minimum_should_match": 1,
            }
        },
        "_source": [
            "@timestamp", "mime_type", "filename",
            "seen_bytes", "tx_hosts", "rx_hosts", "source", "md5", "sha1",
        ],
    }
    try:
        r = _es("/zeek-*/_search", body)
        r.raise_for_status()
        hits = r.json().get("hits", {}).get("hits", [])
        results = []
        for h in hits:
            src  = h["_source"]
            mime = src.get("mime_type", "—")
            tx   = src.get("tx_hosts", [])
            rx   = src.get("rx_hosts", [])
            results.append({
                "timestamp": src.get("@timestamp", ""),
                "mime_type": mime,
                "mime_label": _SUSPICIOUS_MIMES.get(mime, mime),
                "filename":  src.get("filename") or "—",
                "size":      src.get("seen_bytes", 0),
                "md5":       src.get("md5") or "—",
                "sha1":      src.get("sha1") or "—",
                "src":       (tx[0] if isinstance(tx, list) and tx else str(tx or "—")),
                "dst":       (rx[0] if isinstance(rx, list) and rx else str(rx or "—")),
                "source":    src.get("source", "—"),
            })
        return results, None
    except requests.exceptions.ConnectionError:
        return [], "Elasticsearch non joignable"
    except Exception as e:
        return [], str(e)[:120]


def get_weird_events(size=50):
    """
    Violations et anomalies protocolaires (weird.log Zeek).
    Retourne (events: list, error: str|None).
    """
    body = {
        "size": size,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"term": {"_path": "weird"}},
        "_source": ["@timestamp", "name", "addl", "id"],
    }
    try:
        r = _es("/zeek-*/_search", body)
        r.raise_for_status()
        hits = r.json().get("hits", {}).get("hits", [])
        results = []
        for h in hits:
            src = h["_source"]
            id_ = src.get("id", {})
            results.append({
                "timestamp": src.get("@timestamp", ""),
                "name":      src.get("name", "—"),
                "addl":      src.get("addl") or "—",
                "src_ip":    id_.get("orig_h", "—"),
                "dst_ip":    id_.get("resp_h", "—"),
                "src_port":  id_.get("orig_p", ""),
                "dst_port":  id_.get("resp_p", ""),
            })
        return results, None
    except requests.exceptions.ConnectionError:
        return [], "Elasticsearch non joignable"
    except Exception as e:
        return [], str(e)[:120]
