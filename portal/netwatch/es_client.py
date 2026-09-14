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

import copy
import math
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone, timedelta
from functools import wraps

import requests
from requests.adapters import HTTPAdapter

import config

_TIMEOUT = 5

# Session HTTP partagée : keep-alive + pool de connexions vers ES. Sans elle,
# chaque agg ouvrait une nouvelle connexion TCP (handshake à chaque requête —
# sensible sur la VM Shuttle dont l'I/O est lent).
_SESSION = requests.Session()
_SESSION.mount("http://",  HTTPAdapter(pool_connections=4, pool_maxsize=16))
_SESSION.mount("https://", HTTPAdapter(pool_connections=4, pool_maxsize=16))


def _es(path, body=None, method="post"):
    url = config.NETWATCH_ES_URL.rstrip("/") + path
    kw  = {"timeout": _TIMEOUT, "verify": config.ES_VERIFY_SSL}
    if body is not None:
        kw["json"] = body
    return _SESSION.request(method.upper(), url, **kw)


# ------------------------------------------------------------------ #
# Cache TTL en mémoire + exécution parallèle                           #
# ------------------------------------------------------------------ #

_CACHE: dict = {}
_CACHE_LOCK = threading.Lock()
_ERROR_TTL  = 10   # un résultat en erreur (ES down) n'est gardé que 10 s


def _ttl_cache(ttl):
    """Mémoïse le résultat d'une fonction pendant `ttl` s (clé = nom + args).
    Les aggs ES sont relancées par le polling de plusieurs pages (badge nav,
    dashboard, status…) ; les servir depuis le cache évite N requêtes
    identiques par minute. Les résultats sont copiés en profondeur pour que
    l'appelant puisse les modifier sans polluer le cache. Le dernier élément
    d'un tuple retourné est traité comme l'erreur : s'il est non nul, l'entrée
    n'est conservée que _ERROR_TTL s pour ne pas masquer un retour à la normale."""
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            key = (fn.__name__, repr(args), repr(sorted(kwargs.items())))
            now = time.monotonic()
            with _CACHE_LOCK:
                hit = _CACHE.get(key)
                if hit and hit[0] > now:
                    return copy.deepcopy(hit[1])
            result = fn(*args, **kwargs)
            err = result[-1] if isinstance(result, tuple) and isinstance(result[-1], (str, type(None))) else None
            with _CACHE_LOCK:
                _CACHE[key] = (now + (_ERROR_TTL if err else ttl), copy.deepcopy(result))
            return result
        return wrapper
    return deco


def cache_clear():
    """Vide le cache (tests / bouton refresh forcé)."""
    with _CACHE_LOCK:
        _CACHE.clear()


def _parallel(*calls):
    """Exécute des callables sans argument en parallèle et retourne leurs
    résultats dans l'ordre — pour les requêtes indépendantes d'une même page."""
    if len(calls) == 1:
        return [calls[0]()]
    with ThreadPoolExecutor(max_workers=len(calls)) as pool:
        return list(pool.map(lambda c: c(), calls))


run_parallel = _parallel   # nom public pour app.py


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

def get_recent_alerts(size=100, engine=None, severity=None, search=None, days=7):
    """
    Retourne (alerts: list, error: str|None).
    engine   : "suricata" | "snort" | None
    severity : 1 | 2 | 3 | None
    search   : str libre (signature, IP) | None
    days     : fenêtre temporelle en jours (borne la requête, perf en prod)
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
        },
        {"range": {"@timestamp": {"gte": f"now-{days}d"}}},
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
        # community_id est mappé "text" (mapping dynamique ES), pas "keyword" —
        # un term query sur le champ nu ne matche jamais la valeur exacte
        # (tokenisée par l'analyzer standard). D'où .keyword ici.
        "query": {"term": {"community_id.keyword": community_id}},
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
                "must": [{"term": {"community_id.keyword": community_id}}],
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


@_ttl_cache(60)
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


@_ttl_cache(60)
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

    def _fetch_alerts():
        try:
            r = _es("/suricata-*,snort-*/_search", alert_body)
            r.raise_for_status()
            return [_normalize(h) for h in r.json().get("hits", {}).get("hits", [])], None
        except Exception as e:
            return [], str(e)[:80]

    zeek_body = {
        "size": 0,
        "query": {
            "bool": {
                # scope à conn.log — sans ce discriminant, l'agg mélange tous les
                # types de logs Zeek mentionnant cette IP (dns, http, ssl, weird,
                # files, notice, x509 ont aussi id.orig_h/id.resp_h), gonflant
                # total_conns/total_bytes/top_ports au-delà des vraies connexions.
                "filter": [_log_src("conn")],
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

    def _fetch_conn():
        try:
            r = _es("/zeek-*/_search", zeek_body)
            r.raise_for_status()
            data = r.json()
            aggs = data.get("aggregations", {})
            return {
                "total_conns":  data.get("hits", {}).get("total", {}).get("value", 0),
                "top_ports":    [(b["key"], b["doc_count"])
                                 for b in aggs.get("top_ports", {}).get("buckets", [])],
                "total_bytes":  int(aggs.get("total_bytes", {}).get("value") or 0),
                "first_seen":   aggs.get("first_seen", {}).get("value_as_string", ""),
                "last_seen":    aggs.get("last_seen",  {}).get("value_as_string", ""),
                "protocols":    [b["key"] for b in aggs.get("proto", {}).get("buckets", [])],
            }
        except Exception:
            return {}

    # Alertes (suricata/snort) et stats conn (zeek) : deux index, deux requêtes
    # indépendantes → en parallèle.
    (alerts, error), conn_stats = _parallel(_fetch_alerts, _fetch_conn)
    return alerts, conn_stats, error


_EMPTY_ALERT_STATS = {
    "total": 0, "last_24h": 0, "critical": 0, "medium": 0, "low": 0, "mitre": [],
}


@_ttl_cache(30)
def get_alert_stats(days=7):
    """
    Statistiques pour le widget dashboard et le header /alerts.
    days : fenêtre temporelle en jours (borne la requête, perf en prod).
    Retourne (stats: dict, error: str|None).
    """
    body = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": f"now-{days}d"}}},
                ],
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
                    # value_type : indispensable quand le champ n'est pas mappé
                    # dans certains index (missing + champ inconnu → 400 ES)
                    "by_severity_24h": {
                        "terms": {"field": "alert.severity", "size": 5, "missing": 3, "value_type": "long"}
                    }
                },
            },
            "by_severity": {
                "terms": {"field": "alert.severity", "size": 5, "missing": 3, "value_type": "long"}
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
        return _EMPTY_ALERT_STATS.copy(), "Elasticsearch non joignable"
    except Exception as e:
        return _EMPTY_ALERT_STATS.copy(), str(e)[:80]


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
        "query": _log_src("x509"),
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
                "must": [_log_src("files")],
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


@_ttl_cache(60)
def get_exec_stats():
    """
    Statistiques pour le dashboard exécutif RSSI.
    Les 4 sources (stats 24h, top règles, sparkline 7j, AutoBlock) sont
    indépendantes → interrogées en parallèle.
    Retourne (data: dict, error: str|None).
    """
    # --- 1. Stats 24h : total, par sévérité, top IPs, cardinal règles ---
    body_24h = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [{"range": {"@timestamp": {"gte": "now-24h"}}}],
                "should": [
                    {"term":   {"event_type": "alert"}},
                    {"exists": {"field": "rule"}},
                ],
                "minimum_should_match": 1,
            }
        },
        "aggs": {
            "by_severity": {
                "terms": {"field": "alert.severity", "size": 5, "missing": 3, "value_type": "long"}
            },
            "top_src_ip": {
                "terms": {"field": "src_ip", "size": 3},
                "aggs": {
                    "top_engine": {
                        "terms": {"field": "_index", "size": 1}
                    }
                },
            },
            "unique_rules": {
                "cardinality": {"field": "alert.signature.keyword"}
            },
        },
    }

    _empty_24h = {
        "total_24h": 0, "critical_24h": 0, "high_24h": 0,
        "medium_24h": 0, "unique_rules_count": 0, "top_ips": [],
    }

    def _fetch_24h():
        try:
            r = _es("/suricata-*,snort-*/_search", body_24h)
            r.raise_for_status()
            data = r.json()
            aggs  = data.get("aggregations", {})
            sev = {b["key"]: b["doc_count"]
                   for b in aggs.get("by_severity", {}).get("buckets", [])}
            top_ips = []
            for b in aggs.get("top_src_ip", {}).get("buckets", []):
                idx_buckets = b.get("top_engine", {}).get("buckets", [])
                engine = "suricata" if idx_buckets and "suricata" in idx_buckets[0].get("key", "") else "snort"
                top_ips.append({"ip": b["key"], "count": b["doc_count"], "engine": engine})
            return {
                "total_24h":          data.get("hits", {}).get("total", {}).get("value", 0),
                "critical_24h":       sev.get(1, 0),
                "high_24h":           sev.get(2, 0),
                "medium_24h":         sev.get(3, 0),
                "unique_rules_count": int(aggs.get("unique_rules", {}).get("value", 0)),
                "top_ips":            top_ips,
            }, None
        except requests.exceptions.ConnectionError:
            return dict(_empty_24h), "Elasticsearch non joignable"
        except Exception as e:
            return dict(_empty_24h), str(e)[:80]

    # --- 2. Top 5 règles 24h (Suricata — champ alert.signature) ---
    body_rules = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [{"range": {"@timestamp": {"gte": "now-24h"}}}],
                "must": [{"term": {"event_type": "alert"}}],
            }
        },
        "aggs": {
            "top_rules": {
                "terms": {"field": "alert.signature.keyword", "size": 5},
                "aggs": {
                    "min_sev": {"min": {"field": "alert.severity"}}
                },
            }
        },
    }

    def _fetch_rules():
        try:
            r = _es("/suricata-*/_search", body_rules)
            r.raise_for_status()
            aggs = r.json().get("aggregations", {})
            top_rules = []
            for b in aggs.get("top_rules", {}).get("buckets", []):
                sev_val = b.get("min_sev", {}).get("value")
                top_rules.append({
                    "rule":     b["key"],
                    "count":    b["doc_count"],
                    "severity": int(sev_val) if sev_val is not None else 3,
                })
            return top_rules
        except Exception:
            return []

    # --- 3. Sparkline 7 jours ---
    body_7d = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [{"range": {"@timestamp": {"gte": "now-7d"}}}],
                "should": [
                    {"term":   {"event_type": "alert"}},
                    {"exists": {"field": "rule"}},
                ],
                "minimum_should_match": 1,
            }
        },
        "aggs": {
            "per_day": {
                "date_histogram": {
                    "field":             "@timestamp",
                    "calendar_interval": "1d",
                    "min_doc_count":     0,
                    "extended_bounds":   {"min": "now-7d/d", "max": "now/d"},
                }
            }
        },
    }

    def _fetch_7d():
        try:
            r = _es("/suricata-*,snort-*/_search", body_7d)
            r.raise_for_status()
            buckets = (r.json().get("aggregations", {})
                               .get("per_day", {})
                               .get("buckets", []))
            return [{"t": b.get("key_as_string", ""), "count": b.get("doc_count", 0)}
                    for b in buckets]
        except Exception:
            return []

    # --- 4. IPs bloquées (AutoBlock) ---
    def _fetch_blocked():
        try:
            rb = _SESSION.get(config.NETWATCH_AUTOBLOCK_URL.rstrip("/") + "/blocked", timeout=3)
            if rb.status_code == 200:
                blocked = rb.json()
                return len(blocked) if isinstance(blocked, list) else 0
        except Exception:
            pass
        return 0

    (stats_24h, err), top_rules, sparkline, blocked = _parallel(
        _fetch_24h, _fetch_rules, _fetch_7d, _fetch_blocked)
    results: dict = {
        **stats_24h,
        "top_rules":     top_rules,
        "sparkline_7d":  sparkline,
        "blocked_count": blocked,
    }

    # --- 5. Score de posture ---
    crit   = results.get("critical_24h", 0)
    high   = results.get("high_24h", 0)
    unique = results.get("unique_rules_count", 0)

    penalty_crit  = min(crit * 5,   40)
    penalty_high  = min(high * 2,   20)
    penalty_rules = min(unique * 1, 20)

    results["posture_score"] = max(0, 100 - penalty_crit - penalty_high - penalty_rules)

    return results, err


def get_weird_events(size=50):
    """
    Violations et anomalies protocolaires (weird.log Zeek).
    Retourne (events: list, error: str|None).
    """
    body = {
        "size": size,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": _log_src("weird"),
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


# ------------------------------------------------------------------ #
# Flows — T_019                                                        #
# ------------------------------------------------------------------ #

@_ttl_cache(300)
def _index_exists(pattern):
    """Retourne True si le pattern d'index contient au moins un document.
    Mis en cache 5 min : la présence d'un index ne change pas à la seconde."""
    try:
        r = _es(f"/{pattern}/_count", method="get")
        if r.status_code in (400, 404):
            return False
        r.raise_for_status()
        return r.json().get("count", 0) > 0
    except Exception:
        return False


@_ttl_cache(60)
def get_flows_stats():
    """
    Top talkers (src/dst), top proto/ports, timeline 24h.
    Utilise netflow-* si disponible, sinon zeek-* conn.log.
    Retourne (data: dict, error: str|None).
    """
    _empty = {
        "top_src": [], "top_dst": [], "top_ports": [], "timeline": [],
        "source": "unknown", "warning": "index introuvable",
    }

    # ── 1. Essayer netflow-* (GoFlow2) ──
    if _index_exists("netflow-*"):
        body = {
            "size": 0,
            "query": {"range": {"@timestamp": {"gte": "now-24h"}}},
            "aggs": {
                "top_src": {
                    "terms": {"field": "src_addr.keyword", "size": 10},
                    "aggs": {"bytes": {"sum": {"field": "in_bytes"}}},
                },
                "top_dst": {
                    "terms": {"field": "dst_addr.keyword", "size": 10},
                    "aggs": {"bytes": {"sum": {"field": "in_bytes"}}},
                },
                "top_ports": {
                    "terms": {
                        "script": {
                            # src_addr/dst_addr/proto sont mappés "text" par le
                            # mapping dynamique ES (pas de fielddata) — utiliser
                            # le sous-champ .keyword pour l'accès en painless.
                            "source": (
                                "def p = doc.containsKey('proto.keyword') && doc['proto.keyword'].size()>0"
                                " ? doc['proto.keyword'].value : '?';"
                                " def d = doc.containsKey('dst_port') && doc['dst_port'].size()>0"
                                " ? String.valueOf((long)doc['dst_port'].value) : '?';"
                                " return p+'/'+d"
                            ),
                            "lang": "painless",
                        },
                        "size": 10,
                    },
                    "aggs": {"bytes": {"sum": {"field": "in_bytes"}}},
                },
                "timeline": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": "1h",
                        "min_doc_count": 0,
                        "extended_bounds": {"min": "now-24h", "max": "now"},
                    },
                    "aggs": {"bytes": {"sum": {"field": "in_bytes"}}},
                },
            },
        }
        try:
            r = _es("/netflow-*/_search", body)
            r.raise_for_status()
            aggs = r.json().get("aggregations", {})

            def _nf(b):
                return {"ip": b["key"],
                        "bytes": int(b.get("bytes", {}).get("value") or 0),
                        "count": b["doc_count"]}

            # Index netflow-* présent mais vide sur 24h (ex. quelques docs de
            # test GoFlow2) → ne pas afficher « 0 B » alors que Zeek a des flux.
            if not aggs.get("top_src", {}).get("buckets"):
                raise LookupError("netflow-* sans données sur 24h")

            return {
                "source": "netflow",
                "top_src":  [_nf(b) for b in aggs.get("top_src",  {}).get("buckets", [])],
                "top_dst":  [_nf(b) for b in aggs.get("top_dst",  {}).get("buckets", [])],
                "top_ports": [
                    {"port": b["key"],
                     "bytes": int(b.get("bytes", {}).get("value") or 0),
                     "count": b["doc_count"]}
                    for b in aggs.get("top_ports", {}).get("buckets", [])
                ],
                "timeline": [
                    {"t": b.get("key_as_string", ""),
                     "bytes": int(b.get("bytes", {}).get("value") or 0)}
                    for b in aggs.get("timeline", {}).get("buckets", [])
                ],
            }, None
        except requests.exceptions.ConnectionError:
            return {**_empty, "warning": "Elasticsearch non joignable"}, "Elasticsearch non joignable"
        except Exception:
            pass  # Fall through to Zeek

    # ── 2. Fallback zeek-* conn.log ──
    body_z = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": "now-24h"}}},
                    _log_src("conn"),
                ]
            }
        },
        "aggs": {
            "top_src": {
                "terms": {"field": "id.orig_h.keyword", "size": 10},
                "aggs": {
                    "ob": {"sum": {"field": "orig_bytes"}},
                    "rb": {"sum": {"field": "resp_bytes"}},
                },
            },
            "top_dst": {
                "terms": {"field": "id.resp_h.keyword", "size": 10},
                "aggs": {
                    "ob": {"sum": {"field": "orig_bytes"}},
                    "rb": {"sum": {"field": "resp_bytes"}},
                },
            },
            "top_ports": {
                "terms": {
                    "script": {
                        # proto/id.orig_h/id.resp_h sont mappés "text" par le
                        # mapping dynamique ES (pas de fielddata) — utiliser .keyword.
                        "source": (
                            "def p = doc.containsKey('proto.keyword') && doc['proto.keyword'].size()>0"
                            " ? doc['proto.keyword'].value : '?';"
                            " def d = doc.containsKey('id.resp_p') && doc['id.resp_p'].size()>0"
                            " ? String.valueOf((long)doc['id.resp_p'].value) : '?';"
                            " return p+'/'+d"
                        ),
                        "lang": "painless",
                    },
                    "size": 10,
                },
                "aggs": {
                    "ob": {"sum": {"field": "orig_bytes"}},
                    "rb": {"sum": {"field": "resp_bytes"}},
                },
            },
            "timeline": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": "1h",
                    "min_doc_count": 0,
                    "extended_bounds": {"min": "now-24h", "max": "now"},
                },
                "aggs": {
                    "ob": {"sum": {"field": "orig_bytes"}},
                    "rb": {"sum": {"field": "resp_bytes"}},
                },
            },
        },
    }

    try:
        r = _es("/zeek-*/_search", body_z)
        r.raise_for_status()
        aggs = r.json().get("aggregations", {})

        def _sb(b):
            return (int(b.get("ob", {}).get("value") or 0)
                    + int(b.get("rb", {}).get("value") or 0))

        return {
            "source": "zeek",
            "warning": "GoFlow2 non connecté — données issues de Zeek conn.log",
            "top_src": [
                {"ip": b["key"], "bytes": _sb(b), "count": b["doc_count"]}
                for b in aggs.get("top_src", {}).get("buckets", [])
            ],
            "top_dst": [
                {"ip": b["key"], "bytes": _sb(b), "count": b["doc_count"]}
                for b in aggs.get("top_dst", {}).get("buckets", [])
            ],
            "top_ports": [
                {"port": b["key"], "bytes": _sb(b), "count": b["doc_count"]}
                for b in aggs.get("top_ports", {}).get("buckets", [])
            ],
            "timeline": [
                {"t": b.get("key_as_string", ""), "bytes": _sb(b)}
                for b in aggs.get("timeline", {}).get("buckets", [])
            ],
        }, None

    except requests.exceptions.ConnectionError:
        return {**_empty, "warning": "Elasticsearch non joignable"}, "Elasticsearch non joignable"
    except Exception as e:
        return _empty, str(e)[:120]


def _log_src(name):
    """Discriminant de type de log Zeek : log.file.path (posé par Filebeat en
    prod) OU log_source (posé par simulate-traffic.py). Sans le second, toutes
    les requêtes retournent silencieusement vide contre les données simulées."""
    return {
        "bool": {
            "should": [
                {"term": {"log.file.path.keyword": f"/zeek/logs/{name}.log"}},
                {"term": {"log_source": name}},
            ],
            "minimum_should_match": 1,
        }
    }


def _ip_filter(ip):
    """Clause de filtre optionnelle id.orig_h/id.resp_h = ip, pour scoper une requête
    Zeek à un device donné (dashboard par device/hostgroup, T_030)."""
    if not ip:
        return []
    return [{
        "bool": {
            "should": [{"term": {"id.orig_h": ip}}, {"term": {"id.resp_h": ip}}],
            "minimum_should_match": 1,
        }
    }]


def _pct_aggs(field):
    """Sous-aggs percentiles p50/p95/p99 + compte pour un champ de durée."""
    return {
        "pct": {"percentiles": {"field": field, "percents": [50, 95, 99]}},
        "cnt": {"value_count": {"field": field}},
    }


def _pct_entry(agg, conv):
    """Bucket {pct, cnt} → {p50, p95, p99, count} ou None si aucun échantillon."""
    cnt = int(agg.get("cnt", {}).get("value") or 0)
    if cnt <= 0:
        return None
    pts = agg.get("pct", {}).get("values", {})
    return {
        "p50":   conv(pts.get("50.0")),
        "p95":   conv(pts.get("95.0")),
        "p99":   conv(pts.get("99.0")),
        "count": cnt,
    }


@_ttl_cache(60)
def get_art_stats(ip=None):
    """
    Application Response Time p50/p95/p99 par service (http/dns/tls).
    Essaie art.log → fallback conn.log (HTTP/TLS) et dns.log (RTT DNS natif).
    Une seule requête ES : la sonde art.log et les 3 fallbacks sont des
    filter-aggs de la même recherche (4 aller-retours → 1).
    ip : si fourni, restreint aux échanges impliquant ce device (orig ou resp).
    Retourne (data: dict, error: str|None).
    """
    ip_filter = _ip_filter(ip)
    _svc0 = {"p50": None, "p95": None, "p99": None, "count": 0}
    result = {"http": dict(_svc0), "dns": dict(_svc0), "tls": dict(_svc0)}

    def _ms(v):
        """Float secondes → ms arrondi, ou None si absent/NaN."""
        if v is None:
            return None
        try:
            f = float(v)
            return None if math.isnan(f) else round(f * 1000, 1)
        except (TypeError, ValueError):
            return None

    def _ms_direct(v):
        """Float déjà en ms → arrondi, ou None si absent/NaN."""
        if v is None:
            return None
        try:
            f = float(v)
            return None if math.isnan(f) else round(f, 1)
        except (TypeError, ValueError):
            return None

    body = {
        "size": 0,
        "query": {"bool": {"filter": [{"range": {"@timestamp": {"gte": "now-24h"}}}] + ip_filter}},
        "aggs": {
            # Sonde art.log : `global` = hors fenêtre 24h et hors filtre IP, comme
            # avant (on veut savoir si le log existe, pas s'il a bougé aujourd'hui).
            "art_probe": {
                "global": {},
                "aggs": {"probe": {
                    "filter": {"bool": {
                        "should": [
                            {"term":   {"log.file.path.keyword": "/zeek/logs/art.log"}},
                            {"exists": {"field": "art.art_ms"}},
                            {"exists": {"field": "art_ms"}},
                        ],
                        "minimum_should_match": 1,
                    }},
                    "aggs": {"sample": {"top_hits": {
                        "size": 1,
                        "_source": ["art.art_ms", "art_ms", "art.service", "service"],
                    }}},
                }},
            },
            "dns": {
                "filter": {"bool": {"filter": [
                    _log_src("dns"),
                    {"exists": {"field": "rtt"}},
                ]}},
                "aggs": _pct_aggs("rtt"),
            },
            "http": {
                "filter": {"bool": {"filter": [
                    _log_src("conn"),
                    {"exists": {"field": "duration"}},
                    {"term":   {"service": "http"}},
                ]}},
                "aggs": _pct_aggs("duration"),
            },
            "tls": {
                "filter": {"bool": {"filter": [
                    _log_src("conn"),
                    {"exists": {"field": "duration"}},
                    {"bool": {"should": [{"term": {"service": "ssl"}}, {"term": {"service": "tls"}}],
                              "minimum_should_match": 1}},
                ]}},
                "aggs": _pct_aggs("duration"),
            },
        },
    }

    try:
        r = _es("/zeek-*/_search", body)
        r.raise_for_status()
        aggs = r.json().get("aggregations", {})
    except requests.exceptions.ConnectionError:
        return result, "Elasticsearch non joignable"
    except Exception as e:
        return result, str(e)[:120]

    # ── 1. art.log présent → aggs dédiées par service (2e requête, rare) ──
    probe_hits = (aggs.get("art_probe", {}).get("probe", {}).get("sample", {})
                      .get("hits", {}).get("hits", []))
    art_field = svc_field = None
    if probe_hits:
        src = probe_hits[0].get("_source", {})
        if src.get("art", {}).get("art_ms") is not None:
            art_field, svc_field = "art.art_ms", "art.service"
        elif "art_ms" in src:
            art_field, svc_field = "art_ms", "service"
    if art_field:
        try:
            r_art = _es("/zeek-*/_search", {
                "size": 0,
                "query": {"bool": {
                    "filter": ip_filter,
                    "should": [
                        {"term":   {"log.file.path.keyword": "/zeek/logs/art.log"}},
                        {"exists": {"field": art_field}},
                    ],
                    "minimum_should_match": 1,
                }},
                "aggs": {"by_svc": {
                    "terms": {"field": svc_field, "size": 10},
                    "aggs": _pct_aggs(art_field),
                }},
            })
            r_art.raise_for_status()
            for b in r_art.json().get("aggregations", {}).get("by_svc", {}).get("buckets", []):
                svc = b["key"].lower()
                entry = _pct_entry(b, _ms_direct)
                if svc in result and entry:
                    result[svc] = entry
            return result, None
        except Exception:
            pass  # → fallback conn/dns déjà calculé ci-dessous

    # ── 2. Fallback : DNS rtt natif, HTTP/TLS durée conn.log ──
    for svc in ("dns", "http", "tls"):
        entry = _pct_entry(aggs.get(svc, {}), _ms)
        if entry:
            result[svc] = entry

    return result, None


@_ttl_cache(60)
def get_tcp_perf(ip=None):
    """
    Métriques de santé TCP depuis zeek-* conn.log (24h).
    RTT depuis conn.rtt (Zeek 6+), retransmissions et zero-windows via history.
    Une seule requête ES : RTT, volume par IP, retransmissions et zero-windows
    sont des filter-aggs de la même recherche (4 aller-retours → 1).
    ip : si fourni, restreint aux échanges impliquant ce device (orig ou resp).
    Retourne (data: dict, error: str|None).
    """
    result = {
        "avg_rtt_ms": None,
        "p95_rtt_ms": None,
        "top_retransmit_ips": [],
        "zero_windows_count": 0,
        "zero_window_pct": 0.0,
        "top_zero_window_ips": [],
    }

    base = [
        {"range": {"@timestamp": {"gte": "now-24h"}}},
        _log_src("conn"),
        {"term": {"proto": "tcp"}},
    ] + _ip_filter(ip)

    body = {
        "size": 0,
        "track_total_hits": True,   # total exact : dénominateur du ratio zero-window
        "query": {"bool": {"filter": base}},
        "aggs": {
            "rtt": {
                "filter": {"exists": {"field": "rtt"}},
                "aggs": {
                    "avg": {"avg": {"field": "rtt"}},
                    "pct": {"percentiles": {"field": "rtt", "percents": [95]}},
                    "cnt": {"value_count": {"field": "rtt"}},
                },
            },
            # Volume total par IP source (dénominateur du % retransmissions)
            "per_ip": {"terms": {"field": "id.orig_h.keyword", "size": 100}},
            # history contient T ou t → retransmission
            "retrans": {
                "filter": {"regexp": {"history.keyword": ".*[Tt].*"}},
                "aggs": {"per_ip": {"terms": {"field": "id.orig_h.keyword", "size": 10}}},
            },
            # history contient W ou w → zero-window (ratio global + top IPs, à la
            # manière du « TCP zero-window » Netscout/Riverbed)
            "zero_win": {
                "filter": {"regexp": {"history.keyword": ".*[Ww].*"}},
                "aggs": {"per_ip": {"terms": {"field": "id.orig_h.keyword", "size": 10}}},
            },
        },
    }

    try:
        r = _es("/zeek-*/_search", body)
        r.raise_for_status()
        data = r.json()
        aggs = data.get("aggregations", {})
        conn_total_real = int(data.get("hits", {}).get("total", {}).get("value", 0))
    except requests.exceptions.ConnectionError:
        return result, "Elasticsearch non joignable"
    except Exception as e:
        return result, str(e)[:120]

    # ── RTT ──
    rtt = aggs.get("rtt", {})
    if int(rtt.get("cnt", {}).get("value") or 0) > 0:
        avg = rtt.get("avg", {}).get("value")
        p95 = rtt.get("pct", {}).get("values", {}).get("95.0")
        if avg is not None and not math.isnan(float(avg)):
            result["avg_rtt_ms"] = round(float(avg) * 1000, 2)
        if p95 is not None and not math.isnan(float(p95)):
            result["p95_rtt_ms"] = round(float(p95) * 1000, 2)

    # ── Top IPs par retransmissions ──
    total_per_ip = {b["key"]: b["doc_count"]
                    for b in aggs.get("per_ip", {}).get("buckets", [])}
    rows = []
    for b in aggs.get("retrans", {}).get("per_ip", {}).get("buckets", []):
        ip_, cnt = b["key"], b["doc_count"]
        tot = total_per_ip.get(ip_, cnt)
        rows.append({"ip": ip_, "count": cnt,
                     "retransmit_pct": round(cnt / tot * 100, 2) if tot > 0 else 0.0})
    rows.sort(key=lambda x: x["retransmit_pct"], reverse=True)
    result["top_retransmit_ips"] = rows[:10]

    # ── Zero-windows : compteur, ratio global, top IPs ──
    zw = aggs.get("zero_win", {})
    zw_total = int(zw.get("doc_count", 0))
    result["zero_windows_count"] = zw_total
    if conn_total_real > 0:
        result["zero_window_pct"] = round(zw_total / conn_total_real * 100, 2)
    rows = []
    for b in zw.get("per_ip", {}).get("buckets", []):
        ip_, cnt = b["key"], b["doc_count"]
        tot = total_per_ip.get(ip_, cnt)
        rows.append({"ip": ip_, "count": cnt,
                     "zero_window_pct": round(cnt / tot * 100, 2) if tot > 0 else 0.0})
    rows.sort(key=lambda x: x["zero_window_pct"], reverse=True)
    result["top_zero_window_ips"] = rows[:10]

    return result, None


@_ttl_cache(60)
def get_top_talkers(size=10, ip_ranges=None):
    """
    Top devices par volume (octets, 24h) depuis conn.log.
    ip_ranges (optionnel) : plages résolues d'un hostgroup (voir
    netwatch.hostgroups.resolve_ranges) pour restreindre le classement à ce
    groupe — filtré côté Python après une agrégation plus large, cohérent
    avec le filtrage hostgroups déjà utilisé ailleurs dans le portail.
    Retourne (talkers: list[{ip, bytes, conns}], error: str|None).
    """
    body = {
        "size": 0,
        "query": {"bool": {"filter": [
            {"range": {"@timestamp": {"gte": "now-24h"}}},
            _log_src("conn"),
        ]}},
        "aggs": {
            "by_ip": {
                "terms": {"field": "id.orig_h.keyword", "size": 500 if ip_ranges else size},
                "aggs": {
                    "orig_bytes": {"sum": {"field": "orig_bytes"}},
                    "resp_bytes": {"sum": {"field": "resp_bytes"}},
                },
            }
        },
    }
    try:
        r = _es("/zeek-*/_search", body)
        r.raise_for_status()
        buckets = r.json().get("aggregations", {}).get("by_ip", {}).get("buckets", [])
        rows = []
        for b in buckets:
            total = (b.get("orig_bytes", {}).get("value") or 0) + (b.get("resp_bytes", {}).get("value") or 0)
            rows.append({"ip": b["key"], "bytes": int(total), "conns": b["doc_count"]})
        if ip_ranges:
            from .hostgroups import ip_in_ranges
            rows = [row for row in rows if ip_in_ranges(row["ip"], ip_ranges)]
        rows.sort(key=lambda row: row["bytes"], reverse=True)
        return rows[:size], None
    except requests.exceptions.ConnectionError:
        return [], "Elasticsearch non joignable"
    except Exception as e:
        return [], str(e)[:150]


# ------------------------------------------------------------------ #
# SLA Compliance — T_027                                               #
# ------------------------------------------------------------------ #

# Painless script source strings for time-of-day filtering
_BIZ_SCRIPT = (
    "def h=doc['@timestamp'].value.getHour();"
    "def d=doc['@timestamp'].value.getDayOfWeek().getValue();"
    "return h>=8&&h<18&&d>=1&&d<=5"
)
_OFF_SCRIPT = (
    "def h=doc['@timestamp'].value.getHour();"
    "def d=doc['@timestamp'].value.getDayOfWeek().getValue();"
    "return !(h>=8&&h<18&&d>=1&&d<=5)"
)


_BIZ_FILTERS = {
    None:       [],
    "business": [{"script": {"script": {"source": _BIZ_SCRIPT, "lang": "painless"}}}],
    "off":      [{"script": {"script": {"source": _OFF_SCRIPT, "lang": "painless"}}}],
}


def _sla_filter_agg(base_filters, field, biz_filter):
    """filter-agg (spec × plage horaire) → date_histogram 1h → p95 du champ."""
    return {
        "filter": {"bool": {"filter": [*base_filters, *_BIZ_FILTERS[biz_filter]]}},
        "aggs": {"per_hour": {
            "date_histogram": {
                "field":          "@timestamp",
                "fixed_interval": "1h",
                "min_doc_count":  1,
            },
            "aggs": {"p95": {"percentiles": {"field": field, "percents": [95]}}},
        }},
    }


def _compute_sla_compliance(name, target_ms, target_pct, buckets, scale_ms, days):
    """
    Compute SLA compliance from hourly ES buckets.
    scale_ms : True if field is in seconds (multiply ×1000 → ms).
    Returns SLA compliance dict.
    """
    buckets_total = 0
    buckets_ok    = 0
    today = datetime.now(timezone.utc).date()

    # Pre-fill daily slots for the window (oldest → today)
    daily: dict = {}
    for i in range(days, 0, -1):
        d = (today - timedelta(days=i - 1)).isoformat()
        daily[d] = [0, 0]  # [ok_count, total_count]

    for b in buckets:
        if b.get("doc_count", 0) == 0:
            continue
        p95_raw = b.get("p95", {}).get("values", {}).get("95.0")
        if p95_raw is None:
            continue
        try:
            p95_float = float(p95_raw)
        except (TypeError, ValueError):
            continue
        if math.isnan(p95_float):
            continue

        p95_ms   = p95_float * 1000.0 if scale_ms else p95_float
        date_str = b.get("key_as_string", "")[:10]   # YYYY-MM-DD prefix

        buckets_total += 1
        if date_str in daily:
            daily[date_str][1] += 1

        if p95_ms <= target_ms:
            buckets_ok += 1
            if date_str in daily:
                daily[date_str][0] += 1

    compliance_pct = (
        round(buckets_ok / buckets_total * 100, 2) if buckets_total > 0 else 0.0
    )

    if compliance_pct >= target_pct:
        status = "ok"
    elif compliance_pct >= target_pct - 1.0:
        status = "warn"
    else:
        status = "crit"

    timeline = []
    for i in range(days, 0, -1):
        d = (today - timedelta(days=i - 1)).isoformat()
        ok, total = daily.get(d, [0, 0])
        timeline.append({
            "date":           d,
            "compliance_pct": round(ok / total * 100, 1) if total > 0 else None,
        })

    return {
        "name":           name,
        "target_ms":      target_ms,
        "target_pct":     target_pct,
        "compliance_pct": compliance_pct,
        "buckets_ok":     buckets_ok,
        "buckets_total":  buckets_total,
        "status":         status,
        "timeline":       timeline,
    }


@_ttl_cache(120)
def get_sla_stats(days=7):
    """
    SLA compliance sur `days` jours pour HTTP ART, DNS RTT, TCP RTT.
    Sources :
      - HTTP ART : zeek-* http.log  (duration, secondes → ms)
      - DNS RTT  : zeek-* dns.log   (rtt,      secondes → ms)
      - TCP RTT  : zeek-* conn.log  (rtt > 0,  secondes → ms, proto=tcp)
    Business hours : L-V 8h-18h UTC (filtre Painless).
    Une seule requête ES : les 3 SLA × 3 plages horaires sont 9 filter-aggs de
    la même recherche (9 aller-retours → 1).
    Retourne (data: dict, error: str|None).
    """
    target_pct = config.SLA_TARGET_PCT

    sla_specs = [
        {
            "key":       "http",
            "name":      "HTTP ART",
            "target_ms": config.SLA_HTTP_TARGET_MS,
            "filters":   [
                _log_src("http"),
                {"exists": {"field": "duration"}},
            ],
            "field":    "duration",
            "scale_ms": True,
        },
        {
            "key":       "dns",
            "name":      "DNS RTT",
            "target_ms": config.SLA_DNS_TARGET_MS,
            "filters":   [
                _log_src("dns"),
                {"exists": {"field": "rtt"}},
            ],
            "field":    "rtt",
            "scale_ms": True,
        },
        {
            "key":       "tcp",
            "name":      "TCP RTT",
            "target_ms": config.SLA_RTT_TARGET_MS,
            "filters":   [
                _log_src("conn"),
                {"term":  {"proto": "tcp"}},
                {"range": {"rtt": {"gt": 0}}},
            ],
            "field":    "rtt",
            "scale_ms": True,
        },
    ]
    windows = [(None, "slas"), ("business", "business_hours"), ("off", "off_hours")]

    body = {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": f"now-{days}d"}}},
        "aggs": {
            f"{spec['key']}__{biz or 'all'}": _sla_filter_agg(spec["filters"], spec["field"], biz)
            for spec in sla_specs for biz, _ in windows
        },
    }

    aggs, error = {}, None
    try:
        r = _es("/zeek-*/_search", body)
        r.raise_for_status()
        aggs = r.json().get("aggregations", {})
    except requests.exceptions.ConnectionError:
        error = "Elasticsearch non joignable"
    except Exception as e:
        error = str(e)[:120]

    result: dict = {
        "slas":           [],
        "business_hours": {"slas": []},
        "off_hours":      {"slas": []},
    }
    for spec in sla_specs:
        for biz, target_key in windows:
            buckets = (aggs.get(f"{spec['key']}__{biz or 'all'}", {})
                           .get("per_hour", {}).get("buckets", []))
            entry = _compute_sla_compliance(
                spec["name"], spec["target_ms"], target_pct,
                buckets, spec["scale_ms"], days,
            )
            if biz is None:
                result["slas"].append(entry)
            else:
                result[target_key]["slas"].append(entry)

    return result, error
