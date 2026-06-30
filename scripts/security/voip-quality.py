#!/usr/bin/env python3
"""
NetWatch — VoIP Quality Analysis (T_026)

Interroge Elasticsearch (index zeek-*) pour évaluer la qualité VoIP :
  - Source primaire : voip.log indexé (champs directs mos_score, jitter_ms, etc.)
  - Fallback 1 : sip.log + conn.log UDP → reconstruction + calcul MOS E-model G.107
  - Fallback 2 : conn.log UDP seul (plages ports RTP) avec estimation latence RTT

CLI :
    python3 voip-quality.py [--days 1] [--output voip-stats.json] [--demo]

Output JSON :
    {
      "avg_mos": float,
      "calls_total": int,
      "calls_excellent": int,   # MOS >= 4.3
      "calls_good": int,        # MOS >= 4.0
      "calls_fair": int,        # MOS >= 3.6
      "calls_poor": int,        # MOS >= 3.1
      "calls_bad": int,         # MOS < 3.1
      "top_bad_calls": [        # 10 pires appels
        {"src": str, "dst": str, "mos": float, "duration_s": float, "jitter_ms": float}
      ],
      "generated_at": "ISO8601",
      "source": "voip_log|sip_conn|conn_udp|demo"
    }
"""

from __future__ import annotations

import argparse
import json
import logging
import math
import os
import random
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any

# ─────────────────────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────────────────────

ES_URL   = os.environ.get("ES_URL", "http://localhost:9200")
ES_INDEX = "zeek-*"
ES_TIMEOUT = 15  # secondes

# Plages de ports RTP communes
RTP_PORT_RANGES = [
    (16384, 32767),   # RFC 3550 standard
    (10000, 20000),   # Plage alternative (Cisco, Avaya)
]

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s %(message)s",
    stream=sys.stderr,
)
log = logging.getLogger("voip-quality")


# ─────────────────────────────────────────────────────────────────────────────
# E-model G.107 (ITU-T)
# ─────────────────────────────────────────────────────────────────────────────

def calc_mos(latency_ms: float, packet_loss_pct: float) -> float:
    """Calcule le MOS depuis latence one-way (ms) et perte de paquets (%).

    Formule E-model simplifié ITU-T G.107 :
        Id  = 0.024 * latency + 0.11 * max(0, latency - 177.3)
        Ie  = 30 * loss / 100
        R   = clamp(93.2 - Id - Ie, 0, 100)
        MOS = clamp(1 + 0.035*R + R*(R-60)*(100-R)*7e-6, 1.0, 5.0)
    """
    Id = 0.024 * latency_ms + 0.11 * max(0.0, latency_ms - 177.3)
    Ie = 30.0 * packet_loss_pct / 100.0
    R  = max(0.0, min(100.0, 93.2 - Id - Ie))
    mos = 1.0 + 0.035 * R + R * (R - 60.0) * (100.0 - R) * 7e-6
    return max(1.0, min(5.0, mos))


def mos_level(mos: float) -> str:
    """Retourne le niveau qualitatif correspondant au score MOS (ITU-T P.800.1)."""
    if mos >= 4.3:
        return "excellent"
    if mos >= 4.0:
        return "good"
    if mos >= 3.6:
        return "fair"
    if mos >= 3.1:
        return "poor"
    return "bad"


# ─────────────────────────────────────────────────────────────────────────────
# Elasticsearch helpers
# ─────────────────────────────────────────────────────────────────────────────

def es_post(path: str, body: dict) -> dict:
    """Envoie une requête POST JSON à Elasticsearch et retourne la réponse JSON."""
    url  = f"{ES_URL}/{path}"
    data = json.dumps(body).encode()
    req  = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=ES_TIMEOUT) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        body_text = exc.read().decode(errors="replace")[:300]
        raise RuntimeError(f"ES {exc.code}: {body_text}") from exc
    except Exception as exc:
        raise RuntimeError(f"ES request failed: {exc}") from exc


def es_query(index: str, query: dict, size: int = 500) -> list[dict]:
    """Exécute une recherche ES et retourne la liste des _source documents."""
    body: dict = {"query": query, "size": size, "_source": True}
    try:
        resp = es_post(f"{index}/_search", body)
        hits = resp.get("hits", {}).get("hits", [])
        return [h.get("_source", {}) for h in hits]
    except Exception as exc:
        log.warning("es_query error: %s", exc)
        return []


def range_filter_days(days: int) -> dict:
    """Filtre ES sur les X derniers jours (champ @timestamp)."""
    return {"range": {"@timestamp": {"gte": f"now-{days}d/d", "lte": "now"}}}


def _in_rtp_range(port: int) -> bool:
    """Vérifie si un port est dans une plage RTP commune."""
    return any(lo <= port <= hi for lo, hi in RTP_PORT_RANGES)


# ─────────────────────────────────────────────────────────────────────────────
# Source 1 : voip.log directement indexé
# ─────────────────────────────────────────────────────────────────────────────

def fetch_from_voip_log(days: int) -> list[dict] | None:
    """Cherche des documents dans voip.log (log_type:voip ou zeek.type:voip).

    Retourne None si aucun document voip.log n'est disponible.
    Retourne une liste de call dicts sinon.
    """
    query: dict = {
        "bool": {
            "must": [
                range_filter_days(days),
                {
                    "bool": {
                        "should": [
                            {"term": {"log_type": "voip"}},
                            {"term": {"zeek.log_type": "voip"}},
                            {"exists": {"field": "mos_score"}},
                            {"exists": {"field": "zeek.voip.mos_score"}},
                        ],
                        "minimum_should_match": 1,
                    }
                },
            ]
        }
    }
    docs = es_query(ES_INDEX, query, size=1000)
    if not docs:
        return None

    calls = []
    for doc in docs:
        voip = doc.get("zeek", {}).get("voip", doc)
        try:
            mos = float(voip.get("mos_score", 0) or 0)
            if mos <= 0:
                continue
            calls.append(
                {
                    "src":        str(voip.get("src_ip") or doc.get("source", {}).get("ip", "")),
                    "dst":        str(voip.get("dst_ip") or doc.get("destination", {}).get("ip", "")),
                    "mos":        round(mos, 3),
                    "level":      str(voip.get("mos_level") or mos_level(mos)),
                    "duration_s": float(voip.get("duration_s", 0) or 0),
                    "jitter_ms":  float(voip.get("jitter_ms", 0) or 0),
                    "loss_pct":   float(voip.get("packet_loss_pct", 0) or 0),
                    "call_id":    str(voip.get("call_id", "") or ""),
                }
            )
        except (TypeError, ValueError):
            continue

    return calls if calls else None


# ─────────────────────────────────────────────────────────────────────────────
# Source 2 : sip.log + conn.log UDP
# ─────────────────────────────────────────────────────────────────────────────

def fetch_from_sip_conn(days: int) -> list[dict]:
    """Reconstruit les métriques VoIP depuis sip.log + conn.log UDP.

    1. Récupère les appels SIP (call_id, src_ip, dst_ip) depuis sip.log
    2. Pour chaque paire IP SIP, cherche les flux UDP RTP dans conn.log
    3. Estime MOS depuis RTT conn.log et packet loss
    """
    # ── Récupération SIP ────────────────────────────────────────────────────
    sip_query: dict = {
        "bool": {
            "must": [
                range_filter_days(days),
                {
                    "bool": {
                        "should": [
                            {"term": {"log_type": "sip"}},
                            {"term": {"zeek.log_type": "sip"}},
                            {"exists": {"field": "sip.call_id"}},
                            {"exists": {"field": "zeek.sip.call_id"}},
                        ],
                        "minimum_should_match": 1,
                    }
                },
            ]
        }
    }
    sip_docs = es_query(ES_INDEX, sip_query, size=500)

    # Index SIP : call_id → {src_ip, dst_ip}
    sip_calls: dict[str, dict] = {}
    for doc in sip_docs:
        sip = doc.get("zeek", {}).get("sip", doc.get("sip", {}))
        call_id = (
            sip.get("call_id")
            or doc.get("call_id")
            or doc.get("network", {}).get("community_id", "")
        )
        if not call_id:
            continue
        src = (
            sip.get("src_ip")
            or doc.get("source", {}).get("ip")
            or doc.get("src_ip", "")
        )
        dst = (
            sip.get("dst_ip")
            or doc.get("destination", {}).get("ip")
            or doc.get("dst_ip", "")
        )
        if src and dst and call_id not in sip_calls:
            sip_calls[call_id] = {"src": src, "dst": dst}

    # ── Récupération conn.log UDP dans plages RTP ────────────────────────────
    udp_query: dict = {
        "bool": {
            "must": [
                range_filter_days(days),
                {"term": {"network.transport": "udp"}},
            ],
            "should": [
                {"term": {"log_type": "conn"}},
                {"term": {"zeek.log_type": "conn"}},
            ],
            "minimum_should": 0,
        }
    }
    conn_docs = es_query(ES_INDEX, udp_query, size=2000)

    # Filtrer les connexions dans les plages RTP
    rtp_conns: list[dict] = []
    for doc in conn_docs:
        try:
            dp = int(doc.get("destination", {}).get("port") or doc.get("resp_p", 0) or 0)
            sp = int(doc.get("source", {}).get("port") or doc.get("orig_p", 0) or 0)
            if not (_in_rtp_range(dp) or _in_rtp_range(sp)):
                continue
            dur = float(doc.get("zeek", {}).get("conn", {}).get("duration")
                        or doc.get("duration", 0) or 0)
            if dur < 1.0:
                continue
            rtp_conns.append(doc)
        except (TypeError, ValueError):
            continue

    # ── Construction des calls depuis SIP + RTP ──────────────────────────────
    calls: list[dict] = []

    # Paire IP → call_id pour lookup rapide
    ip_pair_to_call: dict[tuple, str] = {
        (v["src"], v["dst"]): k for k, v in sip_calls.items()
    }
    ip_pair_to_call.update(
        {(v["dst"], v["src"]): k for k, v in sip_calls.items()}
    )

    for doc in rtp_conns:
        src = (
            doc.get("source", {}).get("ip")
            or doc.get("zeek", {}).get("conn", {}).get("orig_h", "")
            or doc.get("orig_h", "")
        )
        dst = (
            doc.get("destination", {}).get("ip")
            or doc.get("zeek", {}).get("conn", {}).get("resp_h", "")
            or doc.get("resp_h", "")
        )
        dur = float(
            doc.get("zeek", {}).get("conn", {}).get("duration")
            or doc.get("duration", 0) or 0
        )

        # RTT depuis conn.log (champ rtt, en secondes)
        rtt_s = float(
            doc.get("zeek", {}).get("conn", {}).get("rtt")
            or doc.get("rtt", 0) or 0
        )
        lat_ms = (rtt_s / 2.0 * 1000.0) if rtt_s > 0 else 20.0

        # Estimation packet loss depuis pkts/bytes
        orig_pkts  = int(doc.get("zeek", {}).get("conn", {}).get("orig_pkts") or doc.get("orig_pkts", 0) or 0)
        expected_p = dur * 50.0  # 50 pps G.711
        loss_pct   = 0.0
        if expected_p > 0 and orig_pkts < expected_p:
            loss_pct = max(0.0, min(100.0, (expected_p - orig_pkts) / expected_p * 100.0))

        jitter_ms = min(150.0, 2.0 + loss_pct * 0.5)
        mos       = calc_mos(lat_ms, loss_pct)
        level     = mos_level(mos)

        call_id = ip_pair_to_call.get((src, dst), "")

        calls.append(
            {
                "src":        src,
                "dst":        dst,
                "mos":        round(mos, 3),
                "level":      level,
                "duration_s": round(dur, 1),
                "jitter_ms":  round(jitter_ms, 2),
                "loss_pct":   round(loss_pct, 2),
                "call_id":    call_id,
            }
        )

    return calls


# ─────────────────────────────────────────────────────────────────────────────
# Source 3 : conn.log UDP seul (pas de SIP)
# ─────────────────────────────────────────────────────────────────────────────

def fetch_from_conn_udp(days: int) -> list[dict]:
    """Fallback : conn.log UDP seul, sans SIP.

    Utilise RTT conn.log pour la latence et le ratio pkts/durée pour packet loss.
    """
    udp_query: dict = {
        "bool": {
            "must": [
                range_filter_days(days),
                {"term": {"network.transport": "udp"}},
            ]
        }
    }
    conn_docs = es_query(ES_INDEX, udp_query, size=2000)

    calls: list[dict] = []
    for doc in conn_docs:
        try:
            dp = int(doc.get("destination", {}).get("port") or doc.get("resp_p", 0) or 0)
            sp = int(doc.get("source", {}).get("port") or doc.get("orig_p", 0) or 0)
            if not (_in_rtp_range(dp) or _in_rtp_range(sp)):
                continue

            dur = float(
                doc.get("zeek", {}).get("conn", {}).get("duration")
                or doc.get("duration", 0) or 0
            )
            if dur < 1.0:
                continue

            rtt_s = float(
                doc.get("zeek", {}).get("conn", {}).get("rtt")
                or doc.get("rtt", 0) or 0
            )
            lat_ms = (rtt_s / 2.0 * 1000.0) if rtt_s > 0 else 20.0

            orig_pkts  = int(doc.get("zeek", {}).get("conn", {}).get("orig_pkts") or doc.get("orig_pkts", 0) or 0)
            expected_p = dur * 50.0
            loss_pct   = 0.0
            if expected_p > 0 and orig_pkts < expected_p:
                loss_pct = max(0.0, min(100.0, (expected_p - orig_pkts) / expected_p * 100.0))

            jitter_ms = min(150.0, 2.0 + loss_pct * 0.5)
            mos       = calc_mos(lat_ms, loss_pct)
            level     = mos_level(mos)

            src = doc.get("source", {}).get("ip") or doc.get("orig_h", "")
            dst = doc.get("destination", {}).get("ip") or doc.get("resp_h", "")

            calls.append(
                {
                    "src":        src,
                    "dst":        dst,
                    "mos":        round(mos, 3),
                    "level":      level,
                    "duration_s": round(dur, 1),
                    "jitter_ms":  round(jitter_ms, 2),
                    "loss_pct":   round(loss_pct, 2),
                    "call_id":    "",
                }
            )
        except (TypeError, ValueError):
            continue

    return calls


# ─────────────────────────────────────────────────────────────────────────────
# Agrégation des résultats
# ─────────────────────────────────────────────────────────────────────────────

def aggregate(calls: list[dict], source: str) -> dict:
    """Agrège la liste de calls en statistiques globales."""
    if not calls:
        return {
            "avg_mos":          0.0,
            "calls_total":      0,
            "calls_excellent":  0,
            "calls_good":       0,
            "calls_fair":       0,
            "calls_poor":       0,
            "calls_bad":        0,
            "top_bad_calls":    [],
            "generated_at":     datetime.now(timezone.utc).isoformat(),
            "source":           source,
        }

    mos_values = [c["mos"] for c in calls]
    avg_mos    = round(sum(mos_values) / len(mos_values), 3)

    counts = {"excellent": 0, "good": 0, "fair": 0, "poor": 0, "bad": 0}
    for c in calls:
        level = mos_level(c["mos"])
        counts[level] += 1

    # Top 10 pires appels (MOS le plus bas)
    bad_calls = sorted(calls, key=lambda x: x["mos"])[:10]
    top_bad   = [
        {
            "src":        c.get("src", ""),
            "dst":        c.get("dst", ""),
            "mos":        c["mos"],
            "duration_s": c.get("duration_s", 0),
            "jitter_ms":  c.get("jitter_ms", 0),
            "call_id":    c.get("call_id", ""),
        }
        for c in bad_calls
    ]

    return {
        "avg_mos":         avg_mos,
        "calls_total":     len(calls),
        "calls_excellent": counts["excellent"],
        "calls_good":      counts["good"],
        "calls_fair":      counts["fair"],
        "calls_poor":      counts["poor"],
        "calls_bad":       counts["bad"],
        "top_bad_calls":   top_bad,
        "generated_at":    datetime.now(timezone.utc).isoformat(),
        "source":          source,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Mode démo
# ─────────────────────────────────────────────────────────────────────────────

def demo_stats() -> dict:
    """Génère des statistiques VoIP fictives réalistes (sans ES)."""
    random.seed(42)

    ips_src = [
        "192.168.1.10", "192.168.1.11", "192.168.1.12",
        "10.0.0.5",     "10.0.0.6",     "10.0.0.7",
    ]
    ips_dst = [
        "192.168.2.20", "192.168.2.21", "192.168.2.22",
        "10.1.0.10",    "10.1.0.11",
    ]

    calls = []
    for _ in range(48):
        # Distribution réaliste : majorité de bons appels, quelques mauvais
        # Latence LAN : 5-80ms, WAN : 80-250ms
        scenario = random.choices(
            ["lan_good", "lan_ok", "wan_good", "wan_degraded", "bad"],
            weights=[30, 15, 25, 20, 10],
        )[0]

        if scenario == "lan_good":
            lat   = random.uniform(5, 30)
            loss  = random.uniform(0, 1)
        elif scenario == "lan_ok":
            lat   = random.uniform(30, 80)
            loss  = random.uniform(0.5, 3)
        elif scenario == "wan_good":
            lat   = random.uniform(80, 150)
            loss  = random.uniform(0, 2)
        elif scenario == "wan_degraded":
            lat   = random.uniform(150, 250)
            loss  = random.uniform(2, 8)
        else:  # bad
            lat   = random.uniform(200, 400)
            loss  = random.uniform(5, 20)

        mos = calc_mos(lat, loss)
        dur = random.uniform(30, 600)
        calls.append(
            {
                "src":        random.choice(ips_src),
                "dst":        random.choice(ips_dst),
                "mos":        round(mos, 3),
                "level":      mos_level(mos),
                "duration_s": round(dur, 1),
                "jitter_ms":  round(2.0 + loss * 0.5, 2),
                "loss_pct":   round(loss, 2),
                "call_id":    f"demo-{random.randint(1000, 9999)}@netwatch.local",
            }
        )

    result = aggregate(calls, "demo")
    result["generated_at"] = datetime.now(timezone.utc).isoformat()
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Pipeline principal
# ─────────────────────────────────────────────────────────────────────────────

def run(days: int) -> dict:
    """Exécute la pipeline de collecte VoIP avec fallback automatique.

    Ordre :
        1. voip.log indexé (champs directs)
        2. sip.log + conn.log UDP (reconstruction)
        3. conn.log UDP seul (fallback minimal)
    """
    # ── Source 1 : voip.log ─────────────────────────────────────────────────
    log.info("Tentative source primaire : voip.log (champs directs)")
    try:
        calls = fetch_from_voip_log(days)
        if calls:
            log.info("voip.log : %d appels trouvés", len(calls))
            return aggregate(calls, "voip_log")
        log.info("voip.log : aucun document — essai SIP+conn")
    except Exception as exc:
        log.warning("voip.log fetch error: %s", exc)

    # ── Source 2 : sip.log + conn.log UDP ───────────────────────────────────
    log.info("Tentative source 2 : sip.log + conn.log UDP")
    try:
        calls = fetch_from_sip_conn(days)
        if calls:
            log.info("sip+conn : %d appels trouvés", len(calls))
            return aggregate(calls, "sip_conn")
        log.info("sip+conn : aucun résultat — essai conn.log UDP seul")
    except Exception as exc:
        log.warning("sip+conn fetch error: %s", exc)

    # ── Source 3 : conn.log UDP seul ────────────────────────────────────────
    log.info("Tentative source 3 : conn.log UDP (ports RTP)")
    try:
        calls = fetch_from_conn_udp(days)
        if calls:
            log.info("conn_udp : %d flux trouvés", len(calls))
            return aggregate(calls, "conn_udp")
        log.info("conn_udp : aucun flux RTP détecté")
    except Exception as exc:
        log.warning("conn_udp fetch error: %s", exc)

    # Aucune donnée disponible
    log.warning("Aucune donnée VoIP disponible dans ES (index %s, derniers %d j)", ES_INDEX, days)
    return aggregate([], "none")


# ─────────────────────────────────────────────────────────────────────────────
# Entrée principale
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="NetWatch VoIP Quality Analysis — MOS E-model G.107"
    )
    parser.add_argument(
        "--days", type=int, default=1,
        help="Fenêtre temporelle en jours (défaut : 1)",
    )
    parser.add_argument(
        "--output", default=None,
        help="Fichier JSON de sortie (défaut : stdout)",
    )
    parser.add_argument(
        "--demo", action="store_true",
        help="Mode démo — génère des stats fictives sans ES",
    )
    args = parser.parse_args()

    if args.demo:
        log.info("Mode démo activé")
        result = demo_stats()
    else:
        result = run(args.days)

    output = json.dumps(result, indent=2, ensure_ascii=False)

    if args.output:
        path = args.output
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(output)
        log.info("Résultats écrits dans %s", path)
    else:
        print(output)


if __name__ == "__main__":
    main()
