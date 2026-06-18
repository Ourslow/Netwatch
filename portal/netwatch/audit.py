"""
Audit réseau passif — transforme les données observées (Zeek/Snort/Suricata
dans Elasticsearch) en constats priorisés avec recommandations.

Approche : on interroge en priorité les **logs protocolaires Zeek bruts**
(ssl, http, conn, dns, notice, intel) — indépendamment des règles IDS — pour
un audit exhaustif, complété par les alertes IDS et beacon-detect.

Chaque contrôle renvoie un finding :
  {title, severity (critical|warning|info|ok), count, detail, reco, ref, examples}
Aucun contrôle ne lève d'exception : une requête en échec → finding neutre.
Sévérité graduée par volume (seuils warn/crit).
"""

from netwatch import es_client

ALERTS = "suricata-*,snort-*"
ZEEK   = "zeek-*"
BEACON = "netwatch-beacons-*"

OBSOLETE_TLS = ["TLSv10", "TLSv11", "SSLv3", "SSLv2", "TLSv1", "TLSv1.0", "TLSv1.1"]

# Ports de services à risque s'ils sont exposés
RISKY_PORTS = {
    21: "FTP", 23: "Telnet", 135: "RPC", 139: "NetBIOS", 445: "SMB",
    1433: "MS-SQL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 9200: "Elasticsearch", 27017: "MongoDB",
}

_WEIGHT = {"critical": 25, "warning": 10, "info": 0, "ok": 0}


# ── Helpers ES ──────────────────────────────────────────────
def _search(index, body):
    try:
        r = es_client._es(f"/{index}/_search", body)
        r.raise_for_status()
        return r.json()
    except Exception:
        return None


def _count(index, query):
    data = _search(index, {"size": 0, "query": query})
    return None if data is None else data.get("hits", {}).get("total", {}).get("value", 0)


def _terms(index, field, query=None, size=10):
    body = {"size": 0, "aggs": {"t": {"terms": {"field": field, "size": size}}}}
    if query:
        body["query"] = query
    data = _search(index, body)
    if data is None:
        return None
    return [(b["key"], b["doc_count"])
            for b in data.get("aggregations", {}).get("t", {}).get("buckets", [])]


def _top(index, field, query, size=5, fmt="{k}"):
    """Top valeurs d'un champ → liste de chaînes lisibles (preuves)."""
    rows = _terms(index, field, query, size)
    if not rows:
        return []
    return [fmt.format(k=k, c=c) for k, c in rows]


def _grade(count, warn_at=1, crit_at=None):
    if count is None:
        return "info"
    if count == 0:
        return "ok"
    if crit_at is not None and count >= crit_at:
        return "critical"
    if count >= warn_at:
        return "warning"
    return "ok"


def _finding(title, count, severity, detail_if, reco, ref, examples=None):
    if count is None:
        return {"title": title, "severity": "info", "count": "—",
                "detail": "Données indisponibles (Elasticsearch non joignable ?)",
                "reco": reco, "ref": ref, "examples": []}
    return {
        "title": title, "severity": severity, "count": count,
        "detail": detail_if if count else "Aucune occurrence observée — conforme.",
        "reco": reco if count else "—", "ref": ref,
        "examples": (examples or []) if count else [],
    }


# ── Audit ───────────────────────────────────────────────────
def run_audit():
    ssl_q = {"term": {"log_source": "ssl"}}

    # ════ Axe 1 — Hygiène chiffrement ════ (Zeek brut)
    tls_n = _count(ZEEK, {"bool": {"filter": [ssl_q, {"terms": {"version.keyword": OBSOLETE_TLS}}]}})
    tls_ex = _top(ZEEK, "server_name.keyword",
                  {"bool": {"filter": [ssl_q, {"terms": {"version.keyword": OBSOLETE_TLS}}]}},
                  6, "{k} ({c})")
    clr_q = {"bool": {"filter": [{"term": {"log_source": "http"}}, {"term": {"id.resp_p": 80}}, {"match": {"method": "POST"}}]}}
    clr_n = _count(ZEEK, clr_q)
    clr_ex = _top(ZEEK, "host.keyword", clr_q, 6, "{k} ({c})")
    cert_n = _count(ZEEK, {"bool": {"filter": [{"term": {"log_source": "notice"}}],
                                    "should": [{"term": {"note.keyword": "SSL::Certificate_Expired"}},
                                               {"term": {"note.keyword": "SSL::Certificate_Not_Valid_Yet"}}],
                                    "minimum_should_match": 1}})
    crypto = [
        _finding("Identifiants transmis en clair (HTTP)", clr_n,
                 _grade(clr_n, warn_at=1, crit_at=20),
                 f"{clr_n} requête(s) POST en HTTP non chiffré (port 80) — risque d'interception d'identifiants.",
                 "Forcer HTTPS (HSTS), bannir l'authentification en clair (basic auth HTTP, FTP, Telnet).",
                 "NIS2 21.2.h · ISO A.8.24 · ANSSI hygiène", clr_ex),
        _finding("Sessions TLS obsolètes (v1.0/1.1, SSLv3)", tls_n,
                 _grade(tls_n, warn_at=1, crit_at=50),
                 f"{tls_n} session(s) TLS sur un protocole déprécié observée(s).",
                 "Désactiver TLS < 1.2 ; n'autoriser que TLS 1.2/1.3 et des suites fortes.",
                 "NIS2 21.2.h · ISO A.8.24", tls_ex),
        _finding("Certificats expirés / non valides", cert_n,
                 _grade(cert_n, warn_at=1, crit_at=10),
                 f"{cert_n} notice(s) de certificat expiré ou pas encore valide.",
                 "Surveiller et renouveler automatiquement les certificats (alerting J-30).",
                 "ISO A.8.24"),
    ]

    # ════ Axe 2 — Exposition & surface ════
    intel_n = _count(ZEEK, {"term": {"log_source": "intel"}})
    intel_ex = _top(ZEEK, "seen.indicator.keyword", {"term": {"log_source": "intel"}}, 6, "{k} ({c})")
    # Ports à risque exposés (Zeek conn)
    conn_ports = _terms(ZEEK, "id.resp_p", {"term": {"log_source": "conn"}}, 25) or []
    risky_found = [(RISKY_PORTS[p], c) for p, c in conn_ports if p in RISKY_PORTS]
    risky_total = sum(c for _, c in risky_found)
    risky_ex = [f"{name} ({c})" for name, c in sorted(risky_found, key=lambda x: -x[1])[:6]]
    top_ports_ex = [f"port {p} ({c})" for p, c in conn_ports[:6]]
    # Origine géographique des menaces (GeoIP sur la source des alertes)
    geo = _terms(ALERTS, "source.geo.country_name.keyword",
                 {"bool": {"should": [{"term": {"event_type": "alert"}}, {"exists": {"field": "rule"}}],
                           "minimum_should_match": 1}}, 8) or []
    geo_ex = [f"{c_name} ({c})" for c_name, c in geo]
    surface = [
        _finding("Communications avec des IoC connus (threat intel)", intel_n,
                 _grade(intel_n, warn_at=1, crit_at=1),
                 f"{intel_n} connexion(s) vers des indicateurs de compromission de la watchlist.",
                 "Investiguer et bloquer immédiatement les hôtes concernés (cf. AutoBlock).",
                 "NIS2 21.2.d · ISO A.5.7", intel_ex),
        _finding("Services à risque exposés", risky_total,
                 _grade(risky_total, warn_at=1, crit_at=200),
                 f"Trafic vers des services sensibles ({', '.join(n for n, _ in risky_found) or '—'}) — à exposer le moins possible.",
                 "Vérifier la légitimité de ces services, restreindre/segmenter (Telnet, SMB, RDP, bases de données).",
                 "NIS2 21.2.i · ISO A.8.20 · ANSSI cartographie", risky_ex),
        _finding("Origine géographique des menaces (GeoIP)", (len(geo) if geo else 0), "info",
                 "Pays d'origine des alertes IDS (nécessite l'enrichissement GeoIP).",
                 "Surveiller le trafic en provenance de zones inhabituelles pour l'organisation.",
                 "NIST DE.AE", geo_ex),
    ]
    if top_ports_ex:
        surface.append({"title": "Cartographie des services contactés", "severity": "info",
                        "count": len(conn_ports), "detail": "Ports destination les plus observés sur le réseau.",
                        "reco": "—", "ref": "NIS2 21.2.i", "examples": top_ports_ex})

    # ════ Axe 3 — Comportements suspects ════
    beacon_n = _count(BEACON, {"match_all": {}})
    dns_q = {"bool": {"filter": [{"term": {"log_source": "notice"}}, {"term": {"note.keyword": "DNSEntropy::High_Entropy_DNS"}}]}}
    dns_n = _count(ZEEK, dns_q)
    dns_ex = _top(ZEEK, "msg.keyword", dns_q, 5, "{k}")
    scan_q = {"bool": {"filter": [{"term": {"log_source": "notice"}}, {"term": {"note.keyword": "PortScan::Port_Scan_Detected"}}]}}
    scan_n = _count(ZEEK, scan_q)
    scan_ex = _top(ZEEK, "src.keyword", scan_q, 6, "{k} ({c})")
    behavior = [
        _finding("Beaconing C2 suspecté", beacon_n,
                 _grade(beacon_n, warn_at=1, crit_at=1),
                 f"{beacon_n} flux au comportement périodique (intervalle régulier, faible jitter) — C2/exfiltration potentiel.",
                 "Analyser et confiner les hôtes en beaconing ; corréler avec la threat intel.",
                 "NIS2 21.2.b · NIST DE.AE", []),
        _finding("DNS à haute entropie / DGA", dns_n,
                 _grade(dns_n, warn_at=1, crit_at=10),
                 f"{dns_n} requête(s) DNS vers des domaines à forte entropie (génération algorithmique probable).",
                 "Bloquer les domaines identifiés, inspecter un éventuel tunneling DNS.",
                 "NIS2 21.2.b · NIST DE.CM", dns_ex),
        _finding("Scans de ports détectés", scan_n,
                 _grade(scan_n, warn_at=1, crit_at=10),
                 f"{scan_n} activité(s) de balayage de ports observée(s).",
                 "Identifier la source (interne compromis ou reconnaissance externe) et la traiter.",
                 "NIST DE.CM · ANSSI PA-022", scan_ex),
    ]

    # ════ Axe 4 — Menaces IDS ════
    crit_sur = _count("suricata-*", {"bool": {"filter": [{"term": {"event_type": "alert"}}, {"term": {"alert.severity": 1}}]}}) or 0
    crit_sno = _count("snort-*",    {"bool": {"filter": [{"exists": {"field": "rule"}}, {"term": {"priority": 1}}]}}) or 0
    crit_total = crit_sur + crit_sno
    crit_ex = _top("suricata-*", "alert.signature.keyword",
                   {"bool": {"filter": [{"term": {"event_type": "alert"}}, {"term": {"alert.severity": 1}}]}}, 5, "{k} ({c})")
    total_alerts = _count(ALERTS, {"bool": {"should": [{"term": {"event_type": "alert"}}, {"exists": {"field": "rule"}}], "minimum_should_match": 1}})
    mitre = _terms("suricata-*", "alert.metadata.mitre_tactic_name.keyword", {"term": {"event_type": "alert"}}, 6) or []
    threats = [
        _finding("Alertes critiques (sévérité 1)", crit_total,
                 _grade(crit_total, warn_at=1, crit_at=1),
                 f"{crit_total} alerte(s) IDS de sévérité critique — à traiter en priorité.",
                 "Qualifier, confiner et répondre à chaque alerte critique (cf. AutoBlock / playbooks).",
                 "NIS2 21.2.b · NIST RS · ISO A.5.26", crit_ex),
        _finding("Tactiques MITRE ATT&CK observées", (len(mitre) if mitre else 0), "info",
                 "Répartition des détections selon le framework MITRE ATT&CK.",
                 "Prioriser la couverture défensive sur les tactiques les plus fréquentes.",
                 "NIST DE.AE", [f"{t} ({c})" for t, c in mitre[:6]]),
    ]
    if total_alerts:
        threats.append({"title": "Volume total d'alertes IDS", "severity": "info",
                        "count": total_alerts, "detail": "Activité de détection sur la période.",
                        "reco": "—", "ref": "—", "examples": []})

    axes = [
        {"id": "crypto",   "name": "Hygiène chiffrement",   "icon": "bi-lock",              "findings": crypto},
        {"id": "surface",  "name": "Exposition & surface",  "icon": "bi-diagram-3",          "findings": surface},
        {"id": "behavior", "name": "Comportements suspects","icon": "bi-graph-up-arrow",     "findings": behavior},
        {"id": "threats",  "name": "Menaces IDS",           "icon": "bi-shield-exclamation", "findings": threats},
    ]

    counts = {"critical": 0, "warning": 0, "info": 0, "ok": 0}
    es_ok = False
    for ax in axes:
        for f in ax["findings"]:
            if f["count"] != "—":
                es_ok = True
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    score = max(0, 100 - counts["critical"] * _WEIGHT["critical"] - counts["warning"] * _WEIGHT["warning"])
    if score >= 80:
        label, color = "Bonne posture", "ok"
    elif score >= 50:
        label, color = "Posture à renforcer", "warning"
    else:
        label, color = "Posture critique", "critical"

    return {"axes": axes, "counts": counts, "score": score,
            "score_label": label, "score_color": color, "es_ok": es_ok}
