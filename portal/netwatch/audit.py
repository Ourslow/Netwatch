"""
Audit réseau passif — transforme les données observées (Zeek/Snort/Suricata
dans Elasticsearch) en constats priorisés avec recommandations.

C'est la finalité de l'observabilité : passer de « voici les logs » à
« voici vos points faibles, par ordre de priorité ».

Chaque contrôle renvoie un finding :
  {title, severity (critical|warning|info|ok), count, detail, reco, ref, examples}
Aucun contrôle ne lève d'exception : une requête en échec → finding neutre.
"""

from netwatch import es_client

ALERTS = "suricata-*,snort-*"
ZEEK   = "zeek-*"
BEACON = "netwatch-beacons-*"

# Poids de score par sévérité de finding (et non par événement)
_WEIGHT = {"critical": 25, "warning": 10, "info": 0, "ok": 0}


def _search(index, body):
    try:
        r = es_client._es(f"/{index}/_search", body)
        r.raise_for_status()
        return r.json()
    except Exception:
        return None


def _count(index, query):
    data = _search(index, {"size": 0, "query": query})
    if data is None:
        return None
    return data.get("hits", {}).get("total", {}).get("value", 0)


def _terms(index, field, query=None, size=10):
    body = {"size": 0, "aggs": {"t": {"terms": {"field": field, "size": size}}}}
    if query:
        body["query"] = query
    data = _search(index, body)
    if data is None:
        return None
    return [(b["key"], b["doc_count"])
            for b in data.get("aggregations", {}).get("t", {}).get("buckets", [])]


def _alert_signatures():
    """Compte des alertes par signature, moteurs fusionnés."""
    sigs = {}
    sur = _terms("suricata-*", "alert.signature.keyword", {"term": {"event_type": "alert"}}, 50)
    sno = _terms("snort-*",    "msg.keyword",            {"exists": {"field": "rule"}}, 50)
    for pair in (sur or []) + (sno or []):
        sigs[pair[0]] = sigs.get(pair[0], 0) + pair[1]
    return sigs


def _match_sigs(sigs, *keywords):
    """(total, [signatures correspondantes]) pour les signatures contenant un mot-clé."""
    total, matched = 0, []
    for sig, c in sigs.items():
        if any(kw.lower() in sig.lower() for kw in keywords):
            total += c
            matched.append(sig)
    return total, matched


def _finding(title, count, sev_if_present, detail, reco, ref, examples=None):
    """Construit un finding : 'ok' si count==0, sinon la sévérité indiquée."""
    if count is None:
        return {"title": title, "severity": "info", "count": "—",
                "detail": "Données indisponibles (Elasticsearch non joignable ?)",
                "reco": reco, "ref": ref, "examples": []}
    sev = "ok" if count == 0 else sev_if_present
    return {"title": title, "severity": sev, "count": count,
            "detail": detail if count else "Aucune occurrence observée — conforme.",
            "reco": reco if count else "—", "ref": ref, "examples": examples or []}


def run_audit():
    sigs    = _alert_signatures()
    notices = dict(_terms(ZEEK, "note.keyword", {"term": {"log_source": "notice"}}, 20) or [])

    # ── Axe 1 — Hygiène chiffrement ──
    tls_n,  tls_sigs  = _match_sigs(sigs, "TLS", "Obsolete", "SSLv")
    clr_n,  clr_sigs  = _match_sigs(sigs, "Cleartext", "clair", "password")
    cert_n = notices.get("SSL::Certificate_Expired", 0) + notices.get("SSL::Certificate_Not_Valid_Yet", 0)
    crypto = [
        _finding("Identifiants transmis en clair", clr_n, "critical",
                 f"{clr_n} flux avec identifiants non chiffrés détecté(s) (HTTP).",
                 "Forcer HTTPS et bannir toute authentification en clair (basic auth HTTP, FTP, Telnet).",
                 "NIS2 21.2.h · ISO A.8.24 · ANSSI hygiène", clr_sigs),
        _finding("Chiffrement TLS obsolète", tls_n, "warning",
                 f"{tls_n} alerte(s) sur des versions TLS dépréciées (v1.0/1.1).",
                 "Désactiver TLS < 1.2, n'autoriser que TLS 1.2/1.3 et des suites fortes.",
                 "NIS2 21.2.h · ISO A.8.24", tls_sigs),
        _finding("Certificats expirés / invalides", cert_n, "warning",
                 f"{cert_n} notice(s) de certificat expiré ou non valide.",
                 "Mettre en place une surveillance et un renouvellement automatique des certificats.",
                 "ISO A.8.24"),
    ]

    # ── Axe 2 — Exposition & surface ──
    intel_n = _count(ZEEK, {"term": {"log_source": "intel"}})
    ports   = _terms(ZEEK, "id.resp_p", {"term": {"log_source": "conn"}}, 8) or []
    conn_n  = _count(ZEEK, {"term": {"log_source": "conn"}})
    port_examples = [f"port {p} ({c})" for p, c in ports[:6]]
    surface = [
        _finding("Communications avec des IoC connus (threat intel)", intel_n, "critical",
                 f"{intel_n} connexion(s) vers des indicateurs de compromission de la watchlist.",
                 "Investiguer et bloquer immédiatement les hôtes concernés.",
                 "NIS2 21.2.d · ISO A.5.7", []),
        _finding("Services / ports les plus exposés", (len(ports) if ports else 0), "info",
                 "Cartographie des services contactés — vérifier qu'ils sont tous légitimes et nécessaires.",
                 "Réduire la surface : fermer/segmenter les services non indispensables.",
                 "NIS2 21.2.i · ISO A.8.20 · ANSSI cartographie", port_examples),
    ]
    # Volume analysé (contextuel)
    if conn_n:
        surface.append({"title": "Volume de connexions analysées", "severity": "info",
                        "count": conn_n, "detail": "Trafic réseau passé au crible par les moteurs.",
                        "reco": "—", "ref": "—", "examples": []})

    # ── Axe 3 — Comportements suspects ──
    beacon_n = _count(BEACON, {"match_all": {}})
    dns_notice = notices.get("DNSEntropy::High_Entropy_DNS", 0)
    dns_sig_n, dns_sigs = _match_sigs(sigs, "DGA", "TLD", "DNS Query", "tunnel")
    dns_total = dns_notice + dns_sig_n
    scan_notice = notices.get("PortScan::Port_Scan_Detected", 0)
    scan_sig_n, scan_sigs = _match_sigs(sigs, "scan", "sweep")
    scan_total = scan_notice + scan_sig_n
    behavior = [
        _finding("Beaconing C2 suspecté", beacon_n, "critical",
                 f"{beacon_n} hôte(s)/flux au comportement périodique évoquant une communication C2.",
                 "Analyser les hôtes en beaconing (intervalle régulier, faible jitter) — exfiltration/C2 potentiel.",
                 "NIS2 21.2.b · NIST DE.AE", []),
        _finding("DNS suspect (haute entropie / DGA / tunneling)", dns_total, "warning",
                 f"{dns_total} signal(aux) DNS anormaux (domaines à forte entropie, TLD suspects).",
                 "Bloquer les domaines identifiés et inspecter un éventuel tunneling DNS.",
                 "NIS2 21.2.b · NIST DE.CM", dns_sigs),
        _finding("Scans de ports détectés", scan_total, "warning",
                 f"{scan_total} activité(s) de balayage de ports observée(s).",
                 "Identifier la source des scans (interne compromis ou reconnaissance externe).",
                 "NIST DE.CM · ANSSI PA-022", scan_sigs),
    ]

    # ── Axe 4 — Menaces IDS ──
    crit_sur = _count("suricata-*", {"bool": {"filter": [{"term": {"event_type": "alert"}}, {"term": {"alert.severity": 1}}]}}) or 0
    crit_sno = _count("snort-*",    {"bool": {"filter": [{"exists": {"field": "rule"}}, {"term": {"priority": 1}}]}}) or 0
    crit_total = crit_sur + crit_sno
    total_alerts = _count(ALERTS, {"bool": {"should": [{"term": {"event_type": "alert"}}, {"exists": {"field": "rule"}}], "minimum_should_match": 1}})
    mitre = _terms("suricata-*", "alert.metadata.mitre_tactic_name.keyword", {"term": {"event_type": "alert"}}, 6) or []
    threats = [
        _finding("Alertes critiques (sévérité 1)", crit_total, "critical",
                 f"{crit_total} alerte(s) IDS de sévérité critique — à traiter en priorité.",
                 "Traiter chaque alerte critique : qualification, confinement, réponse (cf. AutoBlock).",
                 "NIS2 21.2.b · NIST RS · ISO A.5.26", []),
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
        {"id": "crypto",   "name": "Hygiène chiffrement",  "icon": "bi-lock",               "findings": crypto},
        {"id": "surface",  "name": "Exposition & surface", "icon": "bi-diagram-3",           "findings": surface},
        {"id": "behavior", "name": "Comportements suspects","icon": "bi-graph-up-arrow",     "findings": behavior},
        {"id": "threats",  "name": "Menaces IDS",          "icon": "bi-shield-exclamation",  "findings": threats},
    ]

    # Score de posture (sur les findings, pas les événements)
    counts = {"critical": 0, "warning": 0, "info": 0, "ok": 0}
    es_ok = False
    for ax in axes:
        for f in ax["findings"]:
            if f["count"] != "—":
                es_ok = True
            if f["severity"] in counts:
                counts[f["severity"]] += 1
    score = max(0, 100 - counts["critical"] * _WEIGHT["critical"] - counts["warning"] * _WEIGHT["warning"])
    if score >= 80:
        label, color = "Bonne posture", "ok"
    elif score >= 50:
        label, color = "Posture à renforcer", "warning"
    else:
        label, color = "Posture critique", "critical"

    return {
        "axes": axes, "counts": counts, "score": score,
        "score_label": label, "score_color": color, "es_ok": es_ok,
    }
