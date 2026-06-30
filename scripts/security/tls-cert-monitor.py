#!/usr/bin/env python3
"""
NetWatch — TLS Certificate Monitor
Lit l'index ES zeek-* (logs ssl), détecte les certificats expirés,
self-signed, ciphers faibles, et versions TLS < 1.2.

Usage:
    python3 tls-cert-monitor.py [--days 1] [--output certs.json]
"""

import argparse
import json
import sys
from datetime import datetime, timezone, timedelta

# ── Weak cipher patterns ────────────────────────────────────────────────────────
WEAK_CIPHER_PATTERNS = [
    "RC4", "DES", "3DES", "EXPORT", "NULL",
    "anon", "ADH", "AECDH",
]

WEAK_TLS_VERSIONS = {"SSLv2", "SSLv3", "TLSv10", "TLSv1", "TLS/1.0", "TLS/1.1", "TLSv1.1"}

# ── ES connectivity (optional) ──────────────────────────────────────────────────
def build_es_query(days: int) -> dict:
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    return {
        "size": 5000,
        "_source": [
            "@timestamp",
            "uid",
            "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
            "ssl.version",
            "ssl.cipher",
            "ssl.subject",
            "ssl.issuer",
            "ssl.not_valid_after",
            "ssl.server_name",
            "ssl.validation_status",
        ],
        "query": {
            "bool": {
                "must": [{"exists": {"field": "ssl.subject"}}],
                "filter": [{"range": {"@timestamp": {"gte": since}}}],
            }
        },
    }


def fetch_from_es(es_url: str, days: int) -> list:
    """Tente de récupérer les entrées ssl depuis ES. Retourne [] si indisponible."""
    try:
        import urllib.request
        import urllib.error

        url = f"{es_url}/zeek-*/_search"
        body = json.dumps(build_es_query(days)).encode()
        req = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
        hits = data.get("hits", {}).get("hits", [])
        return [h["_source"] for h in hits]
    except Exception as exc:
        print(f"[WARN] Impossible de joindre Elasticsearch : {exc}", file=sys.stderr)
        print("[INFO] Utilisation des données demo.", file=sys.stderr)
        return []


def demo_records() -> list:
    """Données de démonstration utilisées quand ES est indisponible."""
    now = datetime.now(timezone.utc)
    return [
        {
            "@timestamp": now.isoformat(),
            "uid": "CxYjL84GlTj3mSXdN1",
            "id.orig_h": "10.0.0.55", "id.orig_p": 51200,
            "id.resp_h": "93.184.216.34", "id.resp_p": 443,
            "ssl.version": "TLSv1.3",
            "ssl.cipher": "TLS_AES_256_GCM_SHA384",
            "ssl.subject": "CN=example.com,O=ICANN,C=US",
            "ssl.issuer": "CN=DigiCert TLS RSA SHA256 2020 CA1,O=DigiCert Inc,C=US",
            "ssl.not_valid_after": (now + timedelta(days=120)).strftime("%Y-%m-%dT%H:%M:%S"),
            "ssl.server_name": "example.com",
            "ssl.validation_status": "ok",
        },
        {
            "@timestamp": now.isoformat(),
            "uid": "CxYjL84GlTj3mSXdN2",
            "id.orig_h": "10.0.0.55", "id.orig_p": 51201,
            "id.resp_h": "192.168.1.1", "id.resp_p": 443,
            "ssl.version": "TLSv1.2",
            "ssl.cipher": "ECDHE-RSA-AES256-GCM-SHA384",
            "ssl.subject": "CN=router.local,O=NetWatch Lab",
            "ssl.issuer": "CN=router.local,O=NetWatch Lab",  # self-signed
            "ssl.not_valid_after": (now + timedelta(days=5)).strftime("%Y-%m-%dT%H:%M:%S"),
            "ssl.server_name": "router.local",
            "ssl.validation_status": "self signed certificate",
        },
        {
            "@timestamp": now.isoformat(),
            "uid": "CxYjL84GlTj3mSXdN3",
            "id.orig_h": "10.0.0.22", "id.orig_p": 51300,
            "id.resp_h": "10.0.0.99", "id.resp_p": 443,
            "ssl.version": "TLSv1.1",  # old TLS
            "ssl.cipher": "RC4-SHA",   # weak cipher
            "ssl.subject": "CN=legacy.internal",
            "ssl.issuer": "CN=OldCA,O=Corp",
            "ssl.not_valid_after": (now + timedelta(days=25)).strftime("%Y-%m-%dT%H:%M:%S"),
            "ssl.server_name": "legacy.internal",
            "ssl.validation_status": "ok",
        },
        {
            "@timestamp": now.isoformat(),
            "uid": "CxYjL84GlTj3mSXdN4",
            "id.orig_h": "10.0.0.33", "id.orig_p": 51400,
            "id.resp_h": "203.0.113.10", "id.resp_p": 443,
            "ssl.version": "TLSv1.2",
            "ssl.cipher": "AES128-SHA",
            "ssl.subject": "CN=expired.example.net",
            "ssl.issuer": "CN=Let's Encrypt Authority X3",
            "ssl.not_valid_after": (now - timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%S"),
            "ssl.server_name": "expired.example.net",
            "ssl.validation_status": "certificate has expired",
        },
    ]


# ── Analysis ────────────────────────────────────────────────────────────────────

def parse_expiry(not_valid_after: str) -> datetime | None:
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ", "%b %d %H:%M:%S %Y GMT"):
        try:
            dt = datetime.strptime(not_valid_after, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def is_weak_cipher(cipher: str) -> bool:
    c = cipher.upper()
    return any(pat.upper() in c for pat in WEAK_CIPHER_PATTERNS)


def is_old_tls(version: str) -> bool:
    return version in WEAK_TLS_VERSIONS or version.replace(" ", "") in {
        v.replace(" ", "") for v in WEAK_TLS_VERSIONS
    }


def analyze_record(rec: dict, warn_days: int = 30, crit_days: int = 7) -> dict | None:
    subject = rec.get("ssl.subject") or rec.get("ssl", {}).get("subject", "")
    issuer  = rec.get("ssl.issuer")  or rec.get("ssl", {}).get("issuer", "")
    cipher  = rec.get("ssl.cipher")  or rec.get("ssl", {}).get("cipher", "")
    version = rec.get("ssl.version") or rec.get("ssl", {}).get("version", "")
    expiry_raw = rec.get("ssl.not_valid_after") or rec.get("ssl", {}).get("not_valid_after", "")
    sni    = rec.get("ssl.server_name") or rec.get("ssl", {}).get("server_name", "")
    host   = rec.get("id.resp_h") or ""

    if not subject:
        return None

    issues: list[str] = []
    severity = "ok"
    expiry_date = None
    expiry_days = None

    now = datetime.now(timezone.utc)

    # ── Expiry ──────────────────────────────────────────────────────────────────
    if expiry_raw:
        expiry_date = parse_expiry(expiry_raw)
        if expiry_date:
            expiry_days = (expiry_date - now).days
            if expiry_days < 0:
                issues.append(f"EXPIRED ({abs(expiry_days)} days ago)")
                severity = "critical"
            elif expiry_days <= crit_days:
                issues.append(f"Expires in {expiry_days} days (CRITICAL)")
                severity = "critical"
            elif expiry_days <= warn_days:
                issues.append(f"Expires in {expiry_days} days (WARNING)")
                if severity == "ok":
                    severity = "warning"

    # ── Self-signed ─────────────────────────────────────────────────────────────
    if subject and issuer and subject.strip() == issuer.strip():
        issues.append("Self-signed certificate")
        if severity == "ok":
            severity = "warning"

    # ── Weak cipher ─────────────────────────────────────────────────────────────
    if cipher and is_weak_cipher(cipher):
        issues.append(f"Weak cipher: {cipher}")
        if severity not in ("critical",):
            severity = "high"

    # ── Old TLS ─────────────────────────────────────────────────────────────────
    if version and is_old_tls(version):
        issues.append(f"Weak TLS version: {version}")
        if severity not in ("critical",):
            severity = "high"

    return {
        "host": host,
        "sni": sni or host,
        "issuer": issuer,
        "subject": subject,
        "expiry_date": expiry_date.isoformat() if expiry_date else None,
        "expiry_days": expiry_days,
        "cipher": cipher,
        "tls_version": version,
        "issues": issues,
        "severity": severity,
    }


def deduplicate(results: list[dict]) -> list[dict]:
    """Garde un seul enregistrement par (sni, issuer), le plus sévère."""
    sev_order = {"critical": 4, "high": 3, "warning": 2, "ok": 1}
    best: dict[tuple, dict] = {}
    for r in results:
        key = (r["sni"], r["issuer"])
        prev = best.get(key)
        if prev is None or sev_order.get(r["severity"], 0) > sev_order.get(prev["severity"], 0):
            best[key] = r
    return sorted(best.values(), key=lambda x: sev_order.get(x["severity"], 0), reverse=True)


# ── CLI ─────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="NetWatch TLS Certificate Monitor — analyse les certificats depuis zeek-* ES"
    )
    parser.add_argument("--days",   type=int,  default=1,    help="Fenêtre de temps en jours (défaut: 1)")
    parser.add_argument("--output", type=str,  default=None, help="Fichier JSON de sortie (défaut: stdout)")
    parser.add_argument("--es",     type=str,  default="http://localhost:9200",
                        help="URL Elasticsearch (défaut: http://localhost:9200)")
    parser.add_argument("--warn",   type=int,  default=30,   help="Seuil warning expiry en jours (défaut: 30)")
    parser.add_argument("--crit",   type=int,  default=7,    help="Seuil critical expiry en jours (défaut: 7)")
    parser.add_argument("--demo",   action="store_true",     help="Utiliser les données de démonstration")
    args = parser.parse_args()

    # Récupération des données
    if args.demo:
        records = demo_records()
    else:
        records = fetch_from_es(args.es, args.days)
        if not records:
            records = demo_records()

    # Analyse
    results = []
    for rec in records:
        analyzed = analyze_record(rec, warn_days=args.warn, crit_days=args.crit)
        if analyzed:
            results.append(analyzed)

    results = deduplicate(results)

    # Résumé
    counts = {"critical": 0, "high": 0, "warning": 0, "ok": 0}
    for r in results:
        counts[r["severity"]] = counts.get(r["severity"], 0) + 1

    print(
        f"[TLS-CERT-MONITOR] {len(results)} certificats uniques — "
        f"critical={counts['critical']} high={counts['high']} "
        f"warning={counts['warning']} ok={counts['ok']}",
        file=sys.stderr,
    )

    output_json = json.dumps(results, indent=2, default=str)

    if args.output:
        with open(args.output, "w") as f:
            f.write(output_json)
        print(f"[TLS-CERT-MONITOR] Résultats écrits dans {args.output}", file=sys.stderr)
    else:
        print(output_json)

    # Exit code : 2 si critical, 1 si warning/high, 0 si tout ok
    if counts["critical"] > 0:
        sys.exit(2)
    if counts["high"] > 0 or counts["warning"] > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
