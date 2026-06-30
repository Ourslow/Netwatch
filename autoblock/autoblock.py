#!/usr/bin/env python3
"""
NetWatch — AutoBlock Webhook
Recoit les alertes Grafana via webhook et bloque automatiquement les IPs suspectes
via iptables (necessite NET_ADMIN + network_mode: host).

Securites :
  - Allowlist : les IPs de l'allowlist ne sont JAMAIS bloquees
  - Rate limit : max 20 blocs par heure
  - Expiration : les blocs expirent apres BLOCK_DURATION_MIN minutes
  - Audit log  : tous les blocs sont loggues dans ES et dans le fichier local
"""

import os
import re
import hmac
import json
import logging
import subprocess
import threading
from functools import wraps
from datetime import datetime, timezone, timedelta
from collections import deque

from flask import Flask, request, jsonify

try:
    from elasticsearch import Elasticsearch
    ES_AVAILABLE = True
except ImportError:
    ES_AVAILABLE = False

# ─── Config ───────────────────────────────────────────────────────────────────
WEBHOOK_PORT       = int(os.environ.get("WEBHOOK_PORT", "5001"))
WEBHOOK_SECRET     = os.environ.get("WEBHOOK_SECRET", "")
ES_URL             = os.environ.get("ES_URL", "http://elasticsearch:9200")
BLOCK_DURATION_MIN = int(os.environ.get("BLOCK_DURATION_MIN", "60"))
MAX_BLOCKS_PER_HOUR = int(os.environ.get("MAX_BLOCKS_PER_HOUR", "20"))
DRY_RUN            = os.environ.get("DRY_RUN", "false").lower() == "true"

# IPs qui ne seront JAMAIS bloquees (gateway, DNS, infra NetWatch)
ALLOWLIST = set(filter(None, os.environ.get("ALLOWLIST", "").split(","))) | {
    "127.0.0.1", "::1",
    "10.0.0.1", "10.0.0.2",        # Gateways RFC1918 communes
    "172.17.0.1",                   # Docker bridge gateway
    "8.8.8.8", "8.8.4.4",          # Google DNS
    "1.1.1.1", "1.0.0.1",          # Cloudflare DNS
}

# ─── State ────────────────────────────────────────────────────────────────────
blocked_ips = {}             # ip -> datetime d'expiration
block_timestamps = deque()   # timestamps des blocs recents (rate limit)
state_lock = threading.Lock()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger("autoblock")

app = Flask(__name__)


# ─── Authentification ───────────────────────────────────────────────────────────
def require_token(f):
    """
    Protège les endpoints qui modifient l'état (block/unblock).
    - Si WEBHOOK_SECRET est défini : exige un token valide
      (header 'X-Webhook-Token' ou query param '?token=').
    - Si WEBHOOK_SECRET est vide :
        * mode DRY_RUN  -> autorisé (démo/dev)
        * mode LIVE     -> refusé (fail-safe : pas de blocage iptables sans secret)
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        if WEBHOOK_SECRET:
            token = (request.headers.get("X-Webhook-Token", "")
                     or request.args.get("token", ""))
            if not hmac.compare_digest(token, WEBHOOK_SECRET):
                log.warning("Requête rejetée (token invalide) depuis %s",
                            request.remote_addr)
                return jsonify({"status": "error",
                                "message": "Token invalide ou manquant"}), 401
        elif not DRY_RUN:
            log.error("WEBHOOK_SECRET non défini en mode LIVE — requête refusée (fail-safe)")
            return jsonify({"status": "error",
                            "message": "WEBHOOK_SECRET requis en mode LIVE"}), 503
        return f(*args, **kwargs)
    return wrapper


# ─── iptables ─────────────────────────────────────────────────────────────────
def iptables_block(ip: str) -> bool:
    """Ajoute une regle DROP INPUT pour l'IP."""
    if DRY_RUN:
        log.info("[DRY-RUN] Blocage simule : %s", ip)
        return True
    try:
        subprocess.run(
            ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
            check=True, capture_output=True, timeout=5
        )
        return True
    except subprocess.CalledProcessError as e:
        log.error("iptables block %s: %s", ip, e.stderr.decode())
        return False
    except FileNotFoundError:
        log.error("iptables non disponible. Verifiez NET_ADMIN et network_mode:host.")
        return False


def iptables_unblock(ip: str) -> bool:
    """Supprime la regle DROP pour l'IP."""
    if DRY_RUN:
        log.info("[DRY-RUN] Deblocage simule : %s", ip)
        return True
    try:
        subprocess.run(
            ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            check=True, capture_output=True, timeout=5
        )
        return True
    except subprocess.CalledProcessError:
        return False


# ─── Logique de blocage ───────────────────────────────────────────────────────
def is_valid_ip(ip: str) -> bool:
    pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if not re.match(pattern, ip):
        return False
    return all(0 <= int(p) <= 255 for p in ip.split("."))


def rate_limit_ok() -> bool:
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=1)
    while block_timestamps and block_timestamps[0] < cutoff:
        block_timestamps.popleft()
    return len(block_timestamps) < MAX_BLOCKS_PER_HOUR


def expire_blocks():
    """Supprime les blocs expires."""
    now = datetime.now(timezone.utc)
    expired = [ip for ip, exp in blocked_ips.items() if exp < now]
    for ip in expired:
        iptables_unblock(ip)
        del blocked_ips[ip]
        log.info("Bloc expire pour %s", ip)


def block_ip(ip: str, reason: str, severity: str) -> dict:
    """Tente de bloquer une IP. Retourne le resultat de l'operation."""
    event_to_log = None
    with state_lock:
        expire_blocks()

        if ip in ALLOWLIST:
            return {"status": "skipped", "reason": "allowlist", "ip": ip}

        if not is_valid_ip(ip):
            return {"status": "skipped", "reason": "invalid_ip", "ip": ip}

        if ip in blocked_ips:
            return {"status": "already_blocked", "ip": ip,
                    "expires": blocked_ips[ip].isoformat()}

        if not rate_limit_ok():
            return {"status": "rate_limited", "ip": ip,
                    "message": f"Max {MAX_BLOCKS_PER_HOUR} blocs/heure atteint"}

        expires_at = datetime.now(timezone.utc) + timedelta(minutes=BLOCK_DURATION_MIN)
        success = iptables_block(ip)

        if success:
            blocked_ips[ip] = expires_at
            block_timestamps.append(datetime.now(timezone.utc))
            event_to_log = {
                "@timestamp": datetime.now(timezone.utc).isoformat(),
                "event_type":  "autoblock",
                "action":      "block",
                "ip":          ip,
                "reason":      reason,
                "severity":    severity,
                "expires_at":  expires_at.isoformat(),
                "duration_min": BLOCK_DURATION_MIN,
                "dry_run":     DRY_RUN
            }
            result = {"status": "blocked", "ip": ip,
                      "expires": expires_at.isoformat(), "dry_run": DRY_RUN}
        else:
            result = {"status": "error", "ip": ip, "reason": "iptables_failed"}

    # log_event hors du lock — appel ES (timeout=5s) sans bloquer les webhooks concurrents
    if event_to_log:
        log_event(event_to_log)
        log.warning("BLOQUE %s | raison=%s | expire=%s",
                    ip, result["expires"][:19], "")

    return result


def log_event(event: dict):
    """Log dans Elasticsearch et dans stdout."""
    log.info("EVENT: %s", json.dumps(event))
    if ES_AVAILABLE:
        try:
            es = Elasticsearch(ES_URL, request_timeout=5)
            today = datetime.now(timezone.utc).strftime("%Y.%m.%d")
            es.index(index=f"netwatch-autoblock-{today}", document=event)
        except Exception as e:
            log.error("Impossible d'indexer dans ES : %s", e)


# ─── Parsing alerte Grafana ───────────────────────────────────────────────────
def extract_ips_from_alert(payload: dict) -> list[tuple[str, str, str]]:
    """
    Extrait les IPs des alertes Grafana.
    Retourne une liste de (ip, reason, severity).
    Cherche dans : labels, annotations, values.
    """
    results = []
    ip_pattern = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")

    severity = "warning"
    reason   = "Alerte Grafana"

    for alert in payload.get("alerts", []):
        labels      = alert.get("labels", {})
        annotations = alert.get("annotations", {})

        # Severity depuis les labels
        sev = labels.get("severity", "warning")
        if sev in ("critical", "high", "warning", "medium"):
            severity = sev

        reason = annotations.get("summary", labels.get("alertname", "Alerte Grafana"))

        # Chercher une IP explicite dans les labels connus
        for field in ("src_ip", "source_ip", "ip", "attacker_ip"):
            if field in labels:
                ip = labels[field].strip()
                if is_valid_ip(ip):
                    results.append((ip, reason, severity))

        for field in ("src_ip", "source_ip", "ip"):
            if field in annotations:
                ip = annotations[field].strip()
                if is_valid_ip(ip):
                    results.append((ip, reason, severity))

        # Fallback : scan du texte des annotations pour toute IP
        full_text = " ".join(str(v) for v in annotations.values())
        for ip in ip_pattern.findall(full_text):
            if is_valid_ip(ip) and ip not in ALLOWLIST:
                results.append((ip, reason, severity))

    # Deduplication
    seen = set()
    unique = []
    for item in results:
        if item[0] not in seen:
            seen.add(item[0])
            unique.append(item)
    return unique


# ─── Routes Flask ─────────────────────────────────────────────────────────────
@app.route("/health", methods=["GET"])
def health():
    with state_lock:
        expire_blocks()
        return jsonify({
            "status": "ok",
            "blocked_count": len(blocked_ips),
            "dry_run": DRY_RUN,
            "blocked_ips": [
                {"ip": ip, "expires": exp.isoformat()}
                for ip, exp in blocked_ips.items()
            ]
        })


@app.route("/webhook/alert", methods=["POST"])
@require_token
def webhook_alert():
    """Point d'entree pour les alertes Grafana (contact point Webhook)."""
    payload = request.get_json(silent=True)
    if not payload:
        return jsonify({"status": "error", "message": "JSON invalide"}), 400

    log.info("Alerte recue : %s", payload.get("title", payload.get("alerts", [{}])[0].get("labels", {}).get("alertname", "?")))

    ips = extract_ips_from_alert(payload)
    if not ips:
        return jsonify({"status": "no_ip_found", "message": "Aucune IP a bloquer trouvee dans l'alerte"})

    results = []
    for ip, reason, severity in ips:
        result = block_ip(ip, reason, severity)
        results.append(result)

    return jsonify({"status": "processed", "results": results})


@app.route("/block", methods=["POST"])
@require_token
def manual_block():
    """Blocage manuel via API REST."""
    data = request.get_json(silent=True) or {}
    ip       = data.get("ip", "")
    reason   = data.get("reason", "Blocage manuel")
    severity = data.get("severity", "manual")

    if not ip:
        return jsonify({"status": "error", "message": "Champ 'ip' requis"}), 400

    result = block_ip(ip, reason, severity)
    return jsonify(result)


@app.route("/unblock", methods=["POST"])
@require_token
def manual_unblock():
    """Deblocage manuel."""
    data = request.get_json(silent=True) or {}
    ip = data.get("ip", "")
    if not ip:
        return jsonify({"status": "error", "message": "Champ 'ip' requis"}), 400

    with state_lock:
        if ip in blocked_ips:
            iptables_unblock(ip)
            del blocked_ips[ip]
            log.info("DEBLOQUE manuellement : %s", ip)
            return jsonify({"status": "unblocked", "ip": ip})

    return jsonify({"status": "not_blocked", "ip": ip})


# ─── Main ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    mode = "DRY-RUN" if DRY_RUN else "LIVE (iptables actif)"
    log.info("NetWatch AutoBlock demarre — mode=%s port=%d", mode, WEBHOOK_PORT)
    if WEBHOOK_SECRET:
        log.info("Authentification : ACTIVE (token requis sur block/unblock/webhook)")
    elif DRY_RUN:
        log.warning("Authentification : DESACTIVEE (WEBHOOK_SECRET vide, toleree en DRY-RUN)")
    else:
        log.error("WEBHOOK_SECRET vide en mode LIVE — les endpoints de blocage seront refuses (fail-safe)")
    log.info("Allowlist : %s", sorted(ALLOWLIST))
    log.info("Rate limit : %d blocs/heure, expiration : %dmin",
             MAX_BLOCKS_PER_HOUR, BLOCK_DURATION_MIN)
    app.run(host="0.0.0.0", port=WEBHOOK_PORT, debug=False)
