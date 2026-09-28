"""
Licence hors ligne de l'édition Pro.

Une licence est une chaîne « NW1.<kid>.<payload>.<signature> » : charge utile JSON
(client, édition, nombre de sondes, dates, fonctions) signée en Ed25519 par la clé
privée de l'éditeur, conservée hors du dépôt. Le portail n'embarque que la clé
publique : il vérifie sans réseau, aucun appel sortant, aucune télémétrie.

Cycle de vie : valide → tolérance (LICENSE_GRACE_DAYS après l'expiration, tout
fonctionne, bandeau d'avertissement) → expirée (édition Community). Sans licence :
édition Community. Tant que LICENSE_ENFORCE est faux (défaut pendant la phase de
validation), aucune fonction n'est bridée : la licence est seulement affichée.

Source de la clé : le fichier portal/data/license.key (posé depuis la page
« Licence » du portail) a priorité sur la variable LICENSE_KEY du .env.

Émission (éditeur) : scripts/license/netwatch-license.py keygen | issue | inspect.
"""
import base64
import json
import os
from datetime import date, datetime, timezone

import config

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
LICENSE_FILE = os.path.join(DATA_DIR, "license.key")

# Clés publiques Ed25519 (base64) par identifiant ; une nouvelle clé s'ajoute ici
# sans invalider les licences signées par l'ancienne.
PUBLIC_KEYS = {
    "2026-09": "ULX3wobQht63MHBQUmilXZmmjgg0FMV6YUlqnwnjyQA=",
}

PRO_FEATURES = {
    "ia": "Assistant IA (explications, narration PCAP, résumé exécutif)",
    "reports": "Rapports PDF planifiables",
    "compliance": "Conformité NIS2 / NIST / ANSSI / ISO 27001",
    "itsm": "Intégration ITSM (ServiceNow, Jira)",
    "rbac": "Comptes nominatifs et rôles",
    "support": "Support éditeur",
}
GRACE_DAYS = 30


def _b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64e(b):
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _verify_signature(kid, payload_bytes, sig):
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    pub = PUBLIC_KEYS.get(kid)
    if not pub or pub.startswith("__"):
        return False
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(pub)).verify(sig, payload_bytes)
        return True
    except (InvalidSignature, ValueError):
        return False


def parse(key_str):
    """Décode et vérifie la signature. Retourne (payload, erreur)."""
    key_str = (key_str or "").strip()
    if not key_str:
        return None, "aucune licence"
    parts = key_str.split(".")
    if len(parts) != 4 or parts[0] != "NW1":
        return None, "format inconnu (attendu NW1.<kid>.<payload>.<signature>)"
    _, kid, payload_b64, sig_b64 = parts
    try:
        payload_bytes = _b64d(payload_b64)
        sig = _b64d(sig_b64)
        payload = json.loads(payload_bytes)
    except (ValueError, json.JSONDecodeError):
        return None, "licence illisible"
    if not _verify_signature(kid, payload_bytes, sig):
        return None, "signature invalide (clé %s)" % kid
    for field in ("id", "customer", "edition", "issued", "expires"):
        if field not in payload:
            return None, f"champ manquant : {field}"
    return payload, None


def evaluate(key_str, today=None, grace_days=GRACE_DAYS):
    """État complet d'une licence : none | invalid | valid | grace | expired."""
    today = today or datetime.now(timezone.utc).date()
    payload, err = parse(key_str)
    if payload is None:
        state = "none" if err == "aucune licence" else "invalid"
        return {"state": state, "edition": "community", "reason": err, "payload": None,
                "days_left": None, "features": [], "customer": None, "expires": None}
    try:
        expires = date.fromisoformat(payload["expires"])
    except ValueError:
        return {"state": "invalid", "edition": "community", "reason": "date d'expiration invalide",
                "payload": payload, "days_left": None, "features": [], "customer": payload.get("customer"),
                "expires": payload.get("expires")}
    days_left = (expires - today).days
    if days_left >= 0:
        state = "valid"
    elif -days_left <= grace_days:
        state = "grace"
    else:
        state = "expired"
    pro = payload.get("edition") == "pro" and state in ("valid", "grace")
    features = payload.get("features") or list(PRO_FEATURES)
    return {"state": state, "edition": "pro" if pro else "community",
            "reason": {"valid": "licence valide", "grace": f"expirée depuis {-days_left} j — tolérance de {grace_days} j",
                       "expired": f"expirée depuis {-days_left} j"}[state],
            "payload": payload, "days_left": days_left, "features": features if pro else [],
            "customer": payload.get("customer"), "expires": payload["expires"]}


def current_key():
    """Clé active : fichier posé depuis le portail, sinon LICENSE_KEY du .env."""
    try:
        with open(LICENSE_FILE, encoding="utf-8") as f:
            key = f.read().strip()
        if key:
            return key, "fichier"
    except OSError:
        pass
    return (config.LICENSE_KEY or "").strip(), "env"


def status():
    key, source = current_key()
    info = evaluate(key)
    info["source"] = source if key else None
    info["enforce"] = config.LICENSE_ENFORCE
    return info


def feature_enabled(name):
    """Vrai si la fonction Pro est utilisable : toujours tant que LICENSE_ENFORCE est faux."""
    if not config.LICENSE_ENFORCE:
        return True
    return name in status()["features"]


def save_key(key_str):
    """Enregistre une licence signée (refuse une signature invalide ; une licence expirée est acceptée, avec son état)."""
    payload, err = parse(key_str)
    if payload is None:
        raise ValueError(err)
    os.makedirs(DATA_DIR, exist_ok=True)
    tmp = LICENSE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(key_str.strip() + "\n")
    os.replace(tmp, LICENSE_FILE)
    try:
        os.chmod(LICENSE_FILE, 0o600)
    except OSError:
        pass
    return evaluate(key_str)


def remove_key():
    try:
        os.remove(LICENSE_FILE)
        return True
    except OSError:
        return False


def describe():
    """Une ligne pour la CLI / make license-status."""
    s = status()
    if s["state"] == "none":
        return "Édition Community — aucune licence (bridage : %s)" % ("actif" if s["enforce"] else "inactif")
    if s["state"] == "invalid":
        return "Licence invalide : %s" % s["reason"]
    return "Édition %s — %s — client %s — expire le %s (%s) — source : %s" % (
        s["edition"].capitalize(), s["reason"], s["customer"], s["expires"],
        "bridage actif" if s["enforce"] else "bridage inactif", s["source"])
