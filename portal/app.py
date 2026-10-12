import csv
import glob
import io
import json
import os
import secrets
import subprocess
import threading
import time as _time_mod
from datetime import datetime, timezone
from functools import wraps
from urllib.parse import urlsplit, urlunsplit

import yaml

from flask import Flask, g, make_response, render_template, redirect, url_for, flash, request, jsonify, send_from_directory, Response
from werkzeug.utils import secure_filename
from flask_login import (LoginManager, UserMixin,
                         login_user, logout_user,
                         login_required, current_user)

import config
from netwatch import users as nw_users
from netwatch import license as nw_license
from proxmox import client as px_client
from esxi   import client as esxi_client
from netwatch import health as nw_health
from netwatch import es_client
from netwatch import audit as nw_audit
from netwatch import incidents as nw_incidents
from netwatch import hostgroups as nw_hostgroups
from netwatch.experience import app_dictionary as nw_app_dictionary
from netwatch import thresholds as nw_thresholds
from netwatch import dashboard_layout as nw_dashboard_layout
from netwatch import probes as nw_probes
from netwatch import netbox as nw_netbox
from netwatch import extensions as nw_extensions
from netwatch.referentials import NIS2_MATRIX

# ============================================================
# Données de comparaison (matrice feature × outil) — alignées sur
# docs/comparatif-editeurs.md (documentation publique des éditeurs, 28/09/2026).
# Valeurs : "full" | "partial" | "none" | str littéral
# ============================================================

TOOL_COLS = [
    {"id": "netwatch",        "name": "NetWatch",             "type": "open-source", "logo": "🔭"},
    {"id": "security-onion",  "name": "Security Onion",       "type": "open-source", "logo": "🧅"},
    {"id": "wazuh",           "name": "Wazuh",                "type": "open-source", "logo": "🛡️"},
    {"id": "netscout",        "name": "Netscout nGeniusONE",  "type": "commercial",  "logo": "📡"},
    {"id": "gigamon",         "name": "Gigamon",              "type": "commercial",  "logo": "🔬"},
    {"id": "riverbed",        "name": "Riverbed NetProfiler", "type": "commercial",  "logo": "🌊"},
]

COMPARE_MATRIX = [
    {
        "category": "Capture & Analyse réseau",
        "icon": "bi-reception-4",
        "rows": [
            {"feature": "Capture PCAP (SPAN/TAP)",
             "netwatch": "full", "security-onion": "full", "wazuh": "none",
             "netscout": "full", "gigamon": "full", "riverbed": "partial"},
            {"feature": "Analyse protocolaire DPI",
             "netwatch": "full", "security-onion": "full", "wazuh": "none",
             "netscout": "full", "gigamon": "partial", "riverbed": "partial"},
            {"feature": "Fingerprinting JA3 / HASSH",
             "netwatch": "full", "security-onion": "full", "wazuh": "none",
             "netscout": "partial", "gigamon": "none", "riverbed": "none"},
            {"feature": "Analyse NetFlow / IPFIX / sFlow",
             "netwatch": "full", "security-onion": "partial", "wazuh": "none",
             "netscout": "full", "gigamon": "full", "riverbed": "full"},
        ],
    },
    {
        "category": "Détection des menaces",
        "icon": "bi-shield-exclamation",
        "rows": [
            {"feature": "IDS signatures (Snort 3 / Suricata 7)",
             "netwatch": "full", "security-onion": "full", "wazuh": "partial",
             "netscout": "partial", "gigamon": "partial", "riverbed": "none"},
            {"feature": "Mapping MITRE ATT&CK",
             "netwatch": "full", "security-onion": "full", "wazuh": "full",
             "netscout": "partial", "gigamon": "none", "riverbed": "none"},
            {"feature": "Détection beaconing C2 (RITA-lite)",
             "netwatch": "full", "security-onion": "full", "wazuh": "none",
             "netscout": "partial", "gigamon": "partial", "riverbed": "none"},
            {"feature": "Threat Intel (IoC watchlist)",
             "netwatch": "full", "security-onion": "full", "wazuh": "full",
             "netscout": "full", "gigamon": "full", "riverbed": "partial"},
            {"feature": "Détection HIDS (endpoints)",
             "netwatch": "none", "security-onion": "partial", "wazuh": "full",
             "netscout": "none", "gigamon": "none", "riverbed": "none"},
        ],
    },
    {
        "category": "Réponse & Alerting",
        "icon": "bi-bell-fill",
        "rows": [
            {"feature": "Alertes temps réel",
             "netwatch": "full", "security-onion": "full", "wazuh": "full",
             "netscout": "full", "gigamon": "full", "riverbed": "full"},
            {"feature": "Blocage automatique (iptables/firewall)",
             "netwatch": "full", "security-onion": "partial", "wazuh": "full",
             "netscout": "none", "gigamon": "none", "riverbed": "none"},
            {"feature": "Webhook Slack / Teams",
             "netwatch": "full", "security-onion": "partial", "wazuh": "full",
             "netscout": "full", "gigamon": "partial", "riverbed": "partial"},
            {"feature": "Gestion d'incidents (ticketing)",
             "netwatch": "partial", "security-onion": "full", "wazuh": "partial",
             "netscout": "full", "gigamon": "partial", "riverbed": "full"},
        ],
    },
    {
        "category": "Dashboards & Reporting",
        "icon": "bi-bar-chart-line",
        "rows": [
            {"feature": "Dashboards temps réel",
             "netwatch": "full", "security-onion": "full", "wazuh": "full",
             "netscout": "full", "gigamon": "full", "riverbed": "full"},
            {"feature": "Corrélation multi-moteurs",
             "netwatch": "full", "security-onion": "partial", "wazuh": "partial",
             "netscout": "full", "gigamon": "partial", "riverbed": "partial"},
            {"feature": "Reporting exécutif PDF",
             "netwatch": "full", "security-onion": "partial", "wazuh": "partial",
             "netscout": "full", "gigamon": "full", "riverbed": "full"},
            {"feature": "GeoIP & Top Talkers",
             "netwatch": "full", "security-onion": "full", "wazuh": "partial",
             "netscout": "full", "gigamon": "partial", "riverbed": "partial"},
        ],
    },
    {
        "category": "Déploiement & Intégration",
        "icon": "bi-gear-wide-connected",
        "rows": [
            {"feature": "Déploiement Docker Compose",
             "netwatch": "full", "security-onion": "none", "wazuh": "full",
             "netscout": "none", "gigamon": "none", "riverbed": "none"},
            {"feature": "API REST native",
             "netwatch": "full", "security-onion": "full", "wazuh": "full",
             "netscout": "full", "gigamon": "full", "riverbed": "full"},
            {"feature": "Multi-tenant",
             "netwatch": "none", "security-onion": "partial", "wazuh": "full",
             "netscout": "full", "gigamon": "full", "riverbed": "full"},
            {"feature": "Support commercial garanti (SLA)",
             "netwatch": "partial", "security-onion": "none", "wazuh": "partial",
             "netscout": "full", "gigamon": "full", "riverbed": "full"},
        ],
    },
    {
        "category": "Coût & Licence",
        "icon": "bi-currency-euro",
        "rows": [
            {"feature": "Licence",
             "netwatch": "AGPL v3 + Pro", "security-onion": "Elastic License 2.0", "wazuh": "GPL v2",
             "netscout": "Propriétaire", "gigamon": "Propriétaire", "riverbed": "Propriétaire"},
            {"feature": "Modèle tarifaire public",
             "netwatch": "Community gratuite · Pro abonnement", "security-onion": "Gratuit · support payant",
             "wazuh": "Gratuit · cloud payant", "netscout": "Sur devis", "gigamon": "Sur devis", "riverbed": "Sur devis"},
            {"feature": "Complexité déploiement",
             "netwatch": "Faible", "security-onion": "Moyenne", "wazuh": "Moyenne",
             "netscout": "Élevée", "gigamon": "Élevée", "riverbed": "Élevée"},
        ],
    },
]

app = Flask(__name__)
app.secret_key = config.FLASK_SECRET_KEY


# ── Content-Security-Policy ──────────────────────────────────────────────────
# Tout est servi par le portail lui-même (Bootstrap, Chart.js, d3, polices
# vendorisés) : default-src 'self'. Les <script> inline des templates portent
# un nonce par requête ({{ csp_nonce }}) ; les gestionnaires onclick= inline
# sont interdits (remplacés par des attributs data-action). Les attributs
# style= restent tolérés ('unsafe-inline' sur style-src uniquement).
CSP_DIRECTIVES = (
    "default-src 'self'",
    "script-src 'self' 'nonce-{nonce}'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self'",
    "connect-src 'self'",
    "frame-ancestors 'none'",
    "form-action 'self'",
    "base-uri 'self'",
    "object-src 'none'",
    "report-uri /csp-report",
)


def _csp_header(nonce):
    return "; ".join(CSP_DIRECTIVES).format(nonce=nonce)


@app.before_request
def set_csp_nonce():
    g.csp_nonce = secrets.token_urlsafe(16)


@app.context_processor
def inject_csp_nonce():
    return {"csp_nonce": g.get("csp_nonce", "")}


@app.context_processor
def inject_product():
    return {"product": {"name": config.PRODUCT_NAME, "tagline": config.PRODUCT_TAGLINE,
                        "version": config.VERSION, "url": config.PRODUCT_URL, "license": config.PRODUCT_LICENSE}}


@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    mode = config.CSP_MODE
    if mode != "off" and g.get("csp_nonce"):
        name = "Content-Security-Policy-Report-Only" if mode == "report-only" else "Content-Security-Policy"
        response.headers[name] = _csp_header(g.csp_nonce)
    return response


@app.route("/csp-report", methods=["POST"])
def csp_report():
    """Réception des violations CSP envoyées par le navigateur (report-uri) : journal seulement."""
    raw = request.get_data(cache=False, as_text=True)[:4096]
    try:
        body = json.loads(raw) if raw else {}
        rep = body.get("csp-report", body) if isinstance(body, dict) else {}
        app.logger.warning("CSP violation: %s bloqué sur %s (directive %s)",
                           rep.get("blocked-uri", "?"), rep.get("document-uri", "?"),
                           rep.get("effective-directive") or rep.get("violated-directive", "?"))
    except ValueError:
        app.logger.warning("CSP violation (rapport illisible) : %s", raw[:200])
    return "", 204


# Durcissement des cookies de session
#  - HttpOnly : inaccessible au JS (anti-XSS vol de session)
#  - SameSite=Lax : le cookie n'est pas envoyé sur les POST cross-site (anti-CSRF)
#  - Secure : cookie envoyé uniquement en HTTPS (activer en prod via SESSION_COOKIE_SECURE)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=config.SESSION_COOKIE_SECURE,
)

# Derrière Caddy : scheme/host/IP client lus dans les X-Forwarded-* (un seul
# proxy de confiance) — sinon les redirections et `next` pointeraient sur
# localhost:5050. Jamais actif en accès direct : ces en-têtes seraient forgeables.
if config.PROXY_MODE:
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

# ============================================================
# Authentification (Flask-Login)
# ============================================================

login_manager = LoginManager(app)
login_manager.login_view        = "login"
login_manager.login_message     = "Connexion requise pour accéder au portail."
login_manager.login_message_category = "warning"


class _User(UserMixin):
    """Compte nominatif (netwatch.users) : identifiant + rôle viewer / operator / admin."""
    def __init__(self, username, role):
        self.id = username
        self.username = username
        self.role = role

    def has_role(self, minimum):
        return nw_users.ROLE_RANK.get(self.role, -1) >= nw_users.ROLE_RANK[minimum]


@login_manager.user_loader
def _load_user(user_id):
    u = nw_users.get_active(user_id)   # compte supprimé ou désactivé → session invalide
    return _User(u["username"], u["role"]) if u else None


def _check_credentials(username: str, password: str):
    """Compte (sans hash) si les identifiants sont valides, sinon None (temps constant sur le compte d'amorçage)."""
    return nw_users.verify(username, password)


def _forbidden(message):
    """403 : JSON pour l'API, page d'erreur sinon."""
    nw_users.log_event("forbidden", getattr(current_user, "username", None), _login_client_ip(),
                       f"{request.method} {request.path}")
    if request.path.startswith("/api/") or request.accept_mimetypes.best == "application/json":
        return jsonify({"error": message}), 403
    return render_template("403.html", message=message), 403


def admin_required(fn):
    """Réservé au rôle admin (après login_required)."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            return login_manager.unauthorized()
        if current_user.role != "admin":
            return _forbidden("Réservé aux administrateurs.")
        return fn(*args, **kwargs)
    return wrapper


def pro_required(feature):
    """Fonction de l'édition Pro : bloquée (402) seulement si LICENSE_ENFORCE est vrai
    et que la licence installée ne la couvre pas. Voir netwatch/license.py."""
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if nw_license.feature_enabled(feature):
                return fn(*args, **kwargs)
            label = nw_license.PRO_FEATURES.get(feature, feature)
            message = f"« {label} » fait partie de l'édition Pro : licence requise (page Licence du portail)."
            if request.path.startswith("/api/") or request.accept_mimetypes.best == "application/json":
                return jsonify({"error": message, "feature": feature}), 402
            return render_template("403.html", message=message), 402
        return wrapper
    return deco


MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


@app.before_request
def enforce_read_only_role():
    """Rôle lecture : aucune action. Les demandes d'explication IA (POST sans effet
    sur l'état) et la connexion restent permises."""
    if request.method not in MUTATING_METHODS or not current_user.is_authenticated:
        return None
    if request.path in ("/login", "/csp-report") or request.path.endswith("/explain"):
        return None
    if current_user.role == "viewer":
        return _forbidden("Rôle lecture seule : action non autorisée.")
    return None


# Anti-force-brute sur /login : échecs consécutifs comptés par adresse source,
# verrou de LOGIN_LOCK_SECONDS après LOGIN_MAX_FAILURES échecs. État en mémoire
# (un seul processus portail), journalisé en WARNING pour la supervision.
LOGIN_MAX_FAILURES = 5
LOGIN_LOCK_SECONDS = 60
_LOGIN_ATTEMPTS: dict = {}   # ip → [échecs consécutifs, verrouillé jusqu'à (monotonic)]


def _login_client_ip() -> str:
    """Adresse source ; derrière Caddy (profil proxy) c'est X-Forwarded-For qui la porte."""
    if config.PROXY_MODE:
        fwd = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        if fwd:
            return fwd
    return request.remote_addr or "?"


def _login_lock_remaining(ip: str) -> int:
    st = _LOGIN_ATTEMPTS.get(ip)
    return max(0, int(st[1] - _time_mod.monotonic())) if st else 0


def _login_failed(ip: str) -> None:
    st = _LOGIN_ATTEMPTS.setdefault(ip, [0, 0.0])
    st[0] += 1
    if st[0] >= LOGIN_MAX_FAILURES:
        st[0] = 0
        st[1] = _time_mod.monotonic() + LOGIN_LOCK_SECONDS
        app.logger.warning("login : %s verrouillé %s s après %s échecs", ip, LOGIN_LOCK_SECONDS, LOGIN_MAX_FAILURES)


def _login_succeeded(ip: str) -> None:
    _LOGIN_ATTEMPTS.pop(ip, None)


# ============================================================
# Helpers
# ============================================================

_CATALOG_CACHE = None

def load_catalog():
    global _CATALOG_CACHE
    if _CATALOG_CACHE is None:
        catalog_path = os.path.join(os.path.dirname(__file__), "catalog", "tools.json")
        with open(catalog_path, encoding="utf-8") as f:
            _CATALOG_CACHE = json.load(f)
    return _CATALOG_CACHE


# Proxmox injoignable (Shuttle éteint, portail lancé ailleurs…) : le timeout de
# connexion (5 s) ne doit jamais être payé par une page. Après un échec, on
# mémorise l'indisponibilité avec un TTL qui double (60 s → 10 min) et, à
# l'expiration, on re-sonde dans un thread : la page rend tout de suite sans
# Proxmox, la suivante l'aura si la sonde a réussi.
_PX_FAIL = {"ts": 0.0, "ttl": 60, "probing": False, "ok": False}
_PX_FAIL_TTL_MAX = 600
_PX_LOCK = threading.Lock()


def _px_mark_failed():
    """Mémorise l'échec Proxmox (TTL doublé à chaque échec consécutif, plafonné)."""
    with _PX_LOCK:
        if _PX_FAIL["ts"]:
            _PX_FAIL["ttl"] = min(_PX_FAIL["ttl"] * 2, _PX_FAIL_TTL_MAX)
        _PX_FAIL["ts"] = _time_mod.monotonic()
        _PX_FAIL["ok"] = False


def _px_probe():
    """Sonde asynchrone : tente une connexion + un appel léger, hors requête HTTP."""
    try:
        px_client.get_node_status(px_client.get_client())
        with _PX_LOCK:
            _PX_FAIL.update({"ts": 0.0, "ttl": 60, "ok": True})
    except Exception:
        _px_mark_failed()
    finally:
        with _PX_LOCK:
            _PX_FAIL["probing"] = False


def get_proxmox():
    """Retourne un client Proxmox, ou None si non configuré / non joignable.
    Ne bloque jamais sur un hôte injoignable (cf. _PX_FAIL)."""
    if not config.PROXMOX_HOST:
        return None
    with _PX_LOCK:
        failed_recently = _time_mod.monotonic() - _PX_FAIL["ts"] < _PX_FAIL["ttl"]
        known_ok = _PX_FAIL["ok"]
        if not known_ok and not failed_recently and not _PX_FAIL["probing"]:
            _PX_FAIL["probing"] = True
            threading.Thread(target=_px_probe, name="px-probe", daemon=True).start()
    if not known_ok:
        return None
    try:
        return px_client.get_client()
    except Exception:
        _px_mark_failed()
        return None


def get_esxi():
    """Retourne (host, session_id) ESXi, ou None si non configuré / non joignable."""
    if not config.ESXI_HOST:
        return None
    try:
        return esxi_client.get_session()
    except Exception:
        return None


def proxmox_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        px = get_proxmox()
        if px is None:
            if not config.PROXMOX_HOST:
                flash("Proxmox non configuré — gestion des VMs réservée au déploiement Proxmox (renseigner PROXMOX_HOST dans .env).", "info")
            else:
                flash("Proxmox non joignable — vérifier PROXMOX_HOST et les credentials dans .env", "danger")
            return redirect(url_for("dashboard"))
        return f(px, *args, **kwargs)
    return decorated


def _safe_int(value, default=None):
    """int() défensif pour les query params — une valeur non numérique ne doit
    jamais faire planter la route (500) mais retomber sur `default`."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def fmt_bytes(b):
    if b is None:
        return "—"
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} PB"


app.jinja_env.filters["fmt_bytes"] = fmt_bytes


def fmt_uptime(seconds):
    if not seconds:
        return "—"
    h, r = divmod(int(seconds), 3600)
    m, _ = divmod(r, 60)
    if h >= 24:
        return f"{h // 24}j {h % 24}h"
    return f"{h}h {m}m"


app.jinja_env.filters["fmt_uptime"] = fmt_uptime


def _proxy_paths():
    """Service interne (URL de config) → préfixe public servi par Caddy."""
    return [
        (config.NETWATCH_GRAFANA_URL, "/grafana"),
        (config.NETWATCH_KIBANA_URL,  "/kibana"),
        (config.NETWATCH_ARKIME_URL,  "/arkime"),
        (config.NETWATCH_NTOPNG_URL,  "/ntopng"),
        (config.NETWATCH_NETBOX_URL,  "/netbox"),
    ]


def browser_url(url):
    """URL d'un service telle que le navigateur doit l'ouvrir.

    Derrière Caddy (config.PROXY_MODE) : l'URL interne d'un outil devient son
    préfixe public (http://localhost:3000/d/x → /grafana/d/x) — même origine,
    même session. Un service non proxifié garde son URL interne.

    Sinon : réécrit localhost/127.0.0.1 vers l'hôte depuis lequel l'utilisateur
    navigue. Les URLs de config (health checks) ciblent localhost = la VM côté
    serveur ; pour qu'un lien soit cliquable depuis un poste distant, on
    substitue le host de la requête courante (ex. 172.31.20.90). Le port est
    conservé."""
    if config.PROXY_MODE:
        for base, prefix in _proxy_paths():
            base = (base or "").rstrip("/")
            if base and (url == base or url.startswith(base + "/") or url.startswith(base + "?")
                         or url.startswith(base + "#")):
                return prefix + url[len(base):]
        return url
    try:
        parts = urlsplit(url)
        if parts.hostname not in ("localhost", "127.0.0.1"):
            return url
        host = request.host.split(":")[0]
        netloc = host + (f":{parts.port}" if parts.port else "")
        return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
    except Exception:
        return url


app.jinja_env.filters["browser_url"] = browser_url


def geo_flag(iso):
    """Convertit un code ISO 2 lettres en emoji drapeau (ex: FR → 🇫🇷)."""
    if not iso or len(iso) != 2:
        return ""
    return "".join(chr(ord(c) + 127397) for c in iso.upper())

app.jinja_env.filters["geo_flag"] = geo_flag


_HG_NAV_CACHE = {"mtime": None, "groups": []}

# Plage temporelle globale (sélecteur topbar) : clé → heures. Lue depuis
# ?range= puis le cookie nw_range (posé par le sélecteur), défaut 24 h.
RANGES = {"1h": 1, "6h": 6, "24h": 24, "7d": 168, "30d": 720}
RANGE_LABELS = {"1h": "1 h", "6h": "6 h", "24h": "24 h", "7d": "7 j", "30d": "30 j"}


def _range():
    """(clé, heures) de la plage temporelle courante."""
    key = request.args.get("range") or request.cookies.get("nw_range") or "24h"
    if key not in RANGES:
        key = "24h"
    return key, RANGES[key]


def _range_days(default=None):
    """Plage en jours entiers (min 1, max 30) pour les modules qui ne
    travaillent qu'en jours (applications, SLA). `?days=` reste prioritaire
    (liens historiques)."""
    explicit = _safe_int(request.args.get("days"))
    if explicit:
        return max(1, min(30, explicit))
    if default is not None and not request.args.get("range") and not request.cookies.get("nw_range"):
        return default
    return max(1, min(30, _range()[1] // 24 or 1))


@app.context_processor
def _inject_globals():
    """Hostgroups pour le sélecteur global de la topbar — injectés côté serveur
    (plus de fetch /api/hostgroups à chaque page), rechargés seulement quand le
    fichier JSON change (mtime). + proxmox_host/node pour la sidebar/topbar."""
    try:
        mtime = os.path.getmtime(nw_hostgroups.STORE_PATH)
    except OSError:
        mtime = None
    if mtime != _HG_NAV_CACHE["mtime"]:
        _HG_NAV_CACHE["groups"] = nw_hostgroups.list_groups() if mtime else []
        _HG_NAV_CACHE["mtime"]  = mtime
    range_key, range_hours = _range()
    return {
        "nav_hostgroups":    _HG_NAV_CACHE["groups"],
        "current_hostgroup": request.args.get("hostgroup", ""),
        "proxmox_host":      config.PROXMOX_HOST,
        "proxmox_node":      config.PROXMOX_NODE,
        "current_range":     range_key,
        "range_hours":       range_hours,
        "range_days":        max(1, min(30, range_hours // 24 or 1)),
        "range_label":       RANGE_LABELS[range_key],
        "range_options":     [(k, RANGE_LABELS[k]) for k in RANGES],
        # Outils complémentaires (liens externes du menu / boutons contextuels)
        "tool_urls": {
            "kibana": config.NETWATCH_KIBANA_URL,
            "ntopng": config.NETWATCH_NTOPNG_URL,
            "arkime": config.NETWATCH_ARKIME_URL,
            "netbox": config.NETWATCH_NETBOX_URL,
        },
        "netbox_enabled": nw_netbox.configured(),
        # Licence Pro (édition, état, tolérance) : bandeau et pages Statut / Licence
        "license": nw_license.status() if current_user.is_authenticated else None,
    }


# Dashboard Grafana correspondant à chaque page NetWatch — mis en avant via un
# lien contextuel dans la topbar plutôt que de réimplémenter des dashboards
# filtrables/éditables dans le portail : Grafana le fait déjà très bien.
GRAFANA_DASHBOARDS = {
    "dashboard":  "netwatch-overview",
    "flows":      "netwatch-toptalkers",
    "alerts":     "netwatch-security",
    "zeek_logs":  "netwatch-overview",
    "status":     "netwatch-vmhealth",
    "topology":   "netwatch-snmp-ifaces",
    "audit":      "netwatch-security",
    "incidents":  "netwatch-beacons",
}


@app.context_processor
def inject_grafana():
    return {
        "grafana_url": config.NETWATCH_GRAFANA_URL,
        "grafana_dashboard_uid": GRAFANA_DASHBOARDS.get(request.endpoint),
    }

# ============================================================
# Routes — Auth
# ============================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        ip = _login_client_ip()
        wait = _login_lock_remaining(ip)
        if wait:
            nw_users.log_event("login_locked", request.form.get("username", ""), ip, f"{wait} s")
            flash(f"Trop de tentatives — réessayez dans {wait} s.", "danger")
            return render_template("login.html"), 429
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        account = _check_credentials(username, password)
        if account:
            _login_succeeded(ip)
            login_user(_User(account["username"], account["role"]), remember=bool(request.form.get("remember")))
            nw_users.touch_login(account["username"])
            nw_users.log_event("login", account["username"], ip, account["role"])
            next_page = request.args.get("next")
            if next_page:
                from urllib.parse import urlparse, urljoin
                parsed = urlparse(urljoin(request.host_url, next_page))
                host   = urlparse(request.host_url)
                if parsed.scheme not in ("http", "https") or parsed.netloc != host.netloc:
                    next_page = None
            return redirect(next_page or url_for("dashboard"))
        _login_failed(ip)
        nw_users.log_event("login_failed", username, ip)
        flash("Identifiants incorrects.", "danger")
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    nw_users.log_event("logout", current_user.username, _login_client_ip())
    logout_user()
    flash("Déconnecté.", "info")
    return redirect(url_for("login"))


@app.route("/auth/check")
def auth_check():
    """Sous-requête d'authentification de Caddy (forward_auth) pour les outils
    servis sous /grafana/, /kibana/… : 2xx = session portail valide, la requête
    passe (Grafana reçoit l'utilisateur dans X-Webauth-User) ; sinon la
    réponse est renvoyée telle quelle au navigateur → page de connexion, puis
    retour à l'URL demandée (X-Forwarded-Uri, validée comme tout `next`)."""
    if current_user.is_authenticated:
        resp = make_response("", 204)
        # Grafana (auth proxy) : les administrateurs NetWatch sont « admin » côté Grafana,
        # les autres comptes sont créés à la volée en lecteurs (GF_AUTH_PROXY_AUTO_SIGN_UP).
        resp.headers["X-Webauth-User"] = "admin" if current_user.role == "admin" else current_user.username
        return resp
    wanted = request.headers.get("X-Forwarded-Uri") or "/"
    return redirect(url_for("login", next=wanted))


# ============================================================
# Comptes et rôles (admin)
# ============================================================

@app.route("/admin/users")
@login_required
@admin_required
def admin_users():
    return render_template("admin_users.html", users=nw_users.list_users(), events=nw_users.list_events(50),
                           roles=nw_users.ROLES, role_labels=nw_users.ROLE_LABELS, min_password=nw_users.MIN_PASSWORD)


@app.route("/admin/users", methods=["POST"])
@login_required
@admin_required
def admin_users_create():
    try:
        u = nw_users.create_user(request.form.get("username", "").strip(), request.form.get("password", ""),
                                 request.form.get("role", "viewer"), actor=current_user.username)
        flash(f"Compte « {u['username']} » créé ({nw_users.ROLE_LABELS[u['role']]}).", "success")
    except ValueError as exc:
        flash(str(exc), "danger")
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<username>", methods=["POST"])
@login_required
@admin_required
def admin_users_update(username):
    action = request.form.get("action", "")
    try:
        if action in ("disable", "delete", "role") and username == current_user.username:
            raise ValueError("Vous ne pouvez pas désactiver, supprimer ni rétrograder votre propre compte.")
        if action == "role":
            nw_users.set_role(username, request.form.get("role", ""), actor=current_user.username)
        elif action == "password":
            nw_users.set_password(username, request.form.get("password", ""), actor=current_user.username)
        elif action in ("disable", "enable"):
            nw_users.set_disabled(username, action == "disable", actor=current_user.username)
        elif action == "delete":
            nw_users.delete_user(username, actor=current_user.username)
        else:
            raise ValueError("Action inconnue.")
        flash(f"Compte « {username} » mis à jour.", "success")
    except ValueError as exc:
        flash(str(exc), "danger")
    return redirect(url_for("admin_users"))


@app.route("/admin/license")
@login_required
@admin_required
def admin_license():
    return render_template("admin_license.html", lic=nw_license.status(), pro_features=nw_license.PRO_FEATURES,
                           grace_days=nw_license.GRACE_DAYS)


@app.route("/admin/license", methods=["POST"])
@login_required
@admin_required
def admin_license_save():
    try:
        info = nw_license.save_key(request.form.get("license", ""))
        nw_users.log_event("license_installed", current_user.username, _login_client_ip(),
                           f"{info['customer']} · expire {info['expires']} · {info['state']}")
        flash(f"Licence installée : {info['customer']}, {info['reason']}.", "success" if info["state"] == "valid" else "warning")
    except ValueError as exc:
        flash(f"Licence refusée : {exc}.", "danger")
    return redirect(url_for("admin_license"))


@app.route("/admin/license/remove", methods=["POST"])
@login_required
@admin_required
def admin_license_remove():
    if nw_license.remove_key():
        nw_users.log_event("license_removed", current_user.username, _login_client_ip())
        flash("Licence retirée — édition Community.", "info")
    return redirect(url_for("admin_license"))


# ============================================================
# Routes
# ============================================================

def _safe(fn, default):
    """Appelle fn() ; retourne `default` en cas d'exception (widgets best-effort)."""
    try:
        return fn()
    except Exception:
        return default


def _triage(alert_stats, perf, services, sla, breaches, probes=None):
    """
    Bandeau de triage de la home : liste des points qui demandent attention,
    triés par gravité, chacun avec un lien vers la page de diagnostic.
    Seuils = ceux déjà utilisés par les widgets (RTT 150 ms, ART 500 ms,
    zero-window / retransmissions 1 % et 3 %).
    """
    items = []

    def add(level, icon, text, href):
        items.append({"level": level, "icon": icon, "text": text, "href": href})

    # Services — un service optionnel (Kibana, ntopng…) absent n'est qu'un avertissement
    down     = [s["name"] for s in services if s["status"] == "down" and not s.get("optional")]
    opt_down = [s["name"] for s in services if s["status"] == "down" and s.get("optional")]
    degraded = [s["name"] for s in services if s["status"] == "degraded"]
    if down:
        add("crit", "bi-x-octagon", f"{', '.join(down)} : indisponible", url_for("status"))
    if degraded:
        add("warn", "bi-exclamation-triangle", f"{', '.join(degraded)} : dégradé", url_for("status"))
    if opt_down:
        add("warn", "bi-plug", f"{', '.join(opt_down)} : non démarré (optionnel)", url_for("status"))

    # Sondes actives Blackbox — une cible injoignable est un fait mesuré, pas une supposition
    for p in (probes or []):
        if not p["up"]:
            add("crit", "bi-broadcast", f"Sonde KO : {p['name']} ({p['module']})", url_for("sla") + "#probes")
    for p in (probes or []):
        av = p.get("availability_pct")
        if p["up"] and av is not None and av < 99:
            add("warn", "bi-broadcast", f"Disponibilité {av} % : {p['name']}", url_for("sla") + "#probes")

    # Alertes IDS
    stats = alert_stats or {}
    crit = stats.get("critical", 0)
    if crit:
        add("crit", "bi-shield-exclamation",
            f"{crit} alerte{'s' if crit > 1 else ''} critique{'s' if crit > 1 else ''} (7 j)",
            url_for("alerts", severity=1))
    w, p = stats.get("window", 0), stats.get("prev_window", 0)
    if p >= 5 and w >= 2 * p:
        add("warn", "bi-graph-up-arrow", f"Alertes ×{w // p} vs période précédente ({w})", url_for("alerts"))

    # Santé TCP
    tcp = perf.get("tcp", {})
    zw = tcp.get("zero_window_pct") or 0
    if zw > 3:
        add("crit", "bi-pause-circle", f"Zero-window sur {zw} % des connexions TCP", url_for("flows"))
    elif zw > 1:
        add("warn", "bi-pause-circle", f"Zero-window sur {zw} % des connexions TCP", url_for("flows"))
    for r in tcp.get("top_retransmit_ips", [])[:3]:
        if r.get("retransmit_pct", 0) > 3:
            add("warn", "bi-arrow-repeat", f"Retransmissions {r['retransmit_pct']} % · {r['ip']}",
                url_for("ip_detail", ip=r["ip"]))
    rtt = tcp.get("avg_rtt_ms")
    if rtt is not None and rtt > 150:
        add("warn", "bi-heart-pulse", f"RTT moyen élevé : {rtt} ms", url_for("flows"))

    # ART
    p50 = perf.get("art", {}).get("http", {}).get("p50")
    if p50 is not None and p50 > 500:
        add("warn", "bi-hourglass-split", f"ART HTTP p50 {p50} ms", url_for("flows"))

    # SLA (ignoré sans données : 0 % sur 0 bucket n'est pas une non-conformité)
    for s in (sla or {}).get("slas", []):
        if not s.get("buckets_total"):
            continue
        if s.get("status") == "crit":
            add("crit", "bi-patch-exclamation", f"SLA {s['name']} non conforme ({s['compliance_pct']} %)", url_for("sla"))
        elif s.get("status") == "warn":
            add("warn", "bi-patch-exclamation", f"SLA {s['name']} limite ({s['compliance_pct']} %)", url_for("sla"))

    # Seuils utilisateur franchis
    for b in breaches or []:
        rule = b.get("rule", {})
        m = nw_thresholds.METRICS.get(rule.get("metric"), {})
        add("crit" if rule.get("severity") == "critical" else "warn", "bi-bell",
            f"Seuil {m.get('label', rule.get('metric'))} {rule.get('operator')} {rule.get('value')}{m.get('unit', '')}"
            f" · {b.get('app')} ({b.get('current')})",
            url_for("thresholds_page"))

    order = {"crit": 0, "warn": 1}
    items.sort(key=lambda i: order[i["level"]])
    level = "crit" if any(i["level"] == "crit" for i in items) else ("warn" if items else "ok")
    # clé « points » (pas « items » : Jinja résoudrait dict.items)
    return {"level": level, "points": items[:8]}


@app.route("/")
@login_required
def dashboard():
    """Home = écran de triage + vue observabilité réseau (esprit Allegro /
    Riverbed) : état global, KPIs trafic, santé TCP, ART, top talkers, alertes
    récentes, points d'écoute, services. Proxmox/VMs/catalogue ont leurs
    propres pages (Projet & infra)."""
    _, hours = _range()
    sla_days = max(1, min(30, hours // 24 or 1))
    ((recent_alerts, _), (alert_stats, _), perf, (services, global_status),
     (sla, _), (breaches, _), (probes, _)) = es_client.run_parallel(
        lambda: es_client.get_recent_alerts(size=8),
        lambda: es_client.get_alert_stats(hours=hours),
        lambda: _perf_dashboard(talkers_size=8, hours=hours),
        _check_health,
        lambda: _safe(lambda: es_client.get_sla_stats(days=sla_days), ({}, None)),
        lambda: _safe(nw_thresholds.evaluate, ([], None)),
        lambda: _safe(lambda: nw_probes.get_probes(hours=hours), ([], None)),
    )
    pcap_points, pcap_top = _pcap_overview()
    return render_template(
        "dashboard.html",
        recent_alerts=recent_alerts,
        alert_stats=alert_stats,
        dashboard=perf,
        services=services,
        global_status=global_status,
        pcap_points=pcap_points,
        pcap_top=pcap_top,
        probes_summary=nw_probes.summarize(probes),
        triage=_triage(alert_stats, perf, services, sla, breaches, probes),
    )


@app.route("/vms")
@login_required
def vms():
    vm_list = []
    px = get_proxmox()
    if px:
        try:
            vm_list.extend(px_client.list_vms(px))
        except Exception as e:
            _px_mark_failed()
            flash(f"Proxmox : impossible de lister les VMs — {e}", "warning")

    esxi = get_esxi()
    if esxi:
        try:
            host, session_id = esxi
            vm_list.extend(esxi_client.list_vms(host, session_id))
        except Exception as e:
            flash(f"ESXi : impossible de lister les VMs — {e}", "warning")

    if not px and not esxi:
        if not config.PROXMOX_HOST and not config.ESXI_HOST:
            flash("Aucun hyperviseur configuré — renseigner PROXMOX_HOST ou ESXI_HOST dans .env", "info")
        else:
            flash("Hyperviseur(s) non joignables — vérifier les credentials dans .env", "danger")

    return render_template("vms.html", vms=vm_list)


@app.route("/vms/<int:vmid>/<action>", methods=["POST"])
@login_required
@proxmox_required
def vm_action(px, vmid, action):
    try:
        px_client.vm_action(px, vmid, action)
        flash(f"Action '{action}' envoyée à la VM {vmid}", "success")
    except Exception as e:
        flash(f"Erreur : {e}", "danger")
    return redirect(url_for("vms"))


@app.route("/vms/<int:vmid>/delete", methods=["POST"])
@login_required
@proxmox_required
def vm_delete(px, vmid):
    try:
        px_client.delete_vm(px, vmid)
        flash(f"VM {vmid} supprimée", "success")
    except Exception as e:
        flash(f"Erreur suppression : {e}", "danger")
    return redirect(url_for("vms"))


@app.route("/vms/esxi/<vm_id>/<action>", methods=["POST"])
@login_required
def esxi_vm_action(vm_id, action):
    esxi = get_esxi()
    if not esxi:
        flash("ESXi non joignable", "danger")
        return redirect(url_for("vms"))
    host, session_id = esxi
    try:
        esxi_client.vm_action(host, session_id, vm_id, action)
        flash(f"Action '{action}' envoyée à {vm_id}", "success")
    except Exception as e:
        flash(f"Erreur ESXi : {e}", "danger")
    return redirect(url_for("vms"))


@app.route("/catalog")
@login_required
def catalog():
    tools = load_catalog()
    type_filter = request.args.get("type", "all")
    if type_filter != "all":
        tools = [t for t in tools if t["type"] == type_filter]
    return render_template("catalog.html", tools=tools, type_filter=type_filter)


@app.route("/catalog/<tool_id>")
@login_required
def tool_detail(tool_id):
    tools = load_catalog()
    tool = next((t for t in tools if t["id"] == tool_id), None)
    if not tool:
        flash("Outil introuvable", "warning")
        return redirect(url_for("catalog"))

    px = get_proxmox()
    templates = []
    if px and tool["deployable"]:
        try:
            all_vms = px_client.list_vms(px)
            templates = [v for v in all_vms if "template" in v.get("tags", "").lower()]
        except Exception:
            pass

    return render_template("tool_detail.html", tool=tool, templates=templates)


@app.route("/deploy/<tool_id>", methods=["GET", "POST"])
@login_required
@proxmox_required
def deploy(px, tool_id):
    tools = load_catalog()
    tool = next((t for t in tools if t["id"] == tool_id), None)
    if not tool or not tool.get("deployable"):
        flash("Cet outil n'est pas déployable depuis le portail", "warning")
        return redirect(url_for("catalog"))

    if request.method == "POST":
        name         = request.form.get("name", f"{tool_id}-vm")
        template_id  = request.form.get("template_vmid")
        try:
            ram_gb  = int(request.form.get("ram_gb", tool["ram_gb"]))
            cpu     = int(request.form.get("cpu", tool["cpu"]))
            disk_gb = int(request.form.get("disk_gb", tool["disk_gb"]))
        except (ValueError, TypeError):
            flash("Valeur numérique invalide pour RAM, CPU ou disque.", "danger")
            return redirect(url_for("deploy", tool_id=tool_id))

        if not template_id:
            flash("Sélectionner un template Proxmox", "warning")
        else:
            try:
                new_vmid = px_client.create_vm_from_template(
                    px,
                    template_vmid=int(template_id),
                    name=name,
                    ram_mb=ram_gb * 1024,
                    cpu=cpu,
                    disk_gb=disk_gb,
                    tags=tool["tags"],
                )
                flash(f"VM '{name}' créée (VMID {new_vmid}) — démarrez-la depuis l'onglet VMs", "success")
                return redirect(url_for("vms"))
            except Exception as e:
                flash(f"Erreur déploiement : {e}", "danger")

    try:
        all_vms = px_client.list_vms(px)
        templates = [v for v in all_vms if "template" in v.get("tags", "").lower()]
    except Exception:
        templates = []

    return render_template("deploy.html", tool=tool, templates=templates)


def _check_health():
    """Health check de tous les services : cœur (ES, Grafana, Prometheus,
    AutoBlock, Ollama) + complémentaires optionnels (Blackbox, Kibana, ntopng,
    Arkime, NetBox) quand leur URL est configurée."""
    return nw_health.check_all(
        es_url         = config.NETWATCH_ES_URL,
        grafana_url    = config.NETWATCH_GRAFANA_URL,
        prometheus_url = config.NETWATCH_PROMETHEUS_URL,
        autoblock_url  = config.NETWATCH_AUTOBLOCK_URL,
        ollama_url     = config.OLLAMA_URL,
        extra          = nw_health.extra_checks(
            blackbox_url = config.NETWATCH_BLACKBOX_URL,
            kibana_url   = config.NETWATCH_KIBANA_URL,
            ntopng_url   = config.NETWATCH_NTOPNG_URL,
            arkime_url   = config.NETWATCH_ARKIME_URL,
            netbox_url   = config.NETWATCH_NETBOX_URL,
            netbox_auth  = nw_netbox.auth_header(),
        ),
    )


def _proxmox_snapshot(px, with_vms=False):
    """(node_status, vms) depuis Proxmox, tolérant aux erreurs."""
    if not px:
        return None, []
    try:
        node = px_client.get_node_status(px)
        vms  = px_client.list_vms(px) if with_vms else []
        return node, vms
    except Exception:
        _px_mark_failed()
        return None, []


@app.route("/status")
@login_required
def status():
    px = get_proxmox()
    hours = _range()[1]   # lit request/cookie : à résoudre ICI, pas dans un thread (pas de contexte Flask)
    # Health checks HTTP, Proxmox, sondes actives, cartes de l'extension Pro : indépendants → en parallèle
    (services, global_status), (node_status, _), (probes, probes_err), ext_status = es_client.run_parallel(
        _check_health,
        lambda: _proxmox_snapshot(px),
        lambda: _safe(lambda: nw_probes.get_probes(hours=hours), ([], None)),
        nw_extensions.api().status_extra,
    )

    return render_template(
        "status.html",
        services=services,
        global_status=global_status,
        probes=probes,
        probes_err=probes_err,
        probes_summary=nw_probes.summarize(probes),
        node_status=node_status,
        proxmox_ok=(px is not None),
        proxmox_configured=bool(config.PROXMOX_HOST),
        proxmox_host=config.PROXMOX_HOST,
        proxmox_node=config.PROXMOX_NODE,
        config_es_url=config.NETWATCH_ES_URL,
        config_grafana_url=config.NETWATCH_GRAFANA_URL,
        config_prometheus_url=config.NETWATCH_PROMETHEUS_URL,
        config_autoblock_url=config.NETWATCH_AUTOBLOCK_URL,
        ext=ext_status,
        lic=nw_license.status(),
    )


@app.route("/api/status")
@login_required
def api_status():
    services, global_status = _check_health()
    return jsonify({"global": global_status, "services": services})


@app.route("/report")
@login_required
def report():
    px = get_proxmox()

    # Proxmox, health checks, 3 requêtes ES et audit : tous indépendants →
    # en parallèle (la génération PDF appelle cette page, chaque seconde compte).
    ((node_status, vms), (services, global_status),
     (critical_alerts, _), (all_alerts, _), (alert_stats, _), audit_result) = es_client.run_parallel(
        lambda: _proxmox_snapshot(px, with_vms=True),
        _check_health,
        lambda: es_client.get_recent_alerts(size=20, severity=1),
        lambda: es_client.get_recent_alerts(size=5),
        es_client.get_alert_stats,
        nw_audit.run_audit,
    )

    # Hostgroups + analyse PCAP (points d'écoute)
    report_hostgroups = nw_hostgroups.list_groups()
    pcap_points, pcap_top_conversations = _pcap_overview()

    return render_template(
        "report.html",
        report_hostgroups      = report_hostgroups,
        pcap_points             = pcap_points,
        pcap_top_conversations  = pcap_top_conversations,
        node_status    = node_status,
        vms            = vms,
        proxmox_ok     = (px is not None),
        proxmox_configured = bool(config.PROXMOX_HOST),
        proxmox_host   = config.PROXMOX_HOST,
        proxmox_node   = config.PROXMOX_NODE,
        services       = services,
        global_status  = global_status,
        critical_alerts= critical_alerts,
        recent_alerts  = all_alerts,
        alert_stats    = alert_stats,
        tool_cols      = TOOL_COLS,
        compare_matrix = COMPARE_MATRIX,
        nis2_measures  = NIS2_MATRIX,
        nis2_summary   = {
            "full":    sum(1 for m in NIS2_MATRIX if m["coverage"] == "full"),
            "partial": sum(1 for m in NIS2_MATRIX if m["coverage"] == "partial"),
            "none":    sum(1 for m in NIS2_MATRIX if m["coverage"] == "none"),
        },
        audit          = audit_result,
        generated_at   = datetime.now().strftime("%d/%m/%Y à %H:%M"),
    )


@app.route("/alerts")
@login_required
def alerts():
    engine    = request.args.get("engine",   "")
    severity  = request.args.get("severity", "")
    search    = request.args.get("q",        "").strip()
    hostgroup = request.args.get("hostgroup", "")

    _, hours = _range()
    (alerts_list, error), (stats, _) = es_client.run_parallel(
        lambda: es_client.get_recent_alerts(
            size=100,
            engine=engine   or None,
            severity=_safe_int(severity),
            search=search   or None,
            hours=hours,
        ),
        lambda: es_client.get_alert_stats(days=max(1, hours // 24 or 1), hours=hours),
    )
    if hostgroup:
        alerts_list = nw_hostgroups.filter_items_by_group(alerts_list, hostgroup, ["src_ip", "dest_ip"])

    return render_template(
        "alerts.html",
        alerts=alerts_list,
        error=error,
        stats=stats,
        engine=engine,
        severity=severity,
        search=search,
        hostgroup=hostgroup,
    )


@app.route("/api/alerts")
@login_required
def api_alerts():
    engine    = request.args.get("engine",   "")
    severity  = request.args.get("severity", "")
    search    = request.args.get("q",        "").strip()
    hostgroup = request.args.get("hostgroup", "")
    alerts_list, error = es_client.get_recent_alerts(
        size=50,
        engine=engine or None,
        severity=_safe_int(severity),
        search=search or None,
        hours=_range()[1],
    )
    if error:
        return jsonify({"error": error}), 503
    if hostgroup:
        alerts_list = nw_hostgroups.filter_items_by_group(alerts_list, hostgroup, ["src_ip", "dest_ip"])
    return jsonify(alerts_list)


import time as _time_sse  # noqa: E402 — kept close to usage


@app.route("/api/alerts/stream")
@login_required
def api_alerts_stream():
    """
    Flux temps réel des alertes IDS (Server-Sent Events) — remplace le
    polling 30s de /api/alerts. Respecte les mêmes filtres engine/severity/
    q/hostgroup que la page /alerts. `since` (ISO 8601, fourni par le
    client au moment de l'ouverture du flux) évite de renvoyer en rafale
    les alertes déjà affichées par le rendu initial de la page.
    """
    engine    = request.args.get("engine",   "")
    severity  = request.args.get("severity", "")
    search    = request.args.get("q",        "").strip()
    hostgroup = request.args.get("hostgroup", "")
    since     = request.args.get("since",    "")
    _, hours  = _range()   # lu ici : pas de contexte de requête dans le générateur

    def generate():
        last_ts = since or None
        # Envoi immédiat pour que le navigateur ouvre le flux sans attendre
        # le premier cycle de poll (sinon EventSource paraît "figé" 3s).
        yield "event: ping\ndata: {}\n\n"
        while True:
            try:
                alerts_list, error = es_client.get_recent_alerts(
                    size=20,
                    engine=engine or None,
                    severity=_safe_int(severity),
                    search=search or None,
                    hours=hours,
                )
                if error:
                    yield f"event: stream-error\ndata: {json.dumps({'error': error})}\n\n"
                else:
                    if hostgroup:
                        alerts_list = nw_hostgroups.filter_items_by_group(
                            alerts_list, hostgroup, ["src_ip", "dest_ip"])
                    new_alerts = [a for a in alerts_list if not last_ts or a["timestamp"] > last_ts]
                    if new_alerts:
                        last_ts = max(a["timestamp"] for a in alerts_list if a.get("timestamp"))
                        for a in sorted(new_alerts, key=lambda x: x["timestamp"]):
                            yield f"data: {json.dumps(a)}\n\n"
                    else:
                        yield "event: ping\ndata: {}\n\n"
            except GeneratorExit:
                raise
            except Exception as e:
                yield f"event: stream-error\ndata: {json.dumps({'error': str(e)[:120]})}\n\n"
            _time_sse.sleep(3)

    return Response(generate(), mimetype="text/event-stream", headers={
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no",
    })


@app.route("/alerts/export.csv")
@login_required
def alerts_export_csv():
    """Export des alertes filtrées au format CSV (max 1000 lignes)."""
    engine    = request.args.get("engine",   "")
    severity  = request.args.get("severity", "")
    search    = request.args.get("q",        "").strip()
    hostgroup = request.args.get("hostgroup", "")

    alerts_list, _ = es_client.get_recent_alerts(
        size=1000,
        engine=engine   or None,
        severity=_safe_int(severity),
        search=search   or None,
        hours=_range()[1],
    )
    if hostgroup:
        alerts_list = nw_hostgroups.filter_items_by_group(alerts_list, hostgroup, ["src_ip", "dest_ip"])

    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=[
        "timestamp", "engine", "severity", "signature", "category",
        "src_ip", "dest_ip", "mitre_tactic", "mitre_tech",
    ])
    writer.writeheader()
    sev_label = {1: "critique", 2: "moyen", 3: "faible"}
    for a in alerts_list:
        writer.writerow({
            "timestamp":    a.get("timestamp", ""),
            "engine":       a.get("engine", ""),
            "severity":     sev_label.get(a.get("severity"), a.get("severity", "")),
            "signature":    a.get("signature", ""),
            "category":     a.get("category", ""),
            "src_ip":       a.get("src_ip", ""),
            "dest_ip":      a.get("dest_ip", ""),
            "mitre_tactic": a.get("mitre_tactic") or "",
            "mitre_tech":   a.get("mitre_tech")   or "",
        })

    filename = f"netwatch-alerts-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M')}.csv"
    resp = make_response(out.getvalue())
    resp.headers["Content-Type"]        = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = f"attachment; filename={filename}"
    return resp


@app.route("/api/stats")
@login_required
def api_stats():
    """Agrégats pour le polling live du dashboard (fenêtre = plage globale)."""
    stats, err = es_client.get_alert_stats(hours=_range()[1])
    if err:
        return jsonify({"error": err}), 503
    return jsonify(stats)


@app.route("/api/correlate/<path:community_id>")
@login_required
def api_correlate(community_id):
    """Retourne le flux Zeek + alertes IDS corrélés par Community ID."""
    flow, err1   = es_client.get_zeek_flow_by_community_id(community_id)
    alerts, err2 = es_client.get_alerts_by_community_id(community_id)
    return jsonify({
        "community_id": community_id,
        "zeek_flow":    flow,
        "alerts":       alerts,
        "error":        err1 or err2,
    })


@app.route("/api/alerts/series")
@login_required
def api_alerts_series():
    """Série temporelle des alertes sur la plage globale (sparklines)."""
    _, hours = _range()
    series, error = es_client.get_alert_timeseries(hours=hours, interval=es_client.hist_interval(hours))
    if error:
        return jsonify({"error": error}), 503
    return jsonify(series)


# ============================================================
# Hostgroups — import CSV (format NetScout) + filtre global par IP
# ============================================================

@app.route("/hostgroups")
@login_required
def hostgroups_page():
    return render_template("hostgroups.html", groups=nw_hostgroups.list_groups())


@app.route("/hostgroups/export.csv")
@login_required
def hostgroups_export_csv():
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=["name", "description", "enabled", "host_count", "member_groups", "tags"])
    writer.writeheader()
    for grp in nw_hostgroups.list_groups():
        writer.writerow({**grp, "member_groups": ", ".join(grp.get("member_groups", []))})
    filename = f"netwatch-hostgroups-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M')}.csv"
    resp = make_response(out.getvalue())
    resp.headers["Content-Type"] = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = f"attachment; filename={filename}"
    return resp


@app.route("/api/hostgroups")
@login_required
def api_hostgroups():
    """Liste des groupes importés — alimente le sélecteur global du portail."""
    return jsonify(nw_hostgroups.list_groups())


# ============================================================
# Applications — dictionnaire applicatif SNI (Network Experience Monitoring)
# ============================================================

@app.route("/applications")
@login_required
def applications_page():
    days = _range_days()
    hostgroup = request.args.get("hostgroup", "").strip()
    apps, unmatched, err = nw_app_dictionary.get_app_traffic_stats(days=days, hostgroup=hostgroup or None)
    scores, _ = nw_app_dictionary.get_app_health_scores(days=days, hostgroup=hostgroup or None)
    return render_template("applications.html", apps=apps, unmatched=unmatched, error=err,
                           days=days, hostgroup=hostgroup, scores=scores)


@app.route("/api/applications")
@login_required
def api_applications():
    days = _range_days()
    hostgroup = request.args.get("hostgroup", "").strip()
    apps, unmatched, err = nw_app_dictionary.get_app_traffic_stats(days=days, hostgroup=hostgroup or None)
    if err:
        return jsonify({"error": err}), 503
    return jsonify({"apps": apps, "unmatched": unmatched})


@app.route("/api/applications/health")
@login_required
def api_applications_health():
    days = _range_days()
    hostgroup = request.args.get("hostgroup", "").strip()
    scores, err = nw_app_dictionary.get_app_health_scores(days=days, hostgroup=hostgroup or None)
    if err:
        return jsonify({"error": err}), 503
    return jsonify({"scores": scores})


@app.route("/thresholds")
@login_required
def thresholds_page():
    rules = nw_thresholds.list_rules()
    breaches, _ = nw_thresholds.evaluate()
    breached_rule_ids = {b["rule"]["id"] for b in breaches}
    events, err = nw_thresholds.get_recent_events()
    return render_template("thresholds.html", rules=rules, events=events, error=err,
                           metrics=nw_thresholds.METRICS, breaches=breaches,
                           breached_rule_ids=breached_rule_ids,
                           config_check_seconds=config.THRESHOLD_CHECK_SECONDS)


@app.route("/api/thresholds", methods=["GET", "POST"])
@login_required
def api_thresholds():
    if request.method == "POST":
        data = request.get_json(silent=True) or request.form
        try:
            rule = nw_thresholds.add_rule(
                metric=data.get("metric", ""),
                scope=(data.get("scope") or "global").strip(),
                operator=data.get("operator", "<"),
                value=data.get("value", 0),
                severity=data.get("severity", "warning"),
            )
        except (ValueError, TypeError) as e:
            return jsonify({"error": str(e)}), 400
        return jsonify(rule)
    return jsonify(nw_thresholds.list_rules())


@app.route("/api/thresholds/<rule_id>", methods=["DELETE", "PATCH"])
@login_required
def api_thresholds_rule(rule_id):
    if request.method == "DELETE":
        nw_thresholds.delete_rule(rule_id)
        return jsonify({"deleted": rule_id})
    data = request.get_json(silent=True) or {}
    nw_thresholds.toggle_rule(rule_id, data.get("enabled", True))
    return jsonify({"id": rule_id, "enabled": bool(data.get("enabled", True))})


@app.route("/api/thresholds/events")
@login_required
def api_thresholds_events():
    events, err = nw_thresholds.get_recent_events()
    if err:
        return jsonify({"error": err}), 503
    return jsonify(events)


@app.route("/custom-dashboard")
@login_required
def custom_dashboard_page():
    return render_template("custom_dashboard.html", layout=nw_dashboard_layout.load())


@app.route("/api/dashboard-layout", methods=["GET", "POST"])
@login_required
def api_dashboard_layout():
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        clean = nw_dashboard_layout.save(data.get("layout", []))
        return jsonify({"layout": clean})
    return jsonify({"layout": nw_dashboard_layout.load()})


@app.route("/api/dashboard-layout/reset", methods=["POST"])
@login_required
def api_dashboard_layout_reset():
    return jsonify({"layout": nw_dashboard_layout.reset()})


@app.route("/app-map")
@login_required
def app_map_page():
    return render_template("app_map.html")


@app.route("/api/app-map")
@login_required
def api_app_map():
    days = _range_days()
    hostgroup = request.args.get("hostgroup", "").strip()
    graph, err = nw_app_dictionary.get_app_dependency_map(days=days, hostgroup=hostgroup or None)
    if err:
        return jsonify({"error": err}), 503
    return jsonify(graph)


@app.route("/api/hostgroups/import", methods=["POST"])
@login_required
def api_hostgroups_import():
    file = request.files.get("file")
    if not file or not file.filename:
        return jsonify({"error": "Aucun fichier fourni"}), 400
    try:
        parsed = nw_hostgroups.parse_csv(file.read())
    except Exception as exc:
        return jsonify({"error": f"Erreur de lecture du CSV : {exc}"}), 400
    if not parsed:
        return jsonify({"error": "Aucun groupe valide trouvé dans ce fichier"}), 400
    existing = nw_hostgroups.load()
    existing.update(parsed)
    nw_hostgroups.save(existing)
    flash(f"{len(parsed)} groupe(s) importé(s) depuis {file.filename}.", "success")
    return jsonify({"imported": len(parsed), "groups": sorted(parsed.keys())})


@app.route("/api/hostgroups/import-netbox", methods=["POST"])
@login_required
def api_hostgroups_import_netbox():
    """Préfixes IPAM NetBox → hostgroups (un groupe par préfixe actif)."""
    prefixes, err = nw_netbox.list_prefixes()
    if err:
        return jsonify({"error": err}), 503
    parsed = nw_netbox.prefixes_to_hostgroups(prefixes)
    if not parsed:
        return jsonify({"error": "Aucun préfixe actif dans NetBox"}), 404
    existing = nw_hostgroups.load()
    existing.update(parsed)
    nw_hostgroups.save(existing)
    flash(f"{len(parsed)} groupe(s) importé(s) depuis NetBox.", "success")
    return jsonify({"imported": len(parsed), "groups": sorted(parsed.keys())})


@app.route("/api/hostgroups/<path:name>", methods=["DELETE"])
@login_required
def api_hostgroups_delete(name):
    groups = nw_hostgroups.load()
    if name not in groups:
        return jsonify({"error": "Groupe introuvable"}), 404
    del groups[name]
    nw_hostgroups.save(groups)
    return jsonify({"deleted": name})


@app.route("/api/hostgroups/clear", methods=["POST"])
@login_required
def api_hostgroups_clear():
    nw_hostgroups.save({})
    flash("Tous les hostgroups ont été supprimés.", "success")
    return jsonify({"cleared": True})


@app.route("/zeek")
@login_required
def zeek_logs():
    hostgroup = request.args.get("hostgroup", "")
    certs,  err1 = es_client.get_tls_certs()
    files,  err2 = es_client.get_suspicious_files()
    weirds, err3 = es_client.get_weird_events()
    error = err1 or err2 or err3
    if hostgroup:
        weirds = nw_hostgroups.filter_items_by_group(weirds, hostgroup, ["src_ip", "dst_ip"])
    return render_template("zeek.html",
                           certs=certs,
                           files=files,
                           weirds=weirds,
                           hostgroup=hostgroup,
                           expired_count=sum(1 for c in certs if c["expired"]),
                           selfsig_count=sum(1 for c in certs if c["self_signed"]),
                           suspicious_count=len(files),
                           weird_count=len(weirds),
                           error=error)


@app.route("/geomap")
@login_required
def geomap():
    countries, total_geo, error = es_client.get_geo_data()
    return render_template("geomap.html",
                           countries=countries,
                           total_geo=total_geo,
                           unique_countries=len(countries),
                           error=error)


@app.route("/api/geo")
@login_required
def api_geo():
    countries, total_geo, error = es_client.get_geo_data()
    if error:
        return jsonify({"error": error}), 503
    return jsonify({"countries": countries, "total": total_geo})


@app.route("/incidents")
@login_required
def incidents():
    alerts_list, error = es_client.get_recent_alerts(size=500, hours=_range()[1])
    inc_list = nw_incidents.build_incidents(alerts_list, window_minutes=5)
    return render_template("incidents.html", incidents=inc_list, error=error)


_PCAP_CACHE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "scripts", "security", "pcap-analysis.json")
_PCAP_CACHE = {"mtime": None, "data": {}}


def _pcap_data():
    """scripts/security/pcap-analysis.json, rechargé seulement si le fichier a
    changé (mtime) — il est lu par la home, les dashboards device/hostgroup et
    le rapport."""
    try:
        mtime = os.path.getmtime(_PCAP_CACHE_PATH)
    except OSError:
        return {}
    if mtime != _PCAP_CACHE["mtime"]:
        try:
            with open(_PCAP_CACHE_PATH, encoding="utf-8") as f:
                _PCAP_CACHE["data"] = json.load(f)
        except Exception:
            _PCAP_CACHE["data"] = {}
        _PCAP_CACHE["mtime"] = mtime
    return _PCAP_CACHE["data"]


def _pcap_overview(top=10):
    """(points d'écoute [{name, count}], top conversations tous points confondus)."""
    data = _pcap_data()
    points = [
        {"name": p.get("name"), "count": p.get("conversation_count", len(p.get("conversations", [])))}
        for p in data.get("listening_points", [])
    ]
    convs = [{**c, "listening_point": p.get("name")}
             for p in data.get("listening_points", []) for c in p.get("conversations", [])]
    convs.sort(key=lambda c: c.get("total_bytes", 0), reverse=True)
    return points, convs[:top]


def _pcap_conversations_for(ip=None, ranges=None):
    """
    Conversations de pcap-analysis.json impliquant cette IP (ou dans ces plages
    hostgroup). Lecture du cache, pas de relance d'analyse — évite de coupler
    la page dashboard à tshark.
    """
    data = _pcap_data()
    out = []
    for point in data.get("listening_points", []):
        for c in point.get("conversations", []):
            match = False
            if ip and (c.get("client_ip") == ip or c.get("server_ip") == ip):
                match = True
            elif ranges and (nw_hostgroups.ip_in_ranges(c.get("client_ip"), ranges)
                              or nw_hostgroups.ip_in_ranges(c.get("server_ip"), ranges)):
                match = True
            if match:
                out.append({**c, "listening_point": point.get("name")})
    out.sort(key=lambda c: c.get("total_bytes", 0), reverse=True)
    return out[:20]


def _perf_dashboard(ip=None, ranges=None, talkers_size=10, hours=24):
    """
    Widgets de dashboard réutilisables (device unique ou hostgroup) — même
    jeu de métriques aux deux échelles, esprit Allegro/Keysight : débit,
    santé TCP, ART décomposé Network/Server/App, top talkers, conversations.
    """
    # 3 requêtes ES indépendantes → en parallèle (chacune est déjà cachée 60 s)
    (art, _), (tcp, _), (talkers, _) = es_client.run_parallel(
        lambda: es_client.get_art_stats(ip=ip, hours=hours),
        lambda: es_client.get_tcp_perf(ip=ip, hours=hours),
        lambda: es_client.get_top_talkers(size=talkers_size, ip_ranges=ranges, hours=hours),
    )

    network_ms = tcp.get("avg_rtt_ms")
    app_ms     = art.get("http", {}).get("p50") or art.get("tls", {}).get("p50")
    server_ms  = round(app_ms - network_ms, 1) if (network_ms is not None and app_ms is not None and app_ms >= network_ms) else None

    return {
        "art": art,
        "tcp": tcp,
        "talkers": talkers,
        "response_split": {"network_ms": network_ms, "server_ms": server_ms, "app_ms": app_ms},
        "pcap_conversations": _pcap_conversations_for(ip=ip, ranges=ranges),
    }


@app.route("/ip/<ip>")
@login_required
def ip_detail(ip):
    _, hours = _range()
    (alerts_list, conn_stats, error), dashboard, (netbox_ctx, netbox_err) = es_client.run_parallel(
        lambda: es_client.get_ip_events(ip),
        lambda: _perf_dashboard(ip=ip, hours=hours),
        lambda: _safe(lambda: nw_netbox.lookup_ip(ip), (None, None)),
    )
    return render_template("ip_detail.html", ip=ip,
                           alerts=alerts_list, conn=conn_stats, error=error,
                           dashboard=dashboard, netbox=netbox_ctx, netbox_err=netbox_err)


@app.route("/hostgroups/<path:name>/dashboard")
@login_required
def hostgroup_dashboard(name):
    groups = nw_hostgroups.load()
    if name not in groups:
        flash(f"Hostgroup « {name} » introuvable.", "danger")
        return redirect(url_for("hostgroups_page"))
    ranges = nw_hostgroups.resolve_ranges(name, groups)
    dashboard = _perf_dashboard(ranges=ranges, talkers_size=15, hours=_range()[1])
    return render_template("hostgroup_dashboard.html", group=groups[name], dashboard=dashboard)


@app.route("/compare")
@login_required
def compare():
    return render_template(
        "compare.html",
        tool_cols=TOOL_COLS,
        compare_matrix=COMPARE_MATRIX,
    )


@app.route("/audit")
@login_required
def audit():
    return render_template("audit.html", result=nw_audit.run_audit())


@app.route("/graph")
@login_required
def graph():
    return render_template("graph.html")


_IOC_GRAPH_CACHE: dict = {"data": None, "ts": 0.0}
_IOC_GRAPH_TTL = 300  # 5 minutes


@app.route("/api/ioc-graph")
@login_required
def api_ioc_graph():
    """Exécute ioc-graph.py et retourne le JSON. Cache TTL 5 min. Timeout 30s → fallback cache."""
    global _IOC_GRAPH_CACHE
    netwatch_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cache_path = os.path.join(netwatch_root, "scripts", "security", "ioc-graph-output.json")

    import time as _time_mod
    now = _time_mod.monotonic()

    if _IOC_GRAPH_CACHE["data"] is not None and (now - _IOC_GRAPH_CACHE["ts"]) < _IOC_GRAPH_TTL:
        return jsonify(_IOC_GRAPH_CACHE["data"])

    def _read_cache():
        with open(cache_path, encoding="utf-8") as f:
            return json.load(f)

    try:
        subprocess.run(
            ["python3", "scripts/security/ioc-graph.py",
             "--es-url", config.NETWATCH_ES_URL],
            cwd=netwatch_root,
            capture_output=True,
            timeout=30,
            check=False,
        )
        data = _read_cache()
        _IOC_GRAPH_CACHE = {"data": data, "ts": now}
        return jsonify(data)
    except subprocess.TimeoutExpired:
        try:
            return jsonify(_read_cache())
        except Exception as exc:
            return jsonify({"error": f"Timeout et pas de cache : {exc}"}), 503
    except Exception as exc:
        try:
            return jsonify(_read_cache())
        except Exception:
            return jsonify({"error": str(exc)}), 503


# ---------------------------------------------------------------------------
# IOC Risk Scores
# ---------------------------------------------------------------------------

import time as _time  # noqa: E402 — kept close to usage

_IOC_SCORES_CACHE: dict = {"data": None, "ts": 0.0}
_IOC_SCORES_TTL   = 300  # 5 minutes


@app.route("/api/ioc-scores")
@login_required
def api_ioc_scores():
    """
    Execute ioc-score.py and return the composite risk scores per source IP.
    Results are cached in memory for 5 minutes (TTL file-backed via ioc-scores-cache.json).
    """
    global _IOC_SCORES_CACHE

    netwatch_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cache_file    = os.path.join(netwatch_root, "scripts", "security", "ioc-scores-cache.json")

    now = _time.monotonic()

    # ---- In-memory TTL check ----
    if _IOC_SCORES_CACHE["data"] is not None and (now - _IOC_SCORES_CACHE["ts"]) < _IOC_SCORES_TTL:
        return jsonify(_IOC_SCORES_CACHE["data"])

    # ---- File cache check (survives process restart) ----
    def _load_file_cache():
        try:
            with open(cache_file, encoding="utf-8") as f:
                cached = json.load(f)
            from datetime import datetime as _dt, timezone as _tz
            gen = cached.get("meta", {}).get("generated_at", "")
            if gen:
                age = (_dt.now(_tz.utc) - _dt.fromisoformat(gen)).total_seconds()
                if age < _IOC_SCORES_TTL:
                    return cached
        except Exception:
            pass
        return None

    cached_data = _load_file_cache()
    if cached_data is not None:
        _IOC_SCORES_CACHE = {"data": cached_data, "ts": now}
        return jsonify(cached_data)

    # ---- Run ioc-score.py ----
    script = os.path.join(netwatch_root, "scripts", "security", "ioc-score.py")
    try:
        result = subprocess.run(
            ["python3", script, "--output", cache_file,
             "--es-url", config.NETWATCH_ES_URL],
            cwd=netwatch_root,
            capture_output=True,
            timeout=60,
            check=False,
        )
        if result.returncode != 0:
            log_msg = (result.stderr or b"").decode(errors="replace")
            app.logger.warning("ioc-score.py exited %d: %s", result.returncode, log_msg[:500])

        with open(cache_file, encoding="utf-8") as f:
            data = json.load(f)

        _IOC_SCORES_CACHE = {"data": data, "ts": now}
        return jsonify(data)

    except subprocess.TimeoutExpired:
        app.logger.warning("ioc-score.py timed out after 60s")
        try:
            with open(cache_file, encoding="utf-8") as f:
                data = json.load(f)
            return jsonify(data)
        except Exception as exc:
            return jsonify({"error": f"Timeout — pas de cache : {exc}"}), 503

    except Exception as exc:
        app.logger.warning("ioc-scores error: %s", exc)
        try:
            with open(cache_file, encoding="utf-8") as f:
                data = json.load(f)
            return jsonify(data)
        except Exception:
            return jsonify({"error": str(exc)}), 503


# ---------------------------------------------------------------------------
# Dashboard exécutif RSSI
# ---------------------------------------------------------------------------

@app.route("/exec")
@login_required
def exec_page():
    """Dashboard exécutif RSSI — posture, KPIs, top règles, sparkline."""
    (stats, es_error), (services, _) = es_client.run_parallel(
        es_client.get_exec_stats, _check_health)
    up_count   = sum(1 for s in services if s["status"] == "up")
    uptime_pct = round(up_count / len(services) * 100) if services else 0

    return render_template(
        "exec.html",
        stats        = stats,
        error        = es_error,
        services     = services,
        uptime_pct   = uptime_pct,
        generated_at = datetime.now().strftime("%d/%m/%Y %H:%M"),
    )


@app.route("/api/exec-stats")
@login_required
def api_exec_stats():
    """Données brutes du dashboard exécutif (JSON)."""
    stats, error = es_client.get_exec_stats()
    if error:
        return jsonify({"error": error, **stats}), 200
    return jsonify(stats)


@app.route("/sla")
@login_required
def sla():
    """Page SLA Compliance — gauges, timeline, analyse Business Hours.
    Fenêtre = plage globale en jours (défaut historique 7 j si aucune plage choisie)."""
    days = _range_days(default=7)
    (sla_data, es_error), (probes, probes_err) = es_client.run_parallel(
        lambda: es_client.get_sla_stats(days=days),
        lambda: _safe(lambda: nw_probes.get_probes(hours=days * 24), ([], None)),
    )
    no_data = all(s["buckets_total"] == 0 for s in sla_data.get("slas", []))
    return render_template(
        "sla.html",
        sla_data  = sla_data,
        no_data   = no_data,
        days      = days,
        error     = es_error,
        probes    = probes,
        probes_err = probes_err,
        probes_summary = nw_probes.summarize(probes),
    )


@app.route("/api/sla-stats")
@login_required
def api_sla_stats():
    """SLA compliance data (JSON) — consommé par le refresh auto."""
    days = _range_days(default=7)
    data, error = es_client.get_sla_stats(days=days)
    if error:
        return jsonify({"error": error}), 503
    return jsonify(data)


# ============================================================
# API JSON (pour intégrations futures)
# ============================================================

@app.route("/api/vms")
@login_required
def api_vms():
    vm_list = []
    px = get_proxmox()
    if px:
        try:
            vm_list.extend(px_client.list_vms(px))
        except Exception:
            pass
    esxi = get_esxi()
    if esxi:
        try:
            host, session_id = esxi
            vm_list.extend(esxi_client.list_vms(host, session_id))
        except Exception:
            pass
    if not vm_list and not px and not esxi:
        return jsonify({"error": "Aucun hyperviseur joignable"}), 503
    return jsonify(vm_list)


@app.route("/api/catalog")
@login_required
def api_catalog():
    return jsonify(load_catalog())


# ---------------------------------------------------------------------------
# Topology
# ---------------------------------------------------------------------------

import time as _time_topo  # noqa: E402

_TOPOLOGY_CACHE: dict = {"data": None, "ts": 0.0}
_TOPOLOGY_TTL   = 300  # 5 minutes


@app.route("/topology")
@login_required
def topology():
    """Page carte réseau L2/L3 — graphe D3.js force-directed."""
    return render_template("topology.html")


@app.route("/api/topology")
@login_required
def api_topology():
    """
    Lance topology-discover.py --output /tmp/topology.json.
    Cache fichier 5 min. force_refresh=true invalide le cache.
    Fallback sur static/topology-demo.json si le script est absent.
    """
    global _TOPOLOGY_CACHE

    force_refresh = request.args.get("force_refresh", "").lower() == "true"
    hostgroup     = request.args.get("hostgroup", "")
    cache_path    = "/tmp/topology.json"
    demo_path     = os.path.join(os.path.dirname(__file__), "static", "topology-demo.json")
    netwatch_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def _topo_response(data):
        if hostgroup and isinstance(data, dict) and "devices" in data:
            kept = nw_hostgroups.filter_items_by_group(data.get("devices", []), hostgroup, ["ip"])
            kept_ids = {d.get("id") for d in kept}
            links = [l for l in data.get("links", [])
                     if l.get("source") in kept_ids and l.get("target") in kept_ids]
            stats = {**data.get("stats", {}), "devices": len(kept), "links": len(links)}
            data = {**data, "devices": kept, "links": links, "stats": stats}
        return jsonify(data)

    now = _time_topo.monotonic()

    # ---- In-memory TTL ----
    if (not force_refresh
            and _TOPOLOGY_CACHE["data"] is not None
            and (now - _TOPOLOGY_CACHE["ts"]) < _TOPOLOGY_TTL):
        return _topo_response(_TOPOLOGY_CACHE["data"])

    # ---- File cache check ----
    def _cache_fresh():
        try:
            mtime = os.path.getmtime(cache_path)
            return (now - mtime) < _TOPOLOGY_TTL
        except OSError:
            return False

    def _load_json(path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)

    if not force_refresh and _cache_fresh():
        try:
            data = _load_json(cache_path)
            _TOPOLOGY_CACHE = {"data": data, "ts": now}
            return _topo_response(data)
        except Exception:
            pass

    # ---- Locate topology-discover.py ----
    script_candidates = [
        os.path.join(netwatch_root, "scripts", "topology-discover.py"),
        os.path.join(netwatch_root, "scripts", "security", "topology-discover.py"),
        "/usr/local/bin/topology-discover.py",
    ]
    script = next((s for s in script_candidates if os.path.isfile(s)), None)

    if script is None:
        # Fallback: demo JSON
        try:
            data = _load_json(demo_path)
            _TOPOLOGY_CACHE = {"data": data, "ts": now}
            return _topo_response(data)
        except Exception as exc:
            return jsonify({"error": f"topology-discover.py introuvable et pas de demo : {exc}"}), 503

    # ---- Run the script ----
    cmd = ["python3", script, "--output", cache_path, "--es-url", config.NETWATCH_ES_URL]
    if config.TOPOLOGY_DEMO:
        cmd.append("--demo")
    try:
        result = subprocess.run(
            cmd,
            cwd=netwatch_root,
            capture_output=True,
            timeout=60,
            check=False,
        )
        if result.returncode != 0:
            app.logger.warning(
                "topology-discover.py exited %d: %s",
                result.returncode,
                (result.stderr or b"").decode(errors="replace")[:500],
            )
        data = _load_json(cache_path)
        _TOPOLOGY_CACHE = {"data": data, "ts": now}
        return _topo_response(data)
    except subprocess.TimeoutExpired:
        app.logger.warning("topology-discover.py timed out after 60s")
    except Exception as exc:
        app.logger.warning("topology-discover error: %s", exc)

    # Try stale cache or demo fallback
    try:
        data = _load_json(cache_path)
        _TOPOLOGY_CACHE = {"data": data, "ts": now}
        return _topo_response(data)
    except Exception:
        pass
    try:
        data = _load_json(demo_path)
        _TOPOLOGY_CACHE = {"data": data, "ts": now}
        return _topo_response(data)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 503


@app.route("/api/snmp-interfaces")
@login_required
def api_snmp_interfaces():
    """
    Interroge Prometheus pour les métriques SNMP ifHCIn/OutOctets + ifOperStatus.
    Retourne l'utilisation % par device + interface.
    Fallback si Prometheus absent : {data:[], warning:"Prometheus indisponible"}.
    """
    prom_url = config.NETWATCH_PROMETHEUS_URL.rstrip("/")

    def _prom_query(metric):
        import urllib.request as _req
        import urllib.parse as _parse
        url = f"{prom_url}/api/v1/query?query={_parse.quote(metric)}"
        with _req.urlopen(url, timeout=5) as resp:
            return json.loads(resp.read())

    try:
        # Octets in/out — rate() sur 5min, pas le compteur cumulatif brut
        # (ifHCInOctets/ifHCOutOctets sont des compteurs SNMP toujours croissants)
        r_in  = _prom_query("rate(ifHCInOctets[5m])")
        r_out = _prom_query("rate(ifHCOutOctets[5m])")
        r_op  = _prom_query("ifOperStatus")

        def _parse_vector(result_json):
            out = {}
            for item in result_json.get("data", {}).get("result", []):
                m     = item.get("metric", {})
                key   = (m.get("instance", m.get("agent_host", "")),
                         m.get("ifDescr", m.get("ifIndex", "")))
                value = float(item["value"][1])
                out[key] = value
            return out

        in_map  = _parse_vector(r_in)
        out_map = _parse_vector(r_out)
        op_map  = _parse_vector(r_op)

        # Merge keys
        all_keys = set(in_map) | set(out_map)
        interfaces = []
        for (device, iface) in sorted(all_keys):
            bps_in  = in_map.get((device, iface), 0) * 8
            bps_out = out_map.get((device, iface), 0) * 8
            op_val  = op_map.get((device, iface))
            oper    = "up" if op_val == 1.0 else ("down" if op_val == 2.0 else "unknown")
            # Assume 1G link if speed unknown (Prometheus doesn't always expose it inline)
            link_bps = 1_000_000_000
            util_in  = round(bps_in  / link_bps * 100, 1)
            util_out = round(bps_out / link_bps * 100, 1)
            util     = max(util_in, util_out)
            interfaces.append({
                "device":    device,
                "interface": iface,
                "oper":      oper,
                "util_in":   util_in,
                "util_out":  util_out,
                "utilization": util,
            })

        return jsonify({"data": interfaces})

    except Exception as exc:
        app.logger.warning("snmp-interfaces Prometheus error: %s", exc)
        return jsonify({"data": [], "warning": "Prometheus indisponible"})


# ---------------------------------------------------------------------------
# Flows
# ---------------------------------------------------------------------------

@app.route("/flows")
@login_required
def flows():
    """Page analyse des flux réseau — top talkers, ART, TCP health."""
    return render_template("flows.html")


def _maybe_refresh():
    """?refresh=1 sur une API → vide le cache TTL (bouton « Rafraîchir »)."""
    if request.args.get("refresh"):
        es_client.cache_clear()


@app.route("/api/flows-stats")
@login_required
def api_flows_stats():
    """Top talkers, top ports, timeline sur la plage globale (netflow-* ou zeek-* fallback)."""
    _maybe_refresh()
    data, error = es_client.get_flows_stats(hours=_range()[1])
    if error and not data.get("source"):
        return jsonify({"error": error}), 503
    return jsonify(data)


@app.route("/api/art-stats")
@login_required
def api_art_stats():
    """ART p50/p95/p99 par service HTTP/DNS/TLS."""
    _maybe_refresh()
    data, error = es_client.get_art_stats(hours=_range()[1])
    if error:
        return jsonify({"error": error}), 503
    return jsonify(data)


@app.route("/api/tcp-perf")
@login_required
def api_tcp_perf():
    """Métriques santé TCP : RTT, retransmissions, zero-windows."""
    _maybe_refresh()
    data, error = es_client.get_tcp_perf(hours=_range()[1])
    if error:
        return jsonify({"error": error}), 503
    return jsonify(data)


# ---------------------------------------------------------------------------
# App Classification
# ---------------------------------------------------------------------------

import time as _time_app  # noqa: E402

_APP_FLOWS_CACHE: dict = {"data": None, "ts": 0.0}
_APP_FLOWS_TTL   = 300  # 5 minutes


@app.route("/api/app-flows")
@login_required
def api_app_flows():
    """
    Classification applicative des flux réseau.

    Lit app-flows-today.json si récent (<5 min), sinon exécute app-classifier.py.
    Retourne {top_apps:[{name,category,bytes,flows}], by_category:[{cat,bytes,pct}]}
    """
    global _APP_FLOWS_CACHE

    netwatch_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cache_file    = os.path.join(netwatch_root, "scripts", "automation", "app-flows-today.json")
    classifier    = os.path.join(netwatch_root, "scripts", "automation", "app-classifier.py")

    now = _time_app.monotonic()

    # ── In-memory TTL ──
    if _APP_FLOWS_CACHE["data"] is not None and (now - _APP_FLOWS_CACHE["ts"]) < _APP_FLOWS_TTL:
        return jsonify(_APP_FLOWS_CACHE["data"])

    # ── File cache (TTL 5 min) ──
    def _load_file():
        try:
            with open(cache_file, encoding="utf-8") as f:
                cached = json.load(f)
            from datetime import datetime as _dt, timezone as _tz
            gen = cached.get("generated_at", "")
            if gen:
                age = (_dt.now(_tz.utc) - _dt.fromisoformat(gen)).total_seconds()
                if age < _APP_FLOWS_TTL:
                    return cached
        except Exception:
            pass
        return None

    cached = _load_file()
    if cached is not None:
        _APP_FLOWS_CACHE = {"data": cached, "ts": now}
        return jsonify(cached)

    # ── Run app-classifier.py ──
    try:
        result = subprocess.run(
            [
                "python3", classifier,
                "--output", cache_file,
                "--days", "1",
            ],
            cwd=netwatch_root,
            capture_output=True,
            timeout=60,
            check=False,
        )
        if result.returncode != 0:
            app.logger.warning(
                "app-classifier.py exited %d: %s",
                result.returncode,
                (result.stderr or b"").decode(errors="replace")[:500],
            )

        with open(cache_file, encoding="utf-8") as f:
            data = json.load(f)

        _APP_FLOWS_CACHE = {"data": data, "ts": now}
        return jsonify(data)

    except subprocess.TimeoutExpired:
        app.logger.warning("app-classifier.py timed out after 60s")
        try:
            with open(cache_file, encoding="utf-8") as f:
                data = json.load(f)
            return jsonify(data)
        except Exception as exc:
            return jsonify({"error": f"Timeout — pas de cache : {exc}"}), 503

    except Exception as exc:
        app.logger.warning("api_app_flows error: %s", exc)
        try:
            with open(cache_file, encoding="utf-8") as f:
                data = json.load(f)
            return jsonify(data)
        except Exception:
            return jsonify({"error": str(exc)}), 503


# ============================================================
# VoIP Quality Stats
# ============================================================

import time as _time_voip  # noqa: E402

_VOIP_STATS_CACHE: dict = {"data": None, "ts": 0.0}
_VOIP_STATS_TTL   = 300  # 5 minutes


@app.route("/api/voip-stats")
@login_required
def api_voip_stats():
    """
    Qualité VoIP : MOS E-model G.107 depuis voip.log / sip.log / conn.log UDP.

    Exécute voip-quality.py (avec fallback automatique entre les 3 sources ES)
    et retourne un JSON :
      {avg_mos, calls_total, calls_excellent, calls_good, calls_fair,
       calls_poor, calls_bad, top_bad_calls, generated_at, source}

    Cache en mémoire + fichier JSON (TTL 5 min).
    """
    global _VOIP_STATS_CACHE

    netwatch_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cache_file    = os.path.join(netwatch_root, "scripts", "security", "voip-stats-cache.json")
    script        = os.path.join(netwatch_root, "scripts", "security", "voip-quality.py")

    now = _time_voip.monotonic()

    # ── Cache mémoire ──
    if _VOIP_STATS_CACHE["data"] is not None and (now - _VOIP_STATS_CACHE["ts"]) < _VOIP_STATS_TTL:
        return jsonify(_VOIP_STATS_CACHE["data"])

    # ── Cache fichier ──
    def _load_file():
        try:
            with open(cache_file, encoding="utf-8") as f:
                cached = json.load(f)
            from datetime import datetime as _dt, timezone as _tz
            gen = cached.get("generated_at", "")
            if gen:
                age = (_dt.now(_tz.utc) - _dt.fromisoformat(gen)).total_seconds()
                if age < _VOIP_STATS_TTL:
                    return cached
        except Exception:
            pass
        return None

    cached = _load_file()
    if cached is not None:
        _VOIP_STATS_CACHE = {"data": cached, "ts": now}
        return jsonify(cached)

    # ── Exécution voip-quality.py ──
    try:
        result = subprocess.run(
            ["python3", script, "--output", cache_file, "--days", "1"],
            cwd=netwatch_root,
            capture_output=True,
            timeout=60,
            check=False,
        )
        if result.returncode != 0:
            app.logger.warning(
                "voip-quality.py exited %d: %s",
                result.returncode,
                (result.stderr or b"").decode(errors="replace")[:500],
            )

        with open(cache_file, encoding="utf-8") as f:
            data = json.load(f)

        _VOIP_STATS_CACHE = {"data": data, "ts": now}
        return jsonify(data)

    except subprocess.TimeoutExpired:
        app.logger.warning("voip-quality.py timed out after 60s")
        try:
            with open(cache_file, encoding="utf-8") as f:
                data = json.load(f)
            return jsonify(data)
        except Exception as exc:
            return jsonify({"error": f"Timeout — pas de cache : {exc}"}), 503

    except Exception as exc:
        app.logger.warning("api_voip_stats error: %s", exc)
        try:
            with open(cache_file, encoding="utf-8") as f:
                data = json.load(f)
            return jsonify(data)
        except Exception:
            return jsonify({"error": str(exc)}), 503


# ============================================================
# Analyse PCAP par conversation TCP (façon Allegro Network Multimeter)
# Chaque PCAP = un "point d'écoute" — architecture prête pour de futurs
# points d'écoute réels sur différents flux de transmission.
# ============================================================

import time as _time_pcap  # noqa: E402

_PCAP_ANALYSIS_TTL = 600  # 10 minutes — analyse tshark coûteuse, pas besoin de la relancer souvent
_PCAP_ANALYSIS_CACHE: dict = {"data": None, "ts": 0.0}


@app.route("/pcap-analysis")
@login_required
def pcap_analysis_page():
    return render_template("pcap_analysis.html")


@app.route("/api/pcap-analysis")
@login_required
def api_pcap_analysis():
    """
    Analyse TCP par conversation sur tous les PCAP de pcap/ (ou un fichier
    donné via ?file=). Exécute scripts/security/pcap-tcp-analysis.py
    (nécessite tshark). Cache mémoire + fichier JSON (TTL 10 min).
    """
    global _PCAP_ANALYSIS_CACHE

    force_refresh = request.args.get("force_refresh", "").lower() == "true"
    single_file   = request.args.get("file", "")
    netwatch_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cache_file    = os.path.join(netwatch_root, "scripts", "security", "pcap-analysis.json")
    script        = os.path.join(netwatch_root, "scripts", "security", "pcap-tcp-analysis.py")
    pcap_dir      = os.path.join(netwatch_root, "pcap")

    pcap_path = None
    if single_file:
        # os.path.basename() élimine tout composant de répertoire (y compris un
        # chemin absolu, que os.path.join sinon laisserait remplacer le préfixe
        # netwatch_root/pcap en entier) — puis vérification de confinement en
        # profondeur avec le chemin résolu, avant de le passer à tshark.
        candidate = os.path.realpath(os.path.join(pcap_dir, os.path.basename(single_file)))
        if os.path.commonpath([os.path.realpath(pcap_dir), candidate]) != os.path.realpath(pcap_dir):
            return jsonify({"error": "Nom de fichier PCAP invalide"}), 400
        pcap_path = candidate

    now = _time_pcap.monotonic()

    if (not force_refresh and not single_file
            and _PCAP_ANALYSIS_CACHE["data"] is not None
            and (now - _PCAP_ANALYSIS_CACHE["ts"]) < _PCAP_ANALYSIS_TTL):
        return jsonify(_PCAP_ANALYSIS_CACHE["data"])

    if not os.path.isfile(script):
        return jsonify({"error": "pcap-tcp-analysis.py introuvable"}), 503

    cmd = ["python3", script, "--output", cache_file]
    if pcap_path:
        cmd += ["--pcap", pcap_path]

    try:
        result = subprocess.run(
            cmd,
            cwd=netwatch_root,
            capture_output=True,
            timeout=240,
            check=False,
        )
        if result.returncode != 0:
            app.logger.warning(
                "pcap-tcp-analysis.py exited %d: %s",
                result.returncode,
                (result.stderr or b"").decode(errors="replace")[:500],
            )
            return jsonify({"error": (result.stderr or b"").decode(errors="replace")[:300]}), 503

        with open(cache_file, encoding="utf-8") as f:
            data = json.load(f)
        if not single_file:
            _PCAP_ANALYSIS_CACHE = {"data": data, "ts": now}
        return jsonify(data)

    except subprocess.TimeoutExpired:
        app.logger.warning("pcap-tcp-analysis.py timed out after 240s")
        return jsonify({"error": "Analyse trop longue (> 240s) — réduire --top ou --max-packets"}), 503
    except Exception as exc:
        app.logger.warning("pcap-analysis error: %s", exc)
        return jsonify({"error": str(exc)}), 503


@app.route("/pcap-analysis/export.csv")
@login_required
def pcap_analysis_export_csv():
    netwatch_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cache_file = os.path.join(netwatch_root, "scripts", "security", "pcap-analysis.json")
    out = io.StringIO()
    fieldnames = [
        "listening_point", "client_ip", "client_port", "server_ip", "server_port",
        "duration_s", "total_bytes", "handshake_server_ms", "handshake_client_ms",
        "retrans_pct_c2s", "retrans_pct_s2c", "out_of_order_c2s", "out_of_order_s2c",
        "dscp_c2s", "dscp_s2c", "vlan_id",
    ]
    writer = csv.DictWriter(out, fieldnames=fieldnames)
    writer.writeheader()
    try:
        with open(cache_file, encoding="utf-8") as f:
            data = json.load(f)
        for point in data.get("listening_points", []):
            for c in point.get("conversations", []):
                writer.writerow({
                    "listening_point": point.get("name"),
                    "client_ip": c.get("client_ip"), "client_port": c.get("client_port"),
                    "server_ip": c.get("server_ip"), "server_port": c.get("server_port"),
                    "duration_s": c.get("duration_s"), "total_bytes": c.get("total_bytes"),
                    "handshake_server_ms": c.get("handshake_ms", {}).get("server"),
                    "handshake_client_ms": c.get("handshake_ms", {}).get("client"),
                    "retrans_pct_c2s": c.get("retransmissions_pct", {}).get("c2s"),
                    "retrans_pct_s2c": c.get("retransmissions_pct", {}).get("s2c"),
                    "out_of_order_c2s": c.get("out_of_order", {}).get("c2s"),
                    "out_of_order_s2c": c.get("out_of_order", {}).get("s2c"),
                    "dscp_c2s": c.get("dscp_name", {}).get("c2s"),
                    "dscp_s2c": c.get("dscp_name", {}).get("s2c"),
                    "vlan_id": c.get("vlan_id", {}).get("c2s") or c.get("vlan_id", {}).get("s2c"),
                })
    except Exception:
        pass
    filename = f"netwatch-pcap-analysis-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M')}.csv"
    resp = make_response(out.getvalue())
    resp.headers["Content-Type"] = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = f"attachment; filename={filename}"
    return resp


# ============================================================
# Extension Pro (paquet netwatch_pro) — chargée après toutes les routes
# Community : blueprints, menu, cartes de statut. Absente → édition Community.
# ============================================================

nw_extensions.load(app, login_required=login_required, admin_required=admin_required,
                   pro_required=pro_required, config=config)


# ============================================================
# Erreurs HTTP
# ============================================================

@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(500)
def server_error(e):
    return render_template("500.html"), 500


# ============================================================
# Main
# ============================================================

if __name__ == "__main__":
    import logging as _logging
    if not config.PORTAL_PASSWORD:
        _logging.warning(
            "⚠️  PORTAL_PASSWORD non défini — toute tentative de connexion sera refusée. "
            "Définissez la variable d'environnement PORTAL_PASSWORD pour activer l'accès."
        )
    # Vérification périodique des seuils (/thresholds) — thread daemon, pas de
    # service Docker séparé. Guard WERKZEUG_RUN_MAIN : évite un double thread
    # si jamais FLASK_DEBUG est activé (le reloader Werkzeug relance ce
    # fichier dans un sous-process, "__main__" s'exécute alors deux fois).
    if not config.FLASK_DEBUG or os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        threading.Thread(
            target=nw_thresholds.run_background_loop,
            args=(config.THRESHOLD_CHECK_SECONDS,),
            daemon=True,
        ).start()

    # threaded=True : indispensable depuis l'ajout du flux SSE
    # (/api/alerts/stream) — une connexion longue durée bloquerait sinon
    # tout le reste du portail sur le serveur de dev Werkzeug (mono-thread
    # par défaut).
    app.run(host="0.0.0.0", port=config.PORT, debug=config.FLASK_DEBUG, threaded=True)
