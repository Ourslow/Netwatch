import csv
import glob
import hmac
import io
import json
import os
import subprocess
from datetime import datetime, timezone
from functools import wraps
from urllib.parse import urlsplit, urlunsplit

import yaml

from flask import Flask, make_response, render_template, redirect, url_for, flash, request, jsonify
from flask_login import (LoginManager, UserMixin,
                         login_user, logout_user,
                         login_required, current_user)

import config
from proxmox import client as px_client
from esxi   import client as esxi_client
from netwatch import health as nw_health
from netwatch import es_client
from netwatch import llm_client
from netwatch import audit as nw_audit
from netwatch import incidents as nw_incidents

# ============================================================
# Données de comparaison (matrice feature × outil)
# Valeurs : "full" | "partial" | "none" | str littéral
# ============================================================

TOOL_COLS = [
    {"id": "netwatch",        "name": "NetWatch v2",          "type": "open-source", "logo": "🔭"},
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
             "netwatch": "none", "security-onion": "partial", "wazuh": "none",
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
             "netwatch": "none", "security-onion": "full", "wazuh": "partial",
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
             "netwatch": "none", "security-onion": "partial", "wazuh": "partial",
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
             "netwatch": "none", "security-onion": "none", "wazuh": "partial",
             "netscout": "full", "gigamon": "full", "riverbed": "full"},
        ],
    },
    {
        "category": "Coût & Licence",
        "icon": "bi-currency-euro",
        "rows": [
            {"feature": "Licence",
             "netwatch": "AGPL v3", "security-onion": "GPL v2", "wazuh": "GPL v2",
             "netscout": "Commercial", "gigamon": "Commercial", "riverbed": "Commercial"},
            {"feature": "Coût estimé (annuel)",
             "netwatch": "0 €", "security-onion": "0 €", "wazuh": "0 € / 50 k€+",
             "netscout": "100 k€+", "gigamon": "150 k€+", "riverbed": "80 k€+"},
            {"feature": "Complexité déploiement",
             "netwatch": "Faible", "security-onion": "Moyenne", "wazuh": "Moyenne",
             "netscout": "Élevée", "gigamon": "Élevée", "riverbed": "Élevée"},
        ],
    },
]

# ============================================================
# Matrice NIS2 — mapping mesures techniques NetWatch ↔ article 21.2
# Couverture : "full" | "partial" | "none" (honnête : NetWatch est un outil
# de détection/réponse réseau, pas une suite GRC complète)
# ============================================================

NIS2_MATRIX = [
    {"ref": "Art. 21.2 (a)", "title": "Analyse des risques & politiques de sécurité des SI",
     "coverage": "partial",
     "netwatch": "Visibilité réseau continue (top-talkers, services exposés, GeoIP) et threat intel alimentent l'analyse de risque. NetWatch n'édite pas les politiques elles-mêmes.",
     "components": ["Dashboards", "Threat Intel", "GeoIP"]},
    {"ref": "Art. 21.2 (b)", "title": "Gestion des incidents — détection & réponse",
     "coverage": "full",
     "netwatch": "Cœur de NetWatch : détection multi-moteurs (Snort 3 + Suricata 7) sur le même trafic, corrélation, mapping MITRE ATT&CK, alerting temps réel et réponse automatique (AutoBlock iptables). Détection de beaconing C2 et de DNS tunneling (RITA-lite).",
     "components": ["Snort 3", "Suricata 7", "AutoBlock", "beacon-detect", "MITRE ATT&CK", "Grafana alerting"]},
    {"ref": "Art. 21.2 (c)", "title": "Continuité d'activité & gestion de crise (sauvegarde, PRA)",
     "coverage": "none",
     "netwatch": "Hors périmètre : NetWatch ne gère ni sauvegarde ni plan de reprise. Apporte indirectement la supervision de disponibilité pour détecter une indisponibilité de service.",
     "components": ["Prometheus (disponibilité)"]},
    {"ref": "Art. 21.2 (d)", "title": "Sécurité de la chaîne d'approvisionnement",
     "coverage": "partial",
     "netwatch": "Détecte les communications sortantes suspectes (C2, domaines DGA), fingerprinting JA3/HASSH des clients/serveurs, threat intel sur IoC. Ne couvre pas l'évaluation contractuelle des fournisseurs.",
     "components": ["JA3/HASSH", "Threat Intel", "beacon-detect"]},
    {"ref": "Art. 21.2 (e)", "title": "Sécurité acquisition/dév./maintenance & vulnérabilités",
     "coverage": "partial",
     "netwatch": "Détecte les tentatives d'exploitation via signatures IDS (Snort community + Suricata ET Open). Ne réalise pas de scan de vulnérabilités ni de gestion du cycle de développement.",
     "components": ["Snort 3", "Suricata 7 (ET Open)"]},
    {"ref": "Art. 21.2 (f)", "title": "Évaluation de l'efficacité des mesures",
     "coverage": "partial",
     "netwatch": "Dashboards, métriques et rapport exécutif (avec résumé IA) donnent une mesure objective de l'activité de détection et de la posture de sécurité. Pas d'audit de conformité formalisé.",
     "components": ["Dashboards", "Rapport exécutif", "Assistant IA"]},
    {"ref": "Art. 21.2 (g)", "title": "Cyber-hygiène & formation",
     "coverage": "partial",
     "netwatch": "Met en évidence les mauvaises pratiques (identifiants en clair sur HTTP, TLS obsolète) — support concret de sensibilisation. Ne dispense pas la formation elle-même.",
     "components": ["Règles NETWATCH custom"]},
    {"ref": "Art. 21.2 (h)", "title": "Cryptographie & chiffrement",
     "coverage": "partial",
     "netwatch": "Détecte le chiffrement faible/obsolète (TLSv1.0, certificats expirés) et l'absence de chiffrement (mots de passe en clair). N'impose pas de politique cryptographique.",
     "components": ["Zeek SSL/TLS", "Règles TLS custom"]},
    {"ref": "Art. 21.2 (i)", "title": "Contrôle d'accès & gestion des actifs",
     "coverage": "partial",
     "netwatch": "Inventaire passif des actifs et services vus sur le réseau (known-hosts, known-services). Le portail applique lui-même un contrôle d'accès (auth, cookies durcis). Pas de gestion IAM.",
     "components": ["Zeek known-hosts/services", "Portail (Flask-Login)"]},
    {"ref": "Art. 21.2 (j)", "title": "MFA & communications sécurisées",
     "coverage": "none",
     "netwatch": "Hors périmètre côté SI surveillé. À noter : l'assistant IA et toute la stack sont 100 % on-prem — souveraineté des données, aucune donnée ne sort du SI.",
     "components": ["—"]},
]

# NIST Cybersecurity Framework 2.0 — par fonction (NetWatch = NDR → fort sur Detect/Respond)
NIST_CSF_MATRIX = [
    {"ref": "GV — Govern", "title": "Gouvernance de la cybersécurité",
     "coverage": "partial",
     "netwatch": "Dashboards, métriques et rapport exécutif alimentent le pilotage et la prise de décision. NetWatch n'édite pas la stratégie ni les politiques.",
     "components": ["Dashboards", "Rapport exécutif"]},
    {"ref": "ID — Identify", "title": "Connaissance du contexte et des actifs",
     "coverage": "partial",
     "netwatch": "Inventaire passif des actifs et services observés sur le réseau (known-hosts/services), threat intel sur IoC. Pas de gestion d'inventaire formelle.",
     "components": ["Zeek known-hosts/services", "Threat Intel", "GeoIP"]},
    {"ref": "PR — Protect", "title": "Mesures de protection",
     "coverage": "partial",
     "netwatch": "Détecte les faiblesses (crypto obsolète, identifiants en clair) ; le portail applique un contrôle d'accès durci. NetWatch ne protège pas activement (ni pare-feu, ni IAM).",
     "components": ["Règles TLS custom", "Portail (Flask-Login)"]},
    {"ref": "DE — Detect", "title": "Détection des événements et anomalies",
     "coverage": "full",
     "netwatch": "Cœur de NetWatch : surveillance continue multi-moteurs (Snort + Suricata), détection d'anomalies (beaconing C2, DNS tunneling), corrélation et mapping MITRE ATT&CK.",
     "components": ["Snort 3", "Suricata 7", "beacon-detect", "MITRE ATT&CK", "Zeek"]},
    {"ref": "RS — Respond", "title": "Réponse aux incidents",
     "coverage": "full",
     "netwatch": "Alerting temps réel, blocage automatique des IP malveillantes (AutoBlock), et assistant IA qui explique chaque alerte pour accélérer l'analyse et la décision.",
     "components": ["Grafana alerting", "AutoBlock", "Assistant IA"]},
    {"ref": "RC — Recover", "title": "Reprise après incident",
     "coverage": "none",
     "netwatch": "Hors périmètre : NetWatch ne gère pas la restauration ni la reprise d'activité.",
     "components": ["—"]},
]

# ANSSI — Guide d'hygiène informatique + recommandations détection (PA-022)
ANSSI_MATRIX = [
    {"ref": "Hygiène · journalisation", "title": "Journaliser, analyser et corréler les événements",
     "coverage": "full",
     "netwatch": "Logs JSON normalisés des 3 moteurs centralisés dans Elasticsearch, corrélation multi-moteurs et tableaux de bord Grafana — répond directement à l'exigence de journalisation/analyse.",
     "components": ["Zeek", "Filebeat", "Elasticsearch", "Grafana"]},
    {"ref": "PA-022 · détection", "title": "Supervision de sécurité & détection des comportements anormaux",
     "coverage": "full",
     "netwatch": "Détection par signatures (Snort/Suricata) et comportementale (beaconing, DNS tunneling, scans). Couvre la logique d'une sonde de détection réseau recommandée par l'ANSSI.",
     "components": ["Snort 3", "Suricata 7", "beacon-detect"]},
    {"ref": "Hygiène · cartographie", "title": "Connaître le SI et maîtriser les flux réseau",
     "coverage": "partial",
     "netwatch": "Cartographie passive des flux, services et destinations externes (GeoIP, top-talkers). N'impose pas le cloisonnement.",
     "components": ["Zeek", "GeoIP", "Top-talkers"]},
    {"ref": "Hygiène · incidents", "title": "Gérer les incidents de sécurité",
     "coverage": "partial",
     "netwatch": "Détection, alerting et réponse automatique (AutoBlock) + aide à l'analyse par l'IA. Ne formalise pas le processus complet de gestion d'incident.",
     "components": ["AutoBlock", "Assistant IA"]},
    {"ref": "Hygiène · chiffrement", "title": "Chiffrer les flux sensibles",
     "coverage": "partial",
     "netwatch": "Détecte les protocoles obsolètes (TLSv1.0) et les flux en clair (mots de passe HTTP). N'impose pas le chiffrement.",
     "components": ["Zeek SSL/TLS", "Règles custom"]},
    {"ref": "Hygiène · sauvegarde", "title": "Sauvegarder et assurer la continuité",
     "coverage": "none",
     "netwatch": "Hors périmètre.",
     "components": ["—"]},
    {"ref": "Hygiène · authentification", "title": "Authentification forte (MFA)",
     "coverage": "none",
     "netwatch": "Hors périmètre côté SI surveillé.",
     "components": ["—"]},
]

# ISO/IEC 27001 / 27002:2022 — contrôles de l'Annexe A pertinents
ISO27001_MATRIX = [
    {"ref": "A.5.7", "title": "Renseignement sur les menaces (threat intelligence)",
     "coverage": "full",
     "netwatch": "Zeek Intel Framework (watchlists IP/domaines) + signatures ET Open : intègre et exploite le renseignement sur les menaces.",
     "components": ["Zeek Intel", "Suricata ET Open"]},
    {"ref": "A.8.15", "title": "Journalisation (logging)",
     "coverage": "full",
     "netwatch": "Journalisation centralisée et structurée de l'activité réseau et des détections dans Elasticsearch.",
     "components": ["Filebeat", "Elasticsearch"]},
    {"ref": "A.8.16", "title": "Activités de surveillance (monitoring)",
     "coverage": "full",
     "netwatch": "Surveillance continue du trafic et des anomalies par les 3 moteurs, dashboards temps réel et alerting.",
     "components": ["Snort 3", "Suricata 7", "Grafana"]},
    {"ref": "A.8.20", "title": "Sécurité des réseaux",
     "coverage": "partial",
     "netwatch": "Visibilité et détection sur les réseaux ; ne réalise pas la segmentation ni le filtrage actif (hors blocage AutoBlock).",
     "components": ["Zeek", "AutoBlock"]},
    {"ref": "A.5.25", "title": "Évaluation et décision sur les événements de sécurité",
     "coverage": "partial",
     "netwatch": "Corrélation, scoring de sévérité et triage des alertes ; explication IA pour aider à la décision.",
     "components": ["Corrélation", "Assistant IA"]},
    {"ref": "A.5.26", "title": "Réponse aux incidents de sécurité",
     "coverage": "partial",
     "netwatch": "Alerting et réponse automatisée (AutoBlock). Ne couvre pas l'ensemble du cycle de gestion d'incident.",
     "components": ["Grafana alerting", "AutoBlock"]},
    {"ref": "A.8.24", "title": "Utilisation de la cryptographie",
     "coverage": "partial",
     "netwatch": "Détecte le chiffrement faible/obsolète et les certificats expirés. N'applique pas de politique cryptographique.",
     "components": ["Zeek SSL/TLS"]},
    {"ref": "A.5.9", "title": "Inventaire des actifs",
     "coverage": "partial",
     "netwatch": "Inventaire passif des hôtes et services vus sur le réseau. Pas de CMDB.",
     "components": ["Zeek known-hosts/services"]},
]

# Référentiels exposés sur la page /compliance
REFERENTIALS = [
    {"id": "nis2",  "name": "NIS2",
     "label": "Directive UE 2022/2555 — art. 21.2",
     "intro": "Les 10 mesures techniques et organisationnelles minimales imposées aux entités essentielles et importantes.",
     "measures": NIS2_MATRIX},
    {"id": "nist",  "name": "NIST CSF 2.0",
     "label": "Cadre international — 6 fonctions",
     "intro": "NetWatch est une solution NDR : il couvre pleinement les fonctions Detect et Respond, cœur de la lutte contre les incidents.",
     "measures": NIST_CSF_MATRIX},
    {"id": "anssi", "name": "ANSSI",
     "label": "Guide d'hygiène + PA-022 (détection)",
     "intro": "Référentiel français de référence : NetWatch répond directement aux exigences de journalisation, supervision et détection.",
     "measures": ANSSI_MATRIX},
    {"id": "iso",   "name": "ISO/IEC 27001 · 27002:2022",
     "label": "Contrôles de l'Annexe A",
     "intro": "Contrôles de sécurité que les organisations certifient : NetWatch outille directement la journalisation, la surveillance et le renseignement sur les menaces.",
     "measures": ISO27001_MATRIX},
]

app = Flask(__name__)
app.secret_key = config.FLASK_SECRET_KEY

# Durcissement des cookies de session
#  - HttpOnly : inaccessible au JS (anti-XSS vol de session)
#  - SameSite=Lax : le cookie n'est pas envoyé sur les POST cross-site (anti-CSRF)
#  - Secure : cookie envoyé uniquement en HTTPS (activer en prod via SESSION_COOKIE_SECURE)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=config.SESSION_COOKIE_SECURE,
)

# ============================================================
# Authentification (Flask-Login)
# ============================================================

login_manager = LoginManager(app)
login_manager.login_view        = "login"
login_manager.login_message     = "Connexion requise pour accéder au portail."
login_manager.login_message_category = "warning"


class _User(UserMixin):
    """Utilisateur unique — identité portée par la session."""
    def __init__(self):
        self.id = "admin"


_SINGLE_USER = _User()


@login_manager.user_loader
def _load_user(user_id):
    return _SINGLE_USER if user_id == "admin" else None


def _check_credentials(username: str, password: str) -> bool:
    """Comparaison constant-time pour éviter les timing attacks."""
    if not config.PORTAL_PASSWORD:
        return False
    ok_u = hmac.compare_digest(username.encode(), config.PORTAL_USERNAME.encode())
    ok_p = hmac.compare_digest(password.encode(), config.PORTAL_PASSWORD.encode())
    return ok_u and ok_p


# ============================================================
# Helpers
# ============================================================

def load_catalog():
    catalog_path = os.path.join(os.path.dirname(__file__), "catalog", "tools.json")
    with open(catalog_path, encoding="utf-8") as f:
        return json.load(f)


def get_proxmox():
    """Retourne un client Proxmox, ou None si non configuré / non joignable."""
    if not config.PROXMOX_HOST:
        return None
    try:
        return px_client.get_client()
    except Exception:
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


def browser_url(url):
    """Réécrit localhost/127.0.0.1 vers l'hôte depuis lequel l'utilisateur navigue.
    Les URLs de config (health checks) ciblent localhost = la VM côté serveur ;
    pour qu'un lien soit cliquable depuis un poste distant, on substitue le host
    de la requête courante (ex. 172.31.20.90). Le port est conservé."""
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

# ============================================================
# Routes — Auth
# ============================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if _check_credentials(username, password):
            login_user(_SINGLE_USER, remember=bool(request.form.get("remember")))
            next_page = request.args.get("next")
            if next_page:
                from urllib.parse import urlparse, urljoin
                parsed = urlparse(urljoin(request.host_url, next_page))
                host   = urlparse(request.host_url)
                if parsed.scheme not in ("http", "https") or parsed.netloc != host.netloc:
                    next_page = None
            return redirect(next_page or url_for("dashboard"))
        flash("Identifiants incorrects.", "danger")
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Déconnecté.", "info")
    return redirect(url_for("login"))


# ============================================================
# Routes
# ============================================================

@app.route("/")
@login_required
def dashboard():
    px = get_proxmox()
    node_status = None
    vms = []
    proxmox_ok = False

    if px:
        try:
            node_status = px_client.get_node_status(px)
            vms = px_client.list_vms(px)
            proxmox_ok = True
        except Exception as e:
            flash(f"Erreur Proxmox : {e}", "warning")

    catalog = load_catalog()
    open_source = [t for t in catalog if t["type"] == "open-source"]
    commercial  = [t for t in catalog if t["type"] == "commercial"]

    # Widget alertes IDS — dernières 5 alertes + stats
    recent_alerts, _ = es_client.get_recent_alerts(size=5)
    alert_stats, _   = es_client.get_alert_stats()

    return render_template(
        "dashboard.html",
        node_status=node_status,
        vms=vms,
        proxmox_ok=proxmox_ok,
        proxmox_configured=bool(config.PROXMOX_HOST),
        open_source_count=len(open_source),
        commercial_count=len(commercial),
        proxmox_host=config.PROXMOX_HOST,
        proxmox_node=config.PROXMOX_NODE,
        recent_alerts=recent_alerts,
        alert_stats=alert_stats,
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
        ram_gb       = int(request.form.get("ram_gb", tool["ram_gb"]))
        cpu          = int(request.form.get("cpu", tool["cpu"]))
        disk_gb      = int(request.form.get("disk_gb", tool["disk_gb"]))

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


@app.route("/status")
@login_required
def status():
    services, global_status = nw_health.check_all(
        es_url         = config.NETWATCH_ES_URL,
        grafana_url    = config.NETWATCH_GRAFANA_URL,
        prometheus_url = config.NETWATCH_PROMETHEUS_URL,
        autoblock_url  = config.NETWATCH_AUTOBLOCK_URL,
        ollama_url     = config.OLLAMA_URL,
    )
    # Infos Proxmox si dispo
    px = get_proxmox()
    node_status = None
    if px:
        try:
            node_status = px_client.get_node_status(px)
        except Exception:
            pass

    return render_template(
        "status.html",
        services=services,
        global_status=global_status,
        node_status=node_status,
        proxmox_ok=(px is not None),
        proxmox_configured=bool(config.PROXMOX_HOST),
        proxmox_host=config.PROXMOX_HOST,
        proxmox_node=config.PROXMOX_NODE,
        config_es_url=config.NETWATCH_ES_URL,
        config_grafana_url=config.NETWATCH_GRAFANA_URL,
        config_prometheus_url=config.NETWATCH_PROMETHEUS_URL,
        config_autoblock_url=config.NETWATCH_AUTOBLOCK_URL,
    )


@app.route("/api/status")
@login_required
def api_status():
    services, global_status = nw_health.check_all(
        es_url         = config.NETWATCH_ES_URL,
        grafana_url    = config.NETWATCH_GRAFANA_URL,
        prometheus_url = config.NETWATCH_PROMETHEUS_URL,
        autoblock_url  = config.NETWATCH_AUTOBLOCK_URL,
        ollama_url     = config.OLLAMA_URL,
    )
    return jsonify({"global": global_status, "services": services})


@app.route("/report")
@login_required
def report():


    # Proxmox
    px = get_proxmox()
    node_status = None
    vms = []
    if px:
        try:
            node_status = px_client.get_node_status(px)
            vms = px_client.list_vms(px)
        except Exception:
            pass

    # Health services
    services, global_status = nw_health.check_all(
        es_url         = config.NETWATCH_ES_URL,
        grafana_url    = config.NETWATCH_GRAFANA_URL,
        prometheus_url = config.NETWATCH_PROMETHEUS_URL,
        autoblock_url  = config.NETWATCH_AUTOBLOCK_URL,
        ollama_url     = config.OLLAMA_URL,
    )

    # Alertes IDS
    critical_alerts, _ = es_client.get_recent_alerts(size=20, severity=1)
    all_alerts,      _ = es_client.get_recent_alerts(size=5)
    alert_stats,     _ = es_client.get_alert_stats()

    return render_template(
        "report.html",
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
        audit          = nw_audit.run_audit(),
        generated_at   = datetime.now().strftime("%d/%m/%Y à %H:%M"),
    )


@app.route("/alerts")
@login_required
def alerts():
    engine   = request.args.get("engine",   "")
    severity = request.args.get("severity", "")
    search   = request.args.get("q",        "").strip()

    alerts_list, error = es_client.get_recent_alerts(
        size=100,
        engine=engine   or None,
        severity=int(severity) if severity else None,
        search=search   or None,
    )
    stats, _ = es_client.get_alert_stats()

    return render_template(
        "alerts.html",
        alerts=alerts_list,
        error=error,
        stats=stats,
        engine=engine,
        severity=severity,
        search=search,
    )


@app.route("/api/alerts")
@login_required
def api_alerts():
    engine   = request.args.get("engine",   "")
    severity = request.args.get("severity", "")
    search   = request.args.get("q",        "").strip()
    alerts_list, error = es_client.get_recent_alerts(
        size=50,
        engine=engine or None,
        severity=int(severity) if severity else None,
        search=search or None,
    )
    if error:
        return jsonify({"error": error}), 503
    return jsonify(alerts_list)


@app.route("/alerts/export.csv")
@login_required
def alerts_export_csv():
    """Export des alertes filtrées au format CSV (max 1000 lignes)."""
    engine   = request.args.get("engine",   "")
    severity = request.args.get("severity", "")
    search   = request.args.get("q",        "").strip()

    alerts_list, _ = es_client.get_recent_alerts(
        size=1000,
        engine=engine   or None,
        severity=int(severity) if severity else None,
        search=search   or None,
    )

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
    """Agrégats pour le polling live du dashboard."""
    stats, err = es_client.get_alert_stats()
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
    """Série horaire des alertes (24h) pour les sparklines."""
    series, error = es_client.get_alert_timeseries(hours=24)
    if error:
        return jsonify({"error": error}), 503
    return jsonify(series)


@app.route("/zeek")
@login_required
def zeek_logs():
    certs,  err1 = es_client.get_tls_certs()
    files,  err2 = es_client.get_suspicious_files()
    weirds, err3 = es_client.get_weird_events()
    error = err1 or err2 or err3
    return render_template("zeek.html",
                           certs=certs,
                           files=files,
                           weirds=weirds,
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
    alerts_list, error = es_client.get_recent_alerts(size=500)
    inc_list = nw_incidents.build_incidents(alerts_list, window_minutes=5)
    return render_template("incidents.html", incidents=inc_list, error=error)


@app.route("/ip/<ip>")
@login_required
def ip_detail(ip):
    alerts_list, conn_stats, error = es_client.get_ip_events(ip)
    return render_template("ip_detail.html", ip=ip,
                           alerts=alerts_list, conn=conn_stats, error=error)


@app.route("/api/explain", methods=["POST"])
@login_required
def api_explain():
    """Explique une alerte IDS en langage naturel via l'assistant LLM local (Ollama)."""
    alert = request.get_json(silent=True) or {}
    if not alert.get("signature"):
        return jsonify({"error": "Alerte invalide"}), 400

    explanation, error = llm_client.explain_alert(alert)
    if error:
        return jsonify({"error": error}), 503
    return jsonify({"explanation": explanation})


@app.route("/api/summary")
@login_required
def api_summary():
    """Résumé exécutif IA des alertes récentes (utilisé sur /report)."""
    alerts_list, es_error = es_client.get_recent_alerts(size=30)
    if es_error:
        return jsonify({"error": es_error}), 503

    summary, llm_error = llm_client.summarize_alerts(alerts_list)
    if llm_error:
        return jsonify({"error": llm_error}), 503
    return jsonify({"summary": summary})


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


@app.route("/compliance")
@login_required
def compliance():
    def _summary(measures):
        return {
            "full":    sum(1 for m in measures if m["coverage"] == "full"),
            "partial": sum(1 for m in measures if m["coverage"] == "partial"),
            "none":    sum(1 for m in measures if m["coverage"] == "none"),
            "total":   len(measures),
        }
    referentials = [{**r, "summary": _summary(r["measures"])} for r in REFERENTIALS]
    return render_template("compliance.html", referentials=referentials)


@app.route("/graph")
@login_required
def graph():
    return render_template("graph.html")


@app.route("/api/ioc-graph")
@login_required
def api_ioc_graph():
    """Exécute ioc-graph.py et retourne le JSON. Timeout 30s → fallback cache."""
    netwatch_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cache_path = os.path.join(netwatch_root, "scripts", "security", "ioc-graph-output.json")

    def _read_cache():
        with open(cache_path, encoding="utf-8") as f:
            return json.load(f)

    try:
        subprocess.run(
            ["python3", "scripts/security/ioc-graph.py"],
            cwd=netwatch_root,
            capture_output=True,
            timeout=30,
            check=False,
        )
        return jsonify(_read_cache())
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
# IOC Risk Scores  (T_014)
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
            ["python3", script, "--output", cache_file],
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
# Dashboard exécutif RSSI  (T_013)
# ---------------------------------------------------------------------------

@app.route("/exec")
@login_required
def exec_page():
    """Dashboard exécutif RSSI — posture, KPIs, top règles, sparkline."""
    stats, es_error = es_client.get_exec_stats()

    services, _ = nw_health.check_all(
        es_url         = config.NETWATCH_ES_URL,
        grafana_url    = config.NETWATCH_GRAFANA_URL,
        prometheus_url = config.NETWATCH_PROMETHEUS_URL,
        autoblock_url  = config.NETWATCH_AUTOBLOCK_URL,
        ollama_url     = config.OLLAMA_URL,
    )
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
    """Page SLA Compliance — gauges, timeline 7j, analyse Business Hours."""
    days = int(request.args.get("days", 7))
    days = max(1, min(days, 30))
    sla_data, es_error = es_client.get_sla_stats(days=days)
    no_data = all(s["buckets_total"] == 0 for s in sla_data.get("slas", []))
    return render_template(
        "sla.html",
        sla_data  = sla_data,
        no_data   = no_data,
        days      = days,
        error     = es_error,
    )


@app.route("/api/sla-stats")
@login_required
def api_sla_stats():
    """SLA compliance data (JSON) — consommé par le refresh auto."""
    days = int(request.args.get("days", 7))
    days = max(1, min(days, 30))
    data, error = es_client.get_sla_stats(days=days)
    if error:
        return jsonify({"error": error}), 503
    return jsonify(data)


@app.route("/agents")
@login_required
def agents_page():
    """Monitoring des agents IA — lit les status.yml depuis agents-deck."""
    _base = os.path.join(os.path.dirname(__file__), "..", "agents-deck")
    state_file = os.path.join(_base, "team-lead", "state.yml")

    # Lecture state.yml team-lead
    team_state = {}
    try:
        with open(state_file, encoding="utf-8") as f:
            team_state = yaml.safe_load(f) or {}
    except Exception:
        pass

    # Lecture des 4 agents
    agents_list = []
    for agent_id in ("infra", "security", "automation", "frontend"):
        status_path = os.path.join(_base, "agents", agent_id, "status.yml")
        info = {
            "id": agent_id,
            "agent": agent_id.capitalize() + "-agent",
            "state": "standby",
            "current_ticket": None,
            "last_activity": None,
            "error": None,
        }
        try:
            with open(status_path, encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            info["agent"]          = data.get("agent",          info["agent"])
            info["state"]          = data.get("state",          "standby")
            info["current_ticket"] = data.get("current_ticket") or data.get("last_ticket")
            info["last_activity"]  = data.get("last_activity")
        except FileNotFoundError:
            info["error"] = f"status.yml introuvable : {status_path}"
        except Exception as exc:
            info["error"] = str(exc)
        agents_list.append(info)

    return render_template(
        "agents.html",
        agents=agents_list,
        team_state=team_state,
        last_update=datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M:%S UTC"),
    )


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
# Topology — T_023
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
    cache_path    = "/tmp/topology.json"
    demo_path     = os.path.join(os.path.dirname(__file__), "static", "topology-demo.json")
    netwatch_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    now = _time_topo.monotonic()

    # ---- In-memory TTL ----
    if (not force_refresh
            and _TOPOLOGY_CACHE["data"] is not None
            and (now - _TOPOLOGY_CACHE["ts"]) < _TOPOLOGY_TTL):
        return jsonify(_TOPOLOGY_CACHE["data"])

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
            return jsonify(data)
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
            return jsonify(data)
        except Exception as exc:
            return jsonify({"error": f"topology-discover.py introuvable et pas de demo : {exc}"}), 503

    # ---- Run the script ----
    try:
        result = subprocess.run(
            ["python3", script, "--output", cache_path],
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
        return jsonify(data)
    except subprocess.TimeoutExpired:
        app.logger.warning("topology-discover.py timed out after 60s")
    except Exception as exc:
        app.logger.warning("topology-discover error: %s", exc)

    # Try stale cache or demo fallback
    try:
        data = _load_json(cache_path)
        _TOPOLOGY_CACHE = {"data": data, "ts": now}
        return jsonify(data)
    except Exception:
        pass
    try:
        data = _load_json(demo_path)
        _TOPOLOGY_CACHE = {"data": data, "ts": now}
        return jsonify(data)
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
        # Octets in/out
        r_in  = _prom_query("ifHCInOctets")
        r_out = _prom_query("ifHCOutOctets")
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
# Flows — T_019
# ---------------------------------------------------------------------------

@app.route("/flows")
@login_required
def flows():
    """Page analyse des flux réseau — top talkers, ART, TCP health."""
    return render_template("flows.html")


@app.route("/api/flows-stats")
@login_required
def api_flows_stats():
    """Top talkers, top ports, timeline 24h (netflow-* ou zeek-* fallback)."""
    data, error = es_client.get_flows_stats()
    if error and not data.get("source"):
        return jsonify({"error": error}), 503
    return jsonify(data)


@app.route("/api/art-stats")
@login_required
def api_art_stats():
    """ART p50/p95/p99 par service HTTP/DNS/TLS."""
    data, error = es_client.get_art_stats()
    if error:
        return jsonify({"error": error}), 503
    return jsonify(data)


@app.route("/api/tcp-perf")
@login_required
def api_tcp_perf():
    """Métriques santé TCP : RTT, retransmissions, zero-windows."""
    data, error = es_client.get_tcp_perf()
    if error:
        return jsonify({"error": error}), 503
    return jsonify(data)


# ---------------------------------------------------------------------------
# App Classification — T_024
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
    app.run(host="0.0.0.0", port=config.PORT, debug=config.FLASK_DEBUG)
