import hmac
import json
import os
from functools import wraps
from urllib.parse import urlsplit, urlunsplit

from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_login import (LoginManager, UserMixin,
                         login_user, logout_user,
                         login_required, current_user)

import config
from proxmox import client as px_client
from netwatch import health as nw_health
from netwatch import es_client
from netwatch import llm_client

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
        return None          # déploiement ESXi/standalone : pas de tentative (évite un hang de 5s)
    try:
        return px_client.get_client()
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
            next_page = request.args.get("next") or url_for("dashboard")
            return redirect(next_page)
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
@proxmox_required
def vms(px):
    try:
        vm_list = px_client.list_vms(px)
    except Exception as e:
        flash(f"Impossible de récupérer les VMs : {e}", "danger")
        vm_list = []
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
    from datetime import datetime

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


@app.route("/api/alerts/series")
@login_required
def api_alerts_series():
    """Série horaire des alertes (24h) pour les sparklines."""
    series, error = es_client.get_alert_timeseries(hours=24)
    if error:
        return jsonify({"error": error}), 503
    return jsonify(series)


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


@app.route("/nis2")
@login_required
def nis2():
    summary = {
        "full":    sum(1 for m in NIS2_MATRIX if m["coverage"] == "full"),
        "partial": sum(1 for m in NIS2_MATRIX if m["coverage"] == "partial"),
        "none":    sum(1 for m in NIS2_MATRIX if m["coverage"] == "none"),
        "total":   len(NIS2_MATRIX),
    }
    return render_template("nis2.html", measures=NIS2_MATRIX, summary=summary)


# ============================================================
# API JSON (pour intégrations futures)
# ============================================================

@app.route("/api/vms")
@login_required
def api_vms():
    px = get_proxmox()
    if not px:
        return jsonify({"error": "Proxmox non joignable"}), 503
    try:
        return jsonify(px_client.list_vms(px))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/catalog")
@login_required
def api_catalog():
    return jsonify(load_catalog())


# ============================================================
# Main
# ============================================================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=config.PORT, debug=config.FLASK_DEBUG)
