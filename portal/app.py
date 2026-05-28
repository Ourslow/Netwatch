import json
import os
from functools import wraps

from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from proxmoxer.core import ResourceException

import config
from proxmox import client as px_client

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

app = Flask(__name__)
app.secret_key = config.FLASK_SECRET_KEY

# ============================================================
# Helpers
# ============================================================

def load_catalog():
    catalog_path = os.path.join(os.path.dirname(__file__), "catalog", "tools.json")
    with open(catalog_path, encoding="utf-8") as f:
        return json.load(f)


def get_proxmox():
    """Retourne un client Proxmox ou None si non joignable."""
    try:
        return px_client.get_client()
    except Exception:
        return None


def proxmox_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        px = get_proxmox()
        if px is None:
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

# ============================================================
# Routes
# ============================================================

@app.route("/")
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

    return render_template(
        "dashboard.html",
        node_status=node_status,
        vms=vms,
        proxmox_ok=proxmox_ok,
        open_source_count=len(open_source),
        commercial_count=len(commercial),
        proxmox_host=config.PROXMOX_HOST,
        proxmox_node=config.PROXMOX_NODE,
    )


@app.route("/vms")
@proxmox_required
def vms(px):
    try:
        vm_list = px_client.list_vms(px)
    except Exception as e:
        flash(f"Impossible de récupérer les VMs : {e}", "danger")
        vm_list = []
    return render_template("vms.html", vms=vm_list)


@app.route("/vms/<int:vmid>/<action>", methods=["POST"])
@proxmox_required
def vm_action(px, vmid, action):
    try:
        px_client.vm_action(px, vmid, action)
        flash(f"Action '{action}' envoyée à la VM {vmid}", "success")
    except Exception as e:
        flash(f"Erreur : {e}", "danger")
    return redirect(url_for("vms"))


@app.route("/vms/<int:vmid>/delete", methods=["POST"])
@proxmox_required
def vm_delete(px, vmid):
    try:
        px_client.delete_vm(px, vmid)
        flash(f"VM {vmid} supprimée", "success")
    except Exception as e:
        flash(f"Erreur suppression : {e}", "danger")
    return redirect(url_for("vms"))


@app.route("/catalog")
def catalog():
    tools = load_catalog()
    type_filter = request.args.get("type", "all")
    if type_filter != "all":
        tools = [t for t in tools if t["type"] == type_filter]
    return render_template("catalog.html", tools=tools, type_filter=type_filter)


@app.route("/catalog/<tool_id>")
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


@app.route("/compare")
def compare():
    return render_template(
        "compare.html",
        tool_cols=TOOL_COLS,
        compare_matrix=COMPARE_MATRIX,
    )


# ============================================================
# API JSON (pour intégrations futures)
# ============================================================

@app.route("/api/vms")
def api_vms():
    px = get_proxmox()
    if not px:
        return jsonify({"error": "Proxmox non joignable"}), 503
    try:
        return jsonify(px_client.list_vms(px))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/catalog")
def api_catalog():
    return jsonify(load_catalog())


# ============================================================
# Main
# ============================================================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=config.PORT, debug=config.FLASK_DEBUG)
