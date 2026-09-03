"""
Disposition du tableau de bord personnalisable (/custom-dashboard) —
widgets réordonnables par glisser-déposer, ajout/suppression, taille par
widget. Portail mono-utilisateur (une seule connexion admin) : une seule
disposition partagée, pas de personnalisation par compte — même limite
que hostgroups.json/thresholds.json.
"""

import json
import os

DATA_DIR    = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
LAYOUT_PATH = os.path.join(DATA_DIR, "dashboard_layout.json")

# Catalogue des widgets disponibles — la clé "type" doit correspondre à une
# entrée de WIDGET_CATALOG côté JS (custom_dashboard.html), qui sait comment
# aller chercher et rendre les données de ce widget.
WIDGET_TYPES = [
    "alert_stats", "app_health", "recent_alerts", "tcp_health",
    "top_apps", "services_status", "threshold_events", "top_talkers",
]

DEFAULT_LAYOUT = [
    {"id": "w1", "type": "alert_stats",     "size": "md"},
    {"id": "w2", "type": "app_health",      "size": "md"},
    {"id": "w3", "type": "recent_alerts",   "size": "lg"},
    {"id": "w4", "type": "tcp_health",      "size": "sm"},
    {"id": "w5", "type": "top_apps",        "size": "sm"},
    {"id": "w6", "type": "services_status", "size": "sm"},
]


def load():
    if not os.path.exists(LAYOUT_PATH):
        return list(DEFAULT_LAYOUT)
    try:
        with open(LAYOUT_PATH, encoding="utf-8") as f:
            data = json.load(f)
        return data if data else list(DEFAULT_LAYOUT)
    except (OSError, json.JSONDecodeError):
        return list(DEFAULT_LAYOUT)


def save(layout):
    """layout : liste de {id, type, size}. Valide le type contre le
    catalogue connu et la taille contre {sm, md, lg} avant d'écrire —
    un widget de type inconnu planterait le rendu JS silencieusement."""
    clean = []
    for w in layout:
        if not isinstance(w, dict):
            continue
        wtype = w.get("type")
        size = w.get("size", "md")
        if wtype not in WIDGET_TYPES or size not in ("sm", "md", "lg"):
            continue
        clean.append({"id": w.get("id") or wtype, "type": wtype, "size": size})

    os.makedirs(DATA_DIR, exist_ok=True)
    tmp_path = LAYOUT_PATH + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(clean, f, ensure_ascii=False, indent=2)
    os.replace(tmp_path, LAYOUT_PATH)
    return clean


def reset():
    if os.path.exists(LAYOUT_PATH):
        os.remove(LAYOUT_PATH)
    return list(DEFAULT_LAYOUT)
