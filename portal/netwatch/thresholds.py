"""
Alertes sur seuil — surveille en continu une métrique (score de santé
applicatif, RTT, zero-window, retransmissions) et notifie au premier
franchissement plutôt que d'attendre qu'un opérateur consulte une page.

Règles stockées dans data/thresholds.json (même pattern que
netwatch.hostgroups). L'état courant (breach/ok par règle+cible) est
gardé dans data/threshold_state.json pour ne notifier qu'au moment de la
transition, pas à chaque vérification périodique.
"""

import json
import os
import time
import uuid
from datetime import datetime, timezone

import requests

import config
from . import es_client
from .experience import app_dictionary as nw_app_dictionary

DATA_DIR       = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
RULES_PATH     = os.path.join(DATA_DIR, "thresholds.json")
STATE_PATH     = os.path.join(DATA_DIR, "threshold_state.json")

METRICS = {
    "health_score":    {"label": "Score de santé",     "unit": "",   "default_op": "<"},
    "zero_window_pct": {"label": "Zero-window",         "unit": "%",  "default_op": ">"},
    "retransmit_pct":  {"label": "Retransmissions",     "unit": "%",  "default_op": ">"},
    "avg_rtt_ms":      {"label": "RTT moyen",           "unit": "ms", "default_op": ">"},
}


def _load(path):
    if not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def _save(path, data):
    os.makedirs(DATA_DIR, exist_ok=True)
    tmp_path = path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp_path, path)


def list_rules():
    rules = _load(RULES_PATH)
    return sorted(rules.values(), key=lambda r: r.get("metric", ""))


def add_rule(metric, scope, operator, value, severity):
    if metric not in METRICS:
        raise ValueError(f"Métrique inconnue : {metric}")
    if operator not in ("<", ">"):
        raise ValueError("Opérateur invalide (attendu < ou >)")
    rules = _load(RULES_PATH)
    rule_id = uuid.uuid4().hex[:10]
    rules[rule_id] = {
        "id": rule_id, "metric": metric, "scope": scope or "global",
        "operator": operator, "value": float(value),
        "severity": severity if severity in ("warning", "critical") else "warning",
        "enabled": True,
    }
    _save(RULES_PATH, rules)
    return rules[rule_id]


def delete_rule(rule_id):
    rules = _load(RULES_PATH)
    rules.pop(rule_id, None)
    _save(RULES_PATH, rules)


def toggle_rule(rule_id, enabled):
    rules = _load(RULES_PATH)
    if rule_id in rules:
        rules[rule_id]["enabled"] = bool(enabled)
        _save(RULES_PATH, rules)


def _breached(rule, current):
    return current < rule["value"] if rule["operator"] == "<" else current > rule["value"]


# Le sélecteur de métrique "health_score" (clé publique, cohérente avec
# METRICS) correspond au champ "score" du dict retourné par
# get_app_health_scores() — les 3 autres métriques ont le même nom des deux
# côtés, seul le score de santé a un nom raccourci côté données.
_METRIC_FIELD = {"health_score": "score"}


def evaluate(days=1):
    """
    Évalue toutes les règles actives contre les scores de santé applicatifs
    courants. Retourne (breaches: list[{rule, app, current, since}], error).
    """
    rules = [r for r in list_rules() if r.get("enabled", True)]
    if not rules:
        return [], None

    scores, err = nw_app_dictionary.get_app_health_scores(days=days)
    if err:
        return [], err

    by_app = {s["name"]: s for s in scores}
    breaches = []
    for rule in rules:
        targets = [by_app[rule["scope"]]] if rule["scope"] != "global" and rule["scope"] in by_app \
            else (list(by_app.values()) if rule["scope"] == "global" else [])
        for s in targets:
            field = _METRIC_FIELD.get(rule["metric"], rule["metric"])
            current = s.get(field)
            if current is None:
                continue
            if _breached(rule, current):
                breaches.append({"rule": rule, "app": s["name"], "current": current})
    return breaches, None


def _log_event(kind, rule, app, current):
    """Journalise un événement (breach/resolved) dans netwatch-threshold-events-*
    — best-effort, ne doit jamais faire planter le check périodique."""
    try:
        now = datetime.now(timezone.utc)
        doc = {
            "@timestamp": now.isoformat(),
            "kind": kind,  # "breach" | "resolved"
            "rule_id": rule["id"], "metric": rule["metric"], "scope": rule["scope"],
            "operator": rule["operator"], "threshold": rule["value"], "severity": rule["severity"],
            "app": app, "current_value": current,
        }
        index = "netwatch-threshold-events-" + now.strftime("%Y.%m.%d")
        es_client._es(f"/{index}/_doc", doc, method="post")
    except Exception:
        pass


def _notify_webhook(kind, rule, app, current):
    if not config.THRESHOLD_WEBHOOK_URL:
        return
    try:
        metric_label = METRICS.get(rule["metric"], {}).get("label", rule["metric"])
        text = (
            f"[NetWatch] {'Seuil franchi' if kind == 'breach' else 'Retour à la normale'} — "
            f"{app} : {metric_label} = {current} (seuil {rule['operator']} {rule['value']})"
        )
        requests.post(config.THRESHOLD_WEBHOOK_URL, json={"text": text}, timeout=5)
    except Exception:
        pass  # une notification externe indisponible ne doit pas casser le check


def check_and_notify():
    """
    Un cycle de vérification : évalue les règles, compare à l'état précédent,
    journalise + notifie uniquement les transitions ok->breach et
    breach->ok (pas de spam à chaque cycle sur un état inchangé).
    """
    breaches, err = evaluate()
    if err:
        return
    state = _load(STATE_PATH)
    current_keys = set()

    for b in breaches:
        key = f"{b['rule']['id']}:{b['app']}"
        current_keys.add(key)
        if state.get(key) != "breach":
            state[key] = "breach"
            _log_event("breach", b["rule"], b["app"], b["current"])
            _notify_webhook("breach", b["rule"], b["app"], b["current"])

    for key in list(state.keys()):
        if state[key] == "breach" and key not in current_keys:
            rule_id, app = key.split(":", 1)
            rules = _load(RULES_PATH)
            rule = rules.get(rule_id)
            state[key] = "ok"
            if rule:
                _log_event("resolved", rule, app, None)
                _notify_webhook("resolved", rule, app, None)

    _save(STATE_PATH, state)


def run_background_loop(interval_seconds):
    """Boucle infinie — destinée à tourner dans un thread daemon démarré une
    fois au lancement du portail (voir app.py)."""
    while True:
        check_and_notify()
        time.sleep(interval_seconds)


def get_recent_events(size=30):
    """Derniers événements (breach/resolved) toutes règles confondues, pour
    affichage sur /thresholds. Retourne (events: list, error: str|None)."""
    try:
        r = es_client._es("/netwatch-threshold-events-*/_search", {
            "size": size,
            "sort": [{"@timestamp": {"order": "desc"}}],
        })
        if r.status_code == 404:
            return [], None
        r.raise_for_status()
        return [h["_source"] for h in r.json().get("hits", {}).get("hits", [])], None
    except requests.exceptions.ConnectionError:
        return [], "Elasticsearch non joignable"
    except Exception as e:
        return [], str(e)[:120]
