"""
Client LLM local (Ollama) — assistant d'explication des alertes IDS.

100% on-prem : aucune donnée d'alerte n'est envoyée à un service tiers,
seule l'API REST locale d'Ollama (http://localhost:11434 par défaut) est
contactée. Cohérent avec la philosophie souveraine de NetWatch.

Chaque appel est aussi journalisé dans netwatch-llmops-* (latence,
succès/échec) — volet LLMOps du pitch Network Experience Monitoring :
voir netwatch.llmops pour l'agrégation/lecture de ces logs.
"""

import time
import requests
import config

from datetime import datetime, timezone
from . import es_client

_TIMEOUT = config.OLLAMA_TIMEOUT  # configurable via OLLAMA_TIMEOUT (inférence CPU lente)

_SYSTEM_PROMPT = (
    "Tu es un assistant SOC qui explique des alertes IDS (Snort/Suricata) "
    "à un analyste non-expert. Réponds en français, de façon concise "
    "(4 à 6 lignes max) : 1) ce que l'alerte signifie concrètement, "
    "2) le risque potentiel, 3) une action recommandée. "
    "Ne pas inventer d'informations absentes de l'alerte."
)


def is_available() -> bool:
    """Vérifie que le serveur Ollama local répond."""
    try:
        r = requests.get(config.OLLAMA_URL.rstrip("/") + "/api/tags", timeout=3)
        return r.ok
    except requests.exceptions.RequestException:
        return False


def _log_call(kind, latency_ms, ok, error, prompt_chars):
    """Journalise un appel Ollama dans netwatch-llmops-* — best-effort, ne doit
    jamais faire échouer l'appel IA lui-même si Elasticsearch est indisponible."""
    try:
        now = datetime.now(timezone.utc)
        doc = {
            "@timestamp":    now.isoformat(),
            "kind":          kind,
            "model":         config.OLLAMA_MODEL,
            "latency_ms":    latency_ms,
            "ok":            ok,
            # "error_message" et non "error" : ce dernier collide avec le champ
            # ECS "error" (objet error.msg/error.code) hérité par tout index
            # netwatch-* via le template Filebeat — casse l'indexation en 400.
            "error_message": error,
            "prompt_chars":  prompt_chars,
        }
        index = "netwatch-llmops-" + now.strftime("%Y.%m.%d")
        es_client._es(f"/{index}/_doc", doc, method="post")
    except Exception:
        pass


def _generate(prompt: str, system: str, kind: str) -> tuple[str | None, str | None]:
    """POST /api/generate + mesure/journalise latence et succès dans netwatch-llmops-*."""
    body = {
        "model":  config.OLLAMA_MODEL,
        "prompt": prompt,
        "system": system,
        "stream": False,
        "options": {"temperature": 0.2},
    }

    t0 = time.monotonic()
    result, error = None, None
    try:
        r = requests.post(
            config.OLLAMA_URL.rstrip("/") + "/api/generate",
            json=body,
            timeout=_TIMEOUT,
        )
        r.raise_for_status()
        result = r.json().get("response", "").strip()
    except requests.exceptions.ConnectionError:
        error = f"Ollama non joignable ({config.OLLAMA_URL}) — vérifier que le conteneur tourne"
    except requests.exceptions.Timeout:
        error = f"Ollama timeout (> {_TIMEOUT}s) — modèle trop lent ou surchargé"
    except Exception as e:
        error = str(e)[:150]

    latency_ms = round((time.monotonic() - t0) * 1000, 1)
    _log_call(kind, latency_ms, result is not None, error, len(prompt))
    return result, error


def explain_alert(alert: dict) -> tuple[str | None, str | None]:
    """
    Génère une explication en langage naturel pour une alerte normalisée
    (format produit par netwatch.es_client._normalize).

    Retourne (explication: str|None, error: str|None).
    """
    prompt = (
        f"Alerte {alert.get('engine', '—')} :\n"
        f"- Signature : {alert.get('signature', '—')}\n"
        f"- Catégorie : {alert.get('category', '—')}\n"
        f"- Sévérité : {alert.get('severity', '—')} (1=critique, 3=faible)\n"
        f"- Source : {alert.get('src_ip', '—')} → Destination : {alert.get('dest_ip', '—')}\n"
        f"- MITRE ATT&CK : {alert.get('mitre_tactic') or '—'} "
        f"({alert.get('mitre_tech') or '—'})\n\n"
        "Explique cette alerte à un analyste."
    )
    return _generate(prompt, _SYSTEM_PROMPT, "explain_alert")


def summarize_alerts(alerts: list, period_label: str = "24 dernières heures") -> tuple[str | None, str | None]:
    """
    Génère un résumé exécutif (pour /report) à partir d'une liste d'alertes
    normalisées. Retourne (résumé: str|None, error: str|None).
    """
    if not alerts:
        return "Aucune alerte détectée sur la période — réseau silencieux.", None

    lines = [
        f"- [{a.get('engine')}] sév.{a.get('severity')} {a.get('signature')} "
        f"({a.get('src_ip')} → {a.get('dest_ip')})"
        for a in alerts[:30]
    ]
    prompt = (
        f"Voici les alertes IDS des {period_label} (max 30 affichées) :\n"
        + "\n".join(lines)
        + "\n\nRédige un résumé exécutif en français (8 lignes max) à destination "
        "d'un décideur non-technique : tendances principales, types de menaces "
        "dominantes, niveau de risque global, et une recommandation."
    )
    return _generate(prompt, _SYSTEM_PROMPT, "summarize_alerts")


_TCP_SYSTEM_PROMPT = (
    "Tu es un ingénieur réseau qui analyse des métriques de conversation TCP "
    "extraites d'un PCAP (façon Allegro Network Multimeter). Réponds en "
    "français, en Markdown, structuré en EXACTEMENT ces 5 sections avec ces "
    "titres ## : 'Handshake & temps de réponse', 'Débit & taux de paquets', "
    "'Fiabilité', 'QoS & MTU', 'À vérifier ensuite'. Dans chaque section, "
    "2-4 puces courtes et concrètes qui interprètent les chiffres donnés "
    "(pas de généralités) : dis si une valeur est bonne/mauvaise et pourquoi, "
    "en te basant sur les seuils indiqués. Ne pas inventer de données absentes."
)


def explain_tcp_conversation(conv: dict) -> tuple[str | None, str | None]:
    """
    Génère une analyse narrative en langage naturel d'une conversation TCP
    (dict produit par scripts/security/pcap-tcp-analysis.py).
    Retourne (analyse: str|None, error: str|None).
    """
    hs = conv.get("handshake_ms", {})
    hs_rating = conv.get("handshake_rating", {})
    rt = conv.get("response_time_ms", {})
    win = conv.get("window_size", {})

    prompt = (
        f"Conversation TCP {conv.get('client_ip')}:{conv.get('client_port')} "
        f"<-> {conv.get('server_ip')}:{conv.get('server_port')}\n"
        f"Durée : {conv.get('duration_s')} s\n"
        f"Paquets : {conv.get('frames', {}).get('c2s')} (client→serveur) / "
        f"{conv.get('frames', {}).get('s2c')} (serveur→client)\n"
        f"Octets : {conv.get('bytes', {}).get('c2s')} / {conv.get('bytes', {}).get('s2c')}\n"
        f"Débit : {conv.get('bps', {}).get('c2s')} bps / {conv.get('bps', {}).get('s2c')} bps\n"
        f"Handshake serveur : {hs.get('server')} ms "
        f"({hs_rating.get('server', {}).get('label')})\n"
        f"Handshake client : {hs.get('client')} ms "
        f"({hs_rating.get('client', {}).get('label')})\n"
        f"Temps de réponse max/moy : {rt.get('max')} / {rt.get('avg')} ms\n"
        f"Retransmissions : {conv.get('retransmissions')} "
        f"({conv.get('retransmissions_pct')} %)\n"
        f"Paquets hors-ordre : {conv.get('out_of_order')}\n"
        f"ACKs dupliqués : {conv.get('duplicate_acks')}\n"
        f"Fenêtres nulles (zero window) : {conv.get('zero_window')}\n"
        f"Taille de fenêtre TCP (max/min) : {win.get('max')} / {win.get('min')}\n"
        f"Usage de fenêtre estimé : {conv.get('window_usage_pct')} %\n"
        f"MSS : {conv.get('mss')}\n"
        f"MTU observé : {conv.get('mtu')}\n"
        f"QoS (DSCP) : {conv.get('dscp_name', conv.get('dscp'))}\n"
        f"VLAN : {conv.get('vlan_id')}\n\n"
        "Analyse cette conversation TCP."
    )
    return _generate(prompt, _TCP_SYSTEM_PROMPT, "explain_tcp_conversation")
