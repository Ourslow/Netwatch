"""
Client LLM local (Ollama) — assistant d'explication des alertes IDS.

100% on-prem : aucune donnée d'alerte n'est envoyée à un service tiers,
seule l'API REST locale d'Ollama (http://localhost:11434 par défaut) est
contactée. Cohérent avec la philosophie souveraine de NetWatch.
"""

import requests
import config

_TIMEOUT = 30  # génération LLM plus lente qu'une requête ES classique

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

    body = {
        "model":  config.OLLAMA_MODEL,
        "prompt": prompt,
        "system": _SYSTEM_PROMPT,
        "stream": False,
        "options": {"temperature": 0.2},
    }

    try:
        r = requests.post(
            config.OLLAMA_URL.rstrip("/") + "/api/generate",
            json=body,
            timeout=_TIMEOUT,
        )
        r.raise_for_status()
        return r.json().get("response", "").strip(), None
    except requests.exceptions.ConnectionError:
        return None, f"Ollama non joignable ({config.OLLAMA_URL}) — vérifier que le conteneur tourne"
    except requests.exceptions.Timeout:
        return None, f"Ollama timeout (> {_TIMEOUT}s) — modèle trop lent ou surchargé"
    except Exception as e:
        return None, str(e)[:150]


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

    body = {
        "model":  config.OLLAMA_MODEL,
        "prompt": prompt,
        "system": _SYSTEM_PROMPT,
        "stream": False,
        "options": {"temperature": 0.2},
    }

    try:
        r = requests.post(
            config.OLLAMA_URL.rstrip("/") + "/api/generate",
            json=body,
            timeout=_TIMEOUT,
        )
        r.raise_for_status()
        return r.json().get("response", "").strip(), None
    except requests.exceptions.ConnectionError:
        return None, f"Ollama non joignable ({config.OLLAMA_URL})"
    except requests.exceptions.Timeout:
        return None, f"Ollama timeout (> {_TIMEOUT}s)"
    except Exception as e:
        return None, str(e)[:150]
