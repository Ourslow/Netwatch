"""
Assistant IA local (édition Pro) — explication d'alertes, résumé exécutif,
narration d'une conversation TCP. 100 % on-prem (Ollama), aucune donnée ne
sort du SI. Les URL sont appelées directement par les templates du portail
(alerts.html, report.html, pcap_analysis.html) : elles ne changent pas.

Édition IA / Core : OLLAMA_URL vide dans .env = Core (boutons ✨ masqués,
endpoints en 503) ; le profil compose `ia` démarre Ollama.
"""
from flask import jsonify, request

from netwatch import es_client

from . import llm_client, llmops

_AI_DISABLED = {"error": "Assistant IA désactivé (édition Core) — renseigner OLLAMA_URL et COMPOSE_PROFILES=ia dans .env"}


def register(bp, api):
    config = api.config

    @bp.route("/api/explain", methods=["POST"])
    @api.login_required
    @api.pro_required("ia")
    def api_explain():
        """Explique une alerte IDS en langage naturel via l'assistant LLM local (Ollama)."""
        if not config.AI_ENABLED:
            return jsonify(_AI_DISABLED), 503
        alert = request.get_json(silent=True) or {}
        if not alert.get("signature"):
            return jsonify({"error": "Alerte invalide"}), 400
        explanation, error = llm_client.explain_alert(alert)
        if error:
            return jsonify({"error": error}), 503
        return jsonify({"explanation": explanation})

    @bp.route("/api/summary")
    @api.login_required
    @api.pro_required("ia")
    def api_summary():
        """Résumé exécutif IA des alertes récentes (utilisé sur /report)."""
        if not config.AI_ENABLED:
            return jsonify(_AI_DISABLED), 503
        alerts_list, es_error = es_client.get_recent_alerts(size=30)
        if es_error:
            return jsonify({"error": es_error}), 503
        summary, llm_error = llm_client.summarize_alerts(alerts_list)
        if llm_error:
            return jsonify({"error": llm_error}), 503
        return jsonify({"summary": summary})

    @bp.route("/api/pcap-analysis/explain", methods=["POST"])
    @api.login_required
    @api.pro_required("ia")
    def api_pcap_analysis_explain():
        """Analyse narrative IA d'une conversation TCP (via Ollama)."""
        if not config.AI_ENABLED:
            return jsonify(_AI_DISABLED), 503
        conv = request.get_json(silent=True) or {}
        if not conv:
            return jsonify({"error": "Conversation manquante"}), 400
        text, error = llm_client.explain_tcp_conversation(conv)
        if error:
            return jsonify({"error": error}), 503
        return jsonify({"explanation": text})

    # Boutons ✨ et résumé exécutif dans les templates Community
    api.provide("ai_enabled", config.AI_ENABLED)
    # Carte « Assistant IA — usage (7 j) » de la page Statut (LLMOps)
    api.add_status_provider("llmops", lambda: llmops.get_llmops_stats(days=7)[0])
    api.add_partial("status", "pro/_status_llmops.html")
