"""
Rapports PDF planifiables (édition Pro) — historique, génération à la demande
(bouton du portail ou n8n), téléchargement. La génération appelle
pro/scripts/generate-report-pdf.py, qui imprime la page
/report (Community) ; les PDF vont dans reports/ à la racine.
"""
import json
import os
import subprocess

from flask import current_app, jsonify, render_template, request, send_from_directory
from werkzeug.utils import secure_filename


def _root():
    """Racine du dépôt NetWatch (portal/ est le root_path de l'application Flask)."""
    return os.path.dirname(os.path.abspath(current_app.root_path))


def _reports_dir():
    return os.path.join(_root(), "reports")


def _entries():
    try:
        with open(os.path.join(_reports_dir(), "index.json"), encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def register(bp, api):
    config = api.config

    @bp.route("/reports")
    @api.login_required
    def reports_page():
        return render_template("pro/reports.html", entries=_entries())

    @bp.route("/api/reports/generate", methods=["POST"])
    @api.login_required
    @api.pro_required("reports")
    def api_reports_generate():
        """Déclenche generate-report-pdf.py à la demande (bouton portail ou n8n)."""
        root = _root()
        script = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts", "generate-report-pdf.py")
        if not os.path.isfile(script):
            return jsonify({"error": "generate-report-pdf.py introuvable"}), 503
        try:
            # username/password passés par variables d'environnement (déjà lues en
            # fallback par generate-report-pdf.py) plutôt qu'en argument CLI — un
            # argument de ligne de commande est visible de tout utilisateur local
            # via `ps`/`/proc/<pid>/cmdline` pendant l'exécution du subprocess.
            result = subprocess.run(
                ["python3", script,
                 "--portal-url", request.host_url.rstrip("/"),
                 "--output-dir", _reports_dir()],
                cwd=root,
                capture_output=True,
                timeout=90,
                check=False,
                env={**os.environ, "PORTAL_USERNAME": config.PORTAL_USERNAME,
                     "PORTAL_PASSWORD": config.PORTAL_PASSWORD},
            )
            if result.returncode != 0:
                current_app.logger.warning("generate-report-pdf.py exited %d: %s", result.returncode,
                                           (result.stderr or b"").decode(errors="replace")[:400])
                return jsonify({"error": "Génération échouée — voir les logs du portail"}), 503
        except subprocess.TimeoutExpired:
            return jsonify({"error": "Génération trop longue (> 90s)"}), 503
        except Exception as exc:
            return jsonify({"error": str(exc)}), 503

        entries = _entries()
        return jsonify(entries[0] if entries else {"status": "unknown"})

    @bp.route("/reports/download/<path:filename>")
    @api.login_required
    def reports_download(filename):
        safe_name = secure_filename(filename)
        if not safe_name.endswith(".pdf"):
            return jsonify({"error": "Fichier invalide"}), 400
        return send_from_directory(_reports_dir(), safe_name, as_attachment=True)

    api.add_nav("report", "Rapports PDF", "pro.reports_page", "bi-file-earmark-pdf", i18n="page_reports")
    api.add_command("Rapports PDF", "/reports", "bi-file-earmark-pdf", hint="Historique · génération", key="g r")
