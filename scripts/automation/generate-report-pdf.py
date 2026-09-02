#!/usr/bin/env python3
"""
NetWatch — génération PDF du rapport exécutif, en mode headless.

Utilisé pour les rapports planifiés (n8n, cron) et le déclenchement à la
demande depuis le portail (/api/reports/generate). Se connecte au portail
(login), récupère /report déjà rendu par Flask (mêmes données et même CSS
d'impression que le bouton "Exporter PDF" du navigateur), et le convertit
en PDF via wkhtmltopdf — pas de logique de rendu dupliquée ici.

Journalise chaque génération dans reports/index.json, consulté par la page
/reports du portail (historique, façon "Reports" d'Allegro Network
Multimeter : liste avec statut running/finished/failed).

Nécessite wkhtmltopdf (apt install wkhtmltopdf).
"""
import argparse
import json
import logging
import os
import subprocess
import sys
from datetime import datetime, timezone

import requests

logging.basicConfig(format="[%(levelname)s] %(message)s", level=logging.INFO)
log = logging.getLogger(__name__)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _load_index(index_path):
    if not os.path.exists(index_path):
        return []
    try:
        with open(index_path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return []


def _save_index(index_path, entries):
    os.makedirs(os.path.dirname(index_path), exist_ok=True)
    tmp = index_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(entries, f, ensure_ascii=False, indent=2)
    os.replace(tmp, index_path)


def generate(portal_url, username, password, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    index_path = os.path.join(output_dir, "index.json")
    entries = _load_index(index_path)

    timestamp = datetime.now(timezone.utc)
    filename = f"netwatch-report-{timestamp.strftime('%Y%m%d-%H%M%S')}.pdf"
    output_path = os.path.join(output_dir, filename)

    entry = {
        "filename": filename,
        "generated_at": timestamp.isoformat(),
        "status": "running",
        "size_bytes": None,
        "error": None,
    }
    entries.insert(0, entry)
    _save_index(index_path, entries)

    session = requests.Session()
    try:
        r_login = session.post(f"{portal_url}/login", data={"username": username, "password": password}, timeout=15)
        if r_login.status_code not in (200, 302):
            raise RuntimeError(f"Login échoué (HTTP {r_login.status_code})")

        r_report = session.get(f"{portal_url}/report", timeout=30)
        r_report.raise_for_status()
        html_path = output_path + ".html"
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(r_report.text)

        result = subprocess.run(
            ["wkhtmltopdf", "--quiet", "--print-media-type",
             "--margin-top", "8mm", "--margin-bottom", "8mm",
             html_path, output_path],
            capture_output=True, text=True, timeout=60, check=False,
        )
        os.remove(html_path)
        if result.returncode != 0 or not os.path.exists(output_path):
            raise RuntimeError(f"wkhtmltopdf a échoué : {result.stderr[:300]}")

        entry["status"] = "finished"
        entry["size_bytes"] = os.path.getsize(output_path)
        log.info("Rapport généré : %s (%d octets)", filename, entry["size_bytes"])

    except Exception as exc:
        entry["status"] = "failed"
        entry["error"] = str(exc)[:300]
        log.error("Echec génération rapport : %s", exc)

    _save_index(index_path, entries)
    return entry


def main():
    parser = argparse.ArgumentParser(
        description="Génère un PDF du rapport exécutif NetWatch (headless, via wkhtmltopdf)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 generate-report-pdf.py
  python3 generate-report-pdf.py --portal-url http://localhost:5050 --output-dir /home/ubuntu/netwatch/reports
""",
    )
    parser.add_argument("--portal-url", default=os.environ.get("NETWATCH_PORTAL_URL", "http://localhost:5050"))
    parser.add_argument("--username", default=os.environ.get("PORTAL_USERNAME", "admin"))
    parser.add_argument("--password", default=os.environ.get("PORTAL_PASSWORD", "netwatch"))
    parser.add_argument("--output-dir", default=os.path.join(REPO_ROOT, "reports"))
    args = parser.parse_args()

    entry = generate(args.portal_url, args.username, args.password, args.output_dir)
    return 0 if entry["status"] == "finished" else 1


if __name__ == "__main__":
    sys.exit(main())
