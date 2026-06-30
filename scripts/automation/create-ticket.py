#!/usr/bin/env python3
"""
create-ticket.py — NetWatch Auto-Ticket Generator
Prend une alerte JSON (stdin ou argument) et crée un ticket YAML dans
agents-deck/agents/security/tickets/drafts/ avec gestion anti-doublon.

Usage:
    echo '<json>' | python3 create-ticket.py
    python3 create-ticket.py '<json>'
    python3 create-ticket.py --file alert.json
"""

import sys
import os
import json
import re
import argparse
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent.parent
DRAFTS_DIR = REPO_ROOT / "agents-deck" / "agents" / "security" / "tickets" / "drafts"
PORTAL_URL = "http://localhost:5050"


def slugify(text: str, max_len: int = 60) -> str:
    """Convertit une signature en nom de fichier sûr."""
    slug = re.sub(r"[^\w\s-]", "", text.lower())
    slug = re.sub(r"[\s_-]+", "-", slug).strip("-")
    return slug[:max_len]


def get_field(alert: dict, *keys, default="unknown"):
    """Recherche un champ dans un dict imbriqué, essaie plusieurs chemins."""
    for key in keys:
        parts = key.split(".")
        val = alert
        for p in parts:
            if isinstance(val, dict):
                val = val.get(p)
            else:
                val = None
                break
        if val is not None:
            return val
    return default


def parse_alert(raw: str) -> dict:
    """Parse le JSON de l'alerte (Elasticsearch hit ou alerte brute)."""
    data = json.loads(raw)
    # Support Elasticsearch hit (_source) ou alerte directe
    if "_source" in data:
        return data["_source"]
    return data


def extract_fields(alert: dict) -> dict:
    """Extrait les champs pertinents depuis différents formats d'alerte."""
    # Signature / titre
    signature = get_field(
        alert,
        "alert.signature",      # Suricata EVE JSON
        "msg",                  # Snort alert_json
        "signature",            # format direct
        "alert.msg",
        "rule.name",
        default="Unknown Alert",
    )

    # IPs
    src_ip = get_field(
        alert,
        "src_ip",
        "source.ip",
        "alert.src_ip",
        "network.src_ip",
        default="unknown",
    )
    dest_ip = get_field(
        alert,
        "dest_ip",
        "destination.ip",
        "alert.dest_ip",
        "network.dest_ip",
        default="unknown",
    )

    # Ports (optionnel)
    src_port = get_field(alert, "src_port", "source.port", default=None)
    dest_port = get_field(alert, "dest_port", "destination.port", default=None)

    # Timestamp
    timestamp = get_field(
        alert,
        "@timestamp",
        "timestamp",
        "alert.timestamp",
        default=datetime.now(timezone.utc).isoformat(),
    )

    # Sévérité
    severity = get_field(
        alert,
        "alert.severity",
        "event.severity_label",
        "severity",
        default="critical",
    )
    # Suricata: severity 1 = critical, 2 = high
    if str(severity) == "1":
        severity = "critical"
    elif str(severity) == "2":
        severity = "high"

    # Moteur / source
    engine = get_field(alert, "event.module", "engine", "type", default="unknown")

    # Proto
    proto = get_field(alert, "proto", "network.transport", "protocol", default=None)

    return {
        "signature": str(signature),
        "src_ip": str(src_ip),
        "dest_ip": str(dest_ip),
        "src_port": src_port,
        "dest_port": dest_port,
        "timestamp": str(timestamp),
        "severity": str(severity),
        "engine": str(engine),
        "proto": proto,
    }


def check_duplicate(signature: str, drafts_dir: Path) -> tuple[bool, str | None]:
    """
    Vérifie si un ticket avec la même signature existe déjà dans drafts/.
    Retourne (is_duplicate, existing_file_path).
    """
    if not drafts_dir.exists():
        return False, None

    sig_normalized = signature.strip().lower()
    for yaml_file in drafts_dir.glob("*.yml"):
        try:
            content = yaml_file.read_text(encoding="utf-8")
            # Cherche la ligne signature: "..."
            for line in content.splitlines():
                if line.strip().startswith("signature:"):
                    existing_sig = line.split(":", 1)[1].strip().strip('"').strip("'")
                    if existing_sig.lower() == sig_normalized:
                        return True, str(yaml_file)
        except Exception:
            continue
    return False, None


def build_yaml(ticket_id: str, fields: dict) -> str:
    """Construit le contenu YAML du ticket."""
    now = datetime.now(timezone.utc)
    created_date = now.strftime("%Y-%m-%d")
    portal_alerts_url = f"{PORTAL_URL}/alerts"

    # Lignes optionnelles (ports, proto)
    extra_alert_fields = ""
    if fields["src_port"] is not None:
        extra_alert_fields += f"\n  src_port: {fields['src_port']}"
    if fields["dest_port"] is not None:
        extra_alert_fields += f"\n  dest_port: {fields['dest_port']}"
    if fields["proto"] is not None:
        extra_alert_fields += f"\n  proto: \"{fields['proto']}\""
    if fields["engine"] not in ("unknown", None):
        extra_alert_fields += f"\n  engine: \"{fields['engine']}\""

    yaml_content = f"""id: {ticket_id}
title: "AUTO: {fields['signature']}"
agent: Security-agent
phase: 2
priority: {fields['severity']}
category: incident
status: draft
created: "{created_date}"
auto_generated: true
alert:
  src_ip: "{fields['src_ip']}"
  dest_ip: "{fields['dest_ip']}"
  signature: "{fields['signature']}"
  timestamp: "{fields['timestamp']}"{extra_alert_fields}
  portal_url: "{portal_alerts_url}"
acceptance:
  - "Investiguer l'alerte : src_ip={fields['src_ip']}, dest_ip={fields['dest_ip']}, contexte réseau"
  - "Vérifier si l'IP source est dans la watchlist Zeek Intel"
  - "Analyser les logs réseau associés dans Elasticsearch ({fields['engine']})"
  - "Documenter les conclusions et clore ou escalader le ticket"
"""
    return yaml_content


def generate_ticket_id() -> str:
    """Génère un ID unique basé sur le timestamp."""
    now = datetime.now(timezone.utc)
    return f"T_auto_{now.strftime('%Y%m%d_%H%M%S')}"


def main():
    parser = argparse.ArgumentParser(
        description="Crée un ticket YAML depuis une alerte JSON."
    )
    parser.add_argument(
        "json_arg",
        nargs="?",
        help="Alerte JSON passée en argument (sinon lue depuis stdin)",
    )
    parser.add_argument(
        "--file", "-f",
        help="Fichier JSON contenant l'alerte",
    )
    parser.add_argument(
        "--drafts-dir", "-d",
        help=f"Répertoire drafts/ (défaut: {DRAFTS_DIR})",
        default=str(DRAFTS_DIR),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Affiche le ticket YAML sans l'écrire sur disque",
    )
    args = parser.parse_args()

    drafts_dir = Path(args.drafts_dir)

    # --- Lire le JSON ---
    if args.file:
        raw = Path(args.file).read_text(encoding="utf-8")
    elif args.json_arg:
        raw = args.json_arg
    elif not sys.stdin.isatty():
        raw = sys.stdin.read()
    else:
        print("ERREUR: Fournir le JSON en stdin, argument ou via --file", file=sys.stderr)
        sys.exit(1)

    raw = raw.strip()
    if not raw:
        print("ERREUR: JSON vide", file=sys.stderr)
        sys.exit(1)

    # --- Parser ---
    try:
        alert = parse_alert(raw)
    except json.JSONDecodeError as e:
        print(f"ERREUR: JSON invalide — {e}", file=sys.stderr)
        sys.exit(2)

    fields = extract_fields(alert)

    # --- Anti-doublon ---
    is_dup, existing = check_duplicate(fields["signature"], drafts_dir)
    if is_dup:
        print(
            f"SKIP: ticket déjà existant pour signature '{fields['signature']}' → {existing}",
            file=sys.stderr,
        )
        sys.exit(0)

    # --- Générer ticket ---
    ticket_id = generate_ticket_id()
    yaml_content = build_yaml(ticket_id, fields)

    if args.dry_run:
        print(yaml_content)
        return

    # --- Écrire fichier ---
    drafts_dir.mkdir(parents=True, exist_ok=True)
    slug = slugify(fields["signature"])
    filename = f"{ticket_id}_{slug}.yml"
    output_path = drafts_dir / filename

    output_path.write_text(yaml_content, encoding="utf-8")
    print(f"OK: ticket créé → {output_path}", file=sys.stdout)
    sys.exit(0)


if __name__ == "__main__":
    main()
