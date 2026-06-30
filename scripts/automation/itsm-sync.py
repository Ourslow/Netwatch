#!/usr/bin/env python3
"""
itsm-sync.py — NetWatch ITSM Synchronisation
Reads all YAML draft tickets under agents-deck/agents/*/tickets/drafts/*.yml
and pushes them to the configured ITSM backend (ServiceNow or JIRA).

Anti-doublon: tickets already having an `itsm_id:` field are skipped.

Usage:
    python3 itsm-sync.py [--dry-run] [--verbose] [--backend servicenow|jira|none]

Environment variables (read from .env automatically if python-dotenv is available,
otherwise set them in the shell or Docker environment):
    ITSM_BACKEND      servicenow | jira | none  (default: none)
    SNOW_INSTANCE     e.g. mycompany
    SNOW_USER         ServiceNow API user
    SNOW_PASSWORD     ServiceNow API password
    JIRA_URL          e.g. https://mycompany.atlassian.net
    JIRA_USER         e.g. user@company.com
    JIRA_TOKEN        Atlassian API token
    JIRA_PROJECT_KEY  e.g. NOC
"""

import argparse
import base64
import json
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Config / paths
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent.parent
AGENTS_DIR = REPO_ROOT / "agents-deck" / "agents"

SEVERITY_MAP_SNOW = {
    "critical": "1",
    "high": "2",
    "medium": "3",
    "low": "4",
}

PRIORITY_MAP_JIRA = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}

# ---------------------------------------------------------------------------
# Optional .env loading
# ---------------------------------------------------------------------------
def _load_dotenv():
    """Loads .env from repo root if python-dotenv is not available."""
    env_file = REPO_ROOT / ".env"
    if not env_file.exists():
        return
    try:
        from dotenv import load_dotenv  # type: ignore
        load_dotenv(env_file)
        return
    except ImportError:
        pass
    # Minimal fallback
    for line in env_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = val


# ---------------------------------------------------------------------------
# Minimal YAML parser  (stdlib only, no PyYAML required)
# ---------------------------------------------------------------------------
def _parse_yaml_simple(text: str) -> dict:
    """
    Parse a simple flat/1-level-nested YAML file (no sequences, no anchors).
    Good enough for NetWatch ticket YAMLs.
    """
    result: dict = {}
    current_key: str | None = None
    for line in text.splitlines():
        if not line.strip() or line.strip().startswith("#"):
            continue
        # Detect indent level
        stripped = line.lstrip()
        indent = len(line) - len(stripped)
        if indent == 0:
            # Top-level key
            if ":" in stripped:
                k, _, v = stripped.partition(":")
                k = k.strip()
                v = v.strip().strip('"').strip("'")
                result[k] = v if v else {}
                current_key = k
        elif indent > 0 and current_key:
            # Nested value – only for context block
            if isinstance(result.get(current_key), dict):
                if ":" in stripped:
                    k2, _, v2 = stripped.partition(":")
                    result[current_key][k2.strip()] = v2.strip().strip('"').strip("'")
    return result


def read_ticket(path: Path) -> dict:
    """Read and parse a YAML ticket file."""
    try:
        text = path.read_text(encoding="utf-8")
        data = _parse_yaml_simple(text)
        data["_path"] = str(path)
        data["_raw"] = text
        return data
    except Exception as exc:
        return {"_path": str(path), "_error": str(exc)}


def write_itsm_id(path: Path, itsm_id: str) -> None:
    """Append `itsm_id: <value>` to the YAML file (after the first non-comment line)."""
    text = path.read_text(encoding="utf-8")
    # Insert after the first `id:` line
    lines = text.splitlines()
    insert_after = 0
    for i, line in enumerate(lines):
        if line.startswith("id:"):
            insert_after = i + 1
            break
    lines.insert(insert_after, f'itsm_id: "{itsm_id}"')
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------
def _http_request(
    method: str,
    url: str,
    payload: dict,
    auth_user: str,
    auth_pass: str,
    verbose: bool,
) -> tuple[int, dict]:
    """Perform an authenticated JSON HTTP request. Returns (status_code, response_body)."""
    body_bytes = json.dumps(payload).encode("utf-8")
    creds = base64.b64encode(f"{auth_user}:{auth_pass}".encode()).decode()
    # Mask credentials in logs
    log_auth = f"{auth_user}:***"
    if verbose:
        print(f"  --> {method} {url}  auth={log_auth}  body_len={len(body_bytes)}")

    req = urllib.request.Request(
        url,
        data=body_bytes,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Basic {creds}",
        },
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            status = resp.status
            raw = resp.read().decode("utf-8", errors="replace")
            if verbose:
                print(f"  <-- {status} body_len={len(raw)}")
            try:
                return status, json.loads(raw)
            except json.JSONDecodeError:
                return status, {"raw": raw}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
        if verbose:
            print(f"  <-- HTTP {exc.code}  body={raw[:200]}")
        try:
            return exc.code, json.loads(raw)
        except json.JSONDecodeError:
            return exc.code, {"raw": raw}
    except urllib.error.URLError as exc:
        if verbose:
            print(f"  <-- URLError {exc.reason}")
        return 0, {"error": str(exc.reason)}


# ---------------------------------------------------------------------------
# ServiceNow
# ---------------------------------------------------------------------------
def _snow_push(ticket: dict, verbose: bool, dry_run: bool) -> str | None:
    """
    Push one ticket to ServiceNow.
    Returns the INC number on success, None on failure.
    """
    instance = os.environ.get("SNOW_INSTANCE", "")
    user = os.environ.get("SNOW_USER", "")
    password = os.environ.get("SNOW_PASSWORD", "")

    if not instance or not user or not password:
        print("ERREUR: Variables SNOW_INSTANCE / SNOW_USER / SNOW_PASSWORD manquantes.", file=sys.stderr)
        return None

    url = f"https://{instance}.service-now.com/api/now/table/incident"

    severity = ticket.get("priority", ticket.get("severity", "medium")).lower()
    urgency = SEVERITY_MAP_SNOW.get(severity, "3")

    # Build description from context block or acceptance list
    context = ticket.get("context", {})
    if isinstance(context, dict) and context:
        desc_parts = [f"{k}: {v}" for k, v in context.items()]
        description = "\n".join(desc_parts)
    else:
        # Fallback: reconstruct from raw YAML acceptance lines
        raw = ticket.get("_raw", "")
        acc_lines = []
        in_acc = False
        for line in raw.splitlines():
            if line.startswith("acceptance:"):
                in_acc = True
                continue
            if in_acc:
                if line.startswith(" ") or line.startswith("\t"):
                    acc_lines.append(line.strip().lstrip("- ").strip('"'))
                else:
                    break
        description = "\n".join(acc_lines) if acc_lines else f"NetWatch ticket {ticket.get('id', 'N/A')}"

    payload = {
        "short_description": ticket.get("title", ticket.get("id", "NetWatch Alert")),
        "urgency": urgency,
        "category": ticket.get("category", "network"),
        "description": description,
        "caller_id": user,
        "impact": urgency,  # mirror urgency for priority calculation
    }

    if dry_run:
        print(f"  [DRY-RUN] POST {url}")
        print(f"  payload: {json.dumps(payload, ensure_ascii=False)[:200]}")
        return "INC_DRYRUN_0000000"

    status, resp = _http_request("POST", url, payload, user, password, verbose)
    if status in (200, 201):
        inc_number = (resp.get("result") or {}).get("number", "")
        if inc_number:
            return inc_number
        if verbose:
            print(f"  WARN: réponse sans number: {json.dumps(resp)[:200]}")
        return None
    else:
        print(f"  ERREUR ServiceNow: HTTP {status} — {str(resp)[:200]}", file=sys.stderr)
        return None


# ---------------------------------------------------------------------------
# JIRA
# ---------------------------------------------------------------------------
def _jira_push(ticket: dict, verbose: bool, dry_run: bool) -> str | None:
    """
    Push one ticket to JIRA.
    Returns the issue key (e.g. NOC-42) on success, None on failure.
    """
    jira_url = os.environ.get("JIRA_URL", "").rstrip("/")
    user = os.environ.get("JIRA_USER", "")
    token = os.environ.get("JIRA_TOKEN", "")
    project_key = os.environ.get("JIRA_PROJECT_KEY", "NOC")

    if not jira_url or not user or not token:
        print("ERREUR: Variables JIRA_URL / JIRA_USER / JIRA_TOKEN manquantes.", file=sys.stderr)
        return None

    url = f"{jira_url}/rest/api/3/issue"

    severity = ticket.get("priority", ticket.get("severity", "medium")).lower()
    priority_name = PRIORITY_MAP_JIRA.get(severity, "Medium")
    category = ticket.get("category", "network")

    # Build description in JIRA's Atlassian Document Format (ADF)
    raw = ticket.get("_raw", "")
    acc_lines = []
    in_acc = False
    for line in raw.splitlines():
        if line.startswith("acceptance:"):
            in_acc = True
            continue
        if in_acc:
            if line.startswith(" ") or line.startswith("\t"):
                acc_lines.append(line.strip().lstrip("- ").strip('"'))
            else:
                break
    desc_text = "\n".join(acc_lines) if acc_lines else f"NetWatch ticket {ticket.get('id', 'N/A')}"

    payload = {
        "fields": {
            "project": {"key": project_key},
            "summary": ticket.get("title", ticket.get("id", "NetWatch Alert")),
            "issuetype": {"name": "Bug"},
            "priority": {"name": priority_name},
            "labels": [category, "netwatch"],
            "description": {
                "type": "doc",
                "version": 1,
                "content": [
                    {
                        "type": "paragraph",
                        "content": [
                            {
                                "type": "text",
                                "text": desc_text,
                            }
                        ],
                    }
                ],
            },
        }
    }

    if dry_run:
        print(f"  [DRY-RUN] POST {url}")
        print(f"  payload: {json.dumps(payload, ensure_ascii=False)[:200]}")
        return f"{project_key}-DRYRUN"

    status, resp = _http_request("POST", url, payload, user, token, verbose)
    if status in (200, 201):
        issue_key = resp.get("key", "")
        if issue_key:
            return issue_key
        if verbose:
            print(f"  WARN: réponse sans key: {json.dumps(resp)[:200]}")
        return None
    else:
        print(f"  ERREUR JIRA: HTTP {status} — {str(resp)[:200]}", file=sys.stderr)
        return None


# ---------------------------------------------------------------------------
# Discover ticket drafts
# ---------------------------------------------------------------------------
def find_drafts() -> list[Path]:
    """Return all *.yml files under agents-deck/agents/*/tickets/drafts/."""
    if not AGENTS_DIR.exists():
        return []
    drafts = []
    for agent_dir in sorted(AGENTS_DIR.iterdir()):
        drafts_dir = agent_dir / "tickets" / "drafts"
        if drafts_dir.is_dir():
            drafts.extend(sorted(drafts_dir.glob("*.yml")))
    return drafts


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    _load_dotenv()

    parser = argparse.ArgumentParser(
        description="NetWatch ITSM Sync — pousse les tickets draft vers ServiceNow ou JIRA."
    )
    parser.add_argument(
        "--backend",
        choices=["servicenow", "jira", "none"],
        default=None,
        help="Backend ITSM cible (override ITSM_BACKEND env). Défaut: none.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simule les appels API sans créer de tickets ni modifier les YAMLs.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Affiche les détails des requêtes HTTP (credentials masqués).",
    )
    args = parser.parse_args()

    backend = (args.backend or os.environ.get("ITSM_BACKEND", "none")).lower()

    # Discover drafts
    drafts = find_drafts()
    if not drafts:
        print("INFO: Aucun ticket draft trouvé sous agents-deck/agents/*/tickets/drafts/")
        sys.exit(0)

    if args.verbose:
        print(f"INFO: {len(drafts)} fichier(s) draft trouvé(s)")
        print(f"INFO: backend={backend}  dry_run={args.dry_run}")

    # Parse and filter
    tickets = []
    skipped_dup = []
    errors = []
    for path in drafts:
        t = read_ticket(path)
        if "_error" in t:
            errors.append((path, t["_error"]))
            continue
        if "itsm_id" in t and t["itsm_id"]:
            skipped_dup.append((path, t.get("itsm_id", "")))
            continue
        tickets.append(t)

    # Summary for "none" mode or info
    if backend == "none":
        print(f"\n=== Tickets en attente de synchronisation ITSM ({len(tickets)}) ===")
        for t in tickets:
            tid = t.get("id", "?")
            title = t.get("title", "Sans titre")
            sev = t.get("priority", t.get("severity", "?"))
            cat = t.get("category", "?")
            agent_path = Path(t["_path"]).parts
            agent_name = "?"
            for i, part in enumerate(agent_path):
                if part == "agents" and i + 1 < len(agent_path):
                    agent_name = agent_path[i + 1]
                    break
            print(f"  [{sev.upper():<8}] {tid:<20} {cat:<12} {title[:60]}")
        if skipped_dup:
            print(f"\n=== Déjà synchronisés ({len(skipped_dup)}) ===")
            for path, itsm_id in skipped_dup:
                print(f"  SKIP {path.name if isinstance(path, Path) else path} → {itsm_id}")
        if errors:
            print(f"\n=== Erreurs de lecture ({len(errors)}) ===")
            for path, err in errors:
                print(f"  ERREUR {path}: {err}")
        sys.exit(0)

    # Push to ITSM
    created = []
    failed = []

    for t in tickets:
        tid = t.get("id", Path(t["_path"]).stem)
        title = t.get("title", "Sans titre")
        if args.verbose:
            print(f"\n→ Traitement {tid}: {title[:60]}")

        itsm_id = None
        if backend == "servicenow":
            itsm_id = _snow_push(t, args.verbose, args.dry_run)
        elif backend == "jira":
            itsm_id = _jira_push(t, args.verbose, args.dry_run)

        if itsm_id:
            created.append((tid, itsm_id, t["_path"]))
            if not args.dry_run:
                write_itsm_id(Path(t["_path"]), itsm_id)
                print(f"OK: {tid} → {itsm_id}  (YAML mis à jour)")
            else:
                print(f"[DRY-RUN] {tid} → {itsm_id}")
        else:
            failed.append(tid)
            print(f"ECHEC: {tid} — synchronisation impossible", file=sys.stderr)

    # Final summary
    print(f"\n=== Résumé ===")
    print(f"  Créés   : {len(created)}")
    print(f"  Echecs  : {len(failed)}")
    print(f"  Skippés : {len(skipped_dup)} (déjà synchro)")
    for tid, itsm_id, _ in created:
        backend_prefix = "INC" if backend == "servicenow" else os.environ.get("JIRA_PROJECT_KEY", "NOC")
        print(f"  CREE [{backend}] {tid} → {itsm_id}")

    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
