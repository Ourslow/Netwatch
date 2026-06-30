#!/usr/bin/env python3
"""
escalade.py — NetWatch Intelligent Escalation Engine
Reads IOC risk scores and triggers 3 actions for IPs with score >= threshold (default 80):
  1. POST autoblock webhook → http://localhost:5001/webhook/alert
  2. Create critical ticket → create-ticket.py (stdin JSON)
  3. POST Teams urgent Adaptive Card (if TEAMS_WEBHOOK_URL env set)

Score source priority:
  1. scripts/automation/ioc-score.py (subprocess) — T_014 when merged
  2. GET /api/ioc-scores (HTTP, netwatch portal fallback)
  3. Inline ES scoring (minimal logic — always available)

Usage:
    python3 escalade.py [--threshold 80] [--es-url http://localhost:9200]
                        [--autoblock-url http://localhost:5001/webhook/alert]
                        [--portal-url http://localhost:5050]
                        [--dry-run] [--verbose]
"""

import argparse
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone, timedelta
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent.parent
HISTORY_FILE = SCRIPT_DIR / "escalade-history.json"
CREATE_TICKET_SCRIPT = SCRIPT_DIR / "create-ticket.py"
IOC_SCORE_SCRIPT = SCRIPT_DIR / "ioc-score.py"

DEFAULT_ES_URL = "http://localhost:9200"
DEFAULT_AUTOBLOCK_URL = "http://localhost:5001/webhook/alert"
DEFAULT_PORTAL_URL = "http://localhost:5050"
DEFAULT_THRESHOLD = 80
HISTORY_TTL_HOURS = 4

# Weights for inline scoring
WEIGHT_CRITICAL = 5      # points per critical alert
WEIGHT_HIGH = 2          # points per high alert
WEIGHT_MULTI_ENGINE = 15 # bonus for IP seen in 3+ engines
WEIGHT_TWO_ENGINES = 8   # bonus for IP seen in 2 engines
WEIGHT_VOLUME_10 = 10    # bonus if total alerts >= 10
WEIGHT_VOLUME_20 = 15    # bonus if total alerts >= 20
MAX_SCORE = 100


# ---------------------------------------------------------------------------
# History / anti-duplicate management
# ---------------------------------------------------------------------------

def load_history() -> dict:
    """Load escalation history from JSON file."""
    if not HISTORY_FILE.exists():
        return {}
    try:
        raw = HISTORY_FILE.read_text(encoding="utf-8")
        return json.loads(raw)
    except (json.JSONDecodeError, OSError):
        return {}


def save_history(history: dict) -> None:
    """Save escalation history to JSON file."""
    try:
        HISTORY_FILE.write_text(json.dumps(history, indent=2), encoding="utf-8")
    except OSError as e:
        print(f"WARN: cannot write history file: {e}", file=sys.stderr)


def is_in_cooldown(ip: str, history: dict, ttl_hours: int = HISTORY_TTL_HOURS) -> bool:
    """Return True if this IP was escalated within the TTL window."""
    entry = history.get(ip)
    if not entry:
        return False
    try:
        last_ts = datetime.fromisoformat(entry["escalated_at"])
        cutoff = datetime.now(timezone.utc) - timedelta(hours=ttl_hours)
        return last_ts > cutoff
    except (KeyError, ValueError):
        return False


def record_escalation(ip: str, score: int, history: dict) -> None:
    """Record an escalation in the history dict (in-memory, caller must save)."""
    history[ip] = {
        "escalated_at": datetime.now(timezone.utc).isoformat(),
        "score": score,
    }


def purge_expired_history(history: dict, ttl_hours: int = HISTORY_TTL_HOURS) -> dict:
    """Remove entries older than TTL to keep the file compact."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=ttl_hours)
    return {
        ip: v for ip, v in history.items()
        if datetime.fromisoformat(v.get("escalated_at", "1970-01-01T00:00:00+00:00")) > cutoff
    }


# ---------------------------------------------------------------------------
# Score sources
# ---------------------------------------------------------------------------

def scores_from_ioc_score_py(threshold: int, verbose: bool) -> list[dict] | None:
    """
    Try to get scores by running ioc-score.py as subprocess.
    Expected stdout: JSON list of {"ip": "...", "score": N, "reason": "..."}.
    Returns None if script not found or fails.
    """
    if not IOC_SCORE_SCRIPT.exists():
        if verbose:
            print(f"DEBUG: {IOC_SCORE_SCRIPT} not found — skipping subprocess source", file=sys.stderr)
        return None

    try:
        import tempfile, os as _os
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            tmp_path = tmp.name
        try:
            result = subprocess.run(
                [sys.executable, str(IOC_SCORE_SCRIPT), "--threshold", str(threshold), "--output", tmp_path],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                if verbose:
                    print(f"DEBUG: ioc-score.py exited {result.returncode}: {result.stderr[:200]}", file=sys.stderr)
                return None
            with open(tmp_path, encoding="utf-8") as f:
                return json.load(f)
        finally:
            _os.unlink(tmp_path) if _os.path.exists(tmp_path) else None
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError) as e:
        if verbose:
            print(f"DEBUG: ioc-score.py subprocess error: {e}", file=sys.stderr)
        return None


def scores_from_api(portal_url: str, threshold: int, verbose: bool) -> list[dict] | None:
    """
    Try to get scores from GET /api/ioc-scores.
    Expected response: {"scores": [{"ip": "...", "score": N, "reason": "..."}, ...]}
    Returns None if the endpoint is unreachable or returns unexpected data.
    """
    url = f"{portal_url.rstrip('/')}/api/ioc-scores"
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
        scores = data.get("scores", data if isinstance(data, list) else [])
        # Filter by threshold
        return [s for s in scores if s.get("score", 0) >= threshold]
    except (urllib.error.URLError, json.JSONDecodeError, OSError) as e:
        if verbose:
            print(f"DEBUG: /api/ioc-scores unreachable: {e}", file=sys.stderr)
        return None


def scores_inline(es_url: str, threshold: int, verbose: bool) -> list[dict]:
    """
    Minimal inline scoring: query ES for recent alerts (last 30 min),
    compute a risk score per src_ip, return IPs >= threshold.

    Score formula:
      base = critical_count * WEIGHT_CRITICAL + high_count * WEIGHT_HIGH
      + multi-engine bonus + volume bonus
      capped at MAX_SCORE
    """
    window = "now-30m"
    query = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": window, "lte": "now"}}}
                ]
            }
        },
        "aggs": {
            "by_ip": {
                "terms": {"field": "src_ip", "size": 200, "min_doc_count": 1},
                "aggs": {
                    "critical_count": {
                        "filter": {
                            "bool": {
                                "should": [
                                    {"term": {"alert.severity": 1}},
                                    {"term": {"severity": "critical"}},
                                    {"term": {"event.severity_label": "critical"}},
                                ],
                                "minimum_should_match": 1,
                            }
                        }
                    },
                    "high_count": {
                        "filter": {
                            "bool": {
                                "should": [
                                    {"term": {"alert.severity": 2}},
                                    {"term": {"severity": "high"}},
                                    {"term": {"event.severity_label": "high"}},
                                ],
                                "minimum_should_match": 1,
                            }
                        }
                    },
                    "engines": {
                        "terms": {"field": "engine", "size": 10}
                    },
                }
            }
        }
    }

    url = f"{es_url.rstrip('/')}/suricata-*,snort-*,zeek-*/_search"
    try:
        body = json.dumps(query).encode()
        req = urllib.request.Request(
            url, data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
    except (urllib.error.URLError, json.JSONDecodeError, OSError) as e:
        if verbose:
            print(f"DEBUG: ES inline scoring error: {e}", file=sys.stderr)
        return []

    buckets = data.get("aggregations", {}).get("by_ip", {}).get("buckets", [])
    results = []

    for bucket in buckets:
        ip = bucket.get("key", "")
        if not ip or ip in ("unknown", "0.0.0.0"):
            continue

        total = bucket.get("doc_count", 0)
        crit = bucket.get("critical_count", {}).get("doc_count", 0)
        high = bucket.get("high_count", {}).get("doc_count", 0)
        engine_buckets = bucket.get("engines", {}).get("buckets", [])
        engine_count = len(engine_buckets)
        engine_names = [e.get("key", "") for e in engine_buckets]

        score = crit * WEIGHT_CRITICAL + high * WEIGHT_HIGH

        if engine_count >= 3:
            score += WEIGHT_MULTI_ENGINE
        elif engine_count == 2:
            score += WEIGHT_TWO_ENGINES

        if total >= 20:
            score += WEIGHT_VOLUME_20
        elif total >= 10:
            score += WEIGHT_VOLUME_10

        score = min(score, MAX_SCORE)

        if score >= threshold:
            # Build reason string
            parts = []
            if total:
                parts.append(f"{total} alerte(s)")
            if crit:
                parts.append(f"{crit} critique(s)")
            if engine_count > 1:
                parts.append(f"{engine_count} moteurs ({', '.join(engine_names)})")
            reason = " · ".join(parts) if parts else "score calculé"

            results.append({
                "ip": ip,
                "score": score,
                "reason": reason,
                "detail": {
                    "total_alerts": total,
                    "critical_alerts": crit,
                    "high_alerts": high,
                    "engines": engine_names,
                },
            })

    results.sort(key=lambda x: x["score"], reverse=True)
    return results


# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------

def action_autoblock(ip: str, score: int, autoblock_url: str, dry_run: bool, verbose: bool) -> bool:
    """POST to autoblock webhook. Returns True on success."""
    payload = {
        "alerts": [
            {
                "labels": {
                    "ip": ip,
                    "severity": "critical",
                },
                "annotations": {
                    "summary": f"Score risque {score}/100 — escalade automatique",
                },
            }
        ]
    }
    if dry_run:
        print(f"  [DRY-RUN] POST {autoblock_url} body={json.dumps(payload)}")
        return True

    try:
        body = json.dumps(payload).encode()
        req = urllib.request.Request(
            autoblock_url, data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            status = resp.status
        if verbose:
            print(f"  [autoblock] POST {autoblock_url} → HTTP {status}")
        return status < 300
    except urllib.error.URLError as e:
        print(f"  [autoblock] ERREUR POST {autoblock_url}: {e}", file=sys.stderr)
        return False


def action_create_ticket(ip: str, score: int, reason: str, dry_run: bool, verbose: bool) -> bool:
    """
    Pipe alert JSON to create-ticket.py. Returns True on success.
    """
    if not CREATE_TICKET_SCRIPT.exists():
        print(f"  [ticket] SKIP: {CREATE_TICKET_SCRIPT} introuvable", file=sys.stderr)
        return False

    alert_json = json.dumps({
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip": ip,
        "dest_ip": "0.0.0.0",
        "alert": {
            "signature": f"ESCALADE AUTOMATIQUE — IP {ip} (score {score}/100)",
            "severity": 1,
            "category": "Escalade risque élevé",
        },
        "severity": "critical",
        "engine": "escalade",
        "escalade": {
            "score": score,
            "reason": reason,
        },
    })

    if dry_run:
        print(f"  [DRY-RUN] echo '<json>' | python3 create-ticket.py")
        if verbose:
            print(f"  [DRY-RUN] json={alert_json}")
        return True

    try:
        result = subprocess.run(
            [sys.executable, str(CREATE_TICKET_SCRIPT)],
            input=alert_json,
            capture_output=True,
            text=True,
            timeout=30,
        )
        output = (result.stdout or "").strip()
        err = (result.stderr or "").strip()

        if result.returncode == 0:
            if verbose or output:
                print(f"  [ticket] {output or 'OK'}")
            return True
        else:
            # Exit 0 with SKIP is also fine (duplicate)
            if "SKIP" in err:
                if verbose:
                    print(f"  [ticket] {err}")
                return True
            print(f"  [ticket] ERREUR (exit {result.returncode}): {err}", file=sys.stderr)
            return False
    except (subprocess.TimeoutExpired, OSError) as e:
        print(f"  [ticket] ERREUR subprocess: {e}", file=sys.stderr)
        return False


def action_teams(ip: str, score: int, reason: str, dry_run: bool, verbose: bool) -> bool:
    """
    POST urgent Adaptive Card to Teams webhook (TEAMS_WEBHOOK_URL env var).
    Returns True on success or if webhook not configured (graceful skip).
    """
    webhook_url = os.environ.get("TEAMS_WEBHOOK_URL", "").strip()
    if not webhook_url:
        if verbose:
            print("  [teams] TEAMS_WEBHOOK_URL non définie — skip")
        return True  # not a failure

    payload = {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": [
                        {
                            "type": "TextBlock",
                            "text": f"\U0001f6a8 ESCALADE — IP {ip} (score {score}/100)",
                            "size": "Large",
                            "weight": "Bolder",
                            "color": "Attention",
                            "wrap": True,
                        },
                        {
                            "type": "TextBlock",
                            "text": f"Raison : {reason}",
                            "wrap": True,
                            "isSubtle": True,
                        },
                        {
                            "type": "FactSet",
                            "facts": [
                                {"title": "IP", "value": ip},
                                {"title": "Score", "value": f"{score}/100"},
                                {"title": "Horodatage", "value": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")},
                                {"title": "Actions", "value": "Autoblock ✓ · Ticket créé ✓"},
                            ],
                        },
                    ],
                    "actions": [
                        {
                            "type": "Action.OpenUrl",
                            "title": "Ouvrir le portail NetWatch",
                            "url": "http://localhost:5050/alerts",
                        }
                    ],
                },
            }
        ],
    }

    if dry_run:
        print(f"  [DRY-RUN] POST {webhook_url[:60]}... (Teams urgent card)")
        return True

    try:
        body = json.dumps(payload).encode()
        req = urllib.request.Request(
            webhook_url, data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            status = resp.status
        if verbose:
            print(f"  [teams] POST → HTTP {status}")
        return status < 300
    except urllib.error.URLError as e:
        print(f"  [teams] ERREUR POST Teams webhook: {e}", file=sys.stderr)
        return False


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def get_scores(args) -> list[dict]:
    """
    Try score sources in priority order, return list of {"ip", "score", "reason"}.
    Each source should return IPs already filtered by threshold.
    """
    # 1. ioc-score.py subprocess (T_014)
    scores = scores_from_ioc_score_py(args.threshold, args.verbose)
    if scores is not None:
        if args.verbose:
            print(f"DEBUG: using ioc-score.py subprocess ({len(scores)} IPs)", file=sys.stderr)
        return scores

    # 2. HTTP API fallback
    scores = scores_from_api(args.portal_url, args.threshold, args.verbose)
    if scores is not None:
        if args.verbose:
            print(f"DEBUG: using /api/ioc-scores ({len(scores)} IPs)", file=sys.stderr)
        return scores

    # 3. Inline ES scoring
    if args.verbose:
        print("DEBUG: using inline ES scoring", file=sys.stderr)
    return scores_inline(args.es_url, args.threshold, args.verbose)


def escalate_ip(ip: str, score: int, reason: str, args) -> dict:
    """Run all 3 escalation actions for an IP. Returns result summary."""
    print(f"\n==> Escalade IP {ip} | score {score}/100 | {reason}")

    r1 = action_autoblock(ip, score, args.autoblock_url, args.dry_run, args.verbose)
    r2 = action_create_ticket(ip, score, reason, args.dry_run, args.verbose)
    r3 = action_teams(ip, score, reason, args.dry_run, args.verbose)

    return {"ip": ip, "score": score, "autoblock": r1, "ticket": r2, "teams": r3}


def main():
    parser = argparse.ArgumentParser(
        description="NetWatch Intelligent Escalation — déclenche autoblock+ticket+Teams pour IPs score≥seuil."
    )
    parser.add_argument(
        "--threshold", "-t",
        type=int, default=DEFAULT_THRESHOLD,
        help=f"Score minimum pour escalade (défaut: {DEFAULT_THRESHOLD})",
    )
    parser.add_argument(
        "--es-url",
        default=DEFAULT_ES_URL,
        help=f"URL Elasticsearch (défaut: {DEFAULT_ES_URL})",
    )
    parser.add_argument(
        "--autoblock-url",
        default=DEFAULT_AUTOBLOCK_URL,
        help=f"URL webhook autoblock (défaut: {DEFAULT_AUTOBLOCK_URL})",
    )
    parser.add_argument(
        "--portal-url",
        default=DEFAULT_PORTAL_URL,
        help=f"URL portail NetWatch pour fallback /api/ioc-scores (défaut: {DEFAULT_PORTAL_URL})",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simuler les actions sans effectuer de POST ni écrire de ticket",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Afficher les détails de chaque étape",
    )
    parser.add_argument(
        "--history-file",
        default=str(HISTORY_FILE),
        help=f"Fichier JSON historique anti-doublon (défaut: {HISTORY_FILE})",
    )
    parser.add_argument(
        "--ttl",
        type=int, default=HISTORY_TTL_HOURS,
        help=f"TTL en heures pour anti-doublon (défaut: {HISTORY_TTL_HOURS}h)",
    )
    args = parser.parse_args()

    # Override history file if custom
    global HISTORY_FILE
    HISTORY_FILE = Path(args.history_file)

    print(f"[escalade] {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} "
          f"| seuil={args.threshold} | ttl={args.ttl}h"
          + (" | DRY-RUN" if args.dry_run else ""))

    # Load + clean history
    history = load_history()
    history = purge_expired_history(history, args.ttl)

    # Get scored IPs
    scored_ips = get_scores(args)

    if not scored_ips:
        print("[escalade] Aucune IP au-dessus du seuil — rien à faire.")
        save_history(history)
        return

    print(f"[escalade] {len(scored_ips)} IP(s) avec score >= {args.threshold}")

    results = []
    escalated = 0
    skipped = 0

    for entry in scored_ips:
        ip = entry.get("ip", "")
        score = entry.get("score", 0)
        reason = entry.get("reason", "score élevé")

        if not ip:
            continue

        if is_in_cooldown(ip, history, args.ttl):
            if args.verbose:
                print(f"  SKIP {ip} (cooldown {args.ttl}h actif)")
            skipped += 1
            continue

        result = escalate_ip(ip, score, reason, args)
        results.append(result)
        record_escalation(ip, score, history)
        escalated += 1

    save_history(history)

    # Summary
    print(f"\n[escalade] Résumé : {escalated} IP(s) escaladée(s), {skipped} ignorée(s) (cooldown)")
    if results:
        ok = sum(1 for r in results if r["autoblock"] and r["ticket"] and r["teams"])
        print(f"[escalade] {ok}/{len(results)} escalade(s) complète(s) (3/3 actions OK)")

    # Exit non-zero only if partial failures on escalated IPs
    failed = [r for r in results if not (r["autoblock"] and r["ticket"])]
    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
