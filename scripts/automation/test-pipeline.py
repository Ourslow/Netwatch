#!/usr/bin/env python3
"""
test-pipeline.py — Validation du pipeline ES → Teams (sans n8n)
Simule ce que le workflow n8n ferait : query ES → format → POST Teams

Usage :
  # Test complet avec webhook réel Teams :
  python3 scripts/automation/test-pipeline.py --teams-url "https://xxx.webhook.office.com/..."

  # Test avec serveur local (validation sans Teams) :
  python3 scripts/automation/test-pipeline.py --teams-url "http://localhost:9999/test"

  # Dry run (aucun envoi) :
  python3 scripts/automation/test-pipeline.py --teams-url "" --dry-run
"""
import argparse
import json
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone


QUERY = {
    "size": 50,
    "query": {
        "bool": {
            "must": [
                {"range": {"@timestamp": {"gte": "now-5m", "lte": "now"}}},
                {
                    "bool": {
                        "should": [
                            {"term": {"alert.severity": 1}},
                            {"term": {"alert.severity": 2}},
                            {"term": {"priority": 1}},
                            {"term": {"priority": 2}},
                            {"match": {"event.severity_label": "high"}},
                            {"match": {"event.severity_label": "critical"}},
                            {"terms": {"severity": ["high", "critical"]}},
                        ],
                        "minimum_should_match": 1,
                    }
                },
            ]
        }
    },
    "sort": [{"@timestamp": {"order": "desc"}}],
    "_source": [
        "@timestamp", "src_ip", "dest_ip", "alert", "priority", "msg",
        "proto", "dest_port", "engine",
    ],
}


def do_es_query(es_url, index="suricata-*,snort-*"):
    url = f"{es_url}/{index}/_search"
    data = json.dumps(QUERY).encode()
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())


def format_alerts(hits):
    alerts = []
    for hit in hits:
        src = hit["_source"]
        alert_obj = src.get("alert", {})
        alerts.append({
            "ts": src.get("@timestamp", "N/A"),
            "src_ip": src.get("src_ip", "N/A"),
            "dest_ip": src.get("dest_ip", "N/A"),
            "rule": alert_obj.get("signature") or src.get("msg") or "Règle inconnue",
            "severity": alert_obj.get("severity") or src.get("priority") or "N/A",
            "proto": src.get("proto", "N/A"),
            "dest_port": src.get("dest_port", "N/A"),
            "engine": src.get("engine", hit.get("_index", "?").split("-")[0]),
        })
    return alerts


def build_teams_card(alerts, portal_url="http://localhost:3000"):
    count = len(alerts)
    top = alerts[:5]
    fact_sets = []
    for a in top:
        fact_sets.append({
            "type": "FactSet",
            "facts": [
                {"title": "Heure", "value": a["ts"]},
                {"title": "IP source", "value": a["src_ip"]},
                {"title": "IP dest", "value": f"{a['dest_ip']}:{a['dest_port']}"},
                {"title": "Règle", "value": str(a["rule"])[:80]},
                {"title": "Sévérité", "value": str(a["severity"])},
                {"title": "Moteur", "value": a["engine"]},
                {"title": "Proto", "value": a["proto"]},
            ],
        })
    return {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.4",
                "body": [
                    {
                        "type": "TextBlock",
                        "text": f"NetWatch — {count} alerte(s) HIGH/CRITICAL",
                        "weight": "Bolder", "size": "Large", "color": "Attention", "wrap": True,
                    },
                    {
                        "type": "TextBlock",
                        "text": f"Dernières 5 minutes — {datetime.now(timezone.utc).isoformat()}",
                        "size": "Small", "isSubtle": True,
                    },
                    *fact_sets,
                ],
                "actions": [{
                    "type": "Action.OpenUrl",
                    "title": "Ouvrir le portail NetWatch",
                    "url": portal_url,
                }],
            },
        }],
    }


def post_webhook(url, payload):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
    except urllib.error.URLError as e:
        return 0, str(e)


def main():
    parser = argparse.ArgumentParser(description="Test pipeline NetWatch ES → Teams")
    parser.add_argument("--teams-url", default="", help="URL webhook Teams")
    parser.add_argument("--es-url", default="http://localhost:9200", help="URL Elasticsearch")
    parser.add_argument("--dry-run", action="store_true", help="Ne pas envoyer vers Teams")
    args = parser.parse_args()

    print("=== NetWatch Pipeline Test ===")
    print(f"ES     : {args.es_url}")
    print(f"Teams  : {args.teams_url or '(non défini)'}")
    print(f"DryRun : {args.dry_run}")
    print()

    # 1. Query ES
    print("[1/3] Query Elasticsearch (last 5min, severity high/critical)...")
    try:
        result = do_es_query(args.es_url)
    except Exception as e:
        print(f"      ECHEC — {e}", file=sys.stderr)
        sys.exit(1)

    total = result["hits"]["total"]["value"]
    print(f"      {total} alerte(s) trouvée(s)")

    if total == 0:
        print("      Aucune alerte — pipeline OK (rien à envoyer)")
        print("\n[INFO] Pour injecter des alertes de test :")
        print("  python3 simulate-traffic.py --hours 1 --intensity high --attack")
        sys.exit(0)

    hits = result["hits"]["hits"]

    # 2. Format
    print("[2/3] Formatage des alertes...")
    alerts = format_alerts(hits)
    for a in alerts[:3]:
        print(f"      [{a['engine']}] {a['src_ip']} => {a['rule'][:50]} (sev={a['severity']})")
    if len(alerts) > 3:
        print(f"      ... et {len(alerts)-3} autres")

    # 3. Build & Send
    card = build_teams_card(alerts)
    print(f"\n[3/3] Payload Teams OK ({len(json.dumps(card))} octets)")

    if args.dry_run or not args.teams_url:
        print("      DRY RUN — payload non envoyé")
        print("      Aperçu Teams Card :")
        card_body = card["attachments"][0]["content"]["body"]
        for item in card_body[:2]:
            if item.get("type") == "TextBlock":
                print(f"        {item.get('text','')}")
        print("\n=== TEST OK (dry run) ===")
        sys.exit(0)

    print(f"      POST {args.teams_url}...")
    status, body = post_webhook(args.teams_url, card)
    print(f"      HTTP {status} — {body[:200]}")

    if status in (200, 202):
        print("\n=== TEST OK — Notification envoyée ===")
    else:
        print(f"\n=== ECHEC HTTP {status} ===")
        sys.exit(1)


if __name__ == "__main__":
    main()
