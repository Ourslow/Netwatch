#!/usr/bin/env bash
# Usage: ./merge-agent.sh <agent_id> <ticket_id>
# Ex:    ./merge-agent.sh security T_004
set -euo pipefail

AGENT_ID="${1:?Usage: $0 <agent_id> <ticket_id>}"
TICKET_ID="${2:?Usage: $0 <agent_id> <ticket_id>}"
BRANCH="agent/${AGENT_ID}/active"
ROOT="$(git rev-parse --show-toplevel)"

cd "$ROOT"

# 1) S'assurer qu'on est sur main et à jour
git checkout main
git fetch origin main
git merge --ff-only origin/main 2>/dev/null || true

# 2) Merger la branche agent
git fetch origin "${BRANCH}"
git merge "origin/${BRANCH}" --no-ff \
  -m "merge(${AGENT_ID}): ${TICKET_ID} — $(git log -1 --pretty=%s "origin/${BRANCH}")"

# 3) status.yml → done
STATUS="agents-deck/agents/${AGENT_ID}/status.yml"
python3 - "$STATUS" "$TICKET_ID" <<'PY'
import sys, yaml
from datetime import datetime, timezone
path, ticket = sys.argv[1], sys.argv[2]
with open(path) as f:
    d = yaml.safe_load(f) or {}
d["state"]          = "done"
d["current_ticket"] = None
d["last_ticket"]    = ticket
d["last_activity"]  = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
with open(path, "w") as f:
    yaml.dump(d, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
print(f"  {path}: state=done, last_ticket={ticket}")
PY

# 4) team-lead/state.yml → expected_state=done
STATE="agents-deck/team-lead/state.yml"
SHA=$(git rev-parse --short HEAD)
python3 - "$STATE" "$AGENT_ID" "$TICKET_ID" "$SHA" <<'PY'
import sys, yaml
from datetime import datetime, timezone
path, agent, ticket, sha = sys.argv[1:]
with open(path) as f:
    d = yaml.safe_load(f) or {}
d["agents"][agent]["expected_state"]     = "done"
d["agents"][agent]["last_merged_ticket"] = ticket
d["agents"][agent]["last_merged_sha"]    = sha
d["last_update"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
with open(path, "w") as f:
    yaml.dump(d, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
print(f"  {path}: {agent}.expected_state=done")
PY

# 5) Commit de sync + push
git add "$STATUS" "$STATE"
git -c user.name="Fuskerrs" -c user.email="fuskerrs@netwatch.local" \
  commit -m "chore(coordinator): ${AGENT_ID} → done, ${TICKET_ID} merged" || true

git push origin main
echo ""
echo "✓ ${AGENT_ID} / ${TICKET_ID} mergé → main, état synchro"
