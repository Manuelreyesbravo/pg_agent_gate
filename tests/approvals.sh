#!/usr/bin/env bash
# Human-in-the-middle approvals (0.3.0): an agent registered with
# requires_approval cannot commit its own proposal until an approver records
# consent with agent_gate.approve(). The approval only lifts the block -- the
# guards (max_rows, assertions, backstop) still run at commit. No self-approval
# is possible: an agent is behind the gate and cannot call approve(), and
# approve() is granted only to the agent_gate_approver group.
#
#   PG_CONFIG=/path/to/pg_config tests/cluster.sh init && tests/cluster.sh start
#   PG_CONFIG=/path/to/pg_config tests/approvals.sh
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PG_CONFIG=${PG_CONFIG:-pg_config}
BIN=$("$PG_CONFIG" --bindir)
export PGHOST=${PGHOST:-$ROOT/.testcluster}
export PGPORT=${PGPORT:-5499}
SUPERUSER=${SUPERUSER:-$(id -un)}
DB=agent_gate_approvals
AGENT=agent_gate_approvals_agent
APPROVER=agent_gate_approvals_approver
OUTSIDER=agent_gate_approvals_outsider

source "$(dirname "${BASH_SOURCE[0]}")/guard.sh"
trap 'release_claimed' EXIT
require_throwaway_cluster
claim_role "$AGENT"
claim_role "$APPROVER"
claim_role "$OUTSIDER"
claim_database "$DB"

"$BIN/psql" -X -U "$SUPERUSER" -d "$DB" -v ON_ERROR_STOP=1 -q \
    -v agent="$AGENT" -v approver="$APPROVER" >/dev/null <<SQL
CREATE EXTENSION pg_agent_gate;
CREATE TABLE orders (id int primary key, total numeric);
INSERT INTO orders SELECT g, g * 1000 FROM generate_series(1, 8) g;
GRANT SELECT, UPDATE, DELETE ON orders TO :"agent";
SELECT agent_gate.register_agent('approvals_agent', :'agent', 'needs approval agent',
                                 p_max_rows => 5, p_requires_approval => true);
GRANT agent_gate_approver TO :"approver";
SQL

failures=0
check() {
    local what=$1 expected=$2 got=$3
    if [[ "$got" == *"$expected"* ]]; then echo "  ok   $what"; else
        echo "  FAIL $what"; echo "       expected to contain: $expected"
        echo "       got: ${got//$'\n'/ }" | cut -c1-300; failures=$((failures + 1)); fi
}
run()     { "$BIN/psql" -X -U "$1" -d "$DB" -tAc "$2" 2>&1 || true; }
propose() { run "$1" "select agent_gate.propose('$2', '$3')" | grep -o '"proposal": [0-9]*' | grep -o '[0-9]*' | head -1; }

# 1. a requires_approval agent cannot commit its own proposal.
p1=$(propose "$AGENT" "update orders set total = 1 where id = 1" "lower the price")
check "1. commit without approval is refused, pending approval" "this agent requires approval" \
    "$(run "$AGENT" "select agent_gate.commit($p1)")"

# 2. an approver records consent, then the agent commits -> kept, approved_by recorded.
check "2a. an approver records consent" "\"approved_by\": \"$APPROVER\"" \
    "$(run "$APPROVER" "select agent_gate.approve($p1)")"
check "2b. the agent now commits, and it is kept" "\"outcome\": \"kept\"" \
    "$(run "$AGENT" "select agent_gate.commit($p1)")"
check "2c. the record names who approved" "$APPROVER" \
    "$(run "$SUPERUSER" "select approved_by from agent_gate_internal.executions where outcome = 'kept'")"

# 3. a role that is not an approver cannot approve.
p3=$(propose "$AGENT" "update orders set total = 3 where id = 3" "another change")
check "3. a non-approver role is refused by approve()" "permission denied" \
    "$(run "$OUTSIDER" "select agent_gate.approve($p3)")"

# 4. the guards still run after approval: an over-limit delete is aborted.
p4=$(propose "$AGENT" "delete from orders" "cleanup")
run "$APPROVER" "select agent_gate.approve($p4)" >/dev/null
check "4. an approved over-limit change is still aborted by max_rows" "more than this agent may change in one statement" \
    "$(run "$AGENT" "select agent_gate.commit($p4)")"

# 5. propose_and_commit cannot sidestep approval.
check "5. propose_and_commit is refused for a requires_approval agent" "requires approval" \
    "$(run "$AGENT" "select agent_gate.propose_and_commit('update orders set total = 5 where id = 5', 'lower the fifth row')")"

if [ "$failures" -ne 0 ]; then
    echo "$failures check(s) failed"
    exit 1
fi
echo "approvals: an agent commits only what an approver approved, and the guards still run"
