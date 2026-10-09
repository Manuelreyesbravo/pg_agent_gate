#!/usr/bin/env bash
# Does the record survive pg_dump and restore? And what does a database dump
# NOT carry?
#
# The README says the record survives pg_dump: its tables are marked with
# pg_extension_config_dump. Until this script that was a claim nobody had run.
#
# There is also one thing a database dump cannot carry, checked here instead of
# being discovered in production: register_agent marks the ROLE (ALTER ROLE ...
# SET agent_gate.agent), and roles belong to the cluster, not to the database.
# pg_dump leaves them out; pg_dumpall --globals-only has them. Restore a dump
# into another server without the globals and the record still says the role
# is an agent while the role itself is outside the gate.
#
# Not part of the pgrx test suite: it shells out to pg_dump. Run it against the
# throwaway cluster, started with the library preloaded:
#
#   PG_CONFIG=/path/to/pg_config tests/cluster.sh init
#   PG_CONFIG=/path/to/pg_config tests/cluster.sh start
#   PG_CONFIG=/path/to/pg_config tests/dump_restore.sh
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PG_CONFIG=${PG_CONFIG:-pg_config}
BIN=$("$PG_CONFIG" --bindir)
export PGHOST=${PGHOST:-$ROOT/.testcluster}
export PGPORT=${PGPORT:-5499}
SUPERUSER=${SUPERUSER:-$(id -un)}
ORIGIN=agent_gate_dumped
TARGET=agent_gate_restored
AGENT_ROLE=agent_gate_dump_billing
DUMP=$(mktemp "${TMPDIR:-/tmp}/agent_gate_dump.XXXXXX")

su() { "$BIN/psql" -X -U "$SUPERUSER" -v ON_ERROR_STOP=1 -q "$@"; }
value() { "$BIN/psql" -X -U "$SUPERUSER" -tA "$@"; }
# An agent session: every error is an answer to inspect, never a reason to stop.
agent() { "$BIN/psql" -X -U "$AGENT_ROLE" -tA "$@" 2>&1 || true; }
proposal_id() { sed -nE 's/.*"proposal": ([0-9]+).*/\1/p' <<<"$1" | head -1; }

# Claims the names instead of dropping whatever is there: see tests/guard.sh.
source "$(dirname "${BASH_SOURCE[0]}")/guard.sh"

cleanup() {
    release_claimed
    rm -f "$DUMP"
}
trap cleanup EXIT

require_throwaway_cluster
claim_role "$AGENT_ROLE"
claim_database "$ORIGIN"
claim_database "$TARGET"

# ------------------------------------------------------------- the origin --
su -d "$ORIGIN" -v agent_role="$AGENT_ROLE" >/dev/null <<'SQL'
CREATE EXTENSION pg_agent_gate;
CREATE EXTENSION pg_living_assertions;

CREATE TABLE customers (id int PRIMARY KEY, plan text NOT NULL);
INSERT INTO customers VALUES (1, 'free'), (2, 'pro'), (3, 'free');
GRANT USAGE ON SCHEMA public TO :"agent_role";
GRANT SELECT, UPDATE ON customers TO :"agent_role";

SELECT agent_gate.register_agent('billing', :'agent_role',
    'answers billing questions and upgrades plans', p_max_rows => 5);

-- A binding, so the restore has to bring back a row that points outside the
-- gate's own tables and still be enforced afterwards.
SELECT living_assertions.declare('every_customer_has_a_plan',
    'a kept write may never leave a customer without a plan',
    'select not exists (select 1 from public.customers where plan = '''') as holds');
SELECT agent_gate.bind_assertion('billing', 'every_customer_has_a_plan');
SQL

# A history with every outcome that has to survive: a read, a dry run, a kept
# write, a refusal because it was already kept, and a refusal because the
# proposal never verified. A dump test over an empty record proves nothing.
read=$(proposal_id "$(agent -d "$ORIGIN" -c "select agent_gate.propose('select id, plan from customers order by id', 'list the customers')")")
agent -d "$ORIGIN" -c "select agent_gate.commit($read)" >/dev/null
write=$(proposal_id "$(agent -d "$ORIGIN" -c "select agent_gate.propose('update customers set plan = ''pro'' where id = 1', 'upgrade customer 1')")")
agent -d "$ORIGIN" -c "select agent_gate.dry_run($write)" >/dev/null
agent -d "$ORIGIN" -c "select agent_gate.commit($write)" >/dev/null
agent -d "$ORIGIN" -c "select agent_gate.commit($write)" >/dev/null
false_one=$(proposal_id "$(agent -d "$ORIGIN" -c "select agent_gate.propose('update customers set plann = 1 where id = 2', 'a column that does not exist')")")
agent -d "$ORIGIN" -c "select agent_gate.commit($false_one)" >/dev/null

Q_AGENTS="select coalesce(string_agg(concat_ws(':', name, role, max_rows, allow_ddl, description, registered_at), ',' order by name), '') from agent_gate_internal.agents"
Q_PROPOSALS="select count(*) || ' ' || coalesce(md5(string_agg(concat_ws('|', id, agent, role, kind, ok, intent, sql, params::text, checks::text, estimated_rows, proposed_at), E'\n' order by id)), '') from agent_gate_internal.proposals"
Q_EXECUTIONS="select count(*) || ' ' || coalesce(md5(string_agg(concat_ws('|', id, proposal, mode, outcome, reason, rows_affected, rows_returned, truncated, assertions::text, sample::text, started_at), E'\n' order by id)), '') from agent_gate_internal.executions"
Q_BINDINGS="select coalesce(string_agg(agent || ':' || assertion, ',' order by agent, assertion), '') from agent_gate_internal.bindings"

AGENTS_BEFORE=$(value -d "$ORIGIN" -c "$Q_AGENTS")
PROPOSALS_BEFORE=$(value -d "$ORIGIN" -c "$Q_PROPOSALS")
EXECUTIONS_BEFORE=$(value -d "$ORIGIN" -c "$Q_EXECUTIONS")
BINDINGS_BEFORE=$(value -d "$ORIGIN" -c "$Q_BINDINGS")
MAX_PROPOSAL_BEFORE=$(value -d "$ORIGIN" -c "select max(id) from agent_gate_internal.proposals")
ACTS_BEFORE=$(agent -d "$ORIGIN" -c "select agent_gate.acts(50)")

# The control that keeps this from passing on nothing.
if [ "${PROPOSALS_BEFORE%% *}" -lt 3 ] || [ "${EXECUTIONS_BEFORE%% *}" -lt 5 ] || [ -z "$BINDINGS_BEFORE" ]; then
    echo "  FAIL the origin record is too thin to prove anything survived:"
    echo "       proposals=$PROPOSALS_BEFORE executions=$EXECUTIONS_BEFORE bindings=$BINDINGS_BEFORE"
    echo "       acts: $ACTS_BEFORE"
    exit 1
fi

# ------------------------------------------------------ dump and restore --
"$BIN/pg_dump" -U "$SUPERUSER" -d "$ORIGIN" -f "$DUMP"
su -d "$TARGET" -f "$DUMP" >/dev/null

failures=0
compare() {
    if [ "$2" = "$3" ]; then
        echo "  ok   $1"
    else
        echo "  FAIL $1"
        echo "       expected: $2"
        echo "       got:      $3"
        failures=$((failures + 1))
    fi
}
contains() {
    if [[ "$3" == *"$2"* ]]; then
        echo "  ok   $1"
    else
        echo "  FAIL $1"
        echo "       expected to contain: $2"
        echo "       got: $3"
        failures=$((failures + 1))
    fi
}

compare "the agents survive" "$AGENTS_BEFORE" "$(value -d "$TARGET" -c "$Q_AGENTS")"
compare "the proposals survive, with their checks" "$PROPOSALS_BEFORE" "$(value -d "$TARGET" -c "$Q_PROPOSALS")"
compare "the executions survive, with their reasons" "$EXECUTIONS_BEFORE" "$(value -d "$TARGET" -c "$Q_EXECUTIONS")"
compare "the bindings survive" "$BINDINGS_BEFORE" "$(value -d "$TARGET" -c "$Q_BINDINGS")"
compare "acts() tells the agent the same history" "$ACTS_BEFORE" "$(agent -d "$TARGET" -c "select agent_gate.acts(50)")"

contains "the agent is still behind the gate in the restored database" \
    "it proposes, it does not execute" \
    "$(agent -d "$TARGET" -c "select count(*) from customers")"

contains "the record is still append-only" "append-only" \
    "$(value -d "$TARGET" -c "update agent_gate_internal.executions set reason = 'rewritten' where id = (select min(id) from agent_gate_internal.executions)" 2>&1 || true)"

after=$(proposal_id "$(agent -d "$TARGET" -c "select agent_gate.propose('update customers set plan = ''pro'' where id = 3', 'upgrade customer 3 after the restore')")")
if [ -n "$after" ] && [ "$after" -gt "$MAX_PROPOSAL_BEFORE" ]; then
    echo "  ok   new proposals continue after the restored ones ($after > $MAX_PROPOSAL_BEFORE)"
else
    echo "  FAIL new proposals continue after the restored ones: got '$after', restored max $MAX_PROPOSAL_BEFORE"
    failures=$((failures + 1))
fi

kept=$(agent -d "$TARGET" -c "select agent_gate.commit(${after:-0})")
if [[ "$kept" == *'"outcome": "kept"'* && "$kept" == *every_customer_has_a_plan* ]]; then
    echo "  ok   a restored agent commits, and its restored binding is checked"
else
    echo "  FAIL a restored agent commits, and its restored binding is checked"
    echo "       got: $kept"
    failures=$((failures + 1))
fi

# What pg_dump does NOT carry has to be true AND said. Three facts, one case:
# the mark is absent from the dump, present in the globals, and the README tells
# whoever restores that they need the globals.
in_dump=$(grep -c -F 'agent_gate.agent' "$DUMP" || true)
in_globals=$("$BIN/pg_dumpall" -U "$SUPERUSER" --globals-only | grep -c -F "\"agent_gate.agent\" TO 'billing'" || true)
in_readme=$(grep -c -F -- '--globals-only' "$ROOT/README.md" || true)
if [ "$in_dump" -eq 0 ] && [ "$in_globals" -ge 1 ] && [ "$in_readme" -ge 1 ]; then
    echo "  ok   the role mark travels only with pg_dumpall --globals-only, and the README says so"
else
    echo "  FAIL the role mark travels only with pg_dumpall --globals-only, and the README says so"
    echo "       mark in pg_dump output: $in_dump (expected 0)"
    echo "       mark in pg_dumpall --globals-only: $in_globals (expected >= 1)"
    echo "       README mentions --globals-only: $in_readme (expected >= 1)"
    failures=$((failures + 1))
fi

if [ "$failures" -ne 0 ]; then
    echo "$failures check(s) failed: the record does NOT survive a restore as documented"
    exit 1
fi
echo "the record survives pg_dump + restore, and what does not travel is said"
