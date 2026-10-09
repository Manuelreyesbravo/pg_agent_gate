#!/usr/bin/env bash
# The rest of the third external audit (of 0.2.8): the findings closed in 0.2.14, each with its
# tooth and its control.
#
#   GATE-09  dry_run showed one date and commit kept another: DateStyle changed between them
#   GATE-11  a read advanced a sequence 100,000 times and the record said nothing changed
#   GATE-13  a name unregistered and given to another role let that role commit the old one's proposal
#   GATE-15  30 MB of SQL and 5 MB of intent went into the append-only record
#
#   PG_CONFIG=/path/to/pg_config tests/cluster.sh init && tests/cluster.sh start
#   PG_CONFIG=/path/to/pg_config tests/audit4.sh
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PG_CONFIG=${PG_CONFIG:-pg_config}
BIN=$("$PG_CONFIG" --bindir)
export PGHOST=${PGHOST:-$ROOT/.testcluster}
export PGPORT=${PGPORT:-5499}
SUPERUSER=${SUPERUSER:-$(id -un)}
DB=agent_gate_audit4
A=agent_gate_audit4_a
R1=agent_gate_audit4_r1
R2=agent_gate_audit4_r2

as_super() { "$BIN/psql" -X -U "$SUPERUSER" -d "$DB" -tA "$@" 2>&1; }
as() { local r=$1; shift; "$BIN/psql" -X -U "$r" -d "$DB" -tA "$@" 2>&1 || true; }

source "$(dirname "${BASH_SOURCE[0]}")/guard.sh"
trap release_claimed EXIT
require_throwaway_cluster
for r in "$A" "$R1" "$R2"; do claim_role "$r"; done
claim_database "$DB"
"$BIN/psql" -X -U "$SUPERUSER" -d "$DB" -v ON_ERROR_STOP=1 -q -v a="$A" -v r1="$R1" -v r2="$R2" >/dev/null <<SQL
CREATE EXTENSION pg_agent_gate;
CREATE TABLE t (id int PRIMARY KEY, v text);
INSERT INTO t VALUES (1, 'one');
CREATE SEQUENCE s;
GRANT SELECT, UPDATE ON t TO :"a", :"r1", :"r2";
GRANT USAGE, SELECT, UPDATE ON SEQUENCE s TO :"a";
SELECT agent_gate.register_agent('audit4_a', :'a', 'the agent of the fourth round');
SELECT agent_gate.register_agent('audit4_x', :'r1', 'the first owner of this name');
SQL

failures=0
check() {
    local what=$1 expected=$2 got=$3
    if [[ "$got" == *"$expected"* ]]; then echo "  ok   $what"; else
        echo "  FAIL $what"; echo "       expected to contain: $expected"; echo "       got: ${got//$'\n'/ }" | cut -c1-400; failures=$((failures + 1)); fi
}
lacks() {
    local what=$1 forbidden=$2 got=$3
    if [[ -n "$got" && "$got" != *"$forbidden"* ]]; then echo "  ok   $what"; else
        echo "  FAIL $what"; echo "       must not contain: $forbidden"; echo "       got: ${got//$'\n'/ }" | cut -c1-400; failures=$((failures + 1)); fi
}
pid() { sed -n 's/.*"proposal": \([0-9]*\).*/\1/p' | head -1; }

echo "GATE-09: what dry_run showed is what commit keeps"
P=$(as "$A" -c "select agent_gate.propose(\$q\$update t set v = (\$1::date)::text where id = 1\$q\$, 'set the date', array['03/04/2026'])" | pid)
check "control: dry_run under the default DateStyle shows March 4" "2026-03-04" \
    "$(as "$A" -c "select agent_gate.dry_run($P)")"
check "commit after the session changed DateStyle is refused" "session settings changed since it was verified: DateStyle" \
    "$(as "$A" -c "set datestyle = 'ISO, DMY'" -c "select agent_gate.commit($P)")"
check "  ...and nothing was kept" "one" "$(as_super -c "select v from t where id = 1")"
check "control: with DateStyle back, the same commit is kept" '"outcome": "kept"' \
    "$(as "$A" -c "select agent_gate.commit($P)")"
check "  ...and keeps what dry_run showed" "2026-03-04" "$(as_super -c "select v from t where id = 1")"

echo "GATE-11: a read changes nothing"
check "control: a plain read passes" '"ok": true' \
    "$(as "$A" -c "select agent_gate.propose('select count(*) from t', 'count the rows')")"
check "a read that calls nextval() is refused" "read_changes_nothing" \
    "$(as "$A" -c "select agent_gate.propose_and_commit(\$q\$select max(nextval('s')) from generate_series(1, 1000)\$q\$, 'just a read')")"
check "  ...and the sequence did not move" "1|f" "$(as_super -c "select last_value, is_called from s")"
check "a read that takes an advisory lock is refused" "pg_advisory_lock()" \
    "$(as "$A" -c "select agent_gate.propose('select pg_advisory_lock(42)', 'just a read')")"
check "control: nextval() in a write is the write's business" '"ok": true' \
    "$(as "$A" -c "select agent_gate.propose(\$q\$update t set v = nextval('s')::text where id = 1\$q\$, 'number the row')")"

echo "GATE-13: a reused name does not inherit the old registration's proposals"
OLD=$(as "$R1" -c "select agent_gate.propose(\$q\$update t set v = 'by r1' where id = 1\$q\$, 'r1 plan')" | pid)
as_super -q -c "select agent_gate.unregister_agent('audit4_x')" -c "select agent_gate.register_agent('audit4_x', '$R2', 'the second owner of this name')" >/dev/null
check "the new owner of the name cannot commit the old owner's proposal" "this agent has no proposal with that id" \
    "$(as "$R2" -c "select agent_gate.commit($OLD)")"
lacks "  ...nor sees it in its acts" "r1 plan" "$(as "$R2" -c "select agent_gate.acts()")"
check "control: the new owner commits its own" '"outcome": "kept"' \
    "$(as "$R2" -c "select agent_gate.propose_and_commit(\$q\$update t set v = 'by r2' where id = 1\$q\$, 'r2 plan')")"

echo "GATE-15: the record takes bounded proposals"
check "control: the default bounds are set" "1048576|65536" \
    "$(as_super -c "select current_setting('agent_gate.max_proposal_bytes') || '|' || current_setting('agent_gate.max_intent_bytes')")"
before=$(as_super -c "select count(*) from agent_gate_internal.proposals")
check "a 2 MB proposal is refused" "over agent_gate.max_proposal_bytes" \
    "$(python3 -c "print(\"select agent_gate.propose('select 1 /*\" + 'x' * 2_000_000 + \"*/', 'big')\")" | as "$A" -f -)"
check "a 100 kB intent is refused" "over agent_gate.max_intent_bytes" \
    "$(python3 -c "print(\"select agent_gate.propose('select 1', '\" + 'i' * 100_000 + \"')\")" | as "$A" -f -)"
check "  ...and neither went into the record" "$before" "$(as_super -c "select count(*) from agent_gate_internal.proposals")"
check "control: an agent cannot raise its own bound (the session allowlist, since 0.2.0)" "is not one an agent session may change" \
    "$(as "$A" -c "set agent_gate.max_proposal_bytes = 100000000")"

if [ "$failures" -ne 0 ]; then
    echo "$failures check(s) failed"
    exit 1
fi
echo "the rest of the third audit is closed, each finding against its control"
