#!/usr/bin/env bash
# The write budget (0.4.0): max_rows bounds one proposal, and an agent that loops
# split a write it was refused into slices that each fit (agent-gate-demo/compare:
# a 6-row table emptied in two legal commits, 5 + 1). Every agent now also has a
# budget of rows per window, counted from what it already kept; unset, it is
# max_rows per hour. Every verdict here is read back from a superuser's side.
#
# The record is append-only, so no case can rewind what an agent kept: each case
# registers an agent of its own.
#
#   PG_CONFIG=/path/to/pg_config tests/cluster.sh init && tests/cluster.sh start
#   PG_CONFIG=/path/to/pg_config tests/budget.sh
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PG_CONFIG=${PG_CONFIG:-pg_config}
BIN=$("$PG_CONFIG" --bindir)
export PGHOST=${PGHOST:-$ROOT/.testcluster}
export PGPORT=${PGPORT:-5499}
SUPERUSER=${SUPERUSER:-$(id -un)}
DB=agent_gate_budget
ROLE=agent_gate_budget_r          # one role per case: ${ROLE}1 .. ${ROLE}7

source "$(dirname "${BASH_SOURCE[0]}")/guard.sh"
trap 'release_claimed' EXIT
require_throwaway_cluster
for i in 1 2 3 4 5 6 7; do claim_role "$ROLE$i"; done
claim_database "$DB"

"$BIN/psql" -X -U "$SUPERUSER" -d "$DB" -v ON_ERROR_STOP=1 -q >/dev/null <<SQL
CREATE EXTENSION pg_agent_gate;
CREATE TABLE orders (id int primary key, total numeric);
CREATE TABLE audit (n int);
INSERT INTO orders SELECT g, g * 1000 FROM generate_series(1, 40) g;
SQL

failures=0
check() {
    local what=$1 expected=$2 got=$3
    if [[ "$got" == *"$expected"* ]]; then echo "  ok   $what"; else
        echo "  FAIL $what"; echo "       expected to contain: $expected"
        echo "       got: ${got//$'\n'/ }" | cut -c1-300; failures=$((failures + 1)); fi
}
check_not() {
    local what=$1 unexpected=$2 got=$3
    if [[ "$got" != *"$unexpected"* ]]; then echo "  ok   $what"; else
        echo "  FAIL $what"; echo "       must not contain: $unexpected"
        echo "       got: ${got//$'\n'/ }" | cut -c1-300; failures=$((failures + 1)); fi
}
run()  { "$BIN/psql" -X -U "$1" -d "$DB" -tAc "$2" 2>&1 || true; }
su()   { run "$SUPERUSER" "$1"; }
reset_orders() {
    su "delete from orders; insert into orders select g, g * 1000 from generate_series(1, 40) g;
        delete from audit;" >/dev/null
}
# agent <n> <max_rows> [extra register_agent args]: role ${ROLE}n registered as agent bn.
agent() {
    local n=$1 max=$2 extra=${3:-}
    su "grant select, insert, update, delete on orders to $ROLE$n; grant insert on audit to $ROLE$n;
        select agent_gate.register_agent('b$n', '$ROLE$n', 'budget case $n agent',
                                         p_max_rows => $max $extra)" >/dev/null
}
propose() { run "$ROLE$1" "select agent_gate.propose('$2', '$3')" | grep -o '"proposal": [0-9]*' | grep -o '[0-9]*' | head -1; }
commit()  { run "$ROLE$1" "select agent_gate.commit($2)"; }

# 1. the slicing that 0.3.0 let through: 3 rows kept, then 3 more refused by the budget.
reset_orders
agent 1 5
check "1a. unset, the budget is max_rows per hour" "5|3600" \
    "$(su "select max_rows_per_window || '|' || window_seconds from agent_gate_internal.agents where name = 'b1'")"
p=$(propose 1 "delete from orders where id between 1 and 3" "first slice")
check "1b. a first slice within the budget is kept" '"outcome": "kept"' "$(commit 1 "$p")"
p=$(propose 1 "delete from orders where id between 4 and 6" "second slice")
out=$(commit 1 "$p")
check "1c. a second slice that would pass the budget is aborted" "write budget" "$out"
check "1d. a superuser sees 3 rows deleted, not 6" "37" "$(su "select count(*) from orders")"
check_not "1e. the refusal names no number to slice by" "5" "$(echo "$out" | grep -o '"reason": "[^"]*"')"

# 2. dry_run reports the same verdict, and keeps nothing.
p=$(propose 1 "delete from orders where id between 7 and 9" "would it pass?")
check "2a. dry_run reports the budget too" "write budget" "$(run "${ROLE}1" "select agent_gate.dry_run($p)")"
check "2b. nothing was kept by dry_run" "37" "$(su "select count(*) from orders")"

# 3. an administrator raises the budget; the agent cannot.
run "${ROLE}1" "select agent_gate.set_budget('b1', 1000)" >/dev/null
check "3a. an agent cannot change its own budget" "5" \
    "$(su "select max_rows_per_window from agent_gate_internal.agents where name = 'b1'")"
su "select agent_gate.set_budget('b1', 100)" >/dev/null
p=$(propose 1 "delete from orders where id between 4 and 6" "after the raise")
check "3b. after set_budget the same slice is kept" '"outcome": "kept"' "$(commit 1 "$p")"

# 4. the window: what was kept leaves the budget once the window has passed.
reset_orders
agent 4 5 ", p_max_rows_per_window => 3, p_window_seconds => 2"
p=$(propose 4 "delete from orders where id between 1 and 3" "fills the budget")
commit 4 "$p" >/dev/null
p=$(propose 4 "delete from orders where id = 4" "one more, too soon")
check "4a. inside the window the budget is spent" "write budget" "$(commit 4 "$p")"
sleep 3
p=$(propose 4 "delete from orders where id = 4" "one more, later")
check "4b. once the window has passed it is kept" '"outcome": "kept"' "$(commit 4 "$p")"

# 5. concurrency: four sessions of one agent, each committing 3 rows against a budget of 3.
#    The agent's row is locked before the count, so exactly one is kept.
reset_orders
agent 5 5 ", p_max_rows_per_window => 3"
ids=()
for i in 0 1 2 3; do
    lo=$((10 + i * 3)); hi=$((lo + 2))
    ids+=("$(propose 5 "delete from orders where id between $lo and $hi" "parallel slice $i")")
done
for p in "${ids[@]}"; do commit 5 "$p" >/dev/null & done
wait
check "5a. four parallel commits, exactly one kept" "1" \
    "$(su "select count(*) from agent_gate_internal.executions where outcome = 'kept'
           and proposal in (${ids[0]}, ${ids[1]}, ${ids[2]}, ${ids[3]})")"
check "5b. a superuser sees exactly 3 rows gone" "37" "$(su "select count(*) from orders")"

# 6. amplification is charged: a trigger the agent may write past moves a second row,
#    and the budget counts both.
reset_orders
"$BIN/psql" -X -U "$SUPERUSER" -d "$DB" -v ON_ERROR_STOP=1 -q >/dev/null <<SQL
CREATE FUNCTION audit_it() RETURNS trigger LANGUAGE plpgsql AS \$\$
BEGIN INSERT INTO audit VALUES (1); RETURN NEW; END \$\$;
CREATE TRIGGER orders_audit AFTER UPDATE ON orders FOR EACH ROW EXECUTE FUNCTION audit_it();
SQL
agent 6 5 ", p_max_rows_per_window => 3"
su "select agent_gate.allow_write('b6', 'orders', 'audited updates')" >/dev/null
p=$(propose 6 "update orders set total = 1 where id = 20" "audited change")
check "6a. a write and its trigger (2 rows) fit a budget of 3" '"outcome": "kept"' "$(commit 6 "$p")"
check "6b. the record charges the rows the trigger moved" "2" \
    "$(su "select rows_moved from agent_gate_internal.executions where proposal = $p and mode = 'commit'")"
p=$(propose 6 "update orders set total = 1 where id = 21" "audited change again")
check "6c. the next one (2 more) is past the budget" "write budget" "$(commit 6 "$p")"
check "6d. a superuser sees only the first audited change" "1" "$(su "select count(*) from audit")"
# The trigger stays out of the later cases: on a table with one, the gate refuses the write of
# any agent not allowed past it -- a different check from the one they measure.
su "drop trigger orders_audit on orders" >/dev/null

# 7. reset_budget(): an administrator gives the whole budget back; the agent cannot.
reset_orders
agent 7 5 ", p_max_rows_per_window => 3"
p=$(propose 7 "delete from orders where id between 1 and 3" "spends the budget")
commit 7 "$p" >/dev/null
run "${ROLE}7" "select agent_gate.reset_budget('b7')" >/dev/null
check "7a. an agent cannot reset its own budget" "t" \
    "$(su "select budget_since is null from agent_gate_internal.agents where name = 'b7'")"
p=$(propose 7 "delete from orders where id = 4" "after a reset it tried itself")
check "7b. so its budget stays spent" "write budget" "$(commit 7 "$p")"
su "select agent_gate.reset_budget('b7')" >/dev/null
p=$(propose 7 "delete from orders where id = 4" "after a reset by an administrator")
check "7c. after an administrator's reset it is kept" '"outcome": "kept"' "$(commit 7 "$p")"
check "7d. and the record still holds every earlier act" "3" \
    "$(su "select count(*) from agent_gate_internal.executions e join agent_gate_internal.proposals p
           on p.id = e.proposal where p.agent = 'b7' and e.mode = 'commit' and e.outcome in ('kept', 'aborted')")"

echo
if [ "$failures" -eq 0 ]; then echo "budget: all checks passed"; else echo "budget: $failures FAILED"; exit 1; fi
