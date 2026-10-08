#!/usr/bin/env bash
# What runs, and what is told, BEFORE the gate says no.
#
# The gate refuses a user function that is volatile or SECURITY DEFINER, because its
# body is invisible to it. Up to 0.2.5 that refusal came one step too late: the check
# that names and types resolve is an EXPLAIN, and the planner constant-folds an
# IMMUTABLE call with constant arguments -- and estimates a STABLE one -- by RUNNING it.
# So a SECURITY DEFINER function ran, as its owner, before no_opaque_function refused
# it, and whatever it raised came back verbatim in the `resolves` detail. Measured on
# 2026-10-08 against 88b265c (PG 18.6): the counter below moved, and the vault's secret
# was in the JSON the agent received -- under a check whose text said "nothing ran".
#
# The second half is what the plan TELLS. estimated_rows comes from statistics gathered
# over the whole table, beneath row-level security, so an agent that sees none of a
# value's rows read how many another tenant had. The agent cannot run EXPLAIN itself;
# the gate was the only channel.
#
# THE INSTRUMENT, and why it is a sequence: a function marked IMMUTABLE cannot INSERT
# (its SPI is read-only), and a table would be rolled back with the subtransaction the
# EXPLAIN runs in -- either way a counter in a table reads 0 whether the body ran or
# not. nextval() is allowed there and is not transactional, so it remembers a run that
# was undone. Its control is the last case: the superuser calls the function once and
# the counter has to move, or every "0" above it meant nothing.
#
#   PG_CONFIG=/path/to/pg_config tests/cluster.sh init
#   PG_CONFIG=/path/to/pg_config tests/cluster.sh start
#   PG_CONFIG=/path/to/pg_config tests/plan_time.sh
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PG_CONFIG=${PG_CONFIG:-pg_config}
BIN=$("$PG_CONFIG" --bindir)
export PGHOST=${PGHOST:-$ROOT/.testcluster}
export PGPORT=${PGPORT:-5499}
SUPERUSER=${SUPERUSER:-$(id -un)}
DB=agent_gate_plan_time
ROLE=agent_gate_plan_time_agent
SECRET=s3cr3t-from-vault

as_agent() { "$BIN/psql" -X -U "$ROLE" -d "$DB" -tA "$@" 2>&1 || true; }
as_super() { "$BIN/psql" -X -U "$SUPERUSER" -d "$DB" -tA "$@" 2>&1; }

# Claims the names instead of dropping whatever is there: see tests/guard.sh.
source "$(dirname "${BASH_SOURCE[0]}")/guard.sh"

trap release_claimed EXIT
require_throwaway_cluster
claim_role "$ROLE"
claim_database "$DB"
"$BIN/psql" -X -U "$SUPERUSER" -d "$DB" -v ON_ERROR_STOP=1 -q -v role="$ROLE" >/dev/null <<SQL
CREATE EXTENSION pg_agent_gate;

CREATE SCHEMA shop;
CREATE TABLE shop.orders (tenant int NOT NULL, secret text NOT NULL);
-- A hundred tenants, so the policy's own selectivity is about 1/100 and not a cliff that
-- flattens every estimate to 1 (the first version had two tenants and measured nothing).
-- Tenant 1 (the agent) has one row of its own; tenant 2 has 5000 rows of one value,
-- which makes it a most-common value in the statistics.
INSERT INTO shop.orders VALUES (1, 'mine-a');
INSERT INTO shop.orders SELECT 2, 'hot-b' FROM generate_series(1, 5000);
INSERT INTO shop.orders SELECT g % 100 + 1, 'cold-' || g FROM generate_series(1, 10000) g;
ALTER TABLE shop.orders ENABLE ROW LEVEL SECURITY;
CREATE POLICY by_tenant ON shop.orders USING (tenant = current_setting('app.tenant_id')::int);
-- The control for the estimate: a table without row-level security keeps its estimate.
CREATE TABLE shop.catalog (sku text NOT NULL);
INSERT INTO shop.catalog SELECT 'sku-' || (g % 10) FROM generate_series(1, 5000) g;
ANALYZE shop.orders, shop.catalog;

-- A table the agent holds NO grant on, with a trigger: what fails first on it must be the privilege.
CREATE TABLE shop.hidden (id int);
CREATE FUNCTION shop.noop() RETURNS trigger LANGUAGE plpgsql AS \$\$ BEGIN RETURN NEW; END \$\$;
CREATE TRIGGER noop AFTER INSERT ON shop.hidden FOR EACH ROW EXECUTE FUNCTION shop.noop();

CREATE SCHEMA vault;
CREATE TABLE vault.secret (s text);
INSERT INTO vault.secret VALUES ('$SECRET');
CREATE SEQUENCE vault.hits;
CREATE FUNCTION vault.peek() RETURNS text LANGUAGE plpgsql IMMUTABLE SECURITY DEFINER AS
  \$\$ BEGIN PERFORM nextval('vault.hits'); RETURN 'none'; END \$\$;
CREATE FUNCTION vault.peek_stable() RETURNS text LANGUAGE plpgsql STABLE SECURITY DEFINER AS
  \$\$ BEGIN PERFORM nextval('vault.hits'); RETURN 'none'; END \$\$;
CREATE FUNCTION vault.boom() RETURNS text LANGUAGE plpgsql IMMUTABLE SECURITY DEFINER AS
  \$\$ BEGIN RAISE EXCEPTION 'leak: %', (SELECT s FROM vault.secret); END \$\$;

-- 0.2.7: SECURITY DEFINER reached through a body the walker cannot see. An IMMUTABLE wrapper that
-- is NOT security definer passes no_opaque_function; so does a CHECK, which is not in the tree.
CREATE FUNCTION vault.wrap() RETURNS text LANGUAGE plpgsql IMMUTABLE AS
  \$\$ BEGIN RETURN vault.peek(); END \$\$;
CREATE FUNCTION vault.wrap_boom() RETURNS text LANGUAGE plpgsql IMMUTABLE AS
  \$\$ BEGIN RETURN vault.boom(); END \$\$;
CREATE FUNCTION vault.ok(t text) RETURNS boolean LANGUAGE plpgsql IMMUTABLE AS
  \$\$ BEGIN PERFORM vault.peek(); RETURN true; END \$\$;
-- And the wrapper that must keep working: no SECURITY DEFINER anywhere under it.
CREATE FUNCTION vault.shout(t text) RETURNS text LANGUAGE plpgsql IMMUTABLE AS
  \$\$ BEGIN RETURN upper(t); END \$\$;
CREATE TABLE shop.notes (body text CHECK (vault.ok(body)));

GRANT USAGE ON SCHEMA shop, vault TO :"role";
-- SELECT too: the gate appends RETURNING to_jsonb(old/new) to a write it runs, which needs it. With
-- INSERT alone the commit aborts on "permission denied" and the CHECK case below would pass for
-- that reason on a gate without the hook (found by running this file against 0.2.6).
GRANT SELECT, INSERT ON shop.notes TO :"role";
GRANT EXECUTE ON FUNCTION vault.wrap(), vault.wrap_boom(), vault.ok(text), vault.shout(text) TO :"role";
GRANT SELECT ON shop.orders, shop.catalog TO :"role";
GRANT EXECUTE ON FUNCTION vault.peek(), vault.peek_stable(), vault.boom() TO :"role";
ALTER ROLE :"role" SET app.tenant_id = '1';
SELECT agent_gate.register_agent('plan_time', :'role', 'reads the orders of its own tenant');

-- 0.2.8, the estimate. A DBA helper the planner INLINES after the gate's tree was built: STABLE,
-- SECURITY INVOKER, SQL. Its table is in the plan but not in the analyzed tree (audit of 0.2.7).
CREATE FUNCTION shop.orders_by_secret(t text) RETURNS SETOF shop.orders LANGUAGE sql STABLE AS
  \$\$ SELECT * FROM shop.orders WHERE secret = t \$\$;
GRANT EXECUTE ON FUNCTION shop.orders_by_secret(text) TO :"role";
-- Isolation by a view, no row-level security anywhere: the agent reads the view, not the table.
CREATE TABLE shop.invoices (tenant int NOT NULL, secret text NOT NULL);
INSERT INTO shop.invoices VALUES (1, 'mine-a');
INSERT INTO shop.invoices SELECT 2, 'hot-b' FROM generate_series(1, 5000);
INSERT INTO shop.invoices SELECT g % 100 + 1, 'cold-' || g FROM generate_series(1, 10000) g;
ANALYZE shop.invoices;
CREATE VIEW shop.my_invoices AS SELECT * FROM shop.invoices WHERE tenant = current_setting('app.tenant_id')::int;
GRANT SELECT ON shop.my_invoices TO :"role";
-- The control for over-withholding: a view over a table the agent may read in full keeps its estimate.
CREATE VIEW shop.catalog_v AS SELECT * FROM shop.catalog;
GRANT SELECT ON shop.catalog_v TO :"role";
SQL

# 0.2.8, parallel workers. The hook keys on a counter that lives in the backend; a parallel worker
# has its own, at 0. A DDL proposal (an allow_ddl agent) is not walked -- the hook is its only guard
# against a SECURITY DEFINER function -- and CREATE TABLE AS can run its SELECT in workers. With
# the leader not participating, nothing the leader runs would trip the hook.
DDL_ROLE=agent_gate_plan_time_ddl
claim_role "$DDL_ROLE"
"$BIN/psql" -X -U "$SUPERUSER" -d "$DB" -v ON_ERROR_STOP=1 -q -v ddl="$DDL_ROLE" >/dev/null <<SQL
CREATE TABLE shop.big AS SELECT g AS id FROM generate_series(1, 200000) g;
ANALYZE shop.big;
CREATE FUNCTION vault.peek_par(i int) RETURNS text LANGUAGE sql STABLE PARALLEL SAFE SECURITY DEFINER AS
  \$\$ SELECT s FROM vault.secret \$\$;
CREATE SCHEMA loot AUTHORIZATION :"ddl";
GRANT USAGE ON SCHEMA shop, vault TO :"ddl";
GRANT SELECT ON shop.big TO :"ddl";
GRANT EXECUTE ON FUNCTION vault.peek_par(int) TO :"ddl";
SELECT agent_gate.register_agent('plan_time_ddl', :'ddl', 'creates tables in its own schema', p_allow_ddl => true);
-- Make a parallel plan certain, and keep the leader out of it.
ALTER DATABASE $DB SET parallel_setup_cost = 0;
ALTER DATABASE $DB SET parallel_tuple_cost = 0;
ALTER DATABASE $DB SET min_parallel_table_scan_size = 0;
ALTER DATABASE $DB SET max_parallel_workers_per_gather = 2;
ALTER DATABASE $DB SET parallel_leader_participation = off;
SQL

failures=0
contains() {
    local what=$1 expected=$2 got=$3
    if [[ "$got" == *"$expected"* ]]; then
        echo "  ok   $what"
    else
        echo "  FAIL $what"
        echo "       expected to contain: $expected"
        echo "       got: ${got//$'\n'/ }"
        failures=$((failures + 1))
    fi
}
absent() {
    local what=$1 forbidden=$2 got=$3
    if [[ -n "$got" && "$got" != *"$forbidden"* ]]; then
        echo "  ok   $what"
    else
        echo "  FAIL $what"
        echo "       must be a real answer without: $forbidden"
        echo "       got: ${got//$'\n'/ }"
        failures=$((failures + 1))
    fi
}
equals() {
    local what=$1 expected=$2 got=$3
    if [[ "$got" == "$expected" ]]; then
        echo "  ok   $what"
    else
        echo "  FAIL $what"
        echo "       expected: $expected"
        echo "       got: ${got//$'\n'/ }"
        failures=$((failures + 1))
    fi
}
hits() { as_super -c "select case when is_called then last_value else 0 end from vault.hits"; }
propose() { as_agent -c "select agent_gate.propose(\$q\$$1\$q\$, 'read my orders')"; }
# The estimate the agent was given, read back from the record: an agent session may not
# decorate a verb's result, so `propose(...)::jsonb -> ...` is refused before it runs.
estimate() {
    propose "$1" >/dev/null
    as_super -c "select coalesce(estimated_rows::text, 'null') from agent_gate_internal.proposals order by id desc limit 1"
}

# --- B: nothing the gate refuses runs while it is being verified ------------------------
for sql in \
    "select * from shop.orders where secret = vault.peek()" \
    "select * from shop.orders where secret = vault.peek_stable()" \
    "select vault.peek()" \
    "select * from shop.orders o where o.secret in (select vault.peek())"; do
    out=$(propose "$sql")
    contains "refused: ${sql:0:60}" '"ok": false' "$out"
    contains "  ...by no_opaque_function" 'no_opaque_function' "$out"
done
out=$(as_agent -c "select agent_gate.propose_and_commit(\$q\$select * from shop.orders where secret = vault.peek()\$q\$, 'read my orders')")
contains "propose_and_commit refuses it too" '"ok": false' "$out"
equals "and NONE of those calls ran the SECURITY DEFINER body (the counter did not move)" 0 "$(hits)"

out=$(propose "select * from shop.orders where secret = vault.boom()")
contains "a function that raises its owner's secret is refused" '"ok": false' "$out"
absent "  ...and the secret is not in what the agent receives" "$SECRET" "$out"

# --- 0.2.7: nor through a body the walker cannot see --------------------------------------
# The walker sees what the STATEMENT calls. A SECURITY DEFINER function reached through another
# function, a constraint or a trigger is stopped by the gate's fmgr hook, before its body runs.
next_proposal() {
    as_super -c "select coalesce(max(id), 0) + 1 from agent_gate_internal.proposals"
}
before=$(hits)
out=$(propose "select * from shop.orders where secret = vault.wrap()")
contains "an IMMUTABLE wrapper over a SECURITY DEFINER function is refused at propose" '"ok": false' "$out"
contains "  ...naming the function it reached" 'SECURITY DEFINER function vault.peek()' "$out"
id=$(next_proposal)
out=$(as_agent -c "select agent_gate.propose('select vault.wrap()', 'read through the wrapper')" -c "select agent_gate.commit($id)")
contains "  ...and a commit of it is refused too" '"outcome": "refused"' "$out"
out=$(propose "select * from shop.orders where secret = vault.wrap_boom()")
contains "a wrapper over a function that raises its owner's secret is refused" '"ok": false' "$out"
absent "  ...and the secret is not in what the agent receives" "$SECRET" "$out"
# A CHECK is not in the statement's tree and is not evaluated by the planner: the proposal verifies,
# and the SECURITY DEFINER call happens at commit -- where the hook stops it and nothing is kept.
id=$(next_proposal)
out=$(as_agent -c "select agent_gate.propose('insert into shop.notes values (''hello'')', 'write a note')" -c "select agent_gate.commit($id)")
absent "a CHECK that reaches a SECURITY DEFINER function does not keep the write" '"outcome": "kept"' "$out"
contains "  ...the gate says why" 'SECURITY DEFINER function vault.peek()' "$out"
equals "  ...and the table is still empty, seen by the superuser" 0 "$(as_super -c 'select count(*) from shop.notes')"
equals "none of the wrapper, the raising wrapper or the CHECK ran the SECURITY DEFINER body" "$before" "$(hits)"
# What must keep working: a wrapper with no SECURITY DEFINER under it.
id=$(next_proposal)
out=$(as_agent -c "select agent_gate.propose(\$q\$select vault.shout('quiet') as s\$q\$, 'shout')" -c "select agent_gate.commit($id)")
contains "a wrapper with no SECURITY DEFINER under it still verifies and runs" 'QUIET' "$out"
# The control: the wrapper DOES reach the function, or the counter above proved nothing.
before=$(hits)
as_super -c "select vault.wrap()" >/dev/null
equals "control: the superuser calls vault.wrap() once and the counter moves by 1" $((before + 1)) "$(hits)"

# Privileges are still the FIRST thing a proposal fails on. The analyzer that now runs before
# the planner does not check them (EXPLAIN did, at executor start), so without a check of its own
# an agent with no grant on a table would get the gate's reasoning about that table's triggers
# before its "permission denied". The table has a trigger, so no_amplification WOULD refuse it.
out=$(as_agent -c "select agent_gate.propose('insert into shop.hidden values (1)', 'write where I may not')")
contains "a table the agent holds no grant on fails resolves, with permission denied" \
    '"check": "resolves", "detail": "[42501]' "$out"
absent "  ...before any check reasons about the table's triggers" 'no_amplification' "$out"

# --- A: the estimate does not count rows the agent may not see -----------------------
# The superuser's side first: as the agent, the planner DOES tell the hot value of another
# tenant from a value nobody has. If it did not, every "null" below would pass against a
# gate that leaked nothing to begin with.
plan_rows() {
    as_super -c "set role $ROLE" -c "set app.tenant_id = '1'" \
        -c "explain (format json) $1" | sed -nE 's/.*"Plan Rows": ([0-9.]+).*/\1/p' | head -1
}
hot=$(plan_rows "select * from shop.orders where secret = 'hot-b'")
none=$(plan_rows "select * from shop.orders where secret = 'no-such-value'")
if [[ "$hot" =~ ^[0-9.]+$ && "$none" =~ ^[0-9.]+$ ]] && (( ${hot%.*} > 5 * ${none%.*} )); then
    echo "  ok   the planner, as the agent, tells another tenant's hot value ($hot) from an absent one ($none)"
else
    echo "  FAIL the planner, as the agent, tells another tenant's hot value from an absent one"
    echo "       got: hot=$hot absent=$none -- the scenario cannot show the leak"
    failures=$((failures + 1))
fi
equals "under row-level security, a value only another tenant has gets no estimate" null \
    "$(estimate "select * from shop.orders where secret = 'hot-b'")"
equals "nor does the agent's own value" null \
    "$(estimate "select * from shop.orders where secret = 'mine-a'")"
equals "nor a view or subquery over the protected table" null \
    "$(estimate "select * from (select * from shop.orders) o where o.secret = 'hot-b'")"
contains "and the read itself still verifies" '"ok": true' \
    "$(propose "select * from shop.orders where secret = 'hot-b'")"
# The control: without row-level security the estimate is still there, or "null" above
# would only say that the gate stopped estimating.
est=$(estimate "select * from shop.catalog where sku = 'sku-1'")
if [[ "$est" =~ ^[0-9.]+$ ]] && [[ "$est" != 0 ]]; then
    echo "  ok   without row-level security the estimate is kept ($est)"
else
    echo "  FAIL without row-level security the estimate is kept"
    echo "       got: $est"
    failures=$((failures + 1))
fi

# --- 0.2.8: the estimate follows the PLAN, not only the tree ------------------------------
# The instrument first, as the agent: the inlined helper DOES tell the hot value from an absent one.
hot=$(plan_rows "select * from shop.orders_by_secret('hot-b')")
none=$(plan_rows "select * from shop.orders_by_secret('no-such-value')")
if [[ "$hot" =~ ^[0-9.]+$ && "$none" =~ ^[0-9.]+$ ]] && (( ${hot%.*} > 5 * ${none%.*} )); then
    echo "  ok   through an inlined SQL helper the planner, as the agent, still tells hot ($hot) from absent ($none)"
else
    echo "  FAIL through an inlined SQL helper the planner tells hot from absent"
    echo "       got: hot=$hot absent=$none -- the scenario cannot show the leak"
    failures=$((failures + 1))
fi
equals "an inlined SQL helper over a table under row-level security gets no estimate" null \
    "$(estimate "select * from shop.orders_by_secret('hot-b')")"
equals "  ...nor two of them joined (the estimate would square the signal)" null \
    "$(estimate "select * from shop.orders_by_secret('hot-b') o join shop.orders_by_secret('hot-b') p using (tenant)")"
equals "  ...nor one in a sublink" null \
    "$(estimate "select (select count(*) from shop.orders_by_secret('hot-b'))")"
equals "a view that isolates tenants without row-level security gets no estimate (the agent cannot read the table)" null \
    "$(estimate "select * from shop.my_invoices where secret = 'hot-b'")"
est=$(estimate "select * from shop.catalog_v where sku = 'sku-1'")
if [[ "$est" =~ ^[0-9.]+$ ]] && [[ "$est" != 0 ]]; then
    echo "  ok   a view over a table the agent may read in full keeps its estimate ($est)"
else
    echo "  FAIL a view over a table the agent may read in full keeps its estimate"
    echo "       got: $est"
    failures=$((failures + 1))
fi

# --- 0.2.8: no parallel worker runs the agent's SQL ---------------------------------------
# Measured on 0.2.7: a worker inherits agent_gate.agent with its counters at 0, so the session hooks
# refuse whatever it runs -- post_parse refuses the function body it parses, ExecutorStart a plan
# fragment that reads a table. No leak, but by accident, and it broke a plain parallel CREATE
# TABLE AS of an allow_ddl agent. 0.2.8 keeps the agent's SQL out of workers by design, so it runs
# in the backend, where the hook sees it, and the plain one goes through.
# The instrument: as the superuser, with debug_parallel_query, that SELECT runs in a worker.
launched=$(as_super -c "set debug_parallel_query = on" \
    -c "explain (analyze, format json) select vault.peek_par(g) from generate_series(1, 10) g" \
    | sed -nE 's/.*"Workers Launched": ([0-9]+).*/\1/p' | head -1)
if [[ "${launched:-0}" -gt 0 ]]; then
    echo "  ok   control: outside the gate this SELECT runs in $launched parallel worker(s)"
else
    echo "  FAIL control: outside the gate this SELECT runs in a parallel worker"
    echo "       got: Workers Launched=${launched:-none} -- the scenario cannot show a worker skipping the hook"
    failures=$((failures + 1))
fi
as_super -c "alter database $DB set debug_parallel_query = on" >/dev/null
ddl() { "$BIN/psql" -X -U "$DDL_ROLE" -d "$DB" -tA -c "select agent_gate.propose_and_commit(\$q\$$1\$q\$, 'build a table in my own schema')" 2>&1 || true; }
out=$(ddl "create table loot.t as select vault.peek_par(g) as s from generate_series(1, 10) g")
equals "an allow_ddl agent's CREATE TABLE AS over a SECURITY DEFINER function keeps no table" "" \
    "$(as_super -c "select to_regclass('loot.t')")"
contains "  ...stopped by the hook, naming the function" 'SECURITY DEFINER function vault.peek_par()' "$out"
absent "  ...and the secret is not in what it receives" "$SECRET" "$out"
# And what must work: a plain CREATE TABLE AS that the planner would run in parallel.
out=$(ddl "create table loot.ok as select id from shop.big")
equals "a plain CREATE TABLE AS over a big table is kept (the agent's SQL runs in the backend, not in workers)" \
    200000 "$(as_super -c "select count(*) from loot.ok" 2>&1)"
as_super -c "alter database $DB reset debug_parallel_query" >/dev/null

# --- the control of the instrument: a call that DOES run has to move the counter -------
before=$(hits)
as_super -c "select vault.peek()" >/dev/null
equals "control: the superuser calls vault.peek() once and the counter moves by 1" $((before + 1)) "$(hits)"

if [ "$failures" -ne 0 ]; then
    echo "$failures check(s) failed"
    exit 1
fi
echo "nothing the gate refuses runs while it verifies, and the estimate does not see past row-level security"
