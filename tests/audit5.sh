#!/usr/bin/env bash
# The public-readiness review of 0.4.1 (2026-11-05): the findings closed in 0.4.2, each with its
# tooth and its control. Every verdict is read from the effect -- the other tenant's row, the
# sequence, the table -- and not from the gate's own answer alone.
#
#   1. SQL in a text argument. query_to_xml(), ts_stat(), ts_rewrite(), cursor_to_xml(), the
#      table/schema/database_to_xml() family and tablefunc's crosstab()/connectby() run SQL
#      that the gate never parsed: set_config() inside it moved the tenant while the same
#      statement read, and nextval() inside it advanced a sequence from a read.
#   2. An allow_ddl agent's CREATE TABLE AS / SELECT INTO over a CTE that writes deleted rows
#      with no max_rows, no budget and no count.
#   3. A function the agent can alter -- falsely IMMUTABLE, or with a SET clause -- moved the
#      tenant from a body the gate cannot see. So did a DBA's function with SET app.tenant_id.
#
#   PG_CONFIG=/path/to/pg_config tests/cluster.sh init && tests/cluster.sh start
#   PG_CONFIG=/path/to/pg_config tests/audit5.sh
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PG_CONFIG=${PG_CONFIG:-pg_config}
BIN=$("$PG_CONFIG" --bindir)
export PGHOST=${PGHOST:-$ROOT/.testcluster}
export PGPORT=${PGPORT:-5499}
SUPERUSER=${SUPERUSER:-$(id -un)}
DB=agent_gate_audit5
A=agent_gate_audit5_a      # an ordinary agent
D=agent_gate_audit5_d      # an allow_ddl agent, max_rows 2
MINE=doc-of-tenant-one
THEIRS=doc-of-tenant-two

as_super() { "$BIN/psql" -X -U "$SUPERUSER" -d "$DB" -tA "$@" 2>&1; }
as() { local r=$1; shift; "$BIN/psql" -X -U "$r" -d "$DB" -tA "$@" 2>&1 || true; }
pc() { printf "select agent_gate.propose_and_commit(\$q\$%s\$q\$, 'audit5')" "$1"; }

source "$(dirname "${BASH_SOURCE[0]}")/guard.sh"
trap release_claimed EXIT
require_throwaway_cluster
for r in "$A" "$D"; do claim_role "$r"; done
claim_database "$DB"
"$BIN/psql" -X -U "$SUPERUSER" -d "$DB" -v ON_ERROR_STOP=1 -q -v a="$A" -v d="$D" >/dev/null <<SQL
CREATE EXTENSION pg_agent_gate;
CREATE TABLE docs (tenant int NOT NULL, body text NOT NULL);
INSERT INTO docs VALUES (1, '$MINE'), (2, '$THEIRS');
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY by_tenant ON docs USING (tenant = current_setting('app.tenant_id')::int);
CREATE TABLE orders (id int PRIMARY KEY);
INSERT INTO orders SELECT generate_series(1, 20);
CREATE SEQUENCE s;
CREATE SCHEMA ddl AUTHORIZATION :"d";
GRANT USAGE ON SCHEMA public TO :"a", :"d";
GRANT SELECT ON docs TO :"a", :"d";
GRANT SELECT, DELETE ON orders TO :"d";
GRANT USAGE, SELECT, UPDATE ON SEQUENCE s TO :"a";
-- A DBA's functions: one whose SET clause moves the tenant, one whose SET clause only pins its
-- search_path (the usual hardening, and harmless), and one that is not what it says it is.
CREATE FUNCTION public.docs_as_two() RETURNS SETOF docs LANGUAGE sql STABLE
    SET app.tenant_id = '2' AS 'select * from public.docs';
CREATE FUNCTION public.docs_tidy() RETURNS SETOF docs LANGUAGE sql STABLE
    SET search_path = pg_catalog, public AS 'select * from public.docs';
CREATE FUNCTION public.mislabeled() RETURNS int LANGUAGE plpgsql STABLE
    AS \$\$ BEGIN PERFORM set_config('app.tenant_id', '2', true); RETURN 1; END \$\$;
ALTER ROLE :"a" SET app.tenant_id = '1';
ALTER ROLE :"d" SET app.tenant_id = '1';
SELECT agent_gate.register_agent('audit5_a', :'a', 'reads the documents of its own tenant');
SELECT agent_gate.register_agent('audit5_d', :'d', 'schema power in its own schema',
                                 p_max_rows => 2, p_allow_ddl => true, p_max_rows_per_window => 1000);
SQL

failures=0
check() {
    local what=$1 expected=$2 got=$3
    if [[ "$got" == *"$expected"* ]]; then echo "  ok   $what"; else
        echo "  FAIL $what"; echo "       expected to contain: $expected"; echo "       got: ${got//$'\n'/ }" | cut -c1-${CUT:-400}; failures=$((failures + 1)); fi
}
lacks() {
    local what=$1 forbidden=$2 got=$3
    if [[ -n "$got" && "$got" != *"$forbidden"* ]]; then echo "  ok   $what"; else
        echo "  FAIL $what"; echo "       must not contain: $forbidden"; echo "       got: ${got//$'\n'/ }" | cut -c1-${CUT:-400}; failures=$((failures + 1)); fi
}
# A check that FAILED -- not its name somewhere in the list, where a passing one also appears.
refused() {
    local what=$1 name=$2 got=$3
    if grep -qE "\"check\": \"$name\", \"detail\": [^}]*, \"passed\": false" <<<"$got"; then echo "  ok   $what"; else
        echo "  FAIL $what"; echo "       expected check $name to fail"; echo "       got: ${got//$'\n'/ }" | cut -c1-${CUT:-400}; failures=$((failures + 1)); fi
}
equals() {
    local what=$1 expected=$2 got=$3
    if [[ "$got" == "$expected" ]]; then echo "  ok   $what"; else
        echo "  FAIL $what"; echo "       expected exactly: $expected"; echo "       got: ${got//$'\n'/ }" | cut -c1-${CUT:-400}; failures=$((failures + 1)); fi
}
seq_untouched() { equals "  ...and the sequence did not move" "1|f" "$(as_super -c "select last_value, is_called from s")"; }

echo "1. SQL in a text argument is not SQL the gate judged"
check "control: the agent reads its own tenant" "$MINE" "$(as "$A" -c "$(pc 'select body from docs')")"
out=$(as "$A" -c "$(pc "select query_to_xml('select set_config(''app.tenant_id'', ''2'', true)', true, false, '') a, query_to_xml('select body from docs', true, false, '') b")")
lacks "query_to_xml() with set_config() inside does not reach the other tenant" "$THEIRS" "$out"
refused "  ...because it does not verify" no_hidden_sql "$out"
out=$(as "$A" -c "$(pc "select query_to_xml_and_xmlschema('select nextval(''s'')', true, false, '')")")
refused "query_to_xml_and_xmlschema() with nextval() inside is refused" no_hidden_sql "$out"
seq_untouched
out=$(as "$A" -c "$(pc "select body from docs where (select count(*) from ts_stat('select to_tsvector(set_config(''app.tenant_id'', ''2'', true))')) > 0")")
lacks "ts_stat() with set_config() inside does not reach the other tenant" "$THEIRS" "$out"
refused "  ...because it does not verify" no_hidden_sql "$out"
out=$(as "$A" -c "$(pc "select * from ts_stat('select to_tsvector(nextval(''s'')::text)')")")
refused "ts_stat() with nextval() inside is refused" no_hidden_sql "$out"
seq_untouched
out=$(as "$A" -c "$(pc "select ts_rewrite('a'::tsquery, 'select ''a''::tsquery, (''b'' || nextval(''s''))::tsquery')")")
refused "ts_rewrite() over a query is refused" no_hidden_sql "$out"
seq_untouched
for call in "query_to_xmlschema('select 1', true, false, '')" \
            "cursor_to_xml('c', 1, true, false, '')" \
            "table_to_xml('docs', true, false, '')" \
            "schema_to_xml('public', true, false, '')" \
            "database_to_xml(true, false, '')"; do
    refused "${call%%(*}() is refused" no_hidden_sql "$(as "$A" -c "$(pc "select $call")")"
done
if [ -n "$(as_super -c "select 1 from pg_available_extensions where name = 'tablefunc'")" ]; then
    as_super -q -c "create extension if not exists tablefunc" >/dev/null
    out=$(as "$A" -c "$(pc "select * from crosstab('select set_config(''app.tenant_id'', ''2'', true), ''k'', body from docs') as t(r text, v text)")")
    lacks "tablefunc's crosstab() (a STABLE C function of an extension) does not reach the other tenant" "$THEIRS" "$out"
    refused "  ...because it does not verify" no_hidden_sql "$out"
else
    echo "  --   tablefunc is not available in this PostgreSQL: the crosstab() case did not run"
fi
out=$(as "$A" -c "$(pc 'select body from docs where public.mislabeled() = 1')")
lacks "a DBA's function marked STABLE that calls set_config() does not reach the other tenant" "$THEIRS" "$out"
check "  ...because set_config() does not start while the agent's SQL runs" "reached pg_catalog.set_config()" "$out"

echo "2. an allow_ddl agent's CREATE TABLE AS is DDL, not an uncounted write"
check "control: CREATE TABLE AS over a plain read is kept" '"outcome": "kept"' \
    "$(as "$D" -c "$(pc 'create table ddl.copy as select id from orders')")"
equals "  ...with every row" "20" "$(as_super -c "select count(*) from ddl.copy")"
out=$(as "$D" -c "$(pc 'create table ddl.loot as with d as (delete from orders returning *) select * from d')")
refused "CREATE TABLE AS over a CTE that deletes is refused" no_writing_cte "$out"
equals "  ...and no row was deleted, no table kept" "20|" \
    "$(as_super -c "select (select count(*) from orders) || '|' || coalesce(to_regclass('ddl.loot')::text, '')")"
out=$(as "$D" -c "$(pc 'with d as (delete from orders returning *) select * into ddl.loot2 from d')")
refused "SELECT INTO over a CTE that deletes is refused" no_writing_cte "$out"
equals "  ...and no row was deleted" "20" "$(as_super -c "select count(*) from orders")"
out=$(as "$D" -c "$(pc "create table ddl.peek as select set_config('app.tenant_id', '2', true) t, body from docs")")
refused "CREATE TABLE AS that calls set_config() is refused" keeps_its_context "$out"
equals "  ...and keeps no table" "" "$(as_super -c "select to_regclass('ddl.peek')")"
refused "CREATE TABLE AS over query_to_xml() is refused" no_hidden_sql \
    "$(as "$D" -c "$(pc "create table ddl.x as select query_to_xml('select 1', true, false, '') x")")"
refused "CREATE MATERIALIZED VIEW is judged the same way" no_hidden_sql \
    "$(as "$D" -c "$(pc "create materialized view ddl.mv as select query_to_xml('select 1', true, false, '') x")")"

echo "3. a function the agent can alter, or with a SET clause, is opaque"
check "an allow_ddl agent's own SET app.tenant_id on a function is refused by PostgreSQL itself" \
    "permission denied to set parameter" \
    "$(as "$D" -c "$(pc "create function ddl.as_two() returns setof docs language sql stable set app.tenant_id = '2' as 'select * from public.docs'")")"
check "control: the allow_ddl agent can still create a function" '"outcome": "kept"' \
    "$(as "$D" -c "$(pc "create function ddl.peek() returns setof docs language sql stable as 'select * from public.docs'")")"
out=$(as "$D" -c "$(pc 'select body from ddl.peek()')")
refused "  ...but a function it can alter does not verify: its STABLE is its own claim" no_opaque_function "$out"
as "$D" -c "$(pc "create function ddl.imm() returns int language plpgsql immutable as \$f\$ begin perform set_config('app.tenant_id', '2', false); return 1; end \$f\$")" >/dev/null
out=$(as "$D" -c "$(pc 'select body from docs where ddl.imm() = 1')")
lacks "its own falsely IMMUTABLE plpgsql function does not reach the other tenant" "$THEIRS" "$out"
refused "  ...because it does not verify" no_opaque_function "$out"
as "$D" -c "$(pc "create function ddl.imm2() returns text language sql immutable begin atomic select set_config('app.tenant_id', '2', false); end")" >/dev/null
out=$(as "$D" -c "$(pc 'select body from docs where ddl.imm2() is not null')")
lacks "its own falsely IMMUTABLE SQL-standard function does not reach the other tenant" "$THEIRS" "$out"
refused "  ...because it does not verify" no_opaque_function "$out"
as "$D" -c "$(pc 'create table ddl.t (x int check (ddl.imm() = 1))')" >/dev/null
out=$(as "$D" -c "$(pc 'insert into ddl.t values (1)')" -c "$(pc 'select body from docs')")
lacks "its own function in a CHECK of its own table does not move the session's tenant" "$THEIRS" "$out"
check "  ...because the function does not start while the agent's SQL runs" "reached ddl.imm()" "$out"
equals "  ...and the row was not kept" "0" "$(as_super -c "select count(*) from ddl.t")"
out=$(as "$A" -c "$(pc 'select body from public.docs_as_two()')")
lacks "a DBA's STABLE function with SET app.tenant_id does not move an ordinary agent" "$THEIRS" "$out"
refused "  ...because it does not verify" no_opaque_function "$out"
out=$(as "$A" -c "$(pc 'select body from public.docs_tidy()')")
check "control: a DBA's STABLE function with SET search_path still works" "$MINE" "$out"
lacks "  ...under the agent's own tenant" "$THEIRS" "$out"

if [ "$failures" -ne 0 ]; then
    echo "$failures check(s) failed"
    exit 1
fi
echo "the review of 0.4.1 is closed, each finding against its control"
