#!/usr/bin/env bash
# The review of 0.4.2 (2026-11-05): what got past the gate, closed in 0.4.3, each with its tooth
# and its control. Every verdict is read from the effect -- the other tenant's row, the table, the
# sequence, the large objects, the advisory lock -- and not from the gate's own answer alone.
#
# The root they share: code the statement's tree does not show -- a domain's CHECK, a table's
# DEFAULT or CHECK, an aggregate's transition function, a range type's subtype_diff called from
# the type cache -- ran with no judgment, or was judged against the wrong role, or changed rows no
# one counted. 0.4.3 judges every function where it STARTS (the executor's hook and the function
# manager's), against the agent's own role, by the kind of statement running; runs the DDL trial
# at propose inside the executing window; and counts what a DDL changes like a write.
#
#   A. an allow_ddl agent's function as a range type's subtype_diff SET the tenant from a GiST
#      build at propose and raised the other tenant's row into the `executes` detail;
#   B. the same at commit deleted 20 rows under max_rows 2 and advanced a sequence;
#   C. a domain CHECK ran nextval() and pg_advisory_lock() from a read, also for an ordinary agent
#      through pg_input_is_valid();
#   D. ALTER TABLE ... DEFAULT / CHECK over a DBA's volatile function deleted rows elsewhere;
#   E. an aggregate (IMMUTABLE in pg_proc) hid a volatile transition function;
#   F. large objects created by a write were not counted;
#   G. proposing an ALTER ... DEFAULT nextval() advanced a sequence;
#   R1. a write to a table with a citext foreign key was refused (RI runs as the table owner);
#   R2. a DBA's function with SET work_mem / jit / plan_cache_mode was refused, and with it every
#       read of a table whose policy function had one;
#   R3. the floor copied a function's whole body each time it started (~110x on a read).
#
#   PG_CONFIG=/path/to/pg_config tests/cluster.sh init && tests/cluster.sh start
#   PG_CONFIG=/path/to/pg_config tests/audit6.sh
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PG_CONFIG=${PG_CONFIG:-pg_config}
BIN=$("$PG_CONFIG" --bindir)
export PGHOST=${PGHOST:-$ROOT/.testcluster}
export PGPORT=${PGPORT:-5499}
SUPERUSER=${SUPERUSER:-$(id -un)}
DB=agent_gate_audit6
A=agent_gate_audit6_a      # an ordinary agent
D=agent_gate_audit6_d      # an allow_ddl agent, max_rows 2
MINE=doc-of-tenant-one
THEIRS=doc-of-tenant-two

as_super() { "$BIN/psql" -X -U "$SUPERUSER" -d "$DB" -tA "$@" 2>&1; }
as() { local r=$1; shift; "$BIN/psql" -X -U "$r" -d "$DB" -tA "$@" 2>&1 || true; }
pc() { printf "select agent_gate.propose_and_commit(\$q\$%s\$q\$, 'audit6')" "$1"; }
pr() { printf "select agent_gate.propose(\$q\$%s\$q\$, 'audit6')" "$1"; }

source "$(dirname "${BASH_SOURCE[0]}")/guard.sh"
trap release_claimed EXIT
require_throwaway_cluster
for r in "$A" "$D"; do claim_role "$r"; done
claim_database "$DB"
have_citext=$(as_super -c "select count(*) from pg_available_extensions where name = 'citext'")
"$BIN/psql" -X -U "$SUPERUSER" -d "$DB" -v ON_ERROR_STOP=1 -q -v a="$A" -v d="$D" >/dev/null <<SQL
CREATE EXTENSION pg_agent_gate;
CREATE TABLE docs (tenant int NOT NULL, body text NOT NULL);
INSERT INTO docs VALUES (1, '$MINE'), (2, '$THEIRS');
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY by_tenant ON docs USING (tenant = current_setting('app.tenant_id')::int);
CREATE TABLE orders (id int PRIMARY KEY);
INSERT INTO orders SELECT generate_series(1, 20);
CREATE TABLE items (id int PRIMARY KEY, n int NOT NULL);
INSERT INTO items VALUES (104, 0);
CREATE TABLE serials (id serial PRIMARY KEY, v int);
CREATE SEQUENCE s;
CREATE SCHEMA ddl AUTHORIZATION :"d";
GRANT USAGE ON SCHEMA public TO :"a", :"d";
GRANT SELECT ON docs TO :"a", :"d";
GRANT SELECT, DELETE ON orders TO :"d";
GRANT SELECT, UPDATE ON items TO :"a";
GRANT SELECT, INSERT ON serials TO :"a";
GRANT USAGE ON SEQUENCE serials_id_seq TO :"a";
GRANT USAGE, SELECT, UPDATE ON SEQUENCE s TO :"a", :"d";
-- A DBA's housekeeping function: volatile, not SECURITY DEFINER, EXECUTE to PUBLIC by default.
CREATE FUNCTION public.purge_one() RETURNS int LANGUAGE sql VOLATILE
    AS 'delete from public.orders where id = (select min(id) from public.orders) returning 1';
-- A DBA's aggregate over a volatile transition function.
CREATE FUNCTION public.seq_sfunc(st int, n int) RETURNS int LANGUAGE plpgsql VOLATILE
    AS \$\$ BEGIN PERFORM nextval('public.s'); RETURN coalesce(st, 0) + 1; END \$\$;
CREATE AGGREGATE public.count_seq(int) (sfunc = public.seq_sfunc, stype = int);
-- A DBA's functions with a harmless SET clause, one of them a policy's.
CREATE FUNCTION public.f_workmem() RETURNS SETOF docs LANGUAGE sql STABLE SET work_mem = '64MB'
    AS 'select * from public.docs';
CREATE FUNCTION public.f_jit(int) RETURNS int LANGUAGE sql IMMUTABLE SET jit = off AS 'select \$1';
CREATE FUNCTION public.cur_tenant() RETURNS int LANGUAGE sql STABLE SET plan_cache_mode = force_custom_plan
    AS \$\$ select current_setting('app.tenant_id')::int \$\$;
CREATE TABLE docs2 (tenant int, body text);
INSERT INTO docs2 VALUES (1, 'd2-one'), (2, 'd2-two');
ALTER TABLE docs2 ENABLE ROW LEVEL SECURITY;
CREATE POLICY p2 ON docs2 USING (tenant = public.cur_tenant());
GRANT SELECT ON docs2 TO :"a";
-- A large body behind a wrapper that re-runs a query per row (what the floor reads per call).
DO \$d\$ BEGIN EXECUTE 'CREATE FUNCTION public.big(int) RETURNS int LANGUAGE plpgsql IMMUTABLE AS \$b\$ BEGIN /* '
    || (SELECT string_agg(md5(g::text), '') FROM generate_series(1, 30000) g) || ' */ RETURN \$1; END \$b\$'; END \$d\$;
CREATE FUNCTION public.small(int) RETURNS int LANGUAGE plpgsql IMMUTABLE AS \$b\$ BEGIN RETURN \$1; END \$b\$;
CREATE FUNCTION public.wrap_big(int) RETURNS int LANGUAGE plpgsql STABLE
    AS \$w\$ DECLARE r int; BEGIN SELECT public.big(\$1) INTO r FROM (SELECT 1) s; RETURN r; END \$w\$;
CREATE FUNCTION public.wrap_small(int) RETURNS int LANGUAGE plpgsql STABLE
    AS \$w\$ DECLARE r int; BEGIN SELECT public.small(\$1) INTO r FROM (SELECT 1) s; RETURN r; END \$w\$;
CREATE TABLE nums AS SELECT g FROM generate_series(1, 3000) g;
GRANT SELECT ON nums TO :"a";
ALTER ROLE :"a" SET app.tenant_id = '1';
ALTER ROLE :"d" SET app.tenant_id = '1';
SELECT agent_gate.register_agent('audit6_a', :'a', 'reads the documents of its own tenant');
SELECT agent_gate.register_agent('audit6_d', :'d', 'schema power in its own schema',
                                 p_max_rows => 2, p_allow_ddl => true, p_max_rows_per_window => 1000);
SQL
if [ "$have_citext" = 1 ]; then
    "$BIN/psql" -X -U "$SUPERUSER" -d "$DB" -v ON_ERROR_STOP=1 -q -v a="$A" >/dev/null <<SQL
CREATE EXTENSION citext;
CREATE TABLE parent (code citext PRIMARY KEY);
INSERT INTO parent VALUES ('ABC');
CREATE TABLE child (id int, code citext REFERENCES parent);
CREATE TABLE tparent (code text PRIMARY KEY);
INSERT INTO tparent VALUES ('abc');
CREATE TABLE tchild (id int, code text REFERENCES tparent);
GRANT SELECT, INSERT ON child, tchild TO :"a";
SQL
fi

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
seqv() { as_super -c "select last_value || '|' || is_called from s"; }
orders() { as_super -c "select count(*) from orders"; }
los() { as_super -c "select count(*) from pg_largeobject_metadata"; }

echo "A. a range type's subtype_diff, called from the type cache, at propose"
as "$D" -c "$(pc 'create function ddl.diff(a float8, b float8) returns float8 language plpgsql immutable as $f$ declare x text; begin set app.tenant_id = $v$2$v$; select string_agg(body, $v$,$v$) into x from public.docs; raise exception $v$LEAK %$v$, x; end $f$')" >/dev/null
as "$D" -c "$(pc 'create type ddl.fr as range (subtype = float8, subtype_diff = ddl.diff)')" >/dev/null
check "control: a table of that range type is created" '"outcome": "kept"' \
    "$(as "$D" -c "$(pc 'create table ddl.rt as select ($v$[$v$ || g || $v$,$v$ || (g + 1) || $v$)$v$)::ddl.fr r from generate_series(1, 3000) g')")"
as "$D" -c "$(pc 'alter function ddl.diff(float8, float8) volatile')" >/dev/null
out=$(as "$D" -c "$(pc 'create index rt_gist on ddl.rt using gist (r)')")
lacks "the GiST build does not raise the other tenant's row into the agent's answer" "$THEIRS" "$out"
check "  ...because the agent's own function does not start from the type cache" "reached ddl.diff()" "$out"
equals "  ...and no index was kept" "" "$(as_super -c "select to_regclass('ddl.rt_gist')")"

echo "B. the same path, at commit: rows and a sequence"
before=$(seqv)
as "$D" -c "$(pc 'create function ddl.diff2(a float8, b float8) returns float8 language plpgsql immutable as $f$ begin delete from public.orders; perform nextval($v$public.s$v$); return a - b; end $f$')" >/dev/null
as "$D" -c "$(pc 'create type ddl.fr2 as range (subtype = float8, subtype_diff = ddl.diff2)')" >/dev/null
as "$D" -c "$(pc 'create table ddl.rt2 as select ($v$[$v$ || g || $v$,$v$ || (g + 1) || $v$)$v$)::ddl.fr2 r from generate_series(1, 3000) g')" >/dev/null
as "$D" -c "$(pc 'alter function ddl.diff2(float8, float8) volatile')" >/dev/null
out=$(as "$D" -c "$(pc 'create index rt2_gist on ddl.rt2 using gist (r)')")
lacks "CREATE INDEX over the agent's subtype_diff is not kept" '"outcome": "kept"' "$out"
equals "  ...and no row of orders was deleted" "20" "$(orders)"
equals "  ...and the sequence did not move" "$before" "$(seqv)"

echo "C. a domain's CHECK runs under the same rule as the statement"
before=$(seqv)
check "control: a direct nextval() in a read is refused" "read_changes_nothing" \
    "$(as "$D" -c "$(pc 'select nextval($v$public.s$v$)')")"
as "$D" -c "$(pc 'create domain ddl.dm as int check (nextval($v$public.s$v$) > 0)')" >/dev/null
out=$(as "$D" -c "$(pc 'select count(x::ddl.dm) from generate_series(1, 50) x')")
lacks "a read that casts to a domain whose CHECK calls nextval() is not a read" '"outcome": "read"' "$out"
check "  ...because nextval() does not start in a read, wherever it is" "reached pg_catalog.nextval()" "$out"
equals "  ...and the sequence did not move" "$before" "$(seqv)"
as "$D" -c "$(pc 'create domain ddl.sq as int check (nextval($v$public.s$v$) > 0)')" >/dev/null
as_super -q -c "grant usage on schema ddl to $A" >/dev/null
out=$(as "$A" -c "$(pc 'select count(*) filter (where pg_input_is_valid(x::text, $v$ddl.sq$v$)) from generate_series(1, 7) x')")
lacks "an ordinary agent's pg_input_is_valid() over that domain is not a read" '"outcome": "read"' "$out"
equals "  ...and the sequence did not move" "$before" "$(seqv)"
as "$D" -c "$(pc 'create domain ddl.lk as int check (pg_advisory_lock(VALUE) is not null)')" >/dev/null
lockf=$(mktemp)
( as "$D" -c "$(pc 'select 4242::ddl.lk')" -c '\! sleep 3' >"$lockf" ) &
sleep 1.5
held=$(as_super -c "select count(*) from pg_locks where locktype = 'advisory' and objid = 4242")
wait
equals "a read through a domain whose CHECK takes a session advisory lock leaves no lock held" "0" "$held"
check "  ...because pg_advisory_lock() does not start" "reached pg_catalog.pg_advisory_lock(" "$(cat "$lockf")"
rm -f "$lockf"
check "control: an INSERT that numbers its rows with nextval() is still kept" '"outcome": "kept"' \
    "$(as "$A" -c "$(pc 'insert into serials (v) values (1)')")"

echo "D. a DDL's DEFAULT or CHECK changes rows elsewhere: counted"
as "$D" -c "$(pc 'create table ddl.t (id int)')" >/dev/null
as_super -q -c "insert into ddl.t select generate_series(1, 10)" >/dev/null
check "control: the same function in a write is refused" "no_opaque_function" \
    "$(as "$D" -c "$(pc 'delete from orders where id = public.purge_one()')")"
out=$(as "$D" -c "$(pc 'alter table ddl.t add column z int default public.purge_one()')")
lacks "ALTER TABLE ... ADD COLUMN DEFAULT over a function that deletes is not kept" '"outcome": "kept"' "$out"
check "  ...because the rows it changed in another table are counted" "rows of tables that existed before it" "$out"
equals "  ...and no row of orders was deleted" "20" "$(orders)"
out=$(as "$D" -c "$(pc 'alter table ddl.t add constraint c check (public.purge_one() > 0)')")
lacks "ALTER TABLE ... ADD CHECK over a function that deletes is not kept" '"outcome": "kept"' "$out"
equals "  ...and no row of orders was deleted" "20" "$(orders)"
check "control: a DDL that changes no other table's rows is kept" '"outcome": "kept"' \
    "$(as "$D" -c "$(pc 'alter table ddl.t add column w int default 0')")"

echo "E. an aggregate is the functions it runs"
before=$(seqv)
check "control: the transition function called directly is refused" "no_opaque_function" \
    "$(as "$A" -c "$(pc 'select public.seq_sfunc(0, 1)')")"
out=$(as "$A" -c "$(pc 'select public.count_seq(x) from generate_series(1, 25) x')")
refused "an aggregate over a volatile transition function is refused" no_opaque_function "$out"
equals "  ...and the sequence did not move" "$before" "$(seqv)"
check "control: a built-in aggregate still reads" '"sum": 325' \
    "$(as "$A" -c "$(pc 'select sum(x) from generate_series(1, 25) x')")"

echo "F. large objects are state outside the rows a write counts"
out=$(as "$A" -c "$(pc 'update items set n = 1 where id = 104 and (select count(lo_from_bytea(0, $v$x$v$)) from generate_series(1, 50)) = 50')")
refused "a write that creates large objects is refused" changes_only_rows "$out"
equals "  ...and no large object exists" "0" "$(los)"
as "$D" -c "$(pc 'create domain ddl.lo5 as int check (lo_from_bytea(0, $v$a$v$) > 0)')" >/dev/null
as "$D" -c "$(pc 'create table ddl.w (x ddl.lo5)')" >/dev/null
out=$(as "$D" -c "$(pc 'insert into ddl.w values (1), (2)')")
check "a write through a domain whose CHECK creates large objects is stopped" "reached pg_catalog.lo_from_bytea()" "$out"
equals "  ...and no large object exists" "0" "$(los)"
check "control: the plain write is kept" '"outcome": "kept"' \
    "$(as "$A" -c "$(pc 'update items set n = 1 where id = 104')")"

echo "G. proposing a DDL changes nothing"
as "$D" -c "$(pc 'create table ddl.g (id int)')" >/dev/null
as_super -q -c "insert into ddl.g select generate_series(1, 10)" >/dev/null
before=$(seqv)
out=$(as "$D" -c "$(pr 'alter table ddl.g add column n bigint default nextval($v$public.s$v$)')")
check "proposing a DEFAULT nextval() over a table's rows is refused" "reached pg_catalog.nextval()" "$out"
equals "  ...and the sequence did not move" "$before" "$(seqv)"
check "control: an identity column numbers the rows" '"outcome": "kept"' \
    "$(as "$D" -c "$(pc 'alter table ddl.g add column k int generated always as identity')")"

echo "R1. a write checked by a foreign key over an extension's type"
if [ "$have_citext" = 1 ]; then
    check "control: a foreign key over text" '"outcome": "kept"' "$(as "$A" -c "$(pc "insert into tchild values (1, 'abc')")")"
    check "a foreign key over citext (its operator owned by the superuser) is kept" '"outcome": "kept"' \
        "$(as "$A" -c "$(pc "insert into child values (1, 'abc')")")"
    equals "  ...with its row" "1" "$(as_super -c "select count(*) from child")"
else
    echo "  --   citext is not available in this PostgreSQL: the R1 case did not run"
fi

echo "R2. a SET clause that only says how a body runs"
check "a DBA's STABLE function with SET work_mem reads" "$MINE" "$(as "$A" -c "$(pc 'select body from public.f_workmem()')")"
check "a DBA's IMMUTABLE function with SET jit reads" '"outcome": "read"' \
    "$(as "$A" -c "$(pc 'select body, public.f_jit(tenant) from docs')")"
out=$(as "$A" -c "$(pc 'select body from docs2')")
check "a table whose policy function sets plan_cache_mode reads" "d2-one" "$out"
lacks "  ...under the agent's own tenant" "d2-two" "$out"

echo "R3. what the floor costs per function start"
ms() { local t0 t1; t0=$(date +%s%N); as "$A" -c "$(pc "$1")" >/dev/null; t1=$(date +%s%N); echo $(((t1 - t0) / 1000000)); }
ms 'select count(*) from nums where public.wrap_small(g) > 0' >/dev/null
small=$(ms 'select count(*) from nums where public.wrap_small(g) > 0')
big=$(ms 'select count(*) from nums where public.wrap_big(g) > 0')
echo "       wrapper over a small body: ${small} ms; over a 960 kB body: ${big} ms"
if [ "$big" -le $((small * 5 + 100)) ]; then echo "  ok   a function's body size does not set the cost of starting it"; else
    echo "  FAIL a function's body size does not set the cost of starting it (${big} ms against ${small} ms)"; failures=$((failures + 1)); fi
check "  ...and the read is correct" '"count": 3000' "$(as "$A" -c "$(pc 'select count(*) from nums where public.wrap_big(g) > 0')")"

if [ "$failures" -ne 0 ]; then
    echo "$failures check(s) failed"
    exit 1
fi
echo "the review of 0.4.2 is closed, each finding against its control"
