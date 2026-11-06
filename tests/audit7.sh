#!/usr/bin/env bash
# The second review of 0.4.3 (2026-11-05): what still got past the gate, closed before 0.4.3 was
# released, each with its tooth and its control. Every verdict is read from the effect -- the other
# tenant's row, the setting, the sequence, the table, the column, the other session -- and not from
# the gate's own answer alone.
#
# The roots they share, and the principle each one is closed by:
#   C1. a verb's parameter of an agent-made domain ran its CHECK when it was BOUND, before any verb:
#       set_config() switched the tenant for the rest of the session. The floor stands for the
#       whole agent session; a verb's argument has a built-in type; the context is an invariant.
#   C2. an allow_ddl agent's TEMPORARY table answered for a name a DBA's policy helper did not
#       qualify (pg_temp is searched first). An agent does not create temporary objects.
#   C3. DROP ... CASCADE, DROP of a DBA's table in the agent's schema, DROP DOMAIN ... CASCADE and
#       ALTER TYPE ... RENAME VALUE reached DBA tables, 0 rows counted. An agent's DDL changes only
#       what the agent owns, judged object by object as PostgreSQL drops or alters it.
#   C4. pg_terminate_backend() passed as a read. A volatile built-in changes state unless it is
#       on a reviewed list of those that only read.
#   C5. ALTER FUNCTION ... OWNER TO a role the agent belongs to WITHOUT INHERIT made its code "the
#       DBA's". Authorship is membership, with or without INHERIT.
#   R1. a DBA function pinning a module's parameter (pg_trgm.*, hnsw.*, plpgsql.*) was refused;
#   R2. a DBA's DDL-audit event trigger (nextval, pg_notify) refused every agent DDL;
#   R3. every MERGE aborted ("unrecognized SPI status code: 19");
#   R4. lo_get() was refused in reads and writes;  R5. intagg's aggregate was refused;
#   R6. ADD COLUMN serial was refused while GENERATED AS IDENTITY passed.
#
#   PG_CONFIG=/path/to/pg_config tests/cluster.sh init && tests/cluster.sh start
#   PG_CONFIG=/path/to/pg_config tests/audit7.sh
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PG_CONFIG=${PG_CONFIG:-pg_config}
BIN=$("$PG_CONFIG" --bindir)
export PGHOST=${PGHOST:-$ROOT/.testcluster}
export PGPORT=${PGPORT:-5499}
SUPERUSER=${SUPERUSER:-$(id -un)}
DB=agent_gate_audit7
A=agent_gate_audit7_a      # an ordinary agent
D=agent_gate_audit7_d      # an allow_ddl agent, max_rows 2
N=agent_gate_audit7_n      # an allow_ddl agent, NOINHERIT member of O
O=agent_gate_audit7_o      # a role N belongs to without inheriting it
MINE=doc-of-tenant-one
THEIRS=doc-of-tenant-two

as_super() { "$BIN/psql" -X -U "$SUPERUSER" -d "$DB" -tA "$@" 2>&1; }
as() { local r=$1; shift; "$BIN/psql" -X -U "$r" -d "$DB" -tA "$@" 2>&1 || true; }
# One session, the script on stdin (temporary tables and settings live as long as the session).
session() { "$BIN/psql" -X -U "$1" -d "$DB" -tA 2>&1 || true; }
pc() { printf "select agent_gate.propose_and_commit(\$q\$%s\$q\$, 'audit7')" "$1"; }
pr() { printf "select agent_gate.propose(\$q\$%s\$q\$, 'audit7')" "$1"; }

source "$(dirname "${BASH_SOURCE[0]}")/guard.sh"
trap release_claimed EXIT
require_throwaway_cluster
for r in "$A" "$D" "$N" "$O"; do claim_role "$r"; done
claim_database "$DB"
available() { as_super -c "select count(*) from pg_available_extensions where name = '$1'"; }
"$BIN/psql" -X -U "$SUPERUSER" -d "$DB" -v ON_ERROR_STOP=1 -q -v a="$A" -v d="$D" -v n="$N" -v o="$O" >/dev/null <<SQL
CREATE EXTENSION pg_agent_gate;
CREATE TABLE docs (tenant int NOT NULL, body text NOT NULL);
INSERT INTO docs VALUES (1, '$MINE'), (2, '$THEIRS');
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY by_tenant ON docs USING (tenant = current_setting('app.tenant_id')::int);
-- C2: a policy helper that names its table without a schema, as the README's helpers do.
CREATE TABLE tenant_of (r name PRIMARY KEY, t int NOT NULL);
INSERT INTO tenant_of VALUES (:'d', 1);
CREATE FUNCTION public.my_tenant() RETURNS int LANGUAGE sql STABLE
    AS 'select t from tenant_of where r = current_user';
CREATE TABLE notes (tenant int NOT NULL, body text NOT NULL);
INSERT INTO notes VALUES (1, 'note-of-tenant-one'), (2, 'note-of-tenant-two');
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY by_helper ON notes USING (tenant = public.my_tenant());
CREATE TABLE orders (id int PRIMARY KEY);
INSERT INTO orders SELECT generate_series(1, 20);
CREATE SEQUENCE s;
CREATE TABLE m (id int PRIMARY KEY, v int NOT NULL);
INSERT INTO m VALUES (1, 1), (2, 2);
CREATE TABLE files (id int PRIMARY KEY, data oid, body text);
INSERT INTO files VALUES (1, lo_from_bytea(0, 'hello'), NULL);
CREATE SCHEMA ddl AUTHORIZATION :"d";
CREATE SCHEMA ddl2 AUTHORIZATION :"d";
CREATE SCHEMA ddl3 AUTHORIZATION :"d";
CREATE SCHEMA ddln AUTHORIZATION :"n";
GRANT USAGE ON SCHEMA public TO :"a", :"d", :"n";
GRANT SELECT ON docs, notes, tenant_of TO :"a", :"d";
GRANT SELECT, DELETE ON orders TO :"n";
GRANT SELECT, INSERT, UPDATE, DELETE ON m TO :"a";
GRANT SELECT, UPDATE ON files TO :"a";
GRANT USAGE, SELECT, UPDATE ON SEQUENCE s TO :"a", :"d";
DO \$\$ BEGIN EXECUTE format('GRANT SELECT ON LARGE OBJECT %s TO %I', (SELECT data FROM files), '$A'); END \$\$;
-- C5: the agent belongs to O without inheriting it, and may hand objects to it.
ALTER ROLE :"n" NOINHERIT;
GRANT :"o" TO :"n" WITH INHERIT FALSE;
GRANT CREATE, USAGE ON SCHEMA ddln TO :"o";
ALTER ROLE :"a" SET app.tenant_id = '1';
ALTER ROLE :"d" SET app.tenant_id = '1';
SELECT agent_gate.register_agent('audit7_a', :'a', 'reads the documents of its own tenant', p_max_rows => 5);
SELECT agent_gate.register_agent('audit7_d', :'d', 'schema power in its own schema',
                                 p_max_rows => 2, p_allow_ddl => true, p_max_rows_per_window => 1000);
SELECT agent_gate.register_agent('audit7_n', :'n', 'schema power in its own schema',
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

echo "C1. a verb's parameter of an agent's domain, bound over the extended protocol"
as "$D" -c "$(pc 'create domain ddl.dtext as text check (pg_catalog.set_config($v$app.tenant_id$v$, $v$2$v$, false) is not null)')" >/dev/null
as "$D" -c "$(pc 'create domain ddl.stext as text check (pg_catalog.setval($v$public.s$v$, 424242) > 0)')" >/dev/null
as "$D" -c "$(pc 'grant usage on schema ddl to public')" >/dev/null
check "control: the ordinary agent reads its own tenant" "$MINE" "$(as "$A" -c "$(pc 'select body from public.docs')")"
out=$(session "$A" <<'S'
select agent_gate.propose_and_commit($1::ddl.dtext, 'audit7') \bind 'select tenant, body from public.docs' \g
show app.tenant_id;
S
)
lacks "a parameter bound as the agent's domain does not read the other tenant" "$THEIRS" "$out"
check "  ...because the verb refuses an argument of a type that is not built in" "not a built-in type" "$out"
equals "  ...and the session's tenant did not move" "1" "$(tail -1 <<<"$out")"
before=$(seqv)
out=$(session "$A" <<'S'
select agent_gate.propose_and_commit($1::ddl.stext, 'audit7') \bind 'select 1 as one' \g
S
)
equals "a parameter whose domain CHECK calls setval() does not move the sequence" "$before" "$(seqv)"
check "control: a parameter of a built-in type still binds" "$MINE" "$(session "$A" <<'S'
select agent_gate.propose_and_commit($1, 'audit7') \bind 'select body from public.docs' \g
S
)"

echo "C2. an allow_ddl agent's temporary table and a DBA's helper that does not qualify a name"
out=$(session "$D" <<S
$(pc 'select body from public.notes');
$(pc 'create temp table tenant_of (r name, t int)');
$(pc 'insert into tenant_of values (current_user, 2)');
$(pc 'select body from public.notes');
S
)
check "control: the agent reads its own tenant's note" "note-of-tenant-one" "$(head -1 <<<"$out")"
lacks "a temporary table does not answer for the DBA's helper" "note-of-tenant-two" "$out"
check "  ...because an agent does not create temporary objects" "does not create temporary objects" "$out"
check "control: a table in its own schema is kept" '"outcome": "kept"' "$(as "$D" -c "$(pc 'create table ddl.mine (id int)')")"

echo "C3. an agent's DDL changes only what the agent owns"
as "$D" -c "$(pc 'create type ddl.comp as (a int, b text)')" >/dev/null
as "$D" -c "$(pc 'create domain ddl.amount as int')" >/dev/null
as "$D" -c "$(pc 'create type ddl.mood as enum ($v$ok$v$, $v$bad$v$)')" >/dev/null
as "$D" -c "$(pc 'create domain ddl.free as int')" >/dev/null
as "$D" -c "$(pc 'create table ddl3.own (id int)')" >/dev/null
as_super -q -v ON_ERROR_STOP=1 >/dev/null <<SQL
CREATE TABLE public.ledger OF ddl.comp;
INSERT INTO public.ledger SELECT g, 'x' FROM generate_series(1, 20) g;
CREATE TABLE ddl.dba_owned (id int);
INSERT INTO ddl.dba_owned SELECT generate_series(1, 50);
CREATE TABLE ddl2.dba_too (id int);
INSERT INTO ddl2.dba_too SELECT generate_series(1, 30);
CREATE TABLE public.accounts (id int PRIMARY KEY, balance ddl.amount, mood ddl.mood);
INSERT INTO public.accounts SELECT g, 100 * g, 'ok' FROM generate_series(1, 20) g;
SQL
out=$(as "$D" -c "$(pc 'drop type ddl.comp cascade')")
lacks "DROP TYPE ... CASCADE over a DBA's typed table is not kept" '"outcome": "kept"' "$out"
check "  ...because it would drop a table that belongs to another role" "which belongs to" "$out"
equals "  ...and the DBA's table keeps its 20 rows" "20" "$(as_super -c "select count(*) from public.ledger")"
out=$(as "$D" -c "$(pc 'drop table ddl.dba_owned')")
lacks "DROP of a DBA's table in the agent's schema is not kept" '"outcome": "kept"' "$out"
equals "  ...and it keeps its 50 rows" "50" "$(as_super -c "select count(*) from ddl.dba_owned")"
out=$(as "$D" -c "$(pc 'drop schema ddl2 cascade')")
lacks "DROP SCHEMA ... CASCADE over a DBA's table is not kept" '"outcome": "kept"' "$out"
equals "  ...and the DBA's table keeps its 30 rows" "30" "$(as_super -c "select count(*) from ddl2.dba_too")"
out=$(as "$D" -c "$(pc 'drop domain ddl.amount cascade')")
lacks "DROP DOMAIN ... CASCADE under a DBA's column is not kept" '"outcome": "kept"' "$out"
equals "  ...and the DBA's column keeps its 20 values" "20" "$(as_super -c "select count(balance) from public.accounts")"
out=$(as "$D" -c "$(pc 'alter type ddl.mood rename value $v$ok$v$ to $v$bad_now$v$')")
lacks "ALTER TYPE ... RENAME VALUE under a DBA's column is not kept" '"outcome": "kept"' "$out"
check "  ...because a DBA's column is made of that type" "is made of a type it alters" "$out"
equals "  ...and the DBA's rows still say ok" "20" "$(as_super -c "select count(*) from public.accounts where mood::text = 'ok'")"
check "control: an unused domain of its own is dropped" '"outcome": "kept"' "$(as "$D" -c "$(pc 'drop domain ddl.free cascade')")"
as "$D" -c "$(pc 'create type ddl.m2 as enum ($v$x$v$)')" >/dev/null
as "$D" -c "$(pc 'create table ddl.t2 (m ddl.m2)')" >/dev/null
check "control: renaming a value of a type only its own table uses is kept" '"outcome": "kept"' \
    "$(as "$D" -c "$(pc 'alter type ddl.m2 rename value $v$x$v$ to $v$y$v$')")"
check "control: a schema of its own, with its own table, is dropped with CASCADE" '"outcome": "kept"' \
    "$(as "$D" -c "$(pc 'drop schema ddl3 cascade')")"

echo "C4. a read does not signal another session"
victim=$(mktemp)
( as "$A" -c "$(pc 'select pg_sleep(4) is null as slept')" >"$victim" ) &
pid=""
for _ in $(seq 1 30); do
    pid=$(as_super -c "select pid from pg_stat_activity where usename = '$A' and query like '%pg_sleep%' and pid <> pg_backend_pid() limit 1")
    [ -n "$pid" ] && break
    sleep 0.1
done
out=$(as "$A" -c "$(pc "select pg_terminate_backend($pid) as killed")")
refused "pg_terminate_backend() in a read is refused" read_changes_nothing "$out"
out=$(as "$A" -c "$(pc "select pg_cancel_backend($pid) as cancelled")")
refused "pg_cancel_backend() in a read is refused" read_changes_nothing "$out"
wait
check "  ...and the other session finished its read" '"outcome": "read"' "$(cat "$victim")"
rm -f "$victim"
check "control: a volatile built-in on the reviewed list still reads" '"outcome": "read"' \
    "$(as "$A" -c "$(pc 'select clock_timestamp() is not null as t, random() < 2 as r')")"

echo "C5. a function handed to a role the agent belongs to without INHERIT is still the agent's"
as "$N" -c "$(pc 'create function ddln.del() returns int language plpgsql volatile as $f$ begin delete from public.orders; return 1; end $f$')" >/dev/null
as "$N" -c "$(pc 'create function ddln.w() returns int language plpgsql stable as $f$ begin return ddln.del(); end $f$')" >/dev/null
refused "control: its STABLE wrapper is refused while it owns it" no_opaque_function "$(as "$N" -c "$(pc 'select ddln.w() as x')")"
as "$N" -c "$(pc "alter function ddln.del() owner to $O")" >/dev/null
check "the agent may hand its functions to the role (PostgreSQL allows it)" '"outcome": "kept"' \
    "$(as "$N" -c "$(pc "alter function ddln.w() owner to $O")")"
equals "  ...and the role owns them" "$O" "$(as_super -c "select proowner::regrole from pg_proc where oid = 'ddln.w()'::regprocedure")"
out=$(as "$N" -c "$(pc 'select ddln.w() as x')")
refused "its wrapper is still refused: what it is marked is the agent's claim" no_opaque_function "$out"
lacks "  ...and it is not read" '"outcome": "read"' "$out"
equals "  ...and no order was deleted" "20" "$(orders)"

echo "R1. a DBA's function pinning a module's parameter"
have_trgm=$(available pg_trgm); have_vector=$(available vector)
as_super -q -v ON_ERROR_STOP=1 -v a="$A" >/dev/null <<'SQL'
CREATE TABLE docs4 (id int PRIMARY KEY, tenant int NOT NULL, body text);
INSERT INTO docs4 VALUES (1, 1, 'alpha beta'), (2, 2, 'gamma'), (3, 1, 'alphabet');
CREATE FUNCTION public.t4() RETURNS int LANGUAGE plpgsql STABLE SET plpgsql.print_strict_params = on
    AS $$ begin return current_setting('app.tenant_id')::int; end $$;
ALTER TABLE docs4 ENABLE ROW LEVEL SECURITY;
CREATE POLICY p4 ON docs4 USING (tenant = public.t4());
CREATE FUNCTION public.ctx() RETURNS SETOF docs4 LANGUAGE sql STABLE SET app.tenant_id = '2'
    AS 'select * from public.docs4';
GRANT SELECT ON docs4 TO :"a";
SQL
out=$(as "$A" -c "$(pc 'select id from docs4 order by id')")
check "a table whose policy function pins plpgsql.print_strict_params reads" '"outcome": "read"' "$out"
lacks "  ...under the agent's own tenant" '"id": 2' "$out"
refused "control: a SET clause of an application's parameter is still refused" no_opaque_function \
    "$(as "$A" -c "$(pc 'select id from public.ctx()')")"
if [ "$have_trgm" = 1 ]; then
    as_super -q -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
CREATE EXTENSION pg_trgm;
CREATE FUNCTION public.search4(q text) RETURNS SETOF docs4 LANGUAGE sql STABLE
    SET pg_trgm.similarity_threshold = 0.1 AS 'select * from public.docs4 where body % q';
SQL
    check "a function pinning pg_trgm.similarity_threshold reads" '"outcome": "read"' \
        "$(as "$A" -c "$(pc 'select id from public.search4($v$alpha$v$)')")"
else
    echo "  --   pg_trgm is not available in this PostgreSQL: that case did not run"
fi
if [ "$have_vector" = 1 ]; then
    as_super -q -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
CREATE EXTENSION vector;
ALTER TABLE docs4 ADD COLUMN emb vector(3);
UPDATE docs4 SET emb = '[1,0,0]';
CREATE FUNCTION public.near4(q vector, k int) RETURNS SETOF int LANGUAGE sql STABLE
    SET hnsw.ef_search = 200 AS 'select id from public.docs4 order by emb <-> q limit k';
SQL
    check "a function pinning hnsw.ef_search reads" '"outcome": "read"' \
        "$(as "$A" -c "$(pc 'select public.near4($v$[1,0,0]$v$, 2)')")"
else
    echo "  --   vector is not available in this PostgreSQL: that case did not run"
fi

echo "R3. MERGE"
out=$(as "$A" -c "$(pc 'merge into m using (values (1, 10)) v(id, q) on m.id = v.id when matched then update set v = v.q')")
check "a MERGE is kept" '"outcome": "kept"' "$out"
equals "  ...with its row" "10" "$(as_super -c "select v from m where id = 1")"
check "a MERGE with a RETURNING of its own is kept" '"outcome": "kept"' \
    "$(as "$A" -c "$(pc 'merge into m using (values (2, 20)) v(id, q) on m.id = v.id when matched then update set v = v.q returning merge_action()')")"

echo "R4. reading a large object"
check "lo_get() reads" '"len": 5' "$(as "$A" -c "$(pc 'select length(convert_from(lo_get(data), $v$UTF8$v$)) as len from files')")"
check "lo_get() in a write is kept" '"outcome": "kept"' \
    "$(as "$A" -c "$(pc 'update files set body = convert_from(lo_get(data), $v$UTF8$v$) where id = 1')")"
refused "control: creating a large object in a read is refused" read_changes_nothing \
    "$(as "$A" -c "$(pc 'select lo_from_bytea(0, $v$x$v$) as o')")"

echo "R5. a contrib aggregate whose support functions are built-ins under another name"
if [ "$(available intagg)" = 1 ]; then
    as_super -q -c "create extension intagg" >/dev/null
    check "intagg's int_array_aggregate() reads" '"n": 5' \
        "$(as "$A" -c "$(pc 'select array_length(int_array_aggregate(g), 1) as n from generate_series(1, 5) g')")"
else
    echo "  --   intagg is not available in this PostgreSQL: that case did not run"
fi

echo "R6. serial and identity number a new column alike"
as_super -q -v ON_ERROR_STOP=1 -v d="$D" >/dev/null <<'SQL'
CREATE TABLE ddl.big (id int PRIMARY KEY);
INSERT INTO ddl.big SELECT generate_series(1, 100);
ALTER TABLE ddl.big OWNER TO :"d";
SQL
check "ADD COLUMN ... GENERATED AS IDENTITY is kept" '"outcome": "kept"' \
    "$(as "$D" -c "$(pc 'alter table ddl.big add column k int generated always as identity')")"
check "ADD COLUMN ... serial is kept" '"outcome": "kept"' "$(as "$D" -c "$(pc 'alter table ddl.big add column s2 serial')")"
equals "  ...and numbers the 100 rows" "100" "$(as_super -c "select count(distinct s2) from ddl.big")"
before=$(seqv)
out=$(as "$D" -c "$(pr 'alter table ddl.big add column n bigint default nextval($v$public.s$v$)')")
check "control: proposing a DEFAULT nextval() of a DBA's sequence is still refused" "nextval()" "$out"
equals "  ...and the sequence did not move" "$before" "$(seqv)"
out=$(as "$D" -c "$(pr 'alter table ddl.big add column s3 serial, add column n2 bigint default nextval($v$public.s$v$)')")
lacks "a serial beside a DEFAULT nextval() of a DBA's sequence is not proposed" '"ok": true' "$out"
check "  ...because the trial drew from a sequence that existed before it" "existed before it" "$out"

echo "R2. a DBA's DDL-audit event trigger"
as_super -q -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
CREATE TABLE public.ddl_log (id bigserial, at timestamptz DEFAULT now(), tag text, who text);
GRANT INSERT ON public.ddl_log TO PUBLIC;
GRANT USAGE ON SEQUENCE ddl_log_id_seq TO PUBLIC;
CREATE FUNCTION public.ddl_watch() RETURNS event_trigger LANGUAGE plpgsql
    AS $$ begin insert into public.ddl_log(tag, who) values (tg_tag, session_user); end $$;
CREATE EVENT TRIGGER ddl_watch ON ddl_command_end EXECUTE FUNCTION public.ddl_watch();
SQL
check "an agent's DDL under a DDL-audit trigger that numbers its log is kept" '"outcome": "kept"' \
    "$(as "$D" -c "$(pc 'create table ddl.et1 (id int)')")"
equals "  ...and the log has its row" "1" "$(as_super -c "select count(*) from ddl_log where who = '$D'")"
as_super -q -c "create or replace function public.ddl_watch() returns event_trigger language plpgsql as \$\$ begin perform pg_notify('schema_changed', tg_tag); end \$\$" >/dev/null
check "an agent's DDL under a trigger that notifies is kept" '"outcome": "kept"' \
    "$(as "$D" -c "$(pc 'create table ddl.et2 (id int)')")"
as_super -q -c "create or replace function public.ddl_watch() returns event_trigger language plpgsql as \$\$ begin perform pg_catalog.set_config('app.tenant_id', '2', false); end \$\$" >/dev/null
lacks "control: what the floor stops is still stopped in the DBA's event-trigger code" '"outcome": "kept"' \
    "$(as "$D" -c "$(pc 'create table ddl.et3 (id int)')")"
as_super -q -c "drop event trigger ddl_watch" >/dev/null

if [ "$failures" -ne 0 ]; then
    echo "$failures check(s) failed"
    exit 1
fi
echo "the second review of 0.4.3 is closed, each finding against its control"
