#!/usr/bin/env bash
# The third review of 0.4.3 (2026-11-05): what still got past the gate, or was refused for no
# reason, closed before 0.4.3 was released -- each with its tooth and its control. Every verdict is
# read from the effect (the setting, the file, the index, the stored column, the DBA's own insert,
# the catalog row) and not from the gate's answer alone.
#
#   F1. a VOLATILE C function of an extension's (pg_trgm's set_limit(), pg_prewarm's
#       autoprewarm_dump_now()) in an allow_ddl agent's own domain CHECK was "the call the DBA
#       placed there": a read wrote a file on the server and a write moved a module's parameter.
#       Code the agent planted is the agent's code: a volatile function an object of the agent's
#       calls is judged as the statement's own call -- native code stopped everywhere, a body the
#       executor runs stopped in a read and run, floored and counted, in a write.
#   F2. CREATE OR REPLACE FUNCTION of an agent's function silently changed a DBA's expression
#       index, generated column and CHECK. An agent's DDL changes only what the agent owns: a
#       function it redefines must have nothing of another role's built on it.
#   F3. a varchar[] verb argument -- pgjdbc's binding for a String[] -- was refused.
#   L1. an index on an agent's partitioned table was built on a DBA's partition and broke the DBA's
#       inserts; L2. DETACH PARTITION took a DBA's table out of the agent's; L3. a verb in a
#       read-only transaction failed on the gate's own INSERT with PostgreSQL's error.
#
#   PG_CONFIG=/path/to/pg_config tests/cluster.sh init && tests/cluster.sh start
#   PG_CONFIG=/path/to/pg_config tests/audit8.sh
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PG_CONFIG=${PG_CONFIG:-pg_config}
BIN=$("$PG_CONFIG" --bindir)
export PGHOST=${PGHOST:-$ROOT/.testcluster}
export PGPORT=${PGPORT:-5499}
SUPERUSER=${SUPERUSER:-$(id -un)}
DB=agent_gate_audit8
A=agent_gate_audit8_a      # an ordinary agent
D=agent_gate_audit8_d      # an allow_ddl agent, max_rows 2

as_super() { "$BIN/psql" -X -U "$SUPERUSER" -d "$DB" -tA "$@" 2>&1; }
as() { local r=$1; shift; "$BIN/psql" -X -U "$r" -d "$DB" -tA "$@" 2>&1 || true; }
# One session, the script on stdin (settings live as long as the session).
session() { "$BIN/psql" -X -U "$1" -d "$DB" -tA 2>&1 || true; }
pc() { printf "select agent_gate.propose_and_commit(\$q\$%s\$q\$, 'audit8')" "$1"; }

source "$(dirname "${BASH_SOURCE[0]}")/guard.sh"
trap release_claimed EXIT
require_throwaway_cluster
for r in "$A" "$D"; do claim_role "$r"; done
claim_database "$DB"
available() { as_super -c "select count(*) from pg_available_extensions where name = '$1'"; }
"$BIN/psql" -X -U "$SUPERUSER" -d "$DB" -v ON_ERROR_STOP=1 -q -v a="$A" -v d="$D" >/dev/null <<SQL
CREATE EXTENSION pg_agent_gate;
CREATE SCHEMA ddl AUTHORIZATION :"d";
GRANT USAGE ON SCHEMA public TO :"a", :"d";
CREATE TABLE public.audit_log (id bigserial, v int);
GRANT INSERT ON public.audit_log TO :"d";
GRANT USAGE ON SEQUENCE public.audit_log_id_seq TO :"d";
-- a DBA's volatile function whose body the executor runs
CREATE FUNCTION public.log_it(v int) RETURNS boolean LANGUAGE plpgsql VOLATILE
    AS \$\$ begin insert into public.audit_log(v) values (v); return true; end \$\$;
CREATE TABLE public.dba_checked (v int CHECK (public.log_it(v)));
GRANT SELECT, INSERT ON public.dba_checked TO :"d";
ALTER ROLE :"a" SET app.tenant_id = '1';
ALTER ROLE :"d" SET app.tenant_id = '1';
SELECT agent_gate.register_agent('audit8_a', :'a', 'reads what it is shown', p_max_rows => 5);
SELECT agent_gate.register_agent('audit8_d', :'d', 'schema power in its own schema',
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
equals() {
    local what=$1 expected=$2 got=$3
    if [[ "$got" == "$expected" ]]; then echo "  ok   $what"; else
        echo "  FAIL $what"; echo "       expected exactly: $expected"; echo "       got: ${got//$'\n'/ }" | cut -c1-${CUT:-400}; failures=$((failures + 1)); fi
}
logged() { as_super -c "select count(*) from public.audit_log"; }

echo "F1. a volatile function of another role's, called from the agent's own domain"
if [ "$(available pg_trgm)" = 1 ]; then
    as_super -q -c "create extension pg_trgm" >/dev/null
    check "control: a direct call of set_limit() is refused" "no_opaque_function" \
        "$(as "$D" -c "$(pc 'select public.set_limit(0.05) as l')")"
    check "the domain whose CHECK calls set_limit() is created" '"outcome": "kept"' \
        "$(as "$D" -c "$(pc 'create domain ddl.trg as real check (public.set_limit(VALUE) > 0)')")"
    as "$D" -c "$(pc 'create table ddl.t (x real)')" >/dev/null
    out=$(session "$D" <<S
$(pc 'insert into ddl.t values (0.05::ddl.trg)');
$(pc 'select public.show_limit() as lim');
S
)
    lacks "a write through that domain is not kept" '"outcome": "kept"' "$out"
    check "  ...because the agent placed the call" "code the agent placed is judged as the agent's own" "$out"
    check "  ...and the session's pg_trgm threshold did not move" '"lim": 0.3' "$(tail -1 <<<"$out")"
    out=$(session "$D" <<S
$(pc 'select 0.07::ddl.trg as x');
$(pc 'select public.show_limit() as lim');
S
)
    lacks "a read through that domain does not run it" '"outcome": "read"' "$(head -1 <<<"$out")"
    check "  ...and the threshold did not move" '"lim": 0.3' "$(tail -1 <<<"$out")"
else
    echo "  --   pg_trgm is not available in this PostgreSQL: that case did not run"
fi
if [ "$(available pg_prewarm)" = 1 ]; then
    as_super -q -c "create extension pg_prewarm" >/dev/null
    as "$D" -c "$(pc 'create domain ddl.dump as int check (public.autoprewarm_dump_now() >= 0)')" >/dev/null
    out=$(as "$D" -c "$(pc 'select 7::ddl.dump as x')")
    lacks "a read through a domain whose CHECK dumps the buffer list is not run" '"outcome": "read"' "$out"
    equals "  ...and no file was written on the server" "" \
        "$(as_super -c "select (pg_stat_file('autoprewarm.blocks', true)).size")"
else
    echo "  --   pg_prewarm is not available in this PostgreSQL: that case did not run"
fi
as "$D" -c "$(pc 'create domain ddl.logged as int check (public.log_it(VALUE))')" >/dev/null
as "$D" -c "$(pc 'create table ddl.t2 (v int)')" >/dev/null
before=$(logged)
out=$(as "$D" -c "$(pc 'select 5::ddl.logged as v')")
lacks "a read through a domain calling a DBA's volatile PL/pgSQL function is refused" '"outcome": "read"' "$out"
check "  ...because a read changes nothing" "a read or a proposal changes nothing" "$out"
equals "  ...and nothing was logged" "$before" "$(logged)"
check "a write through it runs the function, floored and counted" '"outcome": "kept"' \
    "$(as "$D" -c "$(pc 'insert into ddl.t2 values (6::ddl.logged)')")"
equals "  ...and logged its row" "$((before + 1))" "$(logged)"
check "control: the DBA's own CHECK calling the same function still runs for the agent's write" \
    '"outcome": "kept"' "$(as "$D" -c "$(pc 'insert into public.dba_checked values (7)')")"

echo "F2. CREATE OR REPLACE / ALTER FUNCTION under a DBA's index, stored column and CHECK"
as "$D" -c "$(pc 'create function ddl.norm(t text) returns text language sql immutable as $f$ select lower(t) $f$')" >/dev/null
as "$D" -c "$(pc 'create function ddl.ok(i int) returns boolean language sql immutable as $f$ select i > 0 $f$')" >/dev/null
as "$D" -c "$(pc 'create function ddl.inner(i int) returns int language sql immutable as $f$ select i * 2 $f$')" >/dev/null
as "$D" -c "$(pc 'create function ddl.outer(i int) returns int language sql immutable begin atomic select ddl.inner(i); end')" >/dev/null
as "$D" -c "$(pc 'create function ddl.mine(i int) returns boolean language sql immutable as $f$ select i > 0 $f$')" >/dev/null
as "$D" -c "$(pc 'create table ddl.own (i int check (ddl.mine(i)))')" >/dev/null
as_super -q -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
CREATE TABLE public.users (email text, n int CHECK (ddl.ok(n)),
                           e2 text GENERATED ALWAYS AS (ddl.norm(email)) STORED);
CREATE UNIQUE INDEX users_email ON public.users (ddl.norm(email));
CREATE INDEX users_outer ON public.users (ddl.outer(n));
INSERT INTO public.users(email, n) VALUES ('Alice@X.org', 1), ('BOB@x.org', 2);
SQL
probe() { as_super -c "set enable_seqscan = off; select count(*) from public.users where ddl.norm(email) = 'alice@x.org'" | tail -1; }
equals "control: the DBA's expression index finds alice" "1" "$(probe)"
out=$(as "$D" -c "$(pc 'create or replace function ddl.norm(t text) returns text language sql immutable as $f$ select $s$same$s$ $f$')")
lacks "CREATE OR REPLACE under a DBA's index and stored column is not kept" '"outcome": "kept"' "$out"
check "  ...because the DBA's objects are built on it" "is built on a function it redefines" "$out"
equals "  ...and the DBA's index still finds alice" "1" "$(probe)"
out=$(as "$D" -c "$(pc 'create or replace function ddl.ok(i int) returns boolean language sql immutable as $f$ select false $f$')")
lacks "CREATE OR REPLACE under a DBA's CHECK is not kept" '"outcome": "kept"' "$out"
check "  ...and the DBA's own insert still passes its CHECK" "INSERT 0 1" \
    "$(as_super -c "insert into public.users(email, n) values ('Carol@x.org', 3)")"
out=$(as "$D" -c "$(pc 'alter function ddl.ok(int) volatile')")
lacks "ALTER FUNCTION ... VOLATILE under a DBA's CHECK is not kept" '"outcome": "kept"' "$out"
check "  ...for the same reason" "is built on a function it redefines" "$out"
lacks "ALTER FUNCTION ... SET under a DBA's CHECK is not kept" '"outcome": "kept"' \
    "$(as "$D" -c "$(pc 'alter function ddl.ok(int) set work_mem = $v$64kB$v$')")"
out=$(as "$D" -c "$(pc 'create or replace function ddl.inner(i int) returns int language sql immutable as $f$ select 0 $f$')")
lacks "redefining a function an SQL-body function of the DBA's index calls is not kept" '"outcome": "kept"' "$out"
equals "  ...and the DBA's function still computes what the index holds" "2" \
    "$(as_super -c "select ddl.outer(1)")"
check "control: redefining a function only its own table uses is kept" '"outcome": "kept"' \
    "$(as "$D" -c "$(pc 'create or replace function ddl.mine(i int) returns boolean language sql immutable as $f$ select i >= 0 $f$')")"
check "control: a COMMENT on a function the DBA builds on is kept" '"outcome": "kept"' \
    "$(as "$D" -c "$(pc 'comment on function ddl.ok(int) is $v$used by public.users$v$')")"

echo "F3. a verb's array argument of varchar, as pgjdbc binds a String[]"
check "ARRAY['x'::varchar] as the parameters is accepted" '"v": "x"' \
    "$(as "$A" -c "select agent_gate.propose_and_commit('select \$1::text as v', 'audit8', ARRAY['x'::varchar])")"
check "a varchar[] literal is accepted" '"v": "y"' \
    "$(as "$A" -c "select agent_gate.propose_and_commit('select \$1::text as v', 'audit8', '{y}'::varchar[])")"
out=$(session "$A" <<'S'
select agent_gate.propose_and_commit($1, $2, $3::varchar[]) \bind 'select $1::text as v' 'audit8' '{bound}' \g
S
)
check "a parameter bound as varchar[] over the extended protocol is accepted" '"v": "bound"' "$out"
check "control: an explicit int[]-to-text[] cast, element by element, is still refused" "not expressions that run code" \
    "$(as "$A" -c "select agent_gate.propose_and_commit('select \$1::text as v', 'audit8', '{1,2}'::int[]::text[])")"
check "control: a scalar varchar argument still passes" '"outcome": "read"' \
    "$(as "$A" -c "select agent_gate.propose_and_commit('select 1 as one'::varchar, 'audit8')")"

echo "L1/L2. an agent's partitioned table with a DBA's partition"
as "$D" -c "$(pc 'create table ddl.parent (id int, amount int) partition by range (id)')" >/dev/null
as_super -q -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
CREATE TABLE ddl.dba_part PARTITION OF ddl.parent FOR VALUES FROM (0) TO (1000);
INSERT INTO ddl.dba_part SELECT g, g % 3 FROM generate_series(1, 50) g;
SQL
out=$(as "$D" -c "$(pc 'create unique index pu on ddl.parent (id)')")
lacks "an index on the agent's table that would be built on a DBA's partition is not kept" '"outcome": "kept"' "$out"
check "  ...because it would create an index of another role's table" "which belongs to" "$out"
equals "  ...and no index was left on the DBA's table" "0" \
    "$(as_super -c "select count(*) from pg_index where indrelid = 'ddl.dba_part'::regclass")"
out=$(as "$D" -c "$(pc 'alter table ddl.parent detach partition ddl.dba_part')")
lacks "DETACH PARTITION of a DBA's table is not kept" '"outcome": "kept"' "$out"
equals "  ...and it is still a partition" "t" "$(as_super -c "select relispartition from pg_class where oid = 'ddl.dba_part'::regclass")"
as "$D" -c "$(pc 'create table ddl.p2 (id int, amount int) partition by range (id)')" >/dev/null
as "$D" -c "$(pc 'create table ddl.p2a partition of ddl.p2 for values from (0) to (10)')" >/dev/null
check "control: an index on its own partitioned table of its own partitions is kept" '"outcome": "kept"' \
    "$(as "$D" -c "$(pc 'create index p2i on ddl.p2 (amount)')")"
check "control: detaching its own partition is kept" '"outcome": "kept"' \
    "$(as "$D" -c "$(pc 'alter table ddl.p2 detach partition ddl.p2a')")"
as_super -q -c "create table public.ref (id int primary key); grant references on public.ref to $D" >/dev/null
check "control: a foreign key to a DBA's table it may reference is kept" '"outcome": "kept"' \
    "$(as "$D" -c "$(pc 'create table ddl.child (r int references public.ref (id))')")"

echo "L3. a verb in a read-only transaction"
out=$(session "$A" <<S
begin read only;
$(pc 'select 1 as one');
rollback;
S
)
check "a verb in a READ ONLY transaction is refused by the gate, naming why" "do not run in a read-only transaction" "$out"
check "control: the same read outside it passes" '"outcome": "read"' "$(as "$A" -c "$(pc 'select 1 as one')")"

if [ "$failures" -ne 0 ]; then
    echo "$failures check(s) failed"
    exit 1
fi
echo "the third review of 0.4.3 is closed, each finding against its control"
