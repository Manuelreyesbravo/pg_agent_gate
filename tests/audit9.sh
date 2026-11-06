#!/usr/bin/env bash
# The fourth review of 0.4.3 (2026-11-05): no isolation or accounting bypass; two refusals with no
# reason behind them, and two pooled-client resets that failed -- each closed with its tooth and its
# control. Every verdict is read from the effect (the rows, the sequence, the record, the setting)
# and not from the gate's answer alone.
#
#   F1. a volatile function in the column DEFAULT of a DBA's table (pgcrypto's gen_random_bytes(), a
#       plpgsql order-number generator) refused every agent INSERT that relied on it: the rewriter
#       writes the catalog's DEFAULT into the statement, and the walker took it for the agent's own
#       call. The owner's default is the owner's code, judged by the floor when it runs; what the
#       agent writes, and a default on a table the agent can alter, stay judged as the agent's.
#   F2. an UPDATE that moved rows to another partition was counted twice by the max_rows backstop
#       (a delete and an insert each) and aborted above half the limit, blaming a trigger that did
#       not exist. A moved row is one row; what a trigger adds is still counted, and named.
#   L1. DISCARD ALL (PgBouncer's server_reset_query, Npgsql's pool reset) and DEALLOCATE were
#       refused in an agent's session.
#
#   PG_CONFIG=/path/to/pg_config tests/cluster.sh init && tests/cluster.sh start
#   PG_CONFIG=/path/to/pg_config tests/audit9.sh
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PG_CONFIG=${PG_CONFIG:-pg_config}
BIN=$("$PG_CONFIG" --bindir)
export PGHOST=${PGHOST:-$ROOT/.testcluster}
export PGPORT=${PGPORT:-5499}
SUPERUSER=${SUPERUSER:-$(id -un)}
DB=agent_gate_audit9
A=agent_gate_audit9_a      # an ordinary agent, max_rows 10
D=agent_gate_audit9_d      # an allow_ddl agent, max_rows 2
P=agent_gate_audit9_p      # an ordinary agent on a partitioned table, max_rows 10

as_super() { "$BIN/psql" -X -U "$SUPERUSER" -d "$DB" -tA "$@" 2>&1; }
as() { local r=$1; shift; "$BIN/psql" -X -U "$r" -d "$DB" -tA "$@" 2>&1 || true; }
# One session, the script on stdin (settings live as long as the session).
session() { "$BIN/psql" -X -U "$1" -d "$DB" -tA 2>&1 || true; }
pc() { printf "select agent_gate.propose_and_commit(\$q\$%s\$q\$, 'audit9')" "$1"; }

source "$(dirname "${BASH_SOURCE[0]}")/guard.sh"
trap release_claimed EXIT
require_throwaway_cluster
for r in "$A" "$D" "$P"; do claim_role "$r"; done
claim_database "$DB"
available() { as_super -c "select count(*) from pg_available_extensions where name = '$1'"; }
"$BIN/psql" -X -U "$SUPERUSER" -d "$DB" -v ON_ERROR_STOP=1 -q -v a="$A" -v d="$D" -v p="$P" >/dev/null <<SQL
CREATE EXTENSION pg_agent_gate;
CREATE SCHEMA ddl AUTHORIZATION :"d";
GRANT USAGE ON SCHEMA public TO :"a", :"d", :"p";
ALTER ROLE :"a" SET app.tenant_id = '1';
ALTER ROLE :"d" SET app.tenant_id = '1';
ALTER ROLE :"p" SET app.tenant_id = '1';
-- a DBA's order-number generator, as a column DEFAULT
CREATE SEQUENCE public.ord_seq;
GRANT USAGE ON SEQUENCE public.ord_seq TO :"a";
CREATE FUNCTION public.next_order_no() RETURNS text LANGUAGE plpgsql VOLATILE
    AS \$\$ begin return 'ORD-' || lpad(nextval('public.ord_seq')::text, 6, '0'); end \$\$;
CREATE TABLE public.orders (no text PRIMARY KEY DEFAULT public.next_order_no(), v int);
GRANT SELECT, INSERT, UPDATE ON public.orders TO :"a";
-- a DBA's default that writes a row of its own
CREATE TABLE public.audit_log (id bigserial, v int);
GRANT INSERT ON public.audit_log TO :"a", :"p";
GRANT USAGE ON SEQUENCE public.audit_log_id_seq TO :"a", :"p";
CREATE FUNCTION public.log_default() RETURNS int LANGUAGE plpgsql VOLATILE
    AS \$\$ begin insert into public.audit_log(v) values (1); return 1; end \$\$;
CREATE TABLE public.logged (x int DEFAULT public.log_default(), v int);
GRANT SELECT, INSERT ON public.logged TO :"a";
-- a DBA's SECURITY DEFINER default, and one that moves the context a policy reads
CREATE FUNCTION public.sd_val() RETURNS int LANGUAGE sql VOLATILE SECURITY DEFINER AS 'select 42';
CREATE TABLE public.sd_t (x int DEFAULT public.sd_val(), y int);
GRANT SELECT, INSERT ON public.sd_t TO :"a";
CREATE TABLE public.ctx_t (s text DEFAULT set_config('app.tenant_id', '2', false), y int);
GRANT SELECT, INSERT ON public.ctx_t TO :"a";
-- a DBA's volatile function an agent may place in its own table's DEFAULT
CREATE FUNCTION public.audit_val() RETURNS int LANGUAGE plpgsql VOLATILE AS \$\$ begin return 1; end \$\$;
-- a partitioned table
CREATE TABLE public.events (id int, at date NOT NULL, kind text, payload text) PARTITION BY RANGE (at);
CREATE TABLE public.events_10 PARTITION OF public.events FOR VALUES FROM ('2026-10-01') TO ('2026-11-01');
CREATE TABLE public.events_11 PARTITION OF public.events FOR VALUES FROM ('2026-11-01') TO ('2026-12-01');
GRANT SELECT, UPDATE ON public.events TO :"p";
INSERT INTO public.events
SELECT g, date '2026-10-05',
       CASE WHEN g <= 6 THEN 'mv' WHEN g <= 12 THEN 'stay' WHEN g <= 23 THEN 'big' ELSE 'tr' END, ''
  FROM generate_series(1, 29) g;
SELECT agent_gate.register_agent('audit9_a', :'a', 'an application agent that inserts orders',
                                 p_max_rows => 10, p_max_rows_per_window => 100000);
SELECT agent_gate.register_agent('audit9_d', :'d', 'schema power in its own schema',
                                 p_max_rows => 2, p_allow_ddl => true, p_max_rows_per_window => 1000);
SELECT agent_gate.register_agent('audit9_p', :'p', 'moves events between months',
                                 p_max_rows => 10, p_max_rows_per_window => 100000);
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

echo "F1. a volatile function in the DEFAULT of a DBA's table"
check "an INSERT relying on the DBA's plpgsql order-number DEFAULT is kept" '"outcome": "kept"' \
    "$(as "$A" -c "$(pc 'insert into public.orders(v) values (1) returning no')")"
equals "  ...and the row has the DBA's number" "ORD-000001|1" "$(as_super -c "select no, v from public.orders")"
check "a multi-row VALUES with an explicit DEFAULT is kept" '"outcome": "kept"' \
    "$(as "$A" -c "$(pc 'insert into public.orders(no, v) values (default, 2), (default, 3)')")"
equals "  ...and both rows have the DBA's numbers" "ORD-000002,ORD-000003" \
    "$(as_super -c "select string_agg(no, ',' order by no) from public.orders where v in (2, 3)")"
check "UPDATE ... SET no = DEFAULT is kept" '"outcome": "kept"' \
    "$(as "$A" -c "$(pc 'update public.orders set no = default where v = 1')")"
equals "  ...and it drew the next number" "ORD-000004" "$(as_super -c "select no from public.orders where v = 1")"
out=$(as "$A" -c "$(pc 'insert into public.orders(no, v) values (public.next_order_no(), 9)')")
check "control: the agent calling the same function itself is still refused" "no_opaque_function" "$out"
equals "  ...and nothing was inserted nor drawn" "3|4" \
    "$(as_super -c "select count(*), (select last_value from public.ord_seq) from public.orders")"
as_super -q -c "create view public.orders_v as select no, v from public.orders;
    grant select, insert on public.orders_v to $A" >/dev/null
check "an INSERT through a DBA's view onto that table is kept" '"outcome": "kept"' \
    "$(as "$A" -c "$(pc 'insert into public.orders_v(v) values (5)')")"
check "a MERGE whose INSERT relies on that DEFAULT is kept" '"outcome": "kept"' \
    "$(as "$A" -c "$(pc 'merge into public.orders o using (values (6)) s(v) on o.v = s.v
                         when not matched then insert (v) values (s.v)')")"
equals "  ...and both rows have the DBA's numbers" "ORD-000005|5,ORD-000006|6" \
    "$(as_super -c "select string_agg(no || '|' || v, ',' order by no) from public.orders where v in (5, 6)")"
if [ "$(available pgcrypto)" = 1 ]; then
    as_super -q -c "create extension pgcrypto;
        create table public.tokens (id text primary key default encode(gen_random_bytes(12), 'hex'), label text);
        grant select, insert on public.tokens to $A" >/dev/null
    check "an INSERT relying on a pgcrypto gen_random_bytes() DEFAULT is kept" '"outcome": "kept"' \
        "$(as "$A" -c "$(pc "insert into public.tokens(label) values ('t') returning id")")"
    equals "  ...and the row has a 24-digit key" "1|24" "$(as_super -c "select count(*), max(length(id)) from public.tokens")"
else
    echo "  --   pgcrypto is not available in this PostgreSQL: that case did not run"
fi
out=$(as "$A" -c "$(pc 'insert into public.logged(v) select g from generate_series(1, 6) g')")
lacks "6 rows whose DBA DEFAULT writes a row each (12 under max_rows 10) are not kept" '"outcome": "kept"' "$out"
check "  ...counted by the backstop, which names what the default added" "the 6 it named and 6 more" "$out"
equals "  ...and nothing was written" "0|0" \
    "$(as_super -c "select (select count(*) from public.logged), (select count(*) from public.audit_log)")"
check "control: 4 such rows (8) are kept" '"outcome": "kept"' \
    "$(as "$A" -c "$(pc 'insert into public.logged(v) select g from generate_series(1, 4) g')")"
equals "  ...with the DBA's rows" "4|4" \
    "$(as_super -c "select (select count(*) from public.logged), (select count(*) from public.audit_log)")"
out=$(as "$A" -c "$(pc 'insert into public.sd_t(y) values (1)')")
lacks "a DBA's SECURITY DEFINER DEFAULT is not run" '"outcome": "kept"' "$out"
check "  ...it is stopped as one" "SECURITY DEFINER" "$out"
equals "  ...and nothing was inserted" "0" "$(as_super -c "select count(*) from public.sd_t")"
out=$(session "$A" <<S
$(pc 'insert into public.ctx_t(y) values (1)');
$(pc "select current_setting('app.tenant_id') as t");
S
)
lacks "a DBA's DEFAULT that calls set_config() is not run" '"outcome": "kept"' "$(head -1 <<<"$out")"
check "  ...and the session's tenant did not move" '"t": "1"' "$(tail -1 <<<"$out")"
equals "  ...and nothing was inserted" "0" "$(as_super -c "select count(*) from public.ctx_t")"
as "$D" -c "$(pc "create function ddl.mine() returns int language sql stable as 'select 7'")" >/dev/null
as_super -q -c "create table public.uses_mine (x int default ddl.mine(), y int);
    grant select, insert on public.uses_mine to $D" >/dev/null
out=$(as "$D" -c "$(pc 'insert into public.uses_mine(y) values (1)')")
lacks "a DBA's DEFAULT over a function the agent can alter is not run" '"outcome": "kept"' "$out"
check "  ...it is stopped as the agent's own" "a function this agent can alter" "$out"
equals "  ...and nothing was inserted" "0" "$(as_super -c "select count(*) from public.uses_mine")"
as "$D" -c "$(pc 'create table ddl.own (x int default public.audit_val(), y int)')" >/dev/null
check "control: the agent's own table whose DEFAULT it set to a volatile function stays its call" \
    "no_opaque_function" "$(as "$D" -c "$(pc 'insert into ddl.own(y) values (1)')")"
equals "  ...and nothing was inserted" "0" "$(as_super -c "select count(*) from ddl.own")"

echo "F2. an UPDATE that moves rows to another partition"
check "moving 6 rows from October to November (max_rows 10) is kept" '"outcome": "kept"' \
    "$(as "$P" -c "$(pc "update public.events set at = at + 40 where kind = 'mv'")")"
equals "  ...and they moved" "6" "$(as_super -c "select count(*) from public.events_11 where kind = 'mv'")"
equals "  ...and the budget was charged 6, not 12" "6" \
    "$(as_super -c "select coalesce(sum(e.rows_moved), 0) from agent_gate_internal.executions e
                    join agent_gate_internal.proposals p on p.id = e.proposal
                   where p.agent = 'audit9_p' and e.mode = 'commit' and e.outcome = 'kept'")"
check "control: updating 6 rows inside their partition is kept" '"outcome": "kept"' \
    "$(as "$P" -c "$(pc "update public.events set payload = 'x' where kind = 'stay'")")"
out=$(as "$P" -c "$(pc "update public.events set at = at + 40 where kind = 'big'")")
check "control: moving 11 rows is refused by the top-level count" "it touched 11 rows" "$out"
equals "  ...and none moved" "0" "$(as_super -c "select count(*) from public.events_11 where kind = 'big'")"
as_super -q -c "create function public.ev_log() returns trigger language plpgsql
                    as \$\$ begin insert into public.audit_log(v) values (2); return new; end \$\$;
                create trigger ev_ins after insert on public.events for each row execute function public.ev_log();
                select agent_gate.allow_write('audit9_p', 'public.events')" >/dev/null
out=$(as "$P" -c "$(pc "update public.events set at = at + 40 where kind = 'tr'")")
lacks "moving 6 rows when an allowed trigger logs each one (12) is not kept" '"outcome": "kept"' "$out"
check "  ...and the refusal counts each moved row once and names the trigger's rows" "the 6 it named and 6 more" "$out"
equals "  ...and nothing moved or was logged" "0|0" \
    "$(as_super -c "select (select count(*) from public.events_11 where kind = 'tr'),
                           (select count(*) from public.audit_log where v = 2)")"
check "control: moving 4 rows with that trigger (8) is kept" '"outcome": "kept"' \
    "$(as "$P" -c "$(pc "update public.events set at = at + 40 where kind = 'tr' and id <= 27")")"
equals "  ...and they moved, each logged" "4|4" \
    "$(as_super -c "select (select count(*) from public.events_11 where kind = 'tr'),
                           (select count(*) from public.audit_log where v = 2)")"

echo "L1. a connection pool's reset"
out=$(session "$A" <<S
discard all;
deallocate all;
$(pc 'select 1 as one');
S
)
lacks "DISCARD ALL and DEALLOCATE ALL pass in an agent's session" "ERROR" "$out"
check "  ...and the gate still answers after them" '"outcome": "read"' "$out"
out=$(session "$A" <<S
discard all;
update public.orders set v = 0;
S
)
check "control: after DISCARD ALL raw SQL is still refused" "does not reach the database" "$out"
equals "  ...and nothing changed" "0" "$(as_super -c "select count(*) from public.orders where v = 0")"

if [ "$failures" -ne 0 ]; then
    echo "$failures check(s) failed"
    exit 1
fi
echo "the fourth review of 0.4.3 is closed, each finding against its control"
