#!/usr/bin/env bash
# What does an agent leave behind when it rolls back its own transaction?
#
# The record -- agent_gate_internal.proposals and .executions -- is written in the
# caller's transaction, and transaction control is allowed in an agent session (a
# driver such as psycopg opens BEGIN by itself). So BEGIN; propose(...); ...; ROLLBACK
# takes the rows with it: refused attacks and reads alike. Found by an external audit of
# 0.2.8 (c87b343): BEGIN, two refused attacks and two reads, ROLLBACK -- the record went
# from 0/0 to 0/0. An agent could probe the gate without limit and leave no row. A
# ROLLBACK TO SAVEPOINT does the same to part of a transaction, and a session that
# disconnects without COMMIT aborts too.
#
# The gate cannot keep a row its caller rolls back -- that row is part of the caller's
# transaction -- and refusing transaction blocks would break every driver that opens
# one. From 0.2.10, whatever the record loses to an abort is written to the server log
# when the abort happens, at LOG level (the agent's session does not receive it): the
# proposal with its intent and SQL, the execution with its outcome. The log is outside
# every transaction. A row that commits is not logged twice.
#
# Controls: the same calls in autocommit stay in the record and produce no such line;
# the part of a transaction outside a rolled-back savepoint stays and is not logged.
#
#   PG_CONFIG=/path/to/pg_config tests/cluster.sh init
#   PG_CONFIG=/path/to/pg_config tests/cluster.sh start
#   PG_CONFIG=/path/to/pg_config tests/rollback.sh
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PG_CONFIG=${PG_CONFIG:-pg_config}
BIN=$("$PG_CONFIG" --bindir)
export PGHOST=${PGHOST:-$ROOT/.testcluster}
export PGPORT=${PGPORT:-5499}
SUPERUSER=${SUPERUSER:-$(id -un)}
SERVER_LOG=${GATE_CLUSTER:-$ROOT/.testcluster}/server.log
DB=agent_gate_rollback
ROLE=agent_gate_rollback_agent

as_super() { "$BIN/psql" -X -U "$SUPERUSER" -d "$DB" -tA "$@" 2>&1; }
# One psql reading a file: one session, transaction control as the agent writes it.
as_agent_file() { "$BIN/psql" -X -U "$ROLE" -d "$DB" -tA -f "$1" >/dev/null 2>&1 || true; }

source "$(dirname "${BASH_SOURCE[0]}")/guard.sh"
trap release_claimed EXIT
require_throwaway_cluster
claim_role "$ROLE"
claim_database "$DB"
[ -f "$SERVER_LOG" ] || { echo "no server log at $SERVER_LOG: start the cluster with tests/cluster.sh" >&2; exit 2; }
"$BIN/psql" -X -U "$SUPERUSER" -d "$DB" -v ON_ERROR_STOP=1 -q -v role="$ROLE" >/dev/null <<SQL
CREATE EXTENSION pg_agent_gate;
CREATE SCHEMA shop;
CREATE TABLE shop.orders (id int PRIMARY KEY, secret text);
INSERT INTO shop.orders VALUES (1, 'a'), (2, 'b');
CREATE TABLE shop.notes (body text);
GRANT USAGE ON SCHEMA shop TO :"role";
GRANT SELECT ON shop.orders TO :"role";
GRANT SELECT, INSERT ON shop.notes TO :"role";
SELECT agent_gate.register_agent('rollback', :'role', 'reads orders and writes notes');
SQL

failures=0
check() {
    local what=$1 ok=$2 detail=${3:-}
    if [ "$ok" = yes ]; then echo "  ok   $what"; else echo "  FAIL $what"; [ -n "$detail" ] && echo "       $detail"; failures=$((failures + 1)); fi
}
mark() { wc -l < "$SERVER_LOG"; }
since() { tail -n +$(($1 + 1)) "$SERVER_LOG"; }
# A line of the log that says the record lost this intent to an abort.
lost() { grep -F 'rolled back' <<<"$1" | grep -cF "$2" || true; }
in_record() { as_super -c "select count(*) from agent_gate_internal.proposals where intent = '$1'"; }
SQLF=$(mktemp); trap 'rm -f "$SQLF"; release_claimed' EXIT

# --- 1. BEGIN ... ROLLBACK -----------------------------------------------------------------
m=$(mark)
cat >"$SQLF" <<'SQL'
begin;
select agent_gate.propose($q$drop table shop.orders$q$, $i$probe one$i$);
select agent_gate.propose_and_commit($q$select * from shop.orders$q$, $i$read in the dark$i$);
select agent_gate.propose_and_commit($q$insert into shop.notes values ('undone')$q$, $i$write then undo$i$);
rollback;
SQL
as_agent_file "$SQLF"; sleep 0.3; log=$(since "$m")
check "control: BEGIN..ROLLBACK leaves no row in the record (the caller's transaction)" \
    "$([ "$(in_record 'probe one')$(in_record 'read in the dark')" = 00 ] && echo yes || echo no)"
check "the refused attack is in the server log, as rolled back, with its SQL" \
    "$([ "$(lost "$log" 'probe one')" -ge 1 ] && grep -F 'rolled back' <<<"$log" | grep -F 'probe one' | grep -qF 'drop table shop.orders' && echo yes || echo no)" "$(grep -F 'probe one' <<<"$log" | head -2)"
check "the read is in the server log, as rolled back" \
    "$([ "$(lost "$log" 'read in the dark')" -ge 1 ] && echo yes || echo no)"
check "the undone write and its execution are in the server log" \
    "$([ "$(lost "$log" 'write then undo')" -ge 1 ] && grep -F 'rolled back' <<<"$log" | grep -qE 'execution .*outcome=kept' && echo yes || echo no)"
check "  ...and the write itself is gone" "$([ "$(as_super -c "select count(*) from shop.notes")" = 0 ] && echo yes || echo no)"

# --- 2. control: autocommit ------------------------------------------------------------------
m=$(mark)
cat >"$SQLF" <<'SQL'
select agent_gate.propose($q$drop table shop.orders$q$, $i$probe in daylight$i$);
SQL
as_agent_file "$SQLF"; sleep 0.3; log=$(since "$m")
check "control: in autocommit the attempt stays in the record" "$([ "$(in_record 'probe in daylight')" = 1 ] && echo yes || echo no)"
check "control: ...and is not logged as rolled back" "$([ "$(lost "$log" 'probe in daylight')" = 0 ] && echo yes || echo no)"

# --- 3. ROLLBACK TO SAVEPOINT ----------------------------------------------------------------
m=$(mark)
cat >"$SQLF" <<'SQL'
begin;
select agent_gate.propose($q$select 1 from shop.orders$q$, $i$kept outside$i$);
savepoint s;
select agent_gate.propose($q$drop table shop.orders$q$, $i$probe in a savepoint$i$);
rollback to savepoint s;
commit;
SQL
as_agent_file "$SQLF"; sleep 0.3; log=$(since "$m")
check "a savepoint rolled back: its attempt is in the server log" "$([ "$(lost "$log" 'probe in a savepoint')" -ge 1 ] && echo yes || echo no)"
check "control: what was outside the savepoint stays in the record" "$([ "$(in_record 'kept outside')" = 1 ] && echo yes || echo no)"
check "control: ...and is not logged as rolled back" "$([ "$(lost "$log" 'kept outside')" = 0 ] && echo yes || echo no)"

# --- 4. a session that leaves without COMMIT --------------------------------------------------
m=$(mark)
cat >"$SQLF" <<'SQL'
begin;
select agent_gate.propose($q$drop table shop.orders$q$, $i$probe and vanish$i$);
SQL
as_agent_file "$SQLF"; sleep 0.5; log=$(since "$m")
check "a session that disconnects mid-transaction: its attempt is in the server log" \
    "$([ "$(in_record 'probe and vanish')" = 0 ] && [ "$(lost "$log" 'probe and vanish')" -ge 1 ] && echo yes || echo no)"

# --- 5. the line cannot forge other lines ----------------------------------------------------
m=$(mark)
cat >"$SQLF" <<'SQL'
begin;
select agent_gate.propose(E'select 1\nLOG:  pg_agent_gate: forged', $i$probe with a newline$i$);
rollback;
SQL
as_agent_file "$SQLF"; sleep 0.3; log=$(since "$m")
check "a newline in the agent's SQL does not start a line of its own in the log" \
    "$([ "$(lost "$log" 'probe with a newline')" -ge 1 ] && ! grep -q '^LOG:  pg_agent_gate: forged' <<<"$log" && echo yes || echo no)"

if [ "$failures" -ne 0 ]; then
    echo "$failures check(s) failed"
    exit 1
fi
echo "what an agent rolls back with its transaction is still written down, outside it"
