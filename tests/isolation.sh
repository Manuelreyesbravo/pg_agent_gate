#!/usr/bin/env bash
# Is a proposal committed at most once, whatever isolation level the agent picks?
#
# _load_proposal locks the proposal's row and then reads 'committed' -- whether a kept commit
# execution exists. Under READ COMMITTED that read takes a fresh snapshot after the lock, so a
# second commit sees the first and is refused (tests/hostile.sh). Under REPEATABLE READ or
# SERIALIZABLE the whole transaction reads from the snapshot of its first statement: the lock is
# granted (the row was not modified, only referenced), the read does not see the other session's
# kept execution, and the change runs again. An agent controls its own connections and may set
# its isolation level. Found by an external audit of 0.2.8 (GATE-04): six sessions opened in
# REPEATABLE READ before any commit, each committed the same -10 charge, and the ledger summed -60.
# The agent's configuration (max_rows, allow_ddl, bindings) is read the same way (GATE-05).
#
# From 0.2.12 a verb refuses to run outside READ COMMITTED, and a unique index makes "one kept
# commit per proposal" a constraint rather than a read.
#
#   PG_CONFIG=/path/to/pg_config tests/cluster.sh init && tests/cluster.sh start
#   PG_CONFIG=/path/to/pg_config tests/isolation.sh
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PG_CONFIG=${PG_CONFIG:-pg_config}
BIN=$("$PG_CONFIG" --bindir)
export PGHOST=${PGHOST:-$ROOT/.testcluster}
export PGPORT=${PGPORT:-5499}
SUPERUSER=${SUPERUSER:-$(id -un)}
DB=agent_gate_isolation
ROLE=agent_gate_isolation_agent

as_super() { "$BIN/psql" -X -U "$SUPERUSER" -d "$DB" -tA "$@" 2>&1; }
as_agent() { "$BIN/psql" -X -U "$ROLE" -d "$DB" -tA "$@" 2>&1 || true; }

source "$(dirname "${BASH_SOURCE[0]}")/guard.sh"
TMPD=$(mktemp -d)
trap 'release_claimed; rm -rf "$TMPD"' EXIT
require_throwaway_cluster
claim_role "$ROLE"
claim_database "$DB"
"$BIN/psql" -X -U "$SUPERUSER" -d "$DB" -v ON_ERROR_STOP=1 -q -v role="$ROLE" >/dev/null <<SQL
CREATE EXTENSION pg_agent_gate;
CREATE TABLE ledger (id serial PRIMARY KEY, amount int NOT NULL, note text);
GRANT SELECT, INSERT ON ledger TO :"role";
GRANT USAGE ON SEQUENCE ledger_id_seq TO :"role";
SELECT agent_gate.register_agent('isolation', :'role', 'charges customers, once each');
SQL

failures=0
check() {
    local what=$1 expected=$2 got=$3
    if [[ "$got" == "$expected" ]]; then echo "  ok   $what"; else
        echo "  FAIL $what"; echo "       expected: $expected"; echo "       got: ${got//$'\n'/ }"; failures=$((failures + 1)); fi
}
propose() { as_agent -c "select agent_gate.propose(\$q\$insert into ledger (amount, note) values (-10, '$1')\$q\$, 'charge customer 7')" \
            | sed -nE 's/.*"proposal": ([0-9]+).*/\1/p' | head -1; }

# N sessions, each alive through a named pipe: every one opens its transaction and takes its
# snapshot (a whoami, which any agent may call) BEFORE any of them commits.
race() {  # $1 = isolation level, $2 = proposal id, $3 = sessions
    local level=$1 pid=$2 n=$3 i
    local -a fds
    for i in $(seq 1 "$n"); do
        mkfifo "$TMPD/in$i"
        "$BIN/psql" -X -U "$ROLE" -d "$DB" -tA <"$TMPD/in$i" >"$TMPD/out$i" 2>&1 &
        exec {fd}>"$TMPD/in$i"; fds[i]=$fd
    done
    for i in $(seq 1 "$n"); do echo "begin isolation level $level; select agent_gate.whoami();" >&"${fds[i]}"; done
    sleep 1
    for i in $(seq 1 "$n"); do echo "select agent_gate.commit($pid);" >&"${fds[i]}"; sleep 0.4; done
    for i in $(seq 1 "$n"); do echo "commit;" >&"${fds[i]}"; eval "exec ${fds[i]}>&-"; done
    wait
    rm -f "$TMPD"/in*
    if [ -n "${ISOLATION_DEBUG:-}" ]; then for i in $(seq 1 "$n"); do echo "--- $level session $i"; cut -c1-220 "$TMPD/out$i"; done; fi
}
charges() { as_super -c "select count(*) || ':' || coalesce(sum(amount), 0) from ledger where note = '$1'"; }

# --- the control: READ COMMITTED, the case 0.2.0 fixed ------------------------------------
pid=$(propose rc)
race "read committed" "$pid" 3
check "control: under READ COMMITTED three commits of one proposal charge once" "1:-10" "$(charges rc)"

# --- REPEATABLE READ and SERIALIZABLE ------------------------------------------------------
pid=$(propose rr)
race "repeatable read" "$pid" 4
check "under REPEATABLE READ, sessions opened before any commit charge at most once" "ok" \
    "$( [ "$(charges rr | cut -d: -f1)" -le 1 ] && echo ok || echo "$(charges rr)")"
pid=$(propose ser)
race "serializable" "$pid" 4
check "under SERIALIZABLE, the same" "ok" \
    "$( [ "$(charges ser | cut -d: -f1)" -le 1 ] && echo ok || echo "$(charges ser)")"
check "  ...and the refusal says why" "1" \
    "$(grep -l "READ COMMITTED" "$TMPD"/out* 2>/dev/null | head -1 | wc -l)"

# --- the constraint: one kept commit per proposal ------------------------------------------
check "a unique index allows one kept commit per proposal" "t" \
    "$(as_super -c "select exists (select 1 from pg_indexes where schemaname = 'agent_gate_internal' and indexdef ilike '%unique%executions%(proposal)%kept%')")"

if [ "$failures" -ne 0 ]; then
    echo "$failures check(s) failed"
    exit 1
fi
echo "a proposal is committed at most once, whatever isolation level the agent picks"
