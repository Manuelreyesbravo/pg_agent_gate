#!/usr/bin/env bash
# When the library is loaded per session (session_preload_libraries on the role, the mode
# register_agent sets up when it is not in shared_preload_libraries), can the client take its
# session out from behind the gate at connection start?
#
# Up to 0.2.11 it could: `PGOPTIONS="-c agent_gate.agent="` became a placeholder with source
# PGC_S_CLIENT, which outranks the role's setting, and the library -- loaded only afterwards --
# could not adopt it. The session had no agent: a raw DELETE ran and nothing was recorded
# (external audit of 0.2.8, GATE-01). From 0.2.12 such a connection fails with FATAL.
#
# This suite restarts the throwaway cluster WITHOUT the library preloaded, and leaves it preloaded
# again when it ends, so it must run last.
#
#   PG_CONFIG=/path/to/pg_config tests/cluster.sh init && tests/cluster.sh start
#   PG_CONFIG=/path/to/pg_config tests/session_preload.sh
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PG_CONFIG=${PG_CONFIG:-pg_config}
BIN=$("$PG_CONFIG" --bindir)
export PGHOST=${PGHOST:-$ROOT/.testcluster}
export PGPORT=${PGPORT:-5499}
SUPERUSER=${SUPERUSER:-$(id -un)}
DB=agent_gate_session_preload
ROLE=agent_gate_session_preload_agent

source "$(dirname "${BASH_SOURCE[0]}")/guard.sh"
restore() { bash "$ROOT/tests/cluster.sh" stop fast >/dev/null 2>&1 || true; bash "$ROOT/tests/cluster.sh" start >/dev/null 2>&1 || true; }
trap 'release_claimed; restore' EXIT
require_throwaway_cluster
bash "$ROOT/tests/cluster.sh" stop fast >/dev/null
bash "$ROOT/tests/cluster.sh" start bare >/dev/null
claim_role "$ROLE"
claim_database "$DB"
"$BIN/psql" -X -U "$SUPERUSER" -d "$DB" -v ON_ERROR_STOP=1 -q -v role="$ROLE" >/dev/null <<SQL
CREATE EXTENSION pg_agent_gate;
CREATE TABLE t (id int);
INSERT INTO t SELECT g FROM generate_series(1, 10) g;
GRANT SELECT, DELETE ON t TO :"role";
SELECT agent_gate.register_agent('session_preload', :'role', 'loaded per session');
SQL

failures=0
check() {
    local what=$1 expected=$2 got=$3
    if [[ "$got" == *"$expected"* ]]; then echo "  ok   $what"; else
        echo "  FAIL $what"; echo "       expected to contain: $expected"; echo "       got: ${got//$'\n'/ }" | cut -c1-300; failures=$((failures + 1)); fi
}
check "control: the library is not preloaded in this cluster" "" "$("$BIN/psql" -X -U "$SUPERUSER" -d "$DB" -tAc 'show shared_preload_libraries')"
check "control: the role's session is behind the gate (raw DELETE refused)" "it proposes, it does not execute" \
    "$("$BIN/psql" -X -U "$ROLE" -d "$DB" -tAc 'delete from t' 2>&1 || true)"
out=$(PGOPTIONS="-c agent_gate.agent=" "$BIN/psql" -X -U "$ROLE" -d "$DB" -tAc 'delete from t' 2>&1 || true)
check "GATE-01: a client that sets agent_gate.agent at connection start is turned away" "FATAL" "$out"
check "  ...and no row is gone" "10" "$("$BIN/psql" -X -U "$SUPERUSER" -d "$DB" -tAc 'select count(*) from t')"

if [ "$failures" -ne 0 ]; then
    echo "$failures check(s) failed"
    exit 1
fi
echo "a client cannot take a session loaded per session out from behind the gate"
