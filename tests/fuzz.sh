#!/usr/bin/env bash
# Boot the throwaway cluster and fuzz the gate. See tests/fuzz.py for what it checks.
#
#   make fuzz PG_CONFIG=/path/to/pg_config
#   FUZZ_ITERS=20000 FUZZ_SEED=1 make fuzz PG_CONFIG=...
#
# psycopg 3 is the only dependency; uv fetches it without touching your environment.
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
export PG_CONFIG=${PG_CONFIG:-pg_config}
export USER=${USER:-$(id -un)}
BIN=$("$PG_CONFIG" --bindir)
PORT=${GATE_PORT:-5499}
DB=gate_fuzz

MAJOR=$("$PG_CONFIG" --version | sed -E 's/^PostgreSQL ([0-9]+).*/\1/')
[ -f "target/release/pg_agent_gate-pg$MAJOR$("$PG_CONFIG" --pkglibdir)/pg_agent_gate.so" ] \
    || bash tests/cluster.sh package >/dev/null 2>&1 \
    || { echo "could not build the artifact: run tests/cluster.sh package"; exit 1; }
bash tests/cluster.sh init >/dev/null && bash tests/cluster.sh start >/dev/null || exit 1
trap 'bash tests/cluster.sh stop fast >/dev/null 2>&1 || true' EXIT

"$BIN/psql" -X -q -h "$ROOT/.testcluster" -p "$PORT" -d postgres -c "create database $DB" >/dev/null

FUZZ_DSN="postgresql://$USER@127.0.0.1:$PORT/$DB"
if command -v uv >/dev/null; then
    uv run --quiet --python 3.13 --with 'psycopg[binary]==3.3.6' python tests/fuzz.py "$FUZZ_DSN"
else
    python3 tests/fuzz.py "$FUZZ_DSN"
fi
