#!/usr/bin/env bash
# How many WAL flushes an act pays, counted from a superuser: see tests/flushes.py.
#
#   PG_CONFIG=/path/to/pg_config tests/cluster.sh init
#   PG_CONFIG=/path/to/pg_config tests/cluster.sh start
#   PG_CONFIG=/path/to/pg_config tests/flushes.sh
#
# psycopg 3 is the only dependency; uv fetches it without touching your environment.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PG_CONFIG=${PG_CONFIG:-pg_config}
BIN=$("$PG_CONFIG" --bindir)

# Claims its names instead of dropping whatever is there: see tests/guard.sh.
source "$(dirname "${BASH_SOURCE[0]}")/guard.sh"

export SUPERUSER=${SUPERUSER:-$(id -un)}
export FLUSH_DB=agent_gate_flushes
export FLUSH_AGENT_ROLE=agent_gate_flushes_agent

trap release_claimed EXIT
require_throwaway_cluster
claim_role "$FLUSH_AGENT_ROLE"
claim_database "$FLUSH_DB"

"$BIN/psql" -X -U "$SUPERUSER" -d "$FLUSH_DB" -v ON_ERROR_STOP=1 -q -v agent="$FLUSH_AGENT_ROLE" >/dev/null <<'SQL'
CREATE EXTENSION pg_agent_gate;
CREATE TABLE flujo (id int PRIMARY KEY, n int NOT NULL);
INSERT INTO flujo SELECT g, 0 FROM generate_series(1, 10) g;
GRANT USAGE ON SCHEMA public TO :"agent";
GRANT SELECT, UPDATE ON flujo TO :"agent";
SELECT agent_gate.register_agent('flushes', :'agent', 'counts the WAL flushes an act pays', p_max_rows => 5);
SQL

cd "$ROOT"
if command -v uv >/dev/null; then
    uv run --quiet --python 3.13 --with 'psycopg[binary]==3.3.6' python tests/flushes.py
else
    python3 tests/flushes.py
fi
