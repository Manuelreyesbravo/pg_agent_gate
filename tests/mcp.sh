#!/usr/bin/env bash
# A real MCP client, through gated-mcp, can only operate the gate -- proved end to end.
#
# gated-mcp is the drop-in replacement for an ordinary PostgreSQL MCP server: it connects
# AS THE AGENT ROLE, so it holds no power of its own. This script builds the throwaway
# cluster of tests/cluster.sh, registers an agent, starts gated-mcp against it, and runs
# the suites that an MCP client nobody here wrote speaks to it:
#
#   tests/clients.mjs 2026   the official @modelcontextprotocol/client, pinned to 2026-07-28
#   tests/clients.mjs 2025   the 1.x SDK, the 2025-11-25 handshake
#   tests/resources.mjs      resources and prompts add no power
#   tests/transport.mjs      the Streamable HTTP MUSTs, with plain fetch
#
# Everything a verb did is checked from OUTSIDE the gate, with a superuser connection:
# what you see is the database, not what the server says about it.
#
#   make mcp PG_CONFIG=/path/to/pg_config        # needs node and bun on PATH
#
# Runs on the same throwaway cluster as the demo (it builds the artifact if missing).
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
export PG_CONFIG=${PG_CONFIG:-pg_config}
BIN=$("$PG_CONFIG" --bindir)
export GATE_PORT=${GATE_PORT:-5499}
MCP_PORT=${MCP_PORT:-7878}
SUPERUSER=${USER:-$(id -un)}
DB=gate_mcp
AGENT=billing_agent

command -v node >/dev/null || { echo "needs node on PATH"; exit 2; }
command -v bun  >/dev/null || { echo "needs bun on PATH";  exit 2; }

MAJOR=$("$PG_CONFIG" --version | sed -E 's/^PostgreSQL ([0-9]+).*/\1/')
[ -f "target/release/pg_agent_gate-pg$MAJOR$("$PG_CONFIG" --pkglibdir)/pg_agent_gate.so" ] \
    || bash tests/cluster.sh package >/dev/null 2>&1 \
    || { echo "could not build the artifact: run tests/cluster.sh package"; exit 1; }
bash tests/cluster.sh init >/dev/null && bash tests/cluster.sh start >/dev/null || exit 1

MCP_PID=""
cleanup() {
    [ -n "$MCP_PID" ] && kill "$MCP_PID" >/dev/null 2>&1 || true
    bash tests/cluster.sh stop fast >/dev/null 2>&1 || true
}
trap cleanup EXIT

psql() { "$BIN/psql" -X -q -h "$ROOT/.testcluster" -p "$GATE_PORT" "$@"; }

# The world the client suites expect: customers(id, plan) with SELECT and UPDATE granted to
# the agent, and secrets, which the agent is NOT granted -- so a resource cannot show it.
psql -d postgres -c "create role $AGENT login" >/dev/null
psql -d postgres -c "create database $DB" >/dev/null
psql -d "$DB" <<SQL >/dev/null
create extension pg_agent_gate;
create table customers (id int primary key, plan text not null);
insert into customers values (1, 'free'), (2, 'pro');
create table secrets (id int primary key, passphrase text not null);
insert into secrets values (1, 'do-not-show');
grant select, update on customers to $AGENT;
select agent_gate.register_agent('billing', '$AGENT', 'answers billing questions', p_max_rows => 1000);
SQL

# gated-mcp, AS THE AGENT ROLE. Even if this process were hostile it could only call the
# verbs: the database refuses the agent session anything else.
[ -d gated-mcp/node_modules ] || (cd gated-mcp && bun install >/dev/null 2>&1)

export GATED_MCP_URL="http://127.0.0.1:$MCP_PORT/mcp"
export GATE_SUPERUSER_URL="postgres://$SUPERUSER@127.0.0.1:$GATE_PORT/$DB"
AGENT_GATE_DATABASE_URL="postgres://$AGENT@127.0.0.1:$GATE_PORT/$DB" \
    PORT="$MCP_PORT" HOST=127.0.0.1 \
    bun run gated-mcp/src/index.ts >"$ROOT/gated-mcp.log" 2>&1 &
MCP_PID=$!

# Up when the endpoint answers at all (even a 400 means the server is listening).
for _ in $(seq 1 60); do
    kill -0 "$MCP_PID" 2>/dev/null || { echo "gated-mcp exited early:"; cat "$ROOT/gated-mcp.log"; exit 1; }
    curl -s -o /dev/null "$GATED_MCP_URL" && break
    sleep 0.5
done

rc=0
run() {
    printf '\n\033[1m%s\033[0m\n' "$1"
    node "gated-mcp/test/$2" "${@:3}" || rc=1
}
run "A real MCP client (2026-07-28) operates the gate"    clients.mjs 2026
run "The 2025-11-25 SDK operates the same gate"           clients.mjs 2025
run "Resources and prompts add no power"                  resources.mjs
run "The Streamable HTTP transport MUSTs"                 transport.mjs

echo
[ "$rc" -eq 0 ] && echo "gated-mcp: every suite passed" || echo "gated-mcp: a suite failed (log: gated-mcp.log)"
exit "$rc"
