#!/usr/bin/env bash
# What you REMOVE, and what goes in its place. The same role, the same statement, twice.
#
# An AI agent reaches PostgreSQL today through a server that holds a connection and runs
# the SQL the model sends it: a tool like `query(sql)`. Whatever safety it has lives in
# that server's code -- swap the server and the safety is gone -- and what comes back is
# the result of running it, after it ran.
#
# pg_agent_gate takes that piece out. The gate is in the engine, under the role's own
# privileges, so no client can go around it; and the agent gets back FAR MORE than a
# result -- the catalog it may touch, every check with its verdict, and the exact
# before/after of a change -- BEFORE anything is kept.
#
#   make contrast PG_CONFIG=/path/to/pg_config
#
# Runs on the throwaway cluster of tests/cluster.sh (it builds the artifact if missing).
# A superuser prints the database after each side, so what you see is the database.
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
export PG_CONFIG=${PG_CONFIG:-pg_config}
export USER=${USER:-$(id -un)}
BIN=$("$PG_CONFIG" --bindir)
export PGHOST=$ROOT/.testcluster PGPORT=${GATE_PORT:-5499}
DB=gate_contrast
AGENT=support_agent

MAJOR=$("$PG_CONFIG" --version | sed -E 's/^PostgreSQL ([0-9]+).*/\1/')
[ -f "target/release/pg_agent_gate-pg$MAJOR$("$PG_CONFIG" --pkglibdir)/pg_agent_gate.so" ] \
    || bash tests/cluster.sh package >/dev/null 2>&1 \
    || { echo "could not build the artifact: run tests/cluster.sh package"; exit 1; }
bash tests/cluster.sh init >/dev/null && bash tests/cluster.sh start >/dev/null || exit 1
trap 'bash tests/cluster.sh stop fast >/dev/null 2>&1 || true' EXIT

su()     { "$BIN/psql" -X -q -d "$1" -tA -c "$2" 2>&1; }
agent()  { "$BIN/psql" -X -q -U "$AGENT" -d "$DB" -tA -c "$1" 2>&1; }
pretty() { python3 -m json.tool 2>/dev/null || cat; }

say()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
note() { printf '  \033[2m%s\033[0m\n' "$*"; }
In()   { printf '  \033[36m> %s\033[0m\n' "$*"; }
Out()  { sed 's/^/  < /'; }

# The role owns its table, the way an application's role usually does, so the same DROP
# runs on one side and is refused on the other -- the statement is identical, the engine
# is not. The extension is installed, but it governs only roles registered as agents, so
# before registration this role behaves exactly like any other.
reset_world() {
    su "$DB" "
      drop table if exists clientes;
      create table clientes (id int primary key, plan text not null, email text);
      alter table clientes owner to $AGENT;
      insert into clientes values (1,'free','ana@one.example'), (2,'pro','bruno@one.example'), (3,'free','iris@one.example');" >/dev/null
}
su postgres "create role $AGENT login" >/dev/null
su postgres "create database $DB owner $AGENT" >/dev/null
su "$DB" "create extension pg_agent_gate" >/dev/null
reset_world


say "THE PIECE YOU HAVE TODAY -- a server that holds a connection and runs what the model sends"
note "the same role, not yet an agent: this is what an ordinary PostgreSQL MCP server does with it"
In  "update clientes set plan = 'pro' where id = 1"
agent "update clientes set plan = 'pro' where id = 1" | Out
note "a row count, and it already ran -- no review, no proof of what it touched"
In  "drop table clientes          -- if the model sends this, the server runs it"
agent "drop table clientes" | Out
printf '  \033[31m(superuser) clientes: %s -- the only safety was the server'\''s own code\033[0m\n' \
    "$([ -n "$(su "$DB" "select to_regclass('clientes')")" ] && echo present || echo 'TABLE GONE, irreversibly')"


reset_world
su "$DB" "select agent_gate.register_agent('support', '$AGENT', 'answers customer questions')" >/dev/null

say "THE PIECE WE PUT IN ITS PLACE -- the gate, inside the engine, under the role's own privileges"
note "no tool runs SQL. the agent can only discover / propose / dry_run / commit, and what comes"
note "back is FAR MORE than a result: the catalog it may touch, every check, the exact before/after"

In "discover('clientes')"
agent "select agent_gate.discover('clientes')" | pretty | head -30 | Out
note "the schema it is allowed to see -- columns, types, keys, a fingerprint -- not a query of its own"

In "propose('update clientes set plan = \$1 where id = 1', 'move a customer to the pro plan', {pro})"
PROP=$(agent "select agent_gate.propose('update clientes set plan = \$1 where id = 1', 'move a customer to the pro plan', array['pro'])")
echo "$PROP" | pretty | Out
ID=$(echo "$PROP" | sed -nE 's/.*"proposal": ?([0-9]+).*/\1/p' | head -1)
note "every guard, each with its verdict -- the database checked it against itself, nothing ran"

In "dry_run($ID)"
agent "select agent_gate.dry_run($ID)" | pretty | Out
note "the exact before and after, and whether bound assertions still hold -- and nothing was kept"

In "propose('drop table clientes', 'clean up')   -- the same statement that destroyed the table above"
agent "select agent_gate.propose('drop table clientes', 'clean up')" | pretty | Out
note "refused here, with the reason -- it never reached the table"

In "commit($ID)   -- keep the one that verified"
agent "select agent_gate.commit($ID)" | pretty | Out
printf '  \033[32m(superuser) clientes is still here; id 1 is now %s; nothing else changed\033[0m\n' \
    "$(su "$DB" "select plan from clientes where id = 1")"
echo
