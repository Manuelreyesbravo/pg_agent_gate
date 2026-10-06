#!/usr/bin/env bash
# THE THREAT, IN ONE MINUTE: the same role, with the same privileges, first as an
# ordinary database user -- which is how an AI agent reaches PostgreSQL today -- and then
# registered behind pg_agent_gate. After every attempt a superuser prints what the
# database looks like, so what you see is the database, not what the gate says about it.
#
#   make demo PG_CONFIG=/path/to/pg_config
#
# Runs on the throwaway cluster of tests/cluster.sh (it builds the artifact if missing).
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
export PG_CONFIG=${PG_CONFIG:-pg_config}
export USER=${USER:-$(id -un)}
BIN=$("$PG_CONFIG" --bindir)
export PGHOST=$ROOT/.testcluster PGPORT=${GATE_PORT:-5499}
DB=gate_demo
AGENT=demo_assistant

MAJOR=$("$PG_CONFIG" --version | sed -E 's/^PostgreSQL ([0-9]+).*/\1/')
[ -f "target/release/pg_agent_gate-pg$MAJOR$("$PG_CONFIG" --pkglibdir)/pg_agent_gate.so" ] \
    || bash tests/cluster.sh package >/dev/null 2>&1 \
    || { echo "could not build the artifact: run tests/cluster.sh package"; exit 1; }
bash tests/cluster.sh init >/dev/null && bash tests/cluster.sh start >/dev/null || exit 1
trap 'bash tests/cluster.sh stop fast >/dev/null 2>&1 || true' EXIT

su()    { "$BIN/psql" -X -q -d "$1" -tA -c "$2" 2>&1; }
# The agent's own session. Errors come back as text: they are what this demo shows.
agent() { "$BIN/psql" -X -q -U "$AGENT" -d "$DB" -tA "$@" 2>&1; }

su postgres "create role demo_owners nologin" >/dev/null
su postgres "create role $AGENT login in role demo_owners" >/dev/null
su postgres "alter role $AGENT set app.tenant_id = '1'" >/dev/null
su postgres "alter role $AGENT set search_path = shop" >/dev/null
su postgres "create database $DB" >/dev/null
su "$DB" "create extension pg_agent_gate" >/dev/null

# Two tenants. The assistant works for tenant 1; row-level security keeps tenant 2 out of
# its sight through the parameter its role is given. Its role owns the tables, the way an
# application's role usually does.
reset_world() {
    su "$DB" "
      drop schema if exists shop cascade;
      create schema shop authorization demo_owners;
      create table shop.customers (id int primary key, tenant int not null, name text, email text);
      create table shop.orders (id int primary key, tenant int not null, customer int references shop.customers, total numeric);
      insert into shop.customers values (1,1,'Ana','ana@one.example'), (2,1,'Bruno','bruno@one.example'),
                                        (3,2,'Iris','iris@TWO.example'), (4,2,'Juan','juan@TWO.example');
      insert into shop.orders select g, 1, 1 + g % 2, g * 1000 from generate_series(1, 8) g;
      alter table shop.customers enable row level security; alter table shop.customers force row level security;
      alter table shop.orders enable row level security;    alter table shop.orders force row level security;
      create policy by_tenant on shop.customers using (tenant = current_setting('app.tenant_id')::int);
      create policy by_tenant on shop.orders    using (tenant = current_setting('app.tenant_id')::int);
      alter table shop.customers owner to demo_owners; alter table shop.orders owner to demo_owners;" >/dev/null
}

# Two queries, not one: a single statement naming a table that was dropped fails to parse,
# and the line meant to show the damage printed a parser error instead (first run).
count() {
    if [ -n "$(su "$DB" "select to_regclass('shop.$1')")" ]; then
        su "$DB" "select count(*) from shop.$1"
    else
        echo "TABLE GONE"
    fi
}
world() { echo "     database now: customers: $(count customers) · orders: $(count orders)"; }


say()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
step() { printf '  \033[33m%s\033[0m\n' "$*"; }
show() { sed -n '1,4p' | cut -c1-160 | sed 's/^/     /'; }

# Through the gate: propose in one call, then commit the id it returned. A verb takes
# literals only, so the id travels through the shell, not through SQL.
id_of()   { sed -nE 's/.*"proposal": ([0-9]+).*/\1/p' | head -1; }
refused() { sed -nE 's/.*\{"check": "([a-z_]+)", "detail": "([^"]*)", "passed": false\}.*/     refused at propose -- \1: \2/p' | cut -c1-170; }
field()   { sed -nE "s/.*\"$1\": \"?([^,\"}]*)\"?.*/\1/p" | head -1; }

say "WITHOUT the gate: an ordinary role, the way an agent connects today"
reset_world; world
step "1. the model 'cleans up' the orders:        DELETE FROM orders"
agent -c "delete from orders" | show; world
reset_world
step "2. the model 'fixes' the schema:             DROP TABLE customers CASCADE"
agent -c "drop table customers cascade" | show; world
reset_world
step "3. the model reads another customer's data:  set_config('app.tenant_id', '2') + SELECT"
agent -c "select set_config('app.tenant_id', '2', false)" -c "select name, email from customers" | show

say "WITH the gate: the same role, registered as an agent (max_rows 5, no DDL)"
reset_world
su "$DB" "select agent_gate.register_agent('assistant', '$AGENT', 'answers customer questions', p_max_rows => 5)" >/dev/null
world
step "1. DELETE FROM orders, typed directly"
agent -c "delete from orders" | show
step "2. DROP TABLE customers CASCADE, typed directly"
agent -c "drop table customers cascade" | show
step "3. set_config to tenant 2, typed directly"
agent -c "select set_config('app.tenant_id', '2', false)" | show
world

say "  ...and the same three, PROPOSED through the gate:"
step "1. propose + commit:  DELETE FROM orders   (8 rows, the agent may touch 5)"
id=$(agent -c "select agent_gate.propose('delete from orders', 'clean up the orders')" | id_of)
echo "     commit: $(agent -c "select agent_gate.commit($id)" | field outcome) -- $(agent -c "select agent_gate.acts(1)" | grep -o 'it touched [0-9]* rows[^"]*' | head -1)"
step "2. propose:  DROP TABLE customers"
agent -c "select agent_gate.propose('drop table customers', 'fix the schema')" | refused
step "3. propose:  a read that moves the tenant from inside the statement"
agent -c "select agent_gate.propose(\$q\$select name, email from customers where set_config('app.tenant_id', '2', true) is not null\$q\$, 'look up a customer')" | refused
world

say "  ...while legitimate work still goes through, and is seen before it is kept:"
id=$(agent -c "select agent_gate.propose(\$q\$update customers set email = 'ana@new.example' where id = 1\$q\$, 'the customer asked')" | id_of)
step "dry_run (nothing kept):"
agent -c "select agent_gate.dry_run($id)" | grep -o '"rows": \[[^]]*\]' | cut -c1-160 | sed 's/^/     /'
step "commit:"
echo "     $(agent -c "select agent_gate.commit($id)" | field outcome), Ana's email is now $(su "$DB" "select email from shop.customers where id = 1")"
world
echo
