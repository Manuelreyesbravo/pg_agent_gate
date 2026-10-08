#!/usr/bin/env bash
# Can an agent hide from the gate what its write would set off?
#
# agent_gate_internal._unsafe_amplifier decides whether writing a relation fires
# something the gate cannot vouch for: a cascading foreign key (its action runs as
# the table owner and past row-level security), a rule (rewritten with the rule
# owner's rights), a user trigger. It reads pg_constraint, pg_rewrite, pg_trigger,
# pg_proc and pg_inherits without a schema, under search_path = pg_catalog,
# agent_gate_internal -- and runs in the AGENT's session, called by propose. pg_temp
# is not named, and PostgreSQL searches an unnamed pg_temp FIRST for relations, even
# before an explicitly listed pg_catalog. An allow_ddl agent may create temporary
# tables: an empty pg_temp.pg_constraint would make the cascade invisible, and the
# delete would run it.
#
# From 0.2.9 every function of the gate names pg_temp last. Each tooth has its
# control: the same write without the temporary catalog is refused, and the
# temporary catalog demonstrably exists in the agent's session, so a green here is
# the gate refusing and not the scenario failing to set itself up.
#
#   PG_CONFIG=/path/to/pg_config tests/cluster.sh init
#   PG_CONFIG=/path/to/pg_config tests/cluster.sh start
#   PG_CONFIG=/path/to/pg_config tests/pg_temp.sh
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PG_CONFIG=${PG_CONFIG:-pg_config}
BIN=$("$PG_CONFIG" --bindir)
export PGHOST=${PGHOST:-$ROOT/.testcluster}
export PGPORT=${PGPORT:-5499}
SUPERUSER=${SUPERUSER:-$(id -un)}
DB=agent_gate_pg_temp
ROLE=agent_gate_pg_temp_agent

as_super() { "$BIN/psql" -X -U "$SUPERUSER" -d "$DB" -tA "$@" 2>&1; }
# One psql, one session: a temporary table lives as long as the connection.
as_agent() { "$BIN/psql" -X -U "$ROLE" -d "$DB" -tA "$@" 2>&1 || true; }
commit() { echo "select agent_gate.propose_and_commit(\$q\$$1\$q\$, 'tidy up')"; }

source "$(dirname "${BASH_SOURCE[0]}")/guard.sh"
trap release_claimed EXIT
require_throwaway_cluster
claim_role "$ROLE"
claim_database "$DB"
"$BIN/psql" -X -U "$SUPERUSER" -d "$DB" -v ON_ERROR_STOP=1 -q -v role="$ROLE" >/dev/null <<SQL
CREATE EXTENSION pg_agent_gate;
CREATE SCHEMA shop;
-- A parent the agent may delete from, and a child it holds no grant on: the cascade
-- would delete child rows as the table owner.
CREATE TABLE shop.parent (id int PRIMARY KEY);
CREATE TABLE shop.child (id int PRIMARY KEY, parent_id int REFERENCES shop.parent ON DELETE CASCADE);
INSERT INTO shop.parent SELECT g FROM generate_series(1, 3) g;
INSERT INTO shop.child SELECT g, g FROM generate_series(1, 3) g;
-- A table with a rule that writes, with the owner's rights, where the agent cannot.
CREATE TABLE shop.drafts (id int PRIMARY KEY);
CREATE TABLE shop.tomb (id int);
INSERT INTO shop.drafts SELECT g FROM generate_series(1, 3) g;
CREATE RULE keep_tomb AS ON DELETE TO shop.drafts DO ALSO INSERT INTO shop.tomb VALUES (OLD.id);
GRANT USAGE ON SCHEMA shop TO :"role";
GRANT SELECT, DELETE ON shop.parent, shop.drafts TO :"role";
SELECT agent_gate.register_agent('pg_temp', :'role', 'tidies its tables', p_allow_ddl => true);
SQL

failures=0
contains() {
    local what=$1 expected=$2 got=$3
    if [[ "$got" == *"$expected"* ]]; then
        echo "  ok   $what"
    else
        echo "  FAIL $what"
        echo "       expected to contain: $expected"
        echo "       got: ${got//$'\n'/ }"
        failures=$((failures + 1))
    fi
}
equals() {
    local what=$1 expected=$2 got=$3
    if [[ "$got" == "$expected" ]]; then
        echo "  ok   $what"
    else
        echo "  FAIL $what"
        echo "       expected: $expected"
        echo "       got: ${got//$'\n'/ }"
        failures=$((failures + 1))
    fi
}

# --- the cascading foreign key ------------------------------------------------------------
out=$(as_agent -c "$(commit 'delete from shop.parent where id = 1')")
contains "control: a delete that cascades is refused, naming the foreign key" "cascading foreign key" "$out"
equals "  ...and no child row is gone" 3 "$(as_super -c 'select count(*) from shop.child')"

out=$(as_agent \
    -c "$(commit 'create temp table pg_constraint (conname name, confrelid oid, contype "char", confdeltype "char", confupdtype "char")')" \
    -c "$(commit 'delete from shop.parent where id = 2')")
contains "control: the agent created its temporary pg_constraint (kept, in its session)" '"kind": "ddl", "mode": "commit"' "$(head -1 <<<"$out")"
contains "  ...kept" '"outcome": "kept"' "$(head -1 <<<"$out")"
contains "with a temporary pg_constraint, the cascade is still refused" "cascading foreign key" "$out"
equals "  ...and no child row is gone" 3 "$(as_super -c 'select count(*) from shop.child')"

# --- the rule -----------------------------------------------------------------------------
out=$(as_agent -c "$(commit 'delete from shop.drafts where id = 1')")
contains "control: a delete under a rule is refused, naming the rule" "rule keep_tomb" "$out"

out=$(as_agent \
    -c "$(commit 'create temp table pg_rewrite (rulename name, ev_class oid)')" \
    -c "$(commit 'delete from shop.drafts where id = 2')")
contains "control: the agent created its temporary pg_rewrite (kept, in its session)" '"kind": "ddl", "mode": "commit"' "$(head -1 <<<"$out")"
contains "  ...kept" '"outcome": "kept"' "$(head -1 <<<"$out")"
contains "with a temporary pg_rewrite, the rule is still refused" "rule keep_tomb" "$out"
equals "  ...and the rule wrote nothing" 0 "$(as_super -c 'select count(*) from shop.tomb')"

# --- a bound assertion, and the pg_living_assertions that runs it ------------------------
# Up to pg_living_assertions 0.5.4, run() applied the assertion's recorded path without
# naming pg_temp, so a temporary table of the session that commits -- the agent's --
# stood in for the table the check reads. 0.5.5 names it last. The gate runs bound
# assertions in the agent's session, so from 0.2.9 it refuses to call an older one: a
# check the agent can answer for is not one that passed.
"$BIN/psql" -X -U "$SUPERUSER" -d "$DB" -v ON_ERROR_STOP=1 -q -v role="$ROLE" >/dev/null <<SQL
CREATE TABLE shop.accounts (id int PRIMARY KEY, balance int NOT NULL);
INSERT INTO shop.accounts VALUES (1, 10);
GRANT SELECT, UPDATE ON shop.accounts TO :"role";
SQL
la_round() {  # $1 = pg_living_assertions version to install
    as_super -q -c "drop extension if exists pg_living_assertions cascade" \
             -c "create extension pg_living_assertions version '$1'" \
             -c "set search_path = shop" \
             -c "select living_assertions.declare('no_negative_balance', 'no account below zero',
                   \$a\$select not exists (select 1 from accounts where balance < 0) as holds\$a\$)" \
             -c "select agent_gate.bind_assertion('pg_temp', 'no_negative_balance')" >/dev/null
    as_super -q -c "update shop.accounts set balance = 10" >/dev/null
    as_agent \
        -c "$(commit 'create temp table accounts (id int, balance int)')" \
        -c "$(commit 'update shop.accounts set balance = -5 where id = 1')"
}
if [ -n "$(as_super -c "select 1 from pg_available_extension_versions where name = 'pg_living_assertions' and version = '0.5.4'")" ] \
   && [ -n "$(as_super -c "select 1 from pg_available_extension_versions where name = 'pg_living_assertions' and version = '0.5.5'")" ]; then
    out=$(la_round 0.5.4)
    equals "with pg_living_assertions 0.5.4, the overdraft is not kept" 10 \
        "$(as_super -c 'select balance from shop.accounts where id = 1')"
    contains "  ...and the gate says why: that version can be answered by the agent" "0.5.5" "$out"
    out=$(la_round 0.5.5)
    equals "with pg_living_assertions 0.5.5, the overdraft is not kept" 10 \
        "$(as_super -c 'select balance from shop.accounts where id = 1')"
    contains "  ...because the assertion read the real table: broken" "broken" "$out"
    as_super -q -c "update shop.accounts set balance = 10" >/dev/null
    out=$(as_agent -c "$(commit 'update shop.accounts set balance = 7 where id = 1')")
    equals "control: with 0.5.5, a write that keeps the assertion is kept" 7 \
        "$(as_super -c 'select balance from shop.accounts where id = 1')"
else
    echo "  FAIL pg_living_assertions 0.5.4 and 0.5.5 must both be installable here (install 0.5.5 or later)"
    failures=$((failures + 1))
fi

# --- every function of the gate names pg_temp last --------------------------------------
equals "no function of the gate leaves pg_temp unnamed in its search_path" "" \
    "$(as_super -c "select string_agg(p.oid::regprocedure::text, ', ')
                      from pg_proc p join pg_depend d on d.objid = p.oid and d.deptype = 'e'
                      join pg_extension e on e.oid = d.refobjid and e.extname = 'pg_agent_gate'
                     where p.prolang <> (select oid from pg_language where lanname = 'c')
                       and not exists (select 1 from unnest(p.proconfig) c
                                        where c like 'search_path=%' and c like '%pg_temp')")"

if [ "$failures" -ne 0 ]; then
    echo "$failures check(s) failed"
    exit 1
fi
echo "a temporary catalog of the agent cannot hide what its write would set off"
