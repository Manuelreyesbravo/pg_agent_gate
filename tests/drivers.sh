#!/usr/bin/env bash
# Real drivers against the session allowlist: pgjdbc, node-pg and libpq.
#
# tests/rls_isolation.sh showed that an agent cannot move the parameter its row-level
# policies read by running SET. But the allowlist judges STATEMENTS, and a driver can
# also set parameters in the STARTUP PACKET of the connection -- `options=-c ...`,
# which is PGOPTIONS in libpq and the `options` property in pgjdbc and node-pg. That
# is not a statement and goes through no hook, and a value the client sets at startup
# outranks the one the registrar put on the role with ALTER ROLE ... SET. This file
# asks every channel a real driver offers, not only the one the rule was written for.
#
# EVERY ATTACK IS JUDGED BY WHAT THE SAME CONNECTION THEN READS through the gate. A
# refusal that leaves the session looking at another tenant is not a pass, and an
# unrelated error is not a pass either: an attack passes when the read still returns
# only the agent's own row, or when the gate itself refused (its message says so).
#
# BOTH HALVES, as in rls_isolation.sh: [legit] cases check that what these drivers do
# on their own keeps working -- bound parameters, transactions, pgjdbc's setReadOnly
# and setTransactionIsolation, and a statement_timeout passed through `options`,
# which is legitimate. A fix that simply refused `options` would pass the attacks and
# break the drivers, and a rule that breaks drivers gets turned off.
#
# Drivers are pinned and fetched into tests/drivers/.deps (not versioned): the pgjdbc
# jar is checked against a sha1 written here, not one fetched next to it.
#
#   PG_CONFIG=/path/to/pg_config tests/cluster.sh init
#   PG_CONFIG=/path/to/pg_config tests/cluster.sh start
#   PG_CONFIG=/path/to/pg_config tests/drivers.sh
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PG_CONFIG=${PG_CONFIG:-pg_config}
BIN=$("$PG_CONFIG" --bindir)
export PGHOST=${PGHOST:-$ROOT/.testcluster}
export PGPORT=${PGPORT:-5499}
SUPERUSER=${SUPERUSER:-$(id -un)}
export DB=agent_gate_drivers
export ROLE=agent_gate_drivers_agent
export MINE=doc-of-tenant-one
export THEIRS=doc-of-tenant-two
export GATE_HOST=${GATE_HOST:-localhost}
READ_SQL="select body from docs order by 1"

export DEPS=$ROOT/tests/drivers/.deps
PGJDBC=42.7.13
PGJDBC_SHA1=a6e1bd21b412d6ffb3df23cd13d507bc2cc9e37d
NODE_PG=8.23.0
JAR=$DEPS/postgresql-$PGJDBC.jar

mkdir -p "$DEPS"
if [ ! -f "$JAR" ]; then
    curl -sSfL -o "$JAR.part" "https://repo1.maven.org/maven2/org/postgresql/postgresql/$PGJDBC/postgresql-$PGJDBC.jar"
    got=$(sha1sum "$JAR.part" | cut -c1-40)
    if [ "$got" != "$PGJDBC_SHA1" ]; then
        rm -f "$JAR.part"
        echo "pgjdbc $PGJDBC checksum mismatch: expected $PGJDBC_SHA1, downloaded $got" >&2
        exit 2
    fi
    mv "$JAR.part" "$JAR"
fi
if [ "$(node -e "try { console.log(require('$DEPS/node_modules/pg/package.json').version) } catch {}")" != "$NODE_PG" ]; then
    [ -f "$DEPS/package.json" ] || echo '{"private": true}' >"$DEPS/package.json"
    (cd "$DEPS" && npm install --cache "$DEPS/.npm-cache" --no-audit --no-fund --save-exact "pg@$NODE_PG" >/dev/null)
fi

cleanup() {
    "$BIN/psql" -X -U "$SUPERUSER" -d postgres -qc "drop database if exists $DB" >/dev/null 2>&1 || true
    "$BIN/psql" -X -U "$SUPERUSER" -d postgres -qc "drop role if exists $ROLE" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

"$BIN/psql" -X -U "$SUPERUSER" -d postgres -qc "create role $ROLE login"
"$BIN/psql" -X -U "$SUPERUSER" -d postgres -qc "create database $DB"
"$BIN/psql" -X -U "$SUPERUSER" -d "$DB" -v ON_ERROR_STOP=1 -q -v role="$ROLE" >/dev/null <<SQL
CREATE EXTENSION pg_agent_gate;

CREATE TABLE docs (tenant int NOT NULL, body text NOT NULL);
INSERT INTO docs VALUES (1, '$MINE'), (2, '$THEIRS');
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY by_tenant ON docs USING (tenant = current_setting('app.tenant_id')::int);

GRANT USAGE ON SCHEMA public TO :"role";
GRANT SELECT ON docs TO :"role";

ALTER ROLE :"role" SET app.tenant_id = '1';
SELECT agent_gate.register_agent('drivers', :'role', 'reads the documents of its own tenant, from real drivers');
SQL

failures=0
report() {
    local kind=$1 what=$2 ok=$3 got=$4
    if [ "$ok" = yes ]; then
        echo "  ok   [$kind] $what"
    else
        echo "  FAIL [$kind] $what"
        echo "       got: ${got//$'\n'/ }"
        failures=$((failures + 1))
    fi
}

# ---------------------------------------------------------------- libpq --
next_proposal() {
    "$BIN/psql" -X -U "$SUPERUSER" -d "$DB" -tAc \
        "select coalesce(max(id), 0) + 1 from agent_gate_internal.proposals"
}
id=$(next_proposal)
got=$(PGOPTIONS="-c app.tenant_id=2" "$BIN/psql" -X -U "$ROLE" -d "$DB" -tA \
    -c "select agent_gate.propose('$READ_SQL', 'read the documents I may read')" \
    -c "select agent_gate.commit($id)" 2>&1 || true)
if [[ "$got" != *"$THEIRS"* && ( "$got" == *"$MINE"* || "$got" == *"pg_agent_gate:"* ) ]]; then ok=yes; else ok=no; fi
report attack "libpq: PGOPTIONS=-c app.tenant_id at connect does not move the tenant" "$ok" "$got"

got=$(PGOPTIONS="-c statement_timeout=5000" "$BIN/psql" -X -U "$ROLE" -d "$DB" -tA -c "show statement_timeout" 2>&1 || true)
[ "$got" = "5s" ] && ok=yes || ok=no
report legit "libpq: a statement_timeout passed through PGOPTIONS still applies" "$ok" "$got"

# ------------------------------------------------------ pgjdbc, node-pg --
run_driver() {
    local name=$1 out rc=0
    shift
    out=$("$@" 2>&1) || rc=$?
    echo "$out"
    if ! grep -qE '^  (ok|FAIL) ' <<<"$out"; then
        echo "  !! $name reported no case (exit $rc)"
        failures=$((failures + 1))
    fi
    failures=$((failures + $(grep -c '^  FAIL' <<<"$out" || true)))
}
run_driver "pgjdbc $PGJDBC" java -cp "$JAR" "$ROOT/tests/drivers/Jdbc.java"
run_driver "node-pg $NODE_PG" node "$ROOT/tests/drivers/node_pg.mjs"

if [ "$failures" -ne 0 ]; then
    echo "$failures check(s) failed"
    exit 1
fi
echo "no channel a real driver offers moves the ground an agent's policies stand on"
