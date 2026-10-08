#!/usr/bin/env bash
# Does an EXISTING installation get the fixes, or do they only reach fresh ones?
#
# This is not a theoretical question. On 2026-09-15 the new library was copied
# into a live database and the schema stayed at 0.1.0: no TRUNCATE triggers, and
# _load_proposal with one argument while the library called the two-argument
# one. Every commit an agent made would have died with 'function does not
# exist'. Nothing broke only because that database had no agents yet.
#
# So the case that matters is NOT a clean install -- an extension is installed
# clean once and upgraded forever. This starts from the REAL old schema
# (tests/fixtures/pg_agent_gate--0.1.0.sql, byte for byte what was running),
# gives it history, and then upgrades.
#
# Judged against the catalog AND against the effect: that ALTER EXTENSION did
# not raise is not the question -- whether TRUNCATE is stopped afterwards is.
#
#   PG_CONFIG=/path/to/pg_config tests/cluster.sh init
#   PG_CONFIG=/path/to/pg_config tests/cluster.sh start
#   PG_CONFIG=/path/to/pg_config tests/upgrade.sh
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PG_CONFIG=${PG_CONFIG:-pg_config}
BIN=$("$PG_CONFIG" --bindir)

source "$(dirname "${BASH_SOURCE[0]}")/guard.sh"

SUPERUSER=${SUPERUSER:-$(id -un)}
DB=agent_gate_upgrade
AGENT=agent_gate_upgrade_agent
EXTDIR=$ROOT/target/release/pg_agent_gate-pg$("$PG_CONFIG" --version | sed -E 's/^PostgreSQL ([0-9]+).*/\1/')$("$PG_CONFIG" --sharedir)/extension

trap release_claimed EXIT
require_throwaway_cluster
claim_role "$AGENT"
claim_database "$DB"

failures=0
report() {
    local what=$1 ok=$2 detail=$3
    if [ "$ok" = yes ]; then
        echo "  ok   [upgrade] $what"
    else
        echo "  FAIL [upgrade] $what"
        echo "       ${detail//$'\n'/ }"
        failures=$((failures + 1))
    fi
}
expect() {
    local what=$1 wanted=$2 got=$3
    if [[ "$got" == *"$wanted"* ]]; then report "$what" yes ""; else report "$what" no "expected '$wanted', got: $got"; fi
}

su() { "$BIN/psql" -X -U "$SUPERUSER" -d "$DB" -tA "$@" 2>&1 || true; }
agent() { "$BIN/psql" -X -U "$AGENT" -d "$DB" -tA "$@" 2>&1 || true; }
proposal_id() { sed -nE 's/.*"proposal": ([0-9]+).*/\1/p' <<<"$1" | head -1; }

# THE OLD SCHEMA, put where PostgreSQL looks for it. The package only ships
# 0.2.0 now, so without this fixture the old shape could not be reproduced at
# all -- and a test that can only build the new one proves nothing about an
# upgrade.
if [ ! -d "$EXTDIR" ]; then
    echo "  !! falta el paquete en $EXTDIR: corre PG_CONFIG=$PG_CONFIG tests/cluster.sh package" >&2
    exit 2
fi
cp "$ROOT/tests/fixtures/pg_agent_gate--0.1.0.sql" "$EXTDIR/"

su -c "create extension pg_agent_gate version '0.1.0'" >/dev/null
expect "it starts on the old version" "0.1.0" \
    "$(su -c "select extversion from pg_extension where extname = 'pg_agent_gate'")"

# History, so the upgrade has something it could lose.
su -c "create table libro (id int primary key, texto text not null)" >/dev/null
su -c "insert into libro values (1, 'uno'), (2, 'dos')" >/dev/null
su -c "grant usage on schema public to $AGENT" >/dev/null
su -c "grant select, update on libro to $AGENT" >/dev/null
su -c "select agent_gate.register_agent('viejo', '$AGENT', 'an agent registered before the upgrade')" >/dev/null
antes=$(agent -c "select agent_gate.propose(\$s\$update libro set texto = 'antes' where id = 1\$s\$, \$i\$proposed before the upgrade\$i\$)")
agent -c "select agent_gate.commit($(proposal_id "$antes"))" >/dev/null
HISTORIA=$(su -c "select count(*) || ':' || coalesce(md5(string_agg(id || intent, '|' order by id)), '') from agent_gate_internal.proposals")

# ------------------------------------------------------------- the upgrade --
salida=$(su -c "alter extension pg_agent_gate update")
# The target is whatever this build IS, read from Cargo.toml: a constant here said "0.2.0"
# and failed the day the version moved, with the upgrade itself working.
NUEVA=$(sed -nE 's/^version = "([^"]+)"/\1/p' "$ROOT/Cargo.toml" | head -1)
expect "ALTER EXTENSION UPDATE reaches the new version" "$NUEVA" \
    "$(su -c "select extversion from pg_extension where extname = 'pg_agent_gate'")"

expect "the TRUNCATE triggers are there afterwards" "executions_no_truncate, proposals_no_truncate" \
    "$(su -c "select string_agg(tgname, ', ' order by tgname) from pg_trigger where not tgisinternal and tgname like '%no_truncate'")"
expect "_load_proposal takes the lock argument" "boolean" \
    "$(su -c "select pg_get_function_arguments(oid) from pg_proc where proname = '_load_proposal'")"
expect "and the one-argument shape is gone" "1" \
    "$(su -c "select count(*) from pg_proc where proname = '_load_proposal'")"

expect "the record from before the upgrade is intact" "$HISTORIA" \
    "$(su -c "select count(*) || ':' || coalesce(md5(string_agg(id || intent, '|' order by id)), '') from agent_gate_internal.proposals")"

# The effect, which is the point: an agent registered BEFORE the upgrade keeps
# working, and TRUNCATE no longer empties the history.
despues=$(agent -c "select agent_gate.propose(\$s\$update libro set texto = 'despues' where id = 2\$s\$, \$i\$proposed after the upgrade\$i\$)")
expect "an agent from before the upgrade still commits" '"outcome": "kept"' \
    "$(agent -c "select agent_gate.commit($(proposal_id "$despues"))")"
expect "and the change is really there" "despues" "$(su -c 'select texto from libro where id = 2')"

# The upgraded surface must BE the fresh one, not resemble it: every function of the gate's
# schema -- name, arguments, result, strictness, volatility -- compared with a CREATE EXTENSION of
# the same version in a database of its own. Checking chosen pieces (above) misses the piece
# nobody thought of; a verb an upgrade forgot would make every agent of that database fail.
SURFACE="select string_agg(p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ') -> '
            || pg_get_function_result(p.oid) || ' strict=' || p.proisstrict::text || ' vol=' || p.provolatile::text,
            ' ; ' order by p.proname, pg_get_function_identity_arguments(p.oid))
        from pg_proc p where p.pronamespace = 'agent_gate'::regnamespace"
FRESH=${DB}_fresh
claim_database "$FRESH"
fresh() { "$BIN/psql" -X -U "$SUPERUSER" -d "$FRESH" -tA "$@" 2>&1 || true; }
made=$(fresh -c "create extension pg_agent_gate")
fresh_surface=$(fresh -c "$SURFACE")
upgraded_surface=$(su -c "$SURFACE")
[[ "$made" == *ERROR* ]] && fresh_surface="(the fresh install failed: $made)"
# Equal is not enough: two identical ERRORs are equal too, and that is how the first version of
# this check passed an upgrade that forgot the verb (caught by its negative control, 2026-10-08).
# The fresh surface must be a real list that names this version's verb.
if [[ "$fresh_surface" == *"propose_and_commit("* && "$fresh_surface" != *ERROR* ]] \
    && [ "$fresh_surface" = "$upgraded_surface" ]; then
    report "the upgraded gate has exactly the functions of a fresh install" yes ""
else
    report "the upgraded gate has exactly the functions of a fresh install" no \
        "fresh: $fresh_surface || upgraded: $upgraded_surface"
fi

# And the verb this version adds works for an agent registered before it existed.
expect "an agent from before the upgrade can use propose_and_commit" '"outcome": "kept"' \
    "$(agent -c "select agent_gate.propose_and_commit(\$s\$update libro set texto = 'una llamada' where id = 1\$s\$, \$i\$one call after the upgrade\$i\$)")"
expect "and that change is really there" "una llamada" "$(su -c 'select texto from libro where id = 1')"

su -c "truncate agent_gate_internal.executions, agent_gate_internal.proposals" >/dev/null
expect "TRUNCATE no longer empties the record" "$HISTORIA" \
    "$(su -c "select count(*) || ':' || coalesce(md5(string_agg(id || intent, '|' order by id)), '') from agent_gate_internal.proposals where intent = 'proposed before the upgrade'")"

if [ "$failures" -ne 0 ]; then
    echo "$failures check(s) failed"
    exit 1
fi
echo "an existing installation upgrades, keeps its record, and comes out fixed"
