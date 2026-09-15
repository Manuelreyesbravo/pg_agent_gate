#!/usr/bin/env bash
# Sourced first by every test script here that creates roles and databases.
#
# WHY: these scripts drop what they are about to create. That is fine against
# the throwaway cluster of tests/cluster.sh, which is where they point by
# default -- and it is somebody's data the moment PGHOST and PGPORT say
# otherwise. It is not hypothetical: while working on this extension the author
# ran the sibling suites of pg_living_assertions against a production cluster,
# because that project's own headers documented doing exactly that.
#
# THREE THINGS, AND ONLY THE THIRD HOLDS WHEN SOMEBODY POINTS PGHOST BY HAND:
#   1. the default is tests/cluster.sh, not whatever the environment carries;
#   2. every name carries this extension's prefix;
#   3. CLAIMING: if the object ALREADY EXISTS the suite stops instead of
#      dropping it, and cleanup only drops what this run claimed.
#
# A check that cannot run KILLS the suite instead of assuming the best. The
# first version of the sibling guard asked `psql -c "... = :'n'"`, and psql does
# not interpolate its variables inside -c: the statement reached the server as
# written, failed, and the empty capture read as "no such object". A guard that
# fails open is worse than none, because the suites still pass green. The
# statement now goes in through stdin, where psql really quotes the variable.
#
# Identifiers are checked against a strict pattern before they are ever put into
# DDL: they are written in this repo and not taken from a user, but an extension
# about what may reach the database does not get to build SQL out of unchecked
# text.

GUARD_ROOT=${GUARD_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
PSQL=${PSQL:-$("${PG_CONFIG:-pg_config}" --bindir)/psql}

: "${PGHOST:=$GUARD_ROOT/.testcluster}"
: "${PGPORT:=5499}"
export PGHOST PGPORT

CLAIMED_DATABASES=()
CLAIMED_ROLES=()

die() {
    echo "  !! $*" >&2
    exit 2
}

valid_name() {
    [[ "$1" =~ ^[a-z][a-z0-9_]{0,62}$ ]] || die "identifier not allowed: $1"
}

# Runs one statement and DIES if it could not run: every caller below depends on
# telling "it answered nothing" apart from "it could not answer".
run_sql() {
    local sql=$1 out
    shift
    if ! out=$(printf '%s\n' "$sql" | "$PSQL" -X -d postgres -tAq -v ON_ERROR_STOP=1 "$@" -f - 2>&1); then
        die "could not talk to the server at PGHOST=$PGHOST PGPORT=$PGPORT: $out"
    fi
    printf '%s' "$out"
}

already_there() {
    [ -n "$(run_sql "$1" -v n="$2")" ]
}

# A throwaway cluster has template0, template1 and postgres and nothing else.
# More user databases than that is somebody's server until proven otherwise.
require_throwaway_cluster() {
    local databases
    databases=$(run_sql "select count(*) from pg_database where not datistemplate and datname <> 'postgres'")
    if [ "$databases" -gt 3 ] && [ "${AGENT_GATE_ALLOW_SHARED_CLUSTER:-no}" != yes ]; then
        die "the server at PGHOST=$PGHOST PGPORT=$PGPORT has $databases user databases: this does not look like a throwaway cluster, and this suite creates and drops roles and databases. Use tests/cluster.sh, or export AGENT_GATE_ALLOW_SHARED_CLUSTER=yes if you really mean to run it there"
    fi
}

claim_database() {
    valid_name "$1"
    ! already_there "select 1 from pg_database where datname = :'n'" "$1" ||
        die "database $1 already exists: this suite does not drop what it did not create"
    run_sql "create database $1" >/dev/null
    CLAIMED_DATABASES+=("$1")
}

claim_role() {
    valid_name "$1"
    ! already_there "select 1 from pg_roles where rolname = :'n'" "$1" ||
        die "role $1 already exists: this suite does not drop what it did not create"
    run_sql "create role $1 login" >/dev/null
    CLAIMED_ROLES+=("$1")
}

# Only what this run created. Keeps the caller's exit code, so a failing suite
# still fails.
release_claimed() {
    local code=$?
    local object
    for object in ${CLAIMED_DATABASES[@]+"${CLAIMED_DATABASES[@]}"}; do
        printf '%s\n' "drop database if exists $object" | "$PSQL" -X -d postgres -tAq -f - >/dev/null 2>&1 || true
    done
    for object in ${CLAIMED_ROLES[@]+"${CLAIMED_ROLES[@]}"}; do
        printf '%s\n' "drop role if exists $object" | "$PSQL" -X -d postgres -tAq -f - >/dev/null 2>&1 || true
    done
    CLAIMED_DATABASES=()
    CLAIMED_ROLES=()
    return $code
}
