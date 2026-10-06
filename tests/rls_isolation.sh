#!/usr/bin/env bash
# Row-level security decides what an agent may read. Can the agent move the ground
# that decision stands on?
#
# A multi-tenant database usually writes its policy over a session parameter --
# `current_setting('app.tenant_id')` -- and sets it per role. An agent session that
# could change that parameter would be read as a different tenant by every policy,
# without touching a single privilege. Measured before this test existed: it could,
# and the same read then returned the other tenant's row. The gate only refused
# `role`, `session_authorization` and `agent_gate.*`, and an application parameter
# is in no list of forbidden names -- which is why the rule is now a short allowlist
# plus `agent_gate.settable`.
#
# EVERYTHING THAT MATTERS HAPPENS IN ONE SESSION, and that is not a detail. Two
# versions of this file got it wrong before it measured anything:
#   * the first ran each step as its own `psql` call, so by the time the read ran the
#     parameter was back to the role's value and the case came out GREEN against a
#     gate that stopped nothing. A test that cannot fail on the condition it exists
#     for is not measuring.
#   * the second numbered proposals with a shell counter, and `read_docs` runs inside
#     a command substitution -- a subshell -- so the increment was lost and the commit
#     went to the wrong proposal. The case failed for a reason that had nothing to do
#     with the gate, which is just as useless. The id is now asked of the record.
#
# BOTH HALVES, because a rule that breaks real drivers gets turned off: the last
# cases check that what a driver actually needs (timeouts, application_name, client
# encoding, date style) still works and that the session keeps working afterwards.
#
#   PG_CONFIG=/path/to/pg_config tests/cluster.sh init
#   PG_CONFIG=/path/to/pg_config tests/cluster.sh start
#   PG_CONFIG=/path/to/pg_config tests/rls_isolation.sh
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PG_CONFIG=${PG_CONFIG:-pg_config}
BIN=$("$PG_CONFIG" --bindir)
export PGHOST=${PGHOST:-$ROOT/.testcluster}
export PGPORT=${PGPORT:-5499}
SUPERUSER=${SUPERUSER:-$(id -un)}
DB=agent_gate_rls
ROLE=agent_gate_rls_agent
MINE=doc-of-tenant-one
THEIRS=doc-of-tenant-two
READ_SQL="select body from docs order by 1"

as_agent() { "$BIN/psql" -X -U "$ROLE" -d "$DB" -tA "$@" 2>&1 || true; }

# Claims the names instead of dropping whatever is there: see tests/guard.sh.
source "$(dirname "${BASH_SOURCE[0]}")/guard.sh"

trap release_claimed EXIT
require_throwaway_cluster
claim_role "$ROLE"
claim_database "$DB"
"$BIN/psql" -X -U "$SUPERUSER" -d "$DB" -v ON_ERROR_STOP=1 -q -v role="$ROLE" >/dev/null <<SQL
CREATE EXTENSION pg_agent_gate;

CREATE TABLE docs (tenant int NOT NULL, body text NOT NULL);
INSERT INTO docs VALUES (1, '$MINE'), (2, '$THEIRS');
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY by_tenant ON docs USING (tenant = current_setting('app.tenant_id')::int);

GRANT USAGE ON SCHEMA public TO :"role";
GRANT SELECT ON docs TO :"role";

-- The tenant an agent belongs to is set ON THE ROLE by whoever registers it.
ALTER ROLE :"role" SET app.tenant_id = '1';
SELECT agent_gate.register_agent('tenant_one', :'role', 'reads the documents of its own tenant');
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
absent() {
    local what=$1 forbidden=$2 got=$3
    if [[ -n "$got" && "$got" != *"$forbidden"* ]]; then
        echo "  ok   $what"
    else
        echo "  FAIL $what"
        echo "       must be a real answer without: $forbidden"
        echo "       got: ${got//$'\n'/ }"
        failures=$((failures + 1))
    fi
}

# The id the next proposal will get, asked of the record itself: the agent session
# cannot read it back (a verb's result is not something it may decorate), and a
# counter in this shell does not survive a command substitution.
next_proposal() {
    "$BIN/psql" -X -U "$SUPERUSER" -d "$DB" -tAc \
        "select coalesce(max(id), 0) + 1 from agent_gate_internal.proposals"
}

# ONE session: whatever `extra` did to it is still in force when the read runs.
read_docs() {
    local extra=$1 id
    id=$(next_proposal)
    local propose="select agent_gate.propose('$READ_SQL', 'read the documents I may read')"
    local commit="select agent_gate.commit($id)"
    if [ -n "$extra" ]; then
        as_agent -c "$extra" -c "$propose" -c "$commit"
    else
        as_agent -c "$propose" -c "$commit"
    fi
}

baseline=$(read_docs "")
contains "the agent reads the documents of its own tenant" "$MINE" "$baseline"
absent "and only those" "$THEIRS" "$baseline"

contains "changing the parameter the policy stands on is refused" "agent session" \
    "$(as_agent -c "set app.tenant_id = '2'")"
contains "SET LOCAL inside a transaction is refused too" "agent session" \
    "$(as_agent -c "begin" -c "set local app.tenant_id = '2'" -c "commit")"
contains "a proposal that carries a SET does not verify" '"ok": false' \
    "$(as_agent -c "select agent_gate.propose('set app.tenant_id = ''2''', 'move the tenant from inside a proposal')")"

# THE CASE THIS FILE EXISTS FOR: the change of parameter, the proposal and the read
# all in one session, which is the only way it can come out wrong.
after=$(read_docs "set app.tenant_id = '2'")
contains "after the attempt, in the SAME session, the agent still reads its own tenant" "$MINE" "$after"
absent "and still not the other tenant's" "$THEIRS" "$after"

# set_config() INSIDE A PROPOSAL -- found by the cycle harness of yggdrasil on 2026-10-06,
# with this file green: the allowlist judges SET and the startup parameters, but the
# statement the gate runs is where the hooks step aside, and the function moved the tenant
# while the policy was reading it. Every place in the tree it can hide, because a fix that
# covers only the case that bit is the next leak. Proposal and commit in ONE session.
propose_commit() {
    local sql=$1 id
    id=$(next_proposal)
    as_agent -c "select agent_gate.propose(\$q\$$sql\$q\$, 'read with the tenant moved from inside')" \
             -c "select agent_gate.commit($id)"
}
for sql in \
    "select body from docs where set_config('app.tenant_id', '2', true) is not null" \
    "select d.body from set_config('app.tenant_id', '2', true) s, docs d" \
    "select body from docs where (select set_config('app.tenant_id', '2', true)) is not null" \
    "with s as materialized (select set_config('app.tenant_id', '2', true)) select d.body from s, docs d" \
    "select body from docs where pg_catalog.set_config('app.tenant_id', '2', true) is not null"; do
    out=$(propose_commit "$sql")
    absent "set_config inside the proposal does not reach the other tenant: ${sql:0:60}" "$THEIRS" "$out"
    contains "  ...because it does not verify" '"ok": false' "$out"
done

# And what an actual driver sets on its own keeps working, or the rule gets removed.

for setting in "set statement_timeout = 5000" "set application_name = 'some client'" \
               "set client_encoding = 'UTF8'" "set datestyle = 'ISO, MDY'"; do
    contains "a driver can still: $setting" "SET" "$(as_agent -c "$setting")"
done
contains "and the session still works after them" '"is_agent": true' \
    "$(as_agent -c "set statement_timeout = 5000" -c "set application_name = 'some client'" -c "select agent_gate.whoami()")"

if [ "$failures" -ne 0 ]; then
    echo "$failures check(s) failed"
    exit 1
fi
echo "the agent cannot move the ground its row-level policies stand on"
