#!/usr/bin/env bash
# Who can pretend to be an agent, read the record, or run someone else's
# proposal? Checked in both directions.
#
# What an AGENT session cannot do is measured elsewhere: the hooks refuse raw
# SQL. This script is about everyone else, and about agents towards each other:
#
#   * agent_gate.agent is superuser-only: nobody else puts the mark on
#     themselves, with SET or with ALTER ROLE;
#   * the record is not readable directly, the administration functions are not
#     callable, and the internal functions refuse any caller that is not the
#     gate's own code;
#   * a proposal is executed only by the agent that made it -- not by another
#     agent, and not by a role with MORE privileges than that agent;
#   * an agent without a GRANT does not see, propose or read what it was not
#     granted: the gate adds verification, GRANT is still the authorization.
#
# Each attack counts only if it is stopped for the EXPECTED reason: an error
# from somewhere else proves nothing about the boundary under test. And the
# other half is checked too -- what is legitimate has to pass, because a gate
# that lets nobody through gets removed.
#
#   PG_CONFIG=/path/to/pg_config tests/cluster.sh init
#   PG_CONFIG=/path/to/pg_config tests/cluster.sh start
#   PG_CONFIG=/path/to/pg_config tests/privileges.sh
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PG_CONFIG=${PG_CONFIG:-pg_config}
BIN=$("$PG_CONFIG" --bindir)
export PGHOST=${PGHOST:-$ROOT/.testcluster}
export PGPORT=${PGPORT:-5499}
SUPERUSER=${SUPERUSER:-$(id -un)}
DB=agent_gate_privileges
BILLING=agent_gate_priv_billing
SUPPORT=agent_gate_priv_support
APP=agent_gate_priv_app
STRANGER=agent_gate_priv_stranger
MARK=intent-of-billing-7f3a

# Every answer, error or not, is something to inspect.
as() { local role=$1; shift; "$BIN/psql" -X -U "$role" -d "$DB" -tA "$@" 2>&1 || true; }
proposal_id() { sed -nE 's/.*"proposal": ([0-9]+).*/\1/p' <<<"$1" | head -1; }

# Claims the names instead of dropping whatever is there: see tests/guard.sh.
source "$(dirname "${BASH_SOURCE[0]}")/guard.sh"

cleanup() {
    # A parameter grant is cluster-wide and blocks DROP ROLE if a run stopped halfway.
    "$BIN/psql" -X -U "$SUPERUSER" -d postgres -qc "revoke set on parameter agent_gate.agent from $BILLING" >/dev/null 2>&1 || true
    release_claimed
}
trap cleanup EXIT

require_throwaway_cluster
for r in "$BILLING" "$SUPPORT" "$APP" "$STRANGER"; do
    claim_role "$r"
done
claim_database "$DB"

"$BIN/psql" -X -U "$SUPERUSER" -d "$DB" -v ON_ERROR_STOP=1 -q \
    -v billing="$BILLING" -v support="$SUPPORT" -v app="$APP" -v stranger="$STRANGER" >/dev/null <<'SQL'
CREATE EXTENSION pg_agent_gate;

CREATE TABLE customers (id int PRIMARY KEY, plan text NOT NULL);
INSERT INTO customers VALUES (1, 'free'), (2, 'pro'), (3, 'free');
CREATE TABLE secrets (passphrase text);
INSERT INTO secrets VALUES ('the-bank-key');
REVOKE ALL ON secrets FROM PUBLIC;

GRANT USAGE ON SCHEMA public TO :"billing", :"support", :"app", :"stranger";
GRANT SELECT, UPDATE ON customers TO :"billing";
GRANT SELECT ON customers TO :"support";
-- The app role holds MORE than billing: it may update customers and read secrets.
-- Privileges are not what lets somebody run a proposal, ownership of it is.
GRANT SELECT, UPDATE, DELETE ON customers, secrets TO :"app";
SQL

failures=0
attacks=0
legit=0
check() {
    local kind=$1 what=$2 expected=$3 got=$4
    if [ "$kind" = attack ]; then attacks=$((attacks + 1)); else legit=$((legit + 1)); fi
    if [[ "$got" == *"$expected"* ]]; then
        echo "  ok   [$kind] $what"
    else
        echo "  FAIL [$kind] $what"
        echo "       expected to contain: $expected"
        echo "       got: $got"
        failures=$((failures + 1))
    fi
}
check_absent() {
    local kind=$1 what=$2 forbidden=$3 got=$4
    if [ "$kind" = attack ]; then attacks=$((attacks + 1)); else legit=$((legit + 1)); fi
    if [[ -n "$got" && "$got" != *"$forbidden"* && "$got" != *ERROR* ]]; then
        echo "  ok   [$kind] $what"
    else
        echo "  FAIL [$kind] $what"
        echo "       must be a real answer without: $forbidden"
        echo "       got: $got"
        failures=$((failures + 1))
    fi
}

# ------------------------------------------------------------ legitimate --
check legit "the superuser registers an agent" "enforced_by" \
    "$(as "$SUPERUSER" -c "select agent_gate.register_agent('billing', '$BILLING', 'answers billing questions and upgrades plans')")"
check legit "and a second one" "enforced_by" \
    "$(as "$SUPERUSER" -c "select agent_gate.register_agent('support', '$SUPPORT', 'answers support questions, reads customers')")"

q=$(proposal_id "$(as "$BILLING" -c "select agent_gate.propose('update customers set plan = ''pro'' where id = 3', 'upgrade customer 3')")")
check legit "an agent commits its own write on what it was granted" '"outcome": "kept"' \
    "$(as "$BILLING" -c "select agent_gate.commit(${q:-0})")"
r=$(proposal_id "$(as "$BILLING" -c "select agent_gate.propose('select id, plan from customers order by id', 'list the customers')")")
check legit "an agent reads what it was granted" '"outcome": "read"' \
    "$(as "$BILLING" -c "select agent_gate.commit(${r:-0})")"
check legit "discover shows an agent what it was granted" "customers" \
    "$(as "$BILLING" -c "select agent_gate.discover('', 500)")"

# The proposal every attack below goes after. It stays uncommitted until the end.
p=$(proposal_id "$(as "$BILLING" -c "select agent_gate.propose('update customers set plan = ''free'' where id = 2', '$MARK')")")
check legit "an agent sees its own history" "$MARK" "$(as "$BILLING" -c "select agent_gate.acts(500)")"

# -------------------------------------------------- nobody wears the mark --
check attack "a role cannot SET the agent mark on itself" "permission denied to set parameter" \
    "$(as "$STRANGER" -c "set agent_gate.agent = 'billing'")"
check attack "a role cannot put the agent mark on itself with ALTER ROLE" "permission denied" \
    "$(as "$STRANGER" -c "alter role $STRANGER set agent_gate.agent = 'billing'")"
check attack "an agent cannot switch to another agent's mark" "belongs to agent \"billing\"" \
    "$(as "$BILLING" -c "set agent_gate.agent = 'support'")"
check attack "a superuser role cannot be registered as an agent" "is a superuser" \
    "$(as "$SUPERUSER" -c "select agent_gate.register_agent('root', '$SUPERUSER', 'a superuser pretending to be behind the gate')")"
# RESET ALL goes back to the ROLE's settings, which is exactly where the mark lives.
check attack "RESET ALL does not take an agent out of the gate" "it proposes, it does not execute" \
    "$(as "$BILLING" -c "reset all" -c "select count(*) from customers")"
# One mistaken GRANT must not be the difference between behind the gate and out of
# it. PostgreSQL 15+ can grant SET on a superuser-only parameter, and before the gate
# refused the whole agent_gate.* prefix that was a measured exit: with this grant,
# `set agent_gate.agent = ''` worked and the next raw SELECT ran.
"$BIN/psql" -X -U "$SUPERUSER" -d "$DB" -qc "grant set on parameter agent_gate.agent to $BILLING"
check attack "with SET ON PARAMETER granted by mistake, an agent still cannot clear its mark" "an agent session may change" \
    "$(as "$BILLING" -c "set agent_gate.agent = ''" -c "select count(*) from customers")"
check attack "and the raw SQL after that attempt is still refused" "it proposes, it does not execute" \
    "$(as "$BILLING" -c "set agent_gate.agent = ''" -c "select count(*) from customers")"
"$BIN/psql" -X -U "$SUPERUSER" -d "$DB" -qc "revoke set on parameter agent_gate.agent from $BILLING"

# ------------------------------------------------ the record is the gate's --
check attack "a role cannot read the proposals directly" "permission denied for table proposals" \
    "$(as "$STRANGER" -c "select count(*) from agent_gate_internal.proposals")"
check attack "a role with more privileges cannot read the executions directly" "permission denied for table executions" \
    "$(as "$APP" -c "select count(*) from agent_gate_internal.executions")"
check attack "a role cannot register an agent" "permission denied for function register_agent" \
    "$(as "$STRANGER" -c "select agent_gate.register_agent('evil', '$STRANGER', 'registering itself as an agent')")"
check attack "a role cannot bind an assertion" "permission denied for function bind_assertion" \
    "$(as "$STRANGER" -c "select agent_gate.bind_assertion('billing', 'anything')")"
check attack "a role cannot forge a proposal through the internal writer" "only the gate reads and writes its own record" \
    "$(as "$STRANGER" -c "select agent_gate_internal._record_proposal('billing', 'x', 'forged', 'select 1', null, 'read', true, '[]', 1)")"
check attack "a role cannot read an agent's acts through the internal reader" "only the gate reads and writes its own record" \
    "$(as "$STRANGER" -c "select agent_gate_internal._acts('billing', 50)")"
check attack "a role cannot load a proposal through the internal reader" "only the gate reads and writes its own record" \
    "$(as "$STRANGER" -c "select agent_gate_internal._load_proposal(${p:-0})")"
check attack "a role cannot run a bound assertion on its own" "assertions are run by the gate" \
    "$(as "$STRANGER" -c "select agent_gate_internal._run_assertion('anything')")"

# ---------------------------------------- a proposal runs only for its agent --
check attack "another agent cannot dry-run it" "this agent has no proposal with that id" \
    "$(as "$SUPPORT" -c "select agent_gate.dry_run(${p:-0})")"
check attack "another agent cannot commit it" "this agent has no proposal with that id" \
    "$(as "$SUPPORT" -c "select agent_gate.commit(${p:-0})")"
check attack "a role with MORE privileges cannot commit it" "this agent has no proposal with that id" \
    "$(as "$APP" -c "select agent_gate.commit(${p:-0})")"
check attack "a role with no privileges cannot commit it" "this agent has no proposal with that id" \
    "$(as "$STRANGER" -c "select agent_gate.commit(${p:-0})")"
check_absent attack "another agent's acts() does not show it" "$MARK" \
    "$(as "$SUPPORT" -c "select agent_gate.acts(500)")"
check_absent attack "a non-agent role's acts() does not show it" "$MARK" \
    "$(as "$APP" -c "select agent_gate.acts(500)")"

# ------------------------------------- GRANT is still the authorization --
check attack "an agent cannot propose a read of what it was not granted" "permission denied for table secrets" \
    "$(as "$BILLING" -c "select agent_gate.propose('select passphrase from secrets', 'read the secrets')")"
check_absent attack "discover does not show an agent what it was not granted" "secrets" \
    "$(as "$BILLING" -c "select agent_gate.discover('', 500)")"
check attack "after every attack the row is untouched" "pro" \
    "$(as "$SUPERUSER" -c "select plan from customers where id = 2")"

# -------------------------------------- and the attacks burned nothing --
check legit "the refusals did not burn the proposal: its agent still commits it" '"outcome": "kept"' \
    "$(as "$BILLING" -c "select agent_gate.commit(${p:-0})")"

echo "attacks: $attacks, legitimate: $legit"
if [ "$failures" -ne 0 ]; then
    echo "$failures check(s) failed"
    exit 1
fi
echo "the privilege boundary behaves as documented"
