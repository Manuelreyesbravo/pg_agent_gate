#!/usr/bin/env bash
# An agent role has no members (0.4.1). The gate knows an agent session by agent_gate.agent,
# applied when the agent role CONNECTS; a member that SET ROLEs into the agent's has its
# privileges with no gate (measured on 0.4.0: 20 rows deleted past a max_rows of 2). So
# register_agent refuses a role with members, and no statement may add one -- in any of
# the forms PostgreSQL has. Every verdict is read back from pg_auth_members as a superuser.
#
#   PG_CONFIG=/path/to/pg_config tests/cluster.sh init && tests/cluster.sh start
#   PG_CONFIG=/path/to/pg_config tests/membership.sh
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PG_CONFIG=${PG_CONFIG:-pg_config}
BIN=$("$PG_CONFIG" --bindir)
export PGHOST=${PGHOST:-$ROOT/.testcluster}
export PGPORT=${PGPORT:-5499}
SUPERUSER=${SUPERUSER:-$(id -un)}
DB=agent_gate_membership
AGENT=agent_gate_membership_agent
OTHER=agent_gate_membership_other
ADMIN=agent_gate_membership_admin
NEWROLE=agent_gate_membership_new   # created and dropped by the cases themselves, not claimed
PLAIN=agent_gate_membership_plain

source "$(dirname "${BASH_SOURCE[0]}")/guard.sh"
require_throwaway_cluster
for r in "$AGENT" "$OTHER" "$ADMIN" "$PLAIN"; do claim_role "$r"; done
trap '"$BIN/psql" -X -U "$SUPERUSER" -d postgres -qc "drop role if exists $NEWROLE" >/dev/null 2>&1; release_claimed' EXIT
claim_database "$DB"

"$BIN/psql" -X -U "$SUPERUSER" -d "$DB" -v ON_ERROR_STOP=1 -q \
    -v agent="$AGENT" -v other="$OTHER" -v admin="$ADMIN" -v plain="$PLAIN" >/dev/null <<SQL
CREATE EXTENSION pg_agent_gate;
CREATE TABLE t (id int);
INSERT INTO t SELECT generate_series(1, 20);
GRANT SELECT, DELETE ON t TO :"agent";
-- A role that can manage roles, but is not a superuser: CREATEROLE, with ADMIN on the agent role
-- given before it was registered would be refused; here it only creates and grants roles.
ALTER ROLE :"admin" CREATEROLE;
SELECT agent_gate.register_agent('member_test', :'agent', 'agent for the membership suite', p_max_rows => 2);
SQL

failures=0
check() {
    local what=$1 expected=$2 got=$3
    if [[ "$got" == *"$expected"* ]]; then echo "  ok   $what"; else
        echo "  FAIL $what"; echo "       expected to contain: $expected"
        echo "       got: ${got//$'\n'/ }" | cut -c1-300; failures=$((failures + 1)); fi
}
run()     { "$BIN/psql" -X -U "$1" -d "$DB" -tAc "$2" 2>&1 || true; }
members() { run "$SUPERUSER" "select count(*) from pg_auth_members m join pg_roles r on r.oid = m.roleid where r.rolname = '$AGENT'"; }

# 1. GRANT agent TO another role.
check "1a. GRANT of the agent role is refused" "member of an agent role" \
    "$(run "$SUPERUSER" "grant $AGENT to $OTHER")"
check "1b. and no membership exists" "0" "$(members)"

# 2. CREATE ROLE ... IN ROLE agent (the new role a member of the agent's).
check "2a. CREATE ROLE ... IN ROLE agent is refused" "member of an agent role" \
    "$(run "$SUPERUSER" "create role $NEWROLE in role $AGENT")"
check "2b. and neither the role nor the membership exists" "0|0" \
    "$(run "$SUPERUSER" "select (select count(*) from pg_roles where rolname = '$NEWROLE') || '|' || ($(members))")"

# 3. ALTER GROUP agent ADD USER other.
check "3a. ALTER GROUP ... ADD USER is refused" "member of an agent role" \
    "$(run "$SUPERUSER" "alter group $AGENT add user $OTHER")"
check "3b. and no membership exists" "0" "$(members)"

# 4. The hole itself: with no member, a non-superuser cannot SET ROLE into the agent.
check "4a. a non-superuser cannot SET ROLE into the agent" "permission denied to set role" \
    "$(run "$OTHER" "set role $AGENT")"
check "4b. nor with set_config('role', ...)" "permission denied to set role" \
    "$(run "$OTHER" "select set_config('role', '$AGENT', false)")"
check "4c. the rows are all there" "20" "$(run "$SUPERUSER" "select count(*) from t")"

# 5. register_agent refuses a role that already has members.
run "$SUPERUSER" "grant $OTHER to $PLAIN" >/dev/null          # not an agent: allowed
check "5a. registering a role that has members is refused" "has members" \
    "$(run "$SUPERUSER" "select agent_gate.register_agent('other', '$OTHER', 'a role with a member', p_max_rows => 2)")"
check "5b. and it is not registered" "0" \
    "$(run "$SUPERUSER" "select count(*) from agent_gate_internal.agents where name = 'other'")"

# 6. Controls: role administration that adds no member to an agent still works.
check "6a. GRANT of a role that is not an agent's works" "1" \
    "$(run "$SUPERUSER" "select count(*) from pg_auth_members m join pg_roles a on a.oid = m.roleid join pg_roles b on b.oid = m.member where a.rolname = '$OTHER' and b.rolname = '$PLAIN'")"
check "6b. ALTER ROLE of the agent itself works" "ALTER ROLE" \
    "$(run "$SUPERUSER" "alter role $AGENT connection limit 10")"
check "6c. a CREATEROLE role, not a superuser, can still create roles" "CREATE ROLE" \
    "$(run "$ADMIN" "create role $NEWROLE")"
run "$SUPERUSER" "drop role if exists $NEWROLE" >/dev/null
check "6d. any role can still change its own password" "ALTER ROLE" \
    "$(run "$PLAIN" "alter role $PLAIN password 'a-new-one'")"

# 7. The agent session itself is behind the gate as always.
check "7. the agent, logged in as itself, proposes and does not execute" "it proposes, it does not execute" \
    "$(run "$AGENT" "delete from t")"

echo
if [ "$failures" -eq 0 ]; then echo "membership: all checks passed"; else echo "membership: $failures FAILED"; exit 1; fi
