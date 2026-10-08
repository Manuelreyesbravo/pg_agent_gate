#!/usr/bin/env bash
# Every way an agent could reach the database, tried on purpose.
#
# TWO SURFACES, judged by different code, so they are tested apart:
#
#   [session]  what an agent session can TYPE. The three hooks judge it. A gate
#              that only covers the paths its author had in mind has an unknown
#              hole: the day the connection startup packet was tried -- a channel
#              nobody had looked at -- an agent was reading another tenant's rows
#              within the hour (tests/drivers.sh).
#   [proposal] what an agent can PROPOSE. verify.rs judges that one and the hooks
#              never see it: while a proposal runs, the gate's own SQL is allowed
#              by design.
#
# HOW AN ATTACK IS JUDGED, and this decides whether the measurement is worth
# anything: by its EFFECT ON THE WORLD, read back from a superuser after the
# attempt -- the rows did not change, no table appeared, the marker file was not
# written -- plus, where it applies, that the answer did not carry what it was
# fishing for. NOT by whether an error was raised: an error can come from a typo,
# a missing privilege or bad syntax, and counting "something failed" as success
# is how a measurement ends up reporting a gate that was never exercised.
#
# THE CONTROL IS NOT OPTIONAL: a gate that refuses everything scores perfectly on
# both lists above and leaves the extension useless. The [control] cases check
# that legitimate work still goes through, and there the world SHOULD change --
# which is why they run last, after the world fingerprint has done its job.
#
#   PG_CONFIG=/path/to/pg_config tests/cluster.sh init
#   PG_CONFIG=/path/to/pg_config tests/cluster.sh start
#   PG_CONFIG=/path/to/pg_config tests/adversarial.sh
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PG_CONFIG=${PG_CONFIG:-pg_config}
BIN=$("$PG_CONFIG" --bindir)

# Claims its names instead of dropping whatever is there: see tests/guard.sh.
source "$(dirname "${BASH_SOURCE[0]}")/guard.sh"

SUPERUSER=${SUPERUSER:-$(id -un)}
DB=agent_gate_adversarial
AGENT=agent_gate_adv_agent
OTHER=agent_gate_adv_other
MARKER=${TMPDIR:-/tmp}/agent_gate_adv_marker.$$
SECRET=the-bank-key

finish() {
    release_claimed
    rm -f "$MARKER"
}
trap finish EXIT

require_throwaway_cluster
claim_role "$AGENT"
claim_role "$OTHER"
claim_database "$DB"

"$BIN/psql" -X -U "$SUPERUSER" -d "$DB" -v ON_ERROR_STOP=1 -q \
    -v agent="$AGENT" -v other="$OTHER" >/dev/null <<SQL
CREATE EXTENSION pg_agent_gate;

CREATE TABLE clientes (id int PRIMARY KEY, plan text NOT NULL);
INSERT INTO clientes VALUES (1, 'free'), (2, 'pro'), (3, 'free');

CREATE TABLE secretos (clave text);
INSERT INTO secretos VALUES ('$SECRET');
REVOKE ALL ON secretos FROM PUBLIC;

-- A procedure the agent may EXECUTE: CALL is its own statement kind, and a gate
-- that forgets it would let an agent run whatever somebody left callable.
CREATE PROCEDURE agent_gate_adv_proc() LANGUAGE sql AS
    \$\$ UPDATE clientes SET plan = 'called' WHERE id = 1 \$\$;

GRANT USAGE ON SCHEMA public TO :"agent", :"other";
GRANT SELECT, UPDATE ON clientes TO :"agent";
GRANT EXECUTE ON PROCEDURE agent_gate_adv_proc() TO :"agent";

-- max_rows 2 of 3 customers on purpose: a write that touches everything has to
-- be stopped by the limit and not by luck.
SELECT agent_gate.register_agent('adversary', :'agent', 'the agent under attack in this file', p_max_rows => 2);
SELECT agent_gate.register_agent('bystander', :'other', 'another agent, to try to reach across');
SQL

# Every answer, error or not, is something to inspect: never a reason to stop.
agent() { "$BIN/psql" -X -U "$AGENT" -d "$DB" -tA "$@" 2>&1 || true; }
other() { "$BIN/psql" -X -U "$OTHER" -d "$DB" -tA "$@" 2>&1 || true; }
su() { "$BIN/psql" -X -U "$SUPERUSER" -d "$DB" -tA "$@" 2>&1 || true; }
proposal_id() { sed -nE 's/.*"proposal": ([0-9]+).*/\1/p' <<<"$1" | head -1; }

# The world, in one line: what every customer's plan is, how many objects the
# attacks try to create exist, and how many secrets are there. If an attack got
# through anywhere, this string changes.
WORLD="select (select string_agg(id || '=' || plan, ',' order by id) from clientes) || ' | objetos=' || (select count(*) from pg_class where relname like 'agent!_gate!_adv!_%' escape '!') || ' | secretos=' || (select count(*) from secretos)"
world() { "$BIN/psql" -X -U "$SUPERUSER" -d "$DB" -tAc "$WORLD"; }

failures=0
session=0
proposal=0
control=0

report() {
    local kind=$1 what=$2 ok=$3 detail=$4
    case "$kind" in
        session) session=$((session + 1)) ;;
        proposal) proposal=$((proposal + 1)) ;;
        control) control=$((control + 1)) ;;
    esac
    if [ "$ok" = yes ]; then
        echo "  ok   [$kind] $what"
    else
        echo "  FAIL [$kind] $what"
        echo "       ${detail//$'\n'/ }"
        failures=$((failures + 1))
    fi
}

# An attack passes when the world is untouched, no marker file was written, and
# the answer does not carry what it was fishing for. What the server said is
# printed only when it failed: it is context, not the verdict.
attack() {
    local kind=$1 what=$2 forbidden=$3
    shift 3
    local out now why ok=yes
    out=$("$@")
    now=$(world)
    if [ "$now" != "$BEFORE" ]; then
        ok=no
        why="the world changed: '$BEFORE' -> '$now' | said: $out"
    elif [ -e "$MARKER" ]; then
        ok=no
        why="it wrote $MARKER | said: $out"
        rm -f "$MARKER"
    elif [ -n "$forbidden" ] && [[ "$out" == *"$forbidden"* ]]; then
        ok=no
        why="the answer carried '$forbidden': $out"
    fi
    report "$kind" "$what" "$ok" "${why:-}"
}

expect() {
    local kind=$1 what=$2 wanted=$3 got=$4
    if [[ "$got" == *"$wanted"* ]]; then
        report "$kind" "$what" yes ""
    else
        report "$kind" "$what" no "expected to contain '$wanted', got: $got"
    fi
}

BEFORE=$(world)
if [[ "$BEFORE" != *"1=free,2=pro,3=free"* ]]; then
    echo "  !! the world did not start where this file assumes: $BEFORE"
    exit 2
fi

# ------------------------------------------------------------- [session] --
# What an agent session can TYPE. Judged by the three hooks; every case here is
# judged by what the world looks like afterwards.

attack session "two statements in one simple query" "" \
    agent -c "select agent_gate.whoami(); update clientes set plan = 'hacked' where id = 1"

attack session "PREPARE and EXECUTE, a plan that is not parsed again" "" \
    agent -c "prepare p as update clientes set plan = 'hacked' where id = 1" -c "execute p"

attack session "a cursor over a table it was never granted" "$SECRET" \
    agent -c "begin" -c "declare c cursor for select clave from secretos" -c "fetch all from c"

attack session "COPY TO PROGRAM" "" \
    agent -c "copy clientes to program 'touch $MARKER'"

attack session "COPY FROM PROGRAM" "" \
    agent -c "copy clientes from program 'echo 9,hacked'"

attack session "an anonymous DO block" "" \
    agent -c "do \$x\$ begin update clientes set plan = 'hacked'; end \$x\$"

attack session "CALL of a procedure it may execute" "" \
    agent -c "call agent_gate_adv_proc()"

attack session "EXPLAIN ANALYZE, which executes" "" \
    agent -c "explain analyze update clientes set plan = 'hacked' where id = 1"

attack session "CREATE TABLE" "" agent -c "create table agent_gate_adv_t (x int)"

attack session "CREATE FUNCTION" "" \
    agent -c "create function agent_gate_adv_f() returns int language sql as 'select 1'"

attack session "SELECT INTO a new table" "" \
    agent -c "select * into agent_gate_adv_into from clientes"

attack session "a SELECT whose CTE writes" "" \
    agent -c "with x as (update clientes set plan = 'hacked' where id = 1 returning 1) select agent_gate.whoami()"

attack session "a verb argument that calls a function" "" \
    agent -c "select agent_gate.propose(pg_read_file('/etc/hostname'), 'read a file through an argument')"

attack session "the one-call verb with an argument that calls a function" "" \
    agent -c "select agent_gate.propose_and_commit(pg_read_file('/etc/hostname'), 'read a file through an argument')"

attack session "a subselect of what it was not granted" "$SECRET" \
    agent -c "select (select string_agg(clave, ',') from secretos)"

attack session "SET ROLE to the owner" "" \
    agent -c "set role $SUPERUSER" -c "update clientes set plan = 'hacked' where id = 1"

attack session "SET SESSION AUTHORIZATION" "" \
    agent -c "set session authorization $SUPERUSER" -c "update clientes set plan = 'hacked' where id = 1"

attack session "RESET ALL and then raw SQL" "" \
    agent -c "reset all" -c "update clientes set plan = 'hacked' where id = 1"

attack session "DISCARD ALL and then raw SQL" "" \
    agent -c "discard all" -c "update clientes set plan = 'hacked' where id = 1"

attack session "VACUUM and CHECKPOINT" "" agent -c "vacuum clientes" -c "checkpoint"

attack session "LISTEN and NOTIFY" "" agent -c "listen adv" -c "notify adv, 'x'"

attack session "lo_export writing a file" "" agent -c "select lo_export(0, '$MARKER')"

# The replication sub-protocol is the ONLY one that does not go through the
# normal parser: walsender reads its own commands, so no hook would ever see
# them. What keeps an agent out is the REPLICATION attribute its role does not
# have. BOTH halves are checked: that the role really lacks the attribute -- or
# the refusal below would pass for a reason that has nothing to do with this --
# and that PostgreSQL turns the connection away before any command runs.
expect session "the agent role has no REPLICATION attribute" "f" \
    "$(su -c "select rolreplication from pg_roles where rolname = '$AGENT'")"
# The wording is PostgreSQL's and it changed across versions ('replication role'
# in older ones): what is matched is the WAL sender being refused, not a phrase.
expect session "a replication connection never gets that far" "WAL sender" \
    "$("$BIN/psql" -X -d "dbname=$DB replication=database user=$AGENT" -tAc "IDENTIFY_SYSTEM" 2>&1 || true)"

# ------------------------------------------------------------ [proposal] --
# What an agent can PROPOSE. verify.rs judges this one; the hooks never see it,
# because while a proposal runs the gate's own SQL is allowed by design. The SQL
# travels dollar-quoted so that quoting an attack is not an attack on the quoting.

# Every attack goes through BOTH ways an agent can act: propose then commit (two calls), and
# propose_and_commit (one call, one transaction). The second runs commit's own checks, and this
# is where that is measured instead of assumed.
two_calls() {
    local sql=$1 intent=$2 out id
    out=$(agent -c "select agent_gate.propose(\$s\$$sql\$s\$, \$i\$$intent\$i\$)")
    id=$(proposal_id "$out")
    printf '%s | %s' "$out" "$(agent -c "select agent_gate.commit(${id:-0})")"
}
one_call() {
    local sql=$1 intent=$2
    agent -c "select agent_gate.propose_and_commit(\$s\$$sql\$s\$, \$i\$$intent\$i\$)"
}
attack_both() {  # <what> <sql> <intent>
    attack proposal "$1" "" two_calls "$2" "$3"
    attack proposal "$1 -- in one call" "" one_call "$2" "$3"
}

attack_both "two statements in one proposal" \
    "select 1; update clientes set plan = 'hacked' where id = 1" "two at once"

attack_both "a second statement hidden after a comment" \
    "select 1; -- looks like the end
update clientes set plan = 'hacked' where id = 2" "hidden after a comment"

attack_both "DDL from an agent that was not allowed DDL" \
    "create table agent_gate_adv_ddl (x int)" "make myself a table"

attack_both "COPY TO PROGRAM as a proposal" \
    "copy clientes to program 'touch $MARKER'" "reach the shell"

attack_both "SELECT INTO as a proposal" \
    "select * into agent_gate_adv_into from clientes" "copy the table"

attack_both "SELECT FOR UPDATE beyond max_rows" \
    "select * from clientes for update" "lock every row"

attack_both "a write that touches more rows than max_rows" \
    "update clientes set plan = 'hacked'" "upgrade everyone"

# The same write hidden in a CTE, under a statement that returns ONE row. max_rows counted
# the rows of the outer statement, so this touched all three customers under a limit of
# two (found by the cycle harness of yggdrasil, 2026-10-06). Two shapes of it.
attack_both "a CTE that writes, under a SELECT that returns one row" \
    "with d as (update clientes set plan = 'hacked' returning 1) select count(*) from d" \
    "upgrade everyone, counted as one row"
attack_both "a CTE that writes, under a SELECT that does not even read it" \
    "with d as (update clientes set plan = 'hacked' returning 1) select 1" \
    "upgrade everyone, counted as one row"

# A verification is a statement about the database at a moment. The TTL is SUSET,
# so only the owner can shorten it -- which is what makes this testable at all.
su -c "alter role $AGENT set agent_gate.proposal_ttl_seconds = 1" >/dev/null
stale=$(agent -c "select agent_gate.propose(\$s\$update clientes set plan = 'hacked' where id = 3\$s\$, \$i\$let me go stale\$i\$)")
sleep 2
attack proposal "a verification older than its TTL" "" \
    agent -c "select agent_gate.commit($(proposal_id "$stale"))"
su -c "alter role $AGENT reset agent_gate.proposal_ttl_seconds" >/dev/null

mine=$(agent -c "select agent_gate.propose(\$s\$update clientes set plan = 'hacked' where id = 2\$s\$, \$i\$mine, not yours\$i\$)")
attack proposal "another agent commits a proposal that is not its own" "" \
    other -c "select agent_gate.commit($(proposal_id "$mine"))"

# ------------------------------------------------------------- [control] --
# Without this, everything above is also passed by a gate that refuses all work
# and is therefore useless. Here the world SHOULD change, which is why these run
# last: the fingerprint above has already done its job.

expect control "whoami says the session is behind the gate" '"is_agent": true' \
    "$(agent -c 'select agent_gate.whoami()')"
expect control "discover shows what the agent was granted" "clientes" \
    "$(agent -c "select agent_gate.discover('', 500)")"

read_p=$(agent -c "select agent_gate.propose(\$s\$select id, plan from clientes order by id\$s\$, \$i\$list the customers\$i\$)")
expect control "a legitimate read verifies" '"ok": true' "$read_p"
expect control "and committing it returns rows" '"outcome": "read"' \
    "$(agent -c "select agent_gate.commit($(proposal_id "$read_p"))")"

write_p=$(agent -c "select agent_gate.propose(\$s\$update clientes set plan = 'upgraded' where id = 1\$s\$, \$i\$upgrade customer 1\$i\$)")
expect control "a legitimate write verifies" '"ok": true' "$write_p"
write_id=$(proposal_id "$write_p")

expect control "dry_run shows before and after" '"before"' \
    "$(agent -c "select agent_gate.dry_run(${write_id:-0})")"
expect control "and a dry run keeps nothing" "free" \
    "$(su -c 'select plan from clientes where id = 1')"

expect control "commit keeps the change" '"outcome": "kept"' \
    "$(agent -c "select agent_gate.commit(${write_id:-0})")"
expect control "and the world really changed" "upgraded" \
    "$(su -c 'select plan from clientes where id = 1')"

expect control "committing the same proposal twice is refused" "already committed" \
    "$(agent -c "select agent_gate.commit(${write_id:-0})")"
expect control "acts tells the agent its own history" "upgrade customer 1" \
    "$(agent -c 'select agent_gate.acts(500)')"

# The one-call verb, from a real agent session: a read returns rows, a write is kept and the
# world really changes, and both land in the agent's history.
expect control "a read in one call returns rows" '"outcome": "read"' \
    "$(one_call "select id, plan from clientes order by id" "list the customers in one call")"
expect control "a write in one call is kept" '"outcome": "kept"' \
    "$(one_call "update clientes set plan = 'one call' where id = 3" "upgrade customer 3 in one call")"
expect control "and the world really changed" "one call" \
    "$(su -c 'select plan from clientes where id = 3')"
expect control "acts shows the one-call act" "upgrade customer 3 in one call" \
    "$(agent -c 'select agent_gate.acts(500)')"

echo "session: $session, proposal: $proposal, control: $control"
if [ "$failures" -ne 0 ]; then
    echo "$failures check(s) failed"
    exit 1
fi
echo "no channel reached the database, and legitimate work still does"
