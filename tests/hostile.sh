#!/usr/bin/env bash
# What the first battery did not touch: robustness, indirect writes,
# concurrency, and whether the record can be rewritten.
#
# tests/adversarial.sh walks the channels an agent can EXECUTE or PROPOSE and
# they are all closed. That says nothing about these four, which nobody had
# looked at:
#
#   [robust]   this extension is preloaded, and a crash in preloaded code takes
#              the WHOLE CLUSTER down -- the declared number one risk of the
#              project. The gate parses, plans and runs text a model wrote, and
#              that path had never been fed garbage. The verdict here is NOT
#              that a proposal is refused: it is that the server is still there,
#              same postmaster PID, no recovery in between.
#   [indirect] an agent can write where it has no privilege if the OWNER left a
#              trigger, a SECURITY DEFINER function or a view that does it on its
#              behalf. The README calls this a limit; it was never measured. It
#              is measured here, and what is measured has to match what the
#              README says -- a limit only its author knows is not documented.
#   [race]     the central promise is that a proposal is verified AGAIN before it
#              runs, because the world may have moved. No test covered it.
#   [record]   append-only was tested with UPDATE and nothing else.
#
#   PG_CONFIG=/path/to/pg_config tests/cluster.sh init
#   PG_CONFIG=/path/to/pg_config tests/cluster.sh start
#   PG_CONFIG=/path/to/pg_config tests/hostile.sh
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PG_CONFIG=${PG_CONFIG:-pg_config}
BIN=$("$PG_CONFIG" --bindir)

source "$(dirname "${BASH_SOURCE[0]}")/guard.sh"

SUPERUSER=${SUPERUSER:-$(id -un)}
DB=agent_gate_hostile
AGENT=agent_gate_hostile_agent

trap release_claimed EXIT
require_throwaway_cluster
claim_role "$AGENT"
claim_database "$DB"

"$BIN/psql" -X -U "$SUPERUSER" -d "$DB" -v ON_ERROR_STOP=1 -q -v agent="$AGENT" >/dev/null <<SQL
CREATE EXTENSION pg_agent_gate;

CREATE TABLE book (id int PRIMARY KEY, body text NOT NULL);
INSERT INTO book VALUES (1, 'one'), (2, 'two');

-- The agent has NO privilege on this one. Everything under [indirect] is about
-- whether something the owner left behind writes here on the agent's behalf.
CREATE TABLE audit_log (who text, what text);
REVOKE ALL ON audit_log FROM PUBLIC;

CREATE TABLE secrets (passphrase text);
INSERT INTO secrets VALUES ('the-bank-key');
REVOKE ALL ON secrets FROM PUBLIC;

-- An ordinary trigger: its function runs as whoever fired it, so it should hit
-- the same wall the agent would.
CREATE FUNCTION log_write() RETURNS trigger LANGUAGE plpgsql AS \$t\$
BEGIN
    INSERT INTO audit_log VALUES (current_user, 'trigger');
    RETURN NEW;
END \$t\$;
CREATE TRIGGER book_log AFTER UPDATE ON book FOR EACH ROW EXECUTE FUNCTION log_write();

-- A SECURITY DEFINER function the owner left callable. This one runs as the
-- OWNER, so it can write where the agent cannot. That is PostgreSQL working as
-- designed, and the point of measuring it is to know it happens.
CREATE FUNCTION elevate() RETURNS int LANGUAGE plpgsql SECURITY DEFINER AS \$e\$
BEGIN
    INSERT INTO audit_log VALUES (current_user, 'security definer');
    RETURN 1;
END \$e\$;

-- A view over a table the agent may not read. Without security_invoker it is
-- checked with the OWNER's privileges.
CREATE VIEW secret_view AS SELECT passphrase FROM secrets;

GRANT USAGE ON SCHEMA public TO :"agent";
GRANT SELECT, UPDATE ON book TO :"agent";
GRANT EXECUTE ON FUNCTION elevate() TO :"agent";
GRANT SELECT ON secret_view TO :"agent";

SELECT agent_gate.register_agent('hostile', :'agent', 'the agent used by the second battery', p_max_rows => 5);
SQL

agent() { "$BIN/psql" -X -U "$AGENT" -d "$DB" -tA "$@" 2>&1 || true; }
su() { "$BIN/psql" -X -U "$SUPERUSER" -d "$DB" -tA "$@" 2>&1 || true; }
proposal_id() { sed -nE 's/.*"proposal": ([0-9]+).*/\1/p' <<<"$1" | head -1; }

# Propose and commit in one go, dollar-quoted so that quoting an attack is not
# an attack on the quoting.
propose_and_commit() {
    local sql=$1 intent=$2 out id
    out=$(agent -c "select agent_gate.propose(\$s\$$sql\$s\$, \$i\$$intent\$i\$)")
    id=$(proposal_id "$out")
    printf '%s | %s' "$out" "$(agent -c "select agent_gate.commit(${id:-0})")"
}

failures=0
robust=0
indirect=0
race=0
record=0

report() {
    local kind=$1 what=$2 ok=$3 detail=$4
    case "$kind" in
        robust) robust=$((robust + 1)) ;;
        indirect) indirect=$((indirect + 1)) ;;
        race) race=$((race + 1)) ;;
        record) record=$((record + 1)) ;;
    esac
    if [ "$ok" = yes ]; then
        echo "  ok   [$kind] $what"
    else
        echo "  FAIL [$kind] $what"
        echo "       ${detail//$'\n'/ }"
        failures=$((failures + 1))
    fi
}

expect() {
    local kind=$1 what=$2 wanted=$3 got=$4
    if [[ "$got" == *"$wanted"* ]]; then
        report "$kind" "$what" yes ""
    else
        report "$kind" "$what" no "expected to contain '$wanted', got: $got"
    fi
}

absent() {
    local kind=$1 what=$2 forbidden=$3 got=$4
    if [[ -n "$got" && "$got" != *"$forbidden"* ]]; then
        report "$kind" "$what" yes ""
    else
        report "$kind" "$what" no "must be a real answer without '$forbidden', got: $got"
    fi
}

# The only verdict that matters under [robust]: the server is still the same
# server. A backend may die; the postmaster may not, because it would take every
# other database in the cluster with it.
POSTMASTER=$(su -c "select pg_postmaster_start_time()")
still_alive() {
    local what=$1 out=$2 now
    now=$(su -c "select pg_postmaster_start_time()")
    if [ "$now" = "$POSTMASTER" ] && [ -n "$now" ]; then
        report robust "$what" yes ""
    else
        report robust "$what" no "the postmaster restarted: '$POSTMASTER' -> '$now' | said: $out"
    fi
}
hostile() {
    local what=$1
    shift
    still_alive "$what" "$("$@")"
}

# -------------------------------------------------------------- [robust] --
# Garbage into propose and commit. The verdict is the server, not the answer.

open=$(printf '(%.0s' $(seq 1 500))
close=$(printf ')%.0s' $(seq 1 500))
huge=$(printf 'a%.0s' $(seq 1 100000))
many=$(printf "'{%s}'::text[]" "$(printf 'x,%.0s' $(seq 1 499))x")

hostile "malformed SQL" agent -c "select agent_gate.propose(\$s\$selec 1\$s\$, \$i\$broken\$i\$)"
hostile "unbalanced parentheses" agent -c "select agent_gate.propose(\$s\$select (((((\$s\$, \$i\$unbalanced\$i\$)"
hostile "an unterminated comment" agent -c "select agent_gate.propose(\$s\$select 1 /*\$s\$, \$i\$comment\$i\$)"
hostile "an unterminated dollar quote" agent -c "select agent_gate.propose(\$s\$select \$x\$ hola\$s\$, \$i\$quote\$i\$)"
hostile "a NUL byte inside the SQL" \
    agent -c "select agent_gate.propose(concat('select ', chr(0), '1'), \$i\$nul\$i\$)"
hostile "500 levels of nesting" agent -c "select agent_gate.propose(\$s\$select ${open}1${close}\$s\$, \$i\$deep\$i\$)"
hostile "100 KB of SQL" agent -c "select agent_gate.propose(\$s\$select '${huge}'\$s\$, \$i\$huge\$i\$)"
hostile "500 parameters for a statement with none" \
    agent -c "select agent_gate.propose(\$s\$select 1\$s\$, \$i\$many params\$i\$, ${many})"
hostile "more placeholders than parameters" \
    agent -c "select agent_gate.propose(\$s\$select \$1::int, \$2::int, \$3::int\$s\$, \$i\$short\$i\$, '{1}'::text[])"
hostile "a type that does not exist" \
    agent -c "select agent_gate.propose(\$s\$select 1::nosuchtype\$s\$, \$i\$type\$i\$)"
hostile "an invalid UTF-8 escape" \
    agent -c "select agent_gate.propose(\$s\$select E'\\\\xff'\$s\$, \$i\$unicode\$i\$)"
hostile "a 10 KB identifier" \
    agent -c "select agent_gate.propose(\$s\$select * from ${huge:0:10000}\$s\$, \$i\$long name\$i\$)"
hostile "an empty proposal" agent -c "select agent_gate.propose(\$s\$\$s\$, \$i\$empty\$i\$)"
hostile "committing a proposal id that does not exist" agent -c "select agent_gate.commit(999999)"
hostile "committing a negative id" agent -c "select agent_gate.commit(-1)"

# A query that never ends is not a crash, but it holds a backend. What stops it
# is a statement_timeout, which the OWNER sets on the role -- the gate does not
# impose one. Measured with one in place; that it is needed is said in the README.
su -c "alter role $AGENT set statement_timeout = '2s'" >/dev/null
hostile "an endless query, with the statement_timeout the owner set" \
    agent -c "select agent_gate.propose(\$s\$select count(*) from generate_series(1, 1000000000000)\$s\$, \$i\$forever\$i\$)"
su -c "alter role $AGENT reset statement_timeout" >/dev/null

# ------------------------------------------------------------- [record] --
# Append-only had been tested with UPDATE and nothing else. The verdict is read
# from the record afterwards: the rows are still there and still say the same.

HISTORY="select count(*) || ':' || coalesce(md5(string_agg(id || intent || sql, '|' order by id)), '') from agent_gate_internal.proposals"
BEFORE_RECORD=$(su -c "$HISTORY")

record_intact() {
    local what=$1 out=$2 now
    now=$(su -c "$HISTORY")
    if [ "$now" = "$BEFORE_RECORD" ] && [ -n "$now" ]; then
        report record "$what" yes ""
    else
        report record "$what" no "the record changed: '$BEFORE_RECORD' -> '$now' | said: $out"
    fi
}

record_intact "an agent cannot DELETE from the record" \
    "$(agent -c 'delete from agent_gate_internal.proposals')"
record_intact "an agent cannot TRUNCATE the record" \
    "$(agent -c 'truncate agent_gate_internal.executions')"
record_intact "an agent cannot disable the triggers" \
    "$(agent -c 'alter table agent_gate_internal.proposals disable trigger all')"
record_intact "an agent cannot drop the trigger" \
    "$(agent -c 'drop trigger proposals_append_only on agent_gate_internal.proposals')"
record_intact "even the owner cannot UPDATE the record" \
    "$(su -c \"update agent_gate_internal.proposals set intent = 'rewritten'\")"
record_intact "even the owner cannot DELETE from the record" \
    "$(su -c 'delete from agent_gate_internal.proposals')"
# TRUNCATE does not fire FOR EACH ROW triggers. If the history can be emptied
# without disabling anything, append-only is a promise with a hole in it, and
# this case is here to say so out loud rather than to be quietly true.
record_intact "and the owner cannot TRUNCATE it either" \
    "$(su -c 'truncate agent_gate_internal.executions, agent_gate_internal.proposals')"

# ------------------------------------------------------------ [indirect] --
# What something the OWNER left behind does on the agent's behalf. Nothing here
# is a bug in the gate: it is PostgreSQL working as designed. The point is to
# know it happens, and that the README says so -- a limit only its author knows
# is not a documented limit.

audit_rows() { su -c 'select count(*) from audit_log'; }

# An ordinary trigger runs as whoever fired it, so it hits the same wall the
# agent would: the write does not happen, and neither does the UPDATE.
propose_and_commit "update book set body = 'trigger' where id = 1" "fire the ordinary trigger" >/dev/null
expect indirect "an ordinary trigger cannot write where the agent cannot" "0" "$(audit_rows)"
expect indirect "and the write it was attached to did not happen either" "one" \
    "$(su -c 'select body from book where id = 1')"

# THE TRIGGER COMES OFF HERE, and that is not tidying up: while it was attached,
# every write on book died with 'permission denied for table audit_log', so the
# three cases below it were measuring the trigger instead of what they claim.
# A case that leaves the world changed makes the next ones measure something
# else -- this file learned that about itself on its first run.
su -c 'drop trigger book_log on book' >/dev/null

# A SECURITY DEFINER function called from a READ. Since 0.2.3 the gate refuses it at propose
# (no_opaque_function, because the body is opaque); even if it had not, a read's subtransaction is
# always rolled back, so it would leave nothing either way. Two layers -- the case checks the
# outcome, which is the same: nothing written.
propose_and_commit "select elevate()" "call an elevated function from a read" >/dev/null
expect indirect "a SECURITY DEFINER function called from a READ leaves nothing" "0" "$(audit_rows)"

# The same function inside a WRITE. Until 0.2.3 this was a documented LIMIT: elevate(), being
# SECURITY DEFINER, ran as its owner and wrote to a table the agent cannot touch. 0.2.3 closes it:
# no_opaque_function refuses at propose any statement that calls a volatile or SECURITY DEFINER
# user function, because its body is opaque to the gate. So the write never runs and audit_log stays
# empty -- and the README now says it is refused, not that it writes.
before=$(audit_rows)
refused=$(agent -c "select agent_gate.propose(\$s\$update book set body = 'elevated' || elevate()::text where id = 2\$s\$, \$i\$call an elevated function from a write\$i\$)")
if echo "$refused" | grep -q 'no_opaque_function' && [ "$(audit_rows)" = "$before" ] \
   && [ "$(grep -c -F 'SECURITY DEFINER' "$ROOT/README.md")" -ge 1 ]; then
    report indirect "a SECURITY DEFINER function inside a WRITE is refused at propose, writing nothing" yes ""
else
    report indirect "a SECURITY DEFINER function inside a WRITE is refused at propose, writing nothing" no \
        "audit_log: $(audit_rows) (expected $before); refused by no_opaque_function: $(echo "$refused" | grep -c no_opaque_function); README mentions SECURITY DEFINER: $(grep -c -F 'SECURITY DEFINER' "$ROOT/README.md")"
fi

# A view without security_invoker is checked with the OWNER's privileges, so it
# hands over a table the agent may not read. The gate verifies the proposal; it
# does not re-decide what a view is allowed to show.
through_view=$(propose_and_commit "select passphrase from secret_view" "read a secret through a view")
if [[ "$through_view" == *the-bank-key* ]] && [ "$(grep -c -F 'security_invoker' "$ROOT/README.md")" -ge 1 ]; then
    report indirect "a view reads what the agent cannot, and the README says so" yes ""
else
    report indirect "a view reads what the agent cannot, and the README says so" no \
        "secret came through: $([[ \"$through_view\" == *the-bank-key* ]] && echo yes || echo no); README mentions security_invoker: $(grep -c -F 'security_invoker' "$ROOT/README.md")"
fi

# ---------------------------------------------------------------- [race] --
# The central promise: a proposal is verified AGAIN, now, before it runs. Every
# case here moves the world between propose and commit and then reads what
# happened. Until today none of this had a test.

propose_only() {
    proposal_id "$(agent -c "select agent_gate.propose(\$s\$$1\$s\$, \$i\$$2\$i\$)")"
}

# The table is renamed underneath it.
id=$(propose_only "update book set body = 'renamed' where id = 1" "before the rename")
su -c 'alter table book rename to book_moved' >/dev/null
expect race "a proposal whose table was renamed is refused" "no longer verifies" \
    "$(agent -c "select agent_gate.commit(${id:-0})")"
su -c 'alter table book_moved rename to book' >/dev/null
expect race "and the row it would have touched is untouched" "one" \
    "$(su -c 'select body from book where id = 1')"

# A column it depends on disappears.
su -c 'alter table book add column extra text' >/dev/null
id=$(propose_only "update book set extra = 'x' where id = 1" "before the column is dropped")
su -c 'alter table book drop column extra' >/dev/null
expect race "a proposal whose column was dropped is refused" "no longer verifies" \
    "$(agent -c "select agent_gate.commit(${id:-0})")"

# The privilege is revoked after the proposal verified.
id=$(propose_only "update book set body = 'no permission' where id = 1" "before the revoke")
su -c "revoke update on book from $AGENT" >/dev/null
expect race "a proposal whose privilege was revoked is refused" "no longer verifies" \
    "$(agent -c "select agent_gate.commit(${id:-0})")"
su -c "grant update on book to $AGENT" >/dev/null

# The row is gone. This one is NOT a refusal: the statement is still valid, it
# simply touches nothing, and the record says so. Reporting zero rows honestly is
# the right behaviour -- pretending it failed would be worse.
su -c "insert into book values (9, 'nine')" >/dev/null
id=$(propose_only "update book set body = 'late' where id = 9" "before the row is deleted")
su -c 'delete from book where id = 9' >/dev/null
expect race "a proposal whose row vanished keeps nothing and says zero rows" '"rows_affected": 0' \
    "$(agent -c "select agent_gate.commit(${id:-0})")"

# A bound assertion breaks because of somebody ELSE's change, between propose and
# commit. The agent's own write is innocent and still must not be kept: a
# guarantee that stopped holding stops the change that would ride on it.
su -c "create extension if not exists pg_living_assertions" >/dev/null
su -c "select living_assertions.declare('no_empty_body', 'no book row is empty', \$a\$select not exists (select 1 from public.book where body = '') as holds\$a\$)" >/dev/null
su -c "select agent_gate.bind_assertion('hostile', 'no_empty_body')" >/dev/null
id=$(propose_only "update book set body = 'innocent' where id = 1" "innocent, while somebody else breaks the guarantee")
su -c "insert into book values (8, '')" >/dev/null
expect race "a write is aborted when a bound assertion broke meanwhile" "broken" \
    "$(agent -c "select agent_gate.commit(${id:-0})")"
expect race "and that write was not kept" "one" "$(su -c 'select body from book where id = 1')"
su -c "delete from book where id = 8" >/dev/null
su -c "select agent_gate.unbind_assertion('hostile', 'no_empty_body')" >/dev/null

# Two sessions of the SAME agent at once. The counters that decide whether the
# gate's own SQL may run are static PER PROCESS, so two backends must not be able
# to step into each other's window.
one=$(propose_only "update book set body = 'a' where id = 1" "first of two at once")
two=$(propose_only "update book set body = 'b' where id = 2" "second of two at once")
agent -c "select agent_gate.commit(${one:-0})" >/dev/null &
agent -c "select agent_gate.commit(${two:-0})" >/dev/null &
wait
expect race "two sessions of the same agent commit their own proposals" "a|b" \
    "$(su -c "select string_agg(body, '|' order by id) from book where id in (1, 2)")"

# And the same proposal committed twice at the same time: it may be applied once
# or refused twice, never applied twice.
su -c "update book set body = 'x' where id = 1" >/dev/null
id=$(propose_only "update book set body = body || 'y' where id = 1" "the same proposal, twice at once")
agent -c "select agent_gate.commit(${id:-0})" >/dev/null &
agent -c "select agent_gate.commit(${id:-0})" >/dev/null &
wait
current=$(su -c 'select body from book where id = 1')
if [ "$current" = "xy" ] || [ "$current" = "x" ]; then
    report race "the same proposal committed twice at once is never applied twice" yes ""
else
    report race "the same proposal committed twice at once is never applied twice" no \
        "expected 'xy' or 'x', got: $current"
fi

echo "robust: $robust, indirect: $indirect, race: $race, record: $record"
if [ "$failures" -ne 0 ]; then
    echo "$failures check(s) failed"
    exit 1
fi
echo "nothing brought the server down, and what the indirect paths do is what the README says"
