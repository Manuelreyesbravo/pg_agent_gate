#!/usr/bin/env bash
# The third external audit (of 0.2.8), measured again here: each finding with its tooth and its
# control. The control proves the scenario works -- the same act without the attack, or the attack
# where it must still succeed -- so a green is the gate refusing and not the setup failing.
#
#   GATE-02  a fast-path call (PQfn) reached set_config() and moved the tenant a policy reads
#   GATE-03  a function planted in public ran inside discover(), un-gated, as the calling agent
#   GATE-06  another agent's refused commit was recorded on the owner's proposal and named the owner
#   GATE-07  an allow_ddl agent's DO block deleted past max_rows; its SET moved the tenant
#   GATE-10  register_agent took a REPLICATION role and a member of a superuser
#   GATE-12  PREPARE TRANSACTION let an agent's record outlive its session
#   GATE-14  the allow-list was not dumped with the database
#
#   PG_CONFIG=/path/to/pg_config tests/cluster.sh init && tests/cluster.sh start
#   PG_CONFIG=/path/to/pg_config tests/audit3.sh
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PG_CONFIG=${PG_CONFIG:-pg_config}
BIN=$("$PG_CONFIG" --bindir)
LIBPQ=$("$PG_CONFIG" --libdir)/libpq.so.5
export PGHOST=${PGHOST:-$ROOT/.testcluster}
export PGPORT=${PGPORT:-5499}
SUPERUSER=${SUPERUSER:-$(id -un)}
DB=agent_gate_audit3
A=agent_gate_audit3_a
B=agent_gate_audit3_b
DDL=agent_gate_audit3_ddl
PLANTER=agent_gate_audit3_planter
REPL=agent_gate_audit3_repl
MEMBER=agent_gate_audit3_member

as_super() { "$BIN/psql" -X -U "$SUPERUSER" -d "$DB" -tA "$@" 2>&1; }
as() { local r=$1; shift; "$BIN/psql" -X -U "$r" -d "$DB" -tA "$@" 2>&1 || true; }
commit() { echo "select agent_gate.propose_and_commit(\$q\$$1\$q\$, 'audit three')"; }

source "$(dirname "${BASH_SOURCE[0]}")/guard.sh"
trap release_claimed EXIT
require_throwaway_cluster
for r in "$A" "$B" "$DDL" "$PLANTER" "$REPL" "$MEMBER"; do claim_role "$r"; done
claim_database "$DB"
"$BIN/psql" -X -U "$SUPERUSER" -d "$DB" -v ON_ERROR_STOP=1 -q \
    -v a="$A" -v b="$B" -v ddl="$DDL" -v planter="$PLANTER" >/dev/null <<SQL
CREATE EXTENSION pg_agent_gate;
CREATE TABLE rt (tenant int, v text);
INSERT INTO rt VALUES (1, 'mine'), (2, 'OTHER TENANT SECRET');
ALTER TABLE rt ENABLE ROW LEVEL SECURITY;
CREATE POLICY by_tenant ON rt USING (tenant = current_setting('app.tenant_id')::int);
CREATE TABLE marker (n int);
CREATE TABLE dt (id int);
INSERT INTO dt SELECT g FROM generate_series(1, 50) g;
CREATE TABLE t (id int PRIMARY KEY, v text);
INSERT INTO t VALUES (1, 'one');
GRANT SELECT ON rt TO :"a";
GRANT INSERT ON marker TO :"a";
GRANT SELECT, INSERT, UPDATE, DELETE ON t TO :"a", :"b";
GRANT SELECT, DELETE, TRUNCATE ON dt TO :"ddl";
GRANT CREATE ON SCHEMA public TO :"planter", :"ddl";
ALTER ROLE :"a" SET app.tenant_id = '1';
ALTER ROLE :"ddl" SET app.tenant_id = '1';
SELECT agent_gate.register_agent('audit3_a', :'a', 'reads its tenant');
SELECT agent_gate.register_agent('audit3_b', :'b', 'a second agent');
SELECT agent_gate.register_agent('audit3_ddl', :'ddl', 'changes its schema', 5, true);
SQL

failures=0
check() {
    local what=$1 expected=$2 got=$3
    if [[ "$got" == *"$expected"* ]]; then echo "  ok   $what"; else
        echo "  FAIL $what"; echo "       expected to contain: $expected"; echo "       got: ${got//$'\n'/ }" | cut -c1-400; failures=$((failures + 1)); fi
}
lacks() {
    local what=$1 forbidden=$2 got=$3
    if [[ -n "$got" && "$got" != *"$forbidden"* ]]; then echo "  ok   $what"; else
        echo "  FAIL $what"; echo "       must not contain: $forbidden"; echo "       got: ${got//$'\n'/ }" | cut -c1-400; failures=$((failures + 1)); fi
}

# --- GATE-02: fast path ------------------------------------------------------------------------
FP=$(cat <<'PY'
import ctypes, json, sys
lib = ctypes.CDLL(sys.argv[1])
for f, r, a in [("PQconnectdb", ctypes.c_void_p, [ctypes.c_char_p]), ("PQexec", ctypes.c_void_p, [ctypes.c_void_p, ctypes.c_char_p]),
                ("PQresultErrorMessage", ctypes.c_char_p, [ctypes.c_void_p]), ("PQgetvalue", ctypes.c_char_p, [ctypes.c_void_p, ctypes.c_int, ctypes.c_int]),
                ("PQresultStatus", ctypes.c_int, [ctypes.c_void_p]), ("PQstatus", ctypes.c_int, [ctypes.c_void_p])]:
    getattr(lib, f).restype = r; getattr(lib, f).argtypes = a
class Arg(ctypes.Structure):
    _fields_ = [("len", ctypes.c_int), ("isint", ctypes.c_int), ("ptr", ctypes.c_void_p)]
lib.PQfn.restype = ctypes.c_void_p
lib.PQfn.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int), ctypes.c_int, ctypes.POINTER(Arg), ctypes.c_int]
c = lib.PQconnectdb(sys.argv[2].encode())
args = (Arg * 3)(); keep = []
for i, v in enumerate([b"app.tenant_id", b"2", b"\x00"]):
    b = ctypes.create_string_buffer(v, len(v)); keep.append(b); args[i].len = len(v); args[i].isint = 0; args[i].ptr = ctypes.cast(b, ctypes.c_void_p).value
buf = ctypes.create_string_buffer(4096); rl = ctypes.c_int(0)
res = lib.PQfn(c, 2078, buf, ctypes.byref(rl), 0, args, 3)   # set_config(text, text, bool)
print("fastpath:", "refused" if lib.PQresultStatus(res) == 7 else "ran", (lib.PQresultErrorMessage(res) or b"").decode().split("\n")[0])
r = lib.PQexec(c, b"select agent_gate.propose_and_commit('select v from rt', 'read my tenant')")
v = lib.PQgetvalue(r, 0, 0)
print("read:", v.decode() if v else (lib.PQresultErrorMessage(r) or b"").decode())
PY
)
out=$(python3 -c "$FP" "$LIBPQ" "host=$PGHOST port=$PGPORT dbname=$DB user=$A" 2>&1 || true)
check "control: through the gate the agent reads its own tenant" "mine" "$(as "$A" -c "$(commit 'select v from rt')")"
check "GATE-02: a fast-path set_config() is refused" "fastpath: refused" "$out"
lacks "  ...and the agent does not read the other tenant afterwards" "OTHER TENANT SECRET" "$out"

# --- GATE-03: a planted function in public, inside discover() -----------------------------------
as_super -q -c "set role $PLANTER" -c "create function public.obj_description(oid, text) returns text language plpgsql as \$f\$ begin insert into public.marker values (1); return null; end \$f\$" -c "grant execute on function public.obj_description(oid, text) to public" >/dev/null
out=$(as "$A" -c "select agent_gate.discover('t', 5) is not null")
check "control: discover() answers for the agent" "relation" "$(as "$A" -c "select agent_gate.discover('t', 5)")"
check "GATE-03: discover() does not run a function planted in public" "0" "$(as_super -c 'select count(*) from marker')"

# --- GATE-06: another agent's proposal ----------------------------------------------------------
pid=$(as "$A" -c "select agent_gate.propose(\$q\$update t set v = 'a' where id = 1\$q\$, 'mine')" | sed -nE 's/.*"proposal": ([0-9]+).*/\1/p' | head -1)
before=$(as_super -c "select count(*) from agent_gate_internal.executions where proposal = $pid")
out=$(as "$B" -c "select agent_gate.commit($pid)")
check "control: the owner's proposal exists" "yes" "$( [ -n "$pid" ] && echo yes || echo "no proposal id")"
lacks "GATE-06: another agent's commit does not learn who owns the proposal" "audit3_a" "$out"
check "  ...and writes nothing into the owner's record" "$before" "$(as_super -c "select count(*) from agent_gate_internal.executions where proposal = $pid")"
check "  ...and an unknown id gets the same answer" "$(sed -nE 's/.*"reason": "([^"]+)".*/\1/p' <<<"$out")" "$(as "$B" -c 'select agent_gate.commit(999999)')"

# --- GATE-07: an allow_ddl agent's DO and SET ---------------------------------------------------
check "control: an allow_ddl agent's CREATE TABLE is kept" '"outcome": "kept"' "$(as "$DDL" -c "$(commit 'create table ddl_own (id int)')")"
out=$(as "$DDL" -c "$(commit 'do $d$ begin delete from dt; end $d$')")
check "GATE-07: a DO block is refused" "refused" "$out"
check "  ...and no row of dt is gone" "50" "$(as_super -c 'select count(*) from dt')"
check "GATE-07: a proposed SET is refused" "refused" "$(as "$DDL" -c "$(commit "set app.tenant_id = '2'")")"
check "GATE-07: TRUNCATE is refused" "refused" "$(as "$DDL" -c "$(commit 'truncate dt')")"

# --- GATE-10: roles that reach past the gate ----------------------------------------------------
as_super -q -c "alter role $REPL replication" -c "grant \"$SUPERUSER\" to $MEMBER" >/dev/null
check "GATE-10: a REPLICATION role is not registered" "ERROR:  pg_agent_gate" "$(as_super -c "select agent_gate.register_agent('audit3_repl', '$REPL', 'reads the wal')")"
check "GATE-10: a member of a superuser is not registered" "ERROR:  pg_agent_gate" "$(as_super -c "select agent_gate.register_agent('audit3_member', '$MEMBER', 'can set role out')")"

# --- GATE-12: two-phase commit ------------------------------------------------------------------
check "GATE-12: PREPARE TRANSACTION is refused in an agent session" "two-phase" "$(as "$A" -c 'begin' -c "prepare transaction 'audit3'")"

# --- GATE-14: the allow-list travels with pg_dump ----------------------------------------------
check "GATE-14: the allow-list is dumped with the database" "t" \
    "$(as_super -c "select 'agent_gate_internal.allowlist'::regclass::oid = any(extconfig) from pg_extension where extname = 'pg_agent_gate'")"

if [ "$failures" -ne 0 ]; then
    echo "$failures check(s) failed"
    exit 1
fi
echo "the findings of the third audit are closed, each against its control"
