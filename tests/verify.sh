#!/usr/bin/env bash
# ONE COMMAND for everything the README claims, run where you can watch it fail.
#
#   PG_CONFIG=/path/to/pg_config make verify
#   PG_CONFIG=/path/to/pg_config VERIFY_DRIVERS=1 make verify   # + pgjdbc and node-pg
#
# What it does, in order:
#   1. builds the release artifact for that PostgreSQL (`cargo pgrx package`);
#   2. starts a THROWAWAY cluster from that PostgreSQL's binaries, loading the gate from
#      the artifact -- nothing is installed into that PostgreSQL by this step;
#   3. runs every suite in tests/ against it -- attacks on purpose, each one checking the
#      database from a superuser's side, not the gate's own answer;
#   4. runs the pgrx unit tests, which use pgrx's own instance for that major version.
#
# Exit 0 only if everything passed. A suite that could not RUN counts as failed: a skip
# that reads like a pass is how a security claim goes stale without anybody noticing.
# The one exception is the driver suite, which needs java, node and the network, and is
# therefore opt-in -- and the summary says it was not run.
#
# Prerequisites, checked before anything runs (each failure says how to fix it):
#   * cargo-pgrx 0.19.2;
#   * pg_living_assertions installed in that PostgreSQL (hostile.sh and dump_restore.sh
#     bind assertions from it);
#   * for step 4, pgrx initialised for that major version.
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
export PG_CONFIG=${PG_CONFIG:-pg_config}
# pgrx-tests connects to its test instance as $USER and panics when it is unset, which is
# what a container switched with `USER` and most CI runners give you. Found on the first
# clean-machine run (2026-10-06): the first unit test panicked on it and the other nine
# died on the mutex it left behind -- 0/10 on a machine where every suite passed.
export USER=${USER:-$(id -un)}

LOG=$ROOT/target/verify
PGRX_VERSION=0.19.2

die() { echo "verify: $*" >&2; exit 2; }

command -v "$PG_CONFIG" >/dev/null 2>&1 || [ -x "$PG_CONFIG" ] \
    || die "no pg_config at '$PG_CONFIG': set PG_CONFIG=/path/to/pg_config"
MAJOR=$("$PG_CONFIG" --version | sed -E 's/^PostgreSQL ([0-9]+).*/\1/')
[ "$MAJOR" -ge 18 ] 2>/dev/null || die "PostgreSQL $MAJOR: the gate needs 18 or later (dry_run uses RETURNING old/new)"
SHARE=$("$PG_CONFIG" --sharedir)

cargo pgrx --version 2>/dev/null | grep -q "$PGRX_VERSION" \
    || die "cargo-pgrx $PGRX_VERSION is needed: cargo install cargo-pgrx --version $PGRX_VERSION --locked"
[ -f "$SHARE/extension/pg_living_assertions.control" ] \
    || die "pg_living_assertions is not installed in this PostgreSQL. hostile.sh and dump_restore.sh need it:
    git clone https://github.com/Manuelreyesbravo/pg_living_assertions
    make -C pg_living_assertions install PG_CONFIG=$PG_CONFIG"

SUITES=(adversarial hostile privileges rls_isolation dump_restore upgrade flushes plan_time)
if [ "${VERIFY_DRIVERS:-0}" = 1 ]; then
    SUITES+=(drivers)
fi

mkdir -p "$LOG"
echo "pg_agent_gate $(sed -nE 's/^version = "([^"]+)"/\1/p' Cargo.toml | head -1) against $("$PG_CONFIG" --version)"
echo "logs: $LOG"

echo -n "building the release artifact ... "
if ! bash tests/cluster.sh package >"$LOG/package.log" 2>&1; then
    echo "FAILED"; tail -20 "$LOG/package.log"; exit 1
fi
echo "ok"

trap 'bash tests/cluster.sh stop fast >/dev/null 2>&1 || true' EXIT
bash tests/cluster.sh init >"$LOG/cluster.log" 2>&1 \
    && bash tests/cluster.sh start >>"$LOG/cluster.log" 2>&1 \
    || { echo "the throwaway cluster did not start:"; tail -20 "$LOG/cluster.log"; exit 1; }

declare -a ROWS
total_ok=0
total_fail=0
failed=0

record() {  # name status checks_ok checks_failed summary
    ROWS+=("$(printf '  %-14s %-7s %5s %6s   %s' "$1" "$2" "$3" "$4" "$5")")
}

# Each step says it started and how it ended. The first version printed nothing between
# "building the release artifact ... ok" and the summary, and on a fresh container --
# where the unit tests compile the crate from scratch -- that read as hung (2026-10-06).
for s in "${SUITES[@]}"; do
    out="$LOG/$s.log"
    printf '%-28s' "suite $s ..."
    t0=$SECONDS
    bash "tests/$s.sh" >"$out" 2>&1
    rc=$?
    [ "$rc" -eq 0 ] && echo "ok ($((SECONDS - t0)) s)" || echo "FAILED, exit $rc ($((SECONDS - t0)) s)"

    ok=$(grep -cE '^[[:space:]]+ok[[:space:]]' "$out")
    bad=$(grep -cE '^[[:space:]]+FAIL[[:space:]]' "$out")
    total_ok=$((total_ok + ok))
    total_fail=$((total_fail + bad))
    if [ "$rc" -eq 0 ] && [ "$bad" -eq 0 ]; then
        record "$s" ok "$ok" "$bad" "$(tail -1 "$out" | cut -c1-80)"
    else
        failed=$((failed + 1))
        record "$s" FAILED "$ok" "$bad" "exit $rc -- see $out"
    fi
done

# The unit tests run in pgrx's OWN instance of this major version, which `cargo pgrx init`
# registers. Not registered is a failure with its fix, not a skip.
unit="$LOG/unit.log"
if cargo pgrx info pg-config "pg$MAJOR" >/dev/null 2>&1; then
    printf '%-28s' "unit tests (pgrx) ..."
    echo -n "compiling with pg_test the first time takes minutes ... "
    t0=$SECONDS
    cargo pgrx test "pg$MAJOR" >"$unit" 2>&1
    rc=$?
    [ "$rc" -eq 0 ] && echo "ok ($((SECONDS - t0)) s)" || echo "FAILED, exit $rc ($((SECONDS - t0)) s)"

    passed=$(sed -nE 's/.*test result: [a-zA-Z]+\. ([0-9]+) passed.*/\1/p' "$unit" | tail -1)
    nfail=$(sed -nE 's/.*test result: [a-zA-Z]+\. [0-9]+ passed; ([0-9]+) failed.*/\1/p' "$unit" | tail -1)
    total_ok=$((total_ok + ${passed:-0}))
    total_fail=$((total_fail + ${nfail:-0}))
    if [ "$rc" -eq 0 ]; then
        record "unit (pgrx)" ok "${passed:-0}" "${nfail:-0}" "pg$MAJOR via $(cargo pgrx info pg-config "pg$MAJOR")"
    else
        failed=$((failed + 1))
        record "unit (pgrx)" FAILED "${passed:-0}" "${nfail:-?}" "exit $rc -- see $unit"
    fi
else
    failed=$((failed + 1))
    record "unit (pgrx)" FAILED 0 0 "pgrx has no pg$MAJOR: cargo pgrx init --pg$MAJOR $PG_CONFIG"
fi

if [ "${VERIFY_DRIVERS:-0}" != 1 ]; then
    record "drivers" "not run" - - "opt-in: VERIFY_DRIVERS=1 (needs java, node, network)"
fi

echo
printf '  %-14s %-7s %5s %6s   %s\n' suite result ok failed ""
for r in "${ROWS[@]}"; do echo "$r"; done
echo
if [ "$failed" -eq 0 ]; then
    echo "verified: $total_ok checks passed, 0 failed"
    exit 0
fi
# What failed is printed here and not only named: on a container run with --rm the log
# file is gone with the container, and "see unit.log" pointed at nothing (2026-10-06).
for f in "$LOG"/*.log; do
    case "$(basename "$f" .log)" in package|cluster) continue ;; esac
    if grep -qE '^[[:space:]]+FAIL[[:space:]]|test result: FAILED|^error|panicked' "$f"; then
        echo
        echo "---- last lines of $f"
        grep -E 'FAIL|panicked|error|Error|denied|not found' "$f" | head -15
        tail -15 "$f"
    fi
done
echo
echo "NOT verified: $failed suite(s) failed -- $total_ok checks passed, $total_fail failed"
exit 1

