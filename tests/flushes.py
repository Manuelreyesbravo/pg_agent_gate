#!/usr/bin/env python3
"""How many WAL flushes an act pays -- COUNTED, not inferred from a timing.

The record is most of what an act costs, and the cost of a durable record is a flush: an fsync
of the WAL, 5.1 ms on the btrfs NVMe this was written on, more than all of the gate's own work.
So the durability claims are claims about flushes, and they are checked here by counting them:
the WAL fsyncs of client backends in pg_stat_io, read by a superuser around N acts of a real
agent session (whose statistics reach shared memory when its backend exits).

    fast (default)  an attempt pays no flush of its own: a read act, ~0 per act;
    any setting     a KEPT change always pays its flush -- two calls or one;
    durable         propose + commit pay two (every record its own flush);
                    propose_and_commit pays ONE: proposal and execution ride on one commit.

Each case is N acts with a tolerance of 0.1 per act, so a stray fsync cannot decide a case
while 1 and 2 cannot be confused. The durable two-call case is also the CONTROL of the
instrument: if pg_stat_io did not see this backend's fsyncs, it would read 0 there and fail.

Run by tests/flushes.sh, which prepares the database, the agent and the table.
"""
import os
import sys
import time

import psycopg

HOST, PORT, DB = os.environ["PGHOST"], os.environ["PGPORT"], os.environ["FLUSH_DB"]
SUPERUSER, AGENT = os.environ["SUPERUSER"], os.environ["FLUSH_AGENT_ROLE"]
N = int(os.environ.get("FLUSH_ACTS", "50"))
TOLERANCE = 0.1

READ = "select n from flow where id = $1::int"
WRITE = "update flow set n = n + 1 where id = $1::int"
FSYNCS = ("select coalesce(sum(fsyncs), 0)::bigint from pg_stat_io "
          "where backend_type = 'client backend' and object = 'wal'")


def su():
    return psycopg.connect(host=HOST, port=PORT, dbname=DB, user=SUPERUSER, autocommit=True)


def wal_fsyncs():
    """Read until two reads agree: a backend that just exited may still be flushing its stats."""
    last = None
    for _ in range(50):
        with su() as c:
            now = c.execute(FSYNCS).fetchone()[0]
        if now == last:
            return now
        last = now
        time.sleep(0.2)
    return last


def acts(way, kind):
    sql = READ if kind == "read" else WRITE
    want = "read" if kind == "read" else "kept"
    with psycopg.connect(host=HOST, port=PORT, dbname=DB, user=AGENT, autocommit=True) as a:
        for k in range(N):
            args = (sql, f"flush count {way} {kind}", [str(k % 10 + 1)])
            if way == "two calls":
                p = a.execute("select agent_gate.propose(%s, %s, %s)", args).fetchone()[0]
                got = a.execute("select agent_gate.commit(%s)", (p["proposal"],)).fetchone()[0]["outcome"]
            else:
                got = a.execute("select agent_gate.propose_and_commit(%s, %s, %s)", args).fetchone()[0]["outcome"]
            if got != want:
                raise SystemExit(f"  !! {way} {kind}: act {k} came out {got!r}, not {want!r} -- nothing to count")
    # leaving the block closes the session: the backend exits and its I/O stats are flushed


def per_act(durability, way, kind):
    with su() as c:
        if durability == "durable":
            c.execute(f'alter role "{AGENT}" set agent_gate.attempt_durability = durable')
        else:
            c.execute(f'alter role "{AGENT}" reset agent_gate.attempt_durability')
    before = wal_fsyncs()        # also absorbs the flush of the ALTER ROLE above
    acts(way, kind)
    return (wal_fsyncs() - before) / N


CASES = [  # durability, way, kind, low, high, what it says
    ("fast", "two calls", "read", 0, 0 + TOLERANCE, "a fast read act pays no flush of its own"),
    ("fast", "one call", "read", 0, 0 + TOLERANCE, "a fast read act in one call pays no flush of its own"),
    ("fast", "two calls", "write", 1 - TOLERANCE, 1 + TOLERANCE, "a kept change pays its flush (fast, two calls)"),
    ("fast", "one call", "write", 1 - TOLERANCE, 1 + TOLERANCE, "a kept change pays its flush (fast, one call)"),
    ("durable", "two calls", "read", 2 - TOLERANCE, 2 + TOLERANCE, "durable: propose + commit pay one flush each"),
    ("durable", "one call", "read", 1 - TOLERANCE, 1 + TOLERANCE, "durable: propose_and_commit pays ONE flush"),
    ("durable", "two calls", "write", 2 - TOLERANCE, 2 + TOLERANCE, "durable kept write, two calls: two flushes"),
    ("durable", "one call", "write", 1 - TOLERANCE, 1 + TOLERANCE, "durable kept write in one call: ONE flush"),
]


def main():
    failures = 0
    for durability, way, kind, low, high, what in CASES:
        got = per_act(durability, way, kind)
        ok = low <= got <= high
        failures += not ok
        print(f"  {'ok  ' if ok else 'FAIL'} [flushes] {what}: {got:.2f} per act over {N} "
              f"(expected {low:.1f}..{high:.1f})", flush=True)
    with su() as c:
        c.execute(f'alter role "{AGENT}" reset agent_gate.attempt_durability')
    if failures:
        print(f"{failures} check(s) failed")
        return 1
    print("every act pays the flushes its durability promises, and one call pays one")
    return 0


if __name__ == "__main__":
    sys.exit(main())
