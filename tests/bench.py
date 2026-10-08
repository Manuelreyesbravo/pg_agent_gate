#!/usr/bin/env python3
"""What the gate costs, measured so anyone can repeat it: `make bench PG_CONFIG=...`

Four numbers, each against the threshold it was declared with BEFORE the code existed:

  1. extra time per READ act (propose + commit) over the same query run directly;
  2. extra time per kept WRITE (propose + commit) over the same UPDATE run directly,
     which pays its own durable commit;
  3. throughput lost by sessions that are NOT agents when the library is preloaded
     (pgbench -S), which is what every other session of the server pays;
  4. extra time per read act with attempt_durability = durable;
  5. the same, done in ONE call (propose_and_commit): one transaction, one flush instead of two.

FAIRNESS, because a benchmark of a guard is easy to make flattering:
  * "directly" means an IDENTICAL role -- same grants, same database, same statement,
    same parameters -- that is simply not registered as an agent. Not a superuser.
  * every iteration measures both paths back to back and alternates which goes first,
    so drift (thermal, other processes) does not always fall on the same side;
  * the throughput test runs pairs of (preloaded, bare) restarts of the same cluster,
    alternating order, and reports the MEDIAN loss across pairs, with every pair shown;
  * nothing is discarded, and the cost is explained, not hidden: most of what a client
    sees is the record -- two commits per act -- which is the point of the gate.

Everything runs on the throwaway cluster of tests/cluster.sh. Needs psycopg 3:
`make bench` uses `uv run --with psycopg[binary]` when uv exists, else python3.

Environment: PG_CONFIG, ITER (default 300), PAIRS (7), SECONDS (15), GATE_PORT (5499).
"""

from __future__ import annotations

import json
import os
import platform
import random
import re
import statistics
import subprocess
import sys
import time
from pathlib import Path

import psycopg

ROOT = Path(__file__).resolve().parent.parent
PG_CONFIG = os.environ.get("PG_CONFIG", "pg_config")
BIN = subprocess.run([PG_CONFIG, "--bindir"], capture_output=True, text=True, check=True).stdout.strip()
PORT = os.environ.get("GATE_PORT", "5499")
HOST = str(ROOT / ".testcluster")
USER = os.environ.get("USER") or subprocess.run(["id", "-un"], capture_output=True, text=True).stdout.strip()
ITER = int(os.environ.get("ITER", "300"))
PAIRS = int(os.environ.get("PAIRS", "7"))
SECONDS = int(os.environ.get("SECONDS", "15"))
DB, AGENT, DIRECT = "gate_bench", "bench_agent", "bench_direct"
OUT = ROOT / "target" / "bench"

READ = "select abalance from pgbench_accounts where aid = $1::int"
WRITE = "update pgbench_accounts set abalance = abalance + 1 where aid = $1::int"
THRESHOLDS = {"read": 10.0, "write": 5.0, "non_agent_pct": 3.0, "durable_read": 10.0, "durable_one_call": 10.0}


def cluster(*args: str, check: bool = True) -> None:
    env = dict(os.environ, PG_CONFIG=PG_CONFIG)
    subprocess.run(["bash", str(ROOT / "tests" / "cluster.sh"), *args], check=check, env=env,
                   capture_output=True)



def conn(user: str, db: str = DB, **kw) -> psycopg.Connection:
    return psycopg.connect(host=HOST, port=PORT, dbname=db, user=user, autocommit=True, **kw)


def wait_up() -> None:
    end = time.time() + 30
    while time.time() < end:
        try:
            with conn(USER, "postgres", connect_timeout=2):
                return
        except psycopg.OperationalError:
            time.sleep(0.2)
    raise RuntimeError("the throwaway cluster did not come up")


def start(mode: str) -> None:
    cluster("stop", "fast", check=False)  # right after init there is nothing to stop

    cluster("start", mode)
    wait_up()
    with conn(USER, "postgres") as c:
        got = c.execute("show shared_preload_libraries").fetchone()[0]
    want = "pg_agent_gate" if mode == "preload" else ""
    if got != want:
        raise RuntimeError(f"asked for {mode}, server says shared_preload_libraries='{got}'")


def setup() -> None:
    with conn(USER, "postgres") as c:
        c.execute(f"create database {DB}")
        for r in (AGENT, DIRECT):
            c.execute(f"create role {r} login")
    subprocess.run([f"{BIN}/pgbench", "-h", HOST, "-p", PORT, "-U", USER, "-i", "-q", "-s", "10", DB],
                   check=True, capture_output=True)
    with conn(USER) as c:
        c.execute("create extension pg_agent_gate")
        for r in (AGENT, DIRECT):
            c.execute(f"grant select, update on pgbench_accounts to {r}")
        c.execute("select agent_gate.register_agent('bench', %s::regrole, 'measures the cost of the gate', 1000)",
                  (AGENT,))


def timed(f) -> float:
    t0 = time.perf_counter()
    f()
    return (time.perf_counter() - t0) * 1000


def act(a: psycopg.Connection, sql: str, aid: int, intent: str) -> None:
    p = a.execute("select agent_gate.propose(%s, %s, %s)", (sql, intent, [str(aid)])).fetchone()[0]
    if not p.get("ok"):
        raise RuntimeError(f"a correct proposal was refused: {p}")
    r = a.execute("select agent_gate.commit(%s)", (p["proposal"],)).fetchone()[0]
    if r.get("outcome") not in ("read", "kept"):
        raise RuntimeError(f"the act did not complete: {r}")


def act_one_call(a: psycopg.Connection, sql: str, aid: int, intent: str) -> None:
    r = a.execute("select agent_gate.propose_and_commit(%s, %s, %s)", (sql, intent, [str(aid)])).fetchone()[0]
    if r.get("outcome") not in ("read", "kept"):
        raise RuntimeError(f"the one-call act did not complete: {r}")


def direct(d: psycopg.Connection, sql: str, aid: int) -> None:
    cur = d.execute(sql.replace("$1::int", "%s"), (aid,))
    if cur.description:
        cur.fetchall()


def paired(sql: str, intent: str, how=act) -> dict:
    """ITER iterations, gate and direct back to back, order alternating."""
    extra, gate_ms, direct_ms = [], [], []
    with conn(AGENT) as a, conn(DIRECT) as d:
        for _ in range(20):  # warm both paths, caches and plans
            aid = random.randint(1, 1_000_000)
            how(a, sql, aid, "warm up")
            direct(d, sql, aid)
        for i in range(ITER):
            aid = random.randint(1, 1_000_000)
            if i % 2 == 0:
                g = timed(lambda: how(a, sql, aid, intent))
                x = timed(lambda: direct(d, sql, aid))
            else:
                x = timed(lambda: direct(d, sql, aid))
                g = timed(lambda: how(a, sql, aid, intent))
            gate_ms.append(g)
            direct_ms.append(x)
            extra.append(g - x)
    with conn(USER) as s:
        server = s.execute(
            "select percentile_cont(0.5) within group (order by e.duration_ms) "
            "from agent_gate_internal.executions e join agent_gate_internal.proposals p on p.id = e.proposal "
            "where p.intent = %s", (intent,)).fetchone()[0]
    q = statistics.quantiles(extra, n=4)
    return {"n": ITER, "extra_median_ms": round(statistics.median(extra), 3),
            "extra_p25_ms": round(q[0], 3), "extra_p75_ms": round(q[2], 3),
            "gate_median_ms": round(statistics.median(gate_ms), 3),
            "direct_median_ms": round(statistics.median(direct_ms), 3),
            "gate_work_in_server_median_ms": round(server or 0, 3)}


def tps() -> float:
    out = subprocess.run([f"{BIN}/pgbench", "-h", HOST, "-p", PORT, "-U", USER, "-n", "-S",
                          "-c", "4", "-j", "4", "-T", str(SECONDS), DB],
                         capture_output=True, text=True, check=True).stdout
    return float(re.search(r"tps = ([0-9.]+)", out).group(1))


def non_agent() -> dict:
    pairs = []
    for i in range(PAIRS):
        order = ("preload", "bare") if i % 2 == 0 else ("bare", "preload")
        got = {}
        for mode in order:
            start(mode)
            got[mode] = tps()
        pairs.append({"order": "/".join(order), "tps_preload": round(got["preload"], 1),
                      "tps_bare": round(got["bare"], 1),
                      "loss_pct": round(100 * (got["bare"] - got["preload"]) / got["bare"], 2)})
    start("preload")
    return {"pairs": pairs, "seconds_each": SECONDS,
            "loss_median_pct": round(statistics.median(p["loss_pct"] for p in pairs), 2)}


def machine() -> dict:
    with conn(USER, "postgres") as c:
        version = c.execute("select version()").fetchone()[0]
        settings = dict(c.execute("select name, setting from pg_settings where name in "
                                  "('synchronous_commit','fsync','wal_sync_method','shared_buffers')").fetchall())
    cpu = next((l.split(":", 1)[1].strip() for l in Path("/proc/cpuinfo").read_text().splitlines()
                if l.startswith("model name")), platform.processor()) if Path("/proc/cpuinfo").exists() else ""
    fs = subprocess.run(["df", "-T", HOST], capture_output=True, text=True).stdout.splitlines()[-1].split()[1]
    return {"postgres": version, "cpu": cpu, "filesystem_of_data_dir": fs, "settings": settings}


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    print(f"pg_agent_gate bench: ITER={ITER} PAIRS={PAIRS} SECONDS={SECONDS}", flush=True)
    cluster("init")
    start("preload")
    setup()
    result = {"machine": machine()}
    print("  read act ...", flush=True)
    result["read"] = paired(READ, "bench read")
    print("  write act ...", flush=True)
    result["write"] = paired(WRITE, "bench write")
    print("  read act with attempt_durability = durable ...", flush=True)
    with conn(USER) as s:
        s.execute(f"alter role {AGENT} set agent_gate.attempt_durability = durable")
    result["durable_read"] = paired(READ, "bench durable read")
    print("  read act with attempt_durability = durable, in one call ...", flush=True)
    result["durable_one_call"] = paired(READ, "bench durable read one call", act_one_call)
    with conn(USER) as s:
        s.execute(f"alter role {AGENT} reset agent_gate.attempt_durability")
    print(f"  sessions that are not agents: {PAIRS} pairs of {SECONDS} s ...", flush=True)
    result["non_agent"] = non_agent()
    cluster("stop", "fast")

    rows = [
        ("extra time per read act over running it directly", "read", "extra_median_ms", "ms"),
        ("extra time per kept write over the same UPDATE directly", "write", "extra_median_ms", "ms"),
        ("throughput lost by sessions that are not agents (pgbench -S)", "non_agent", "loss_median_pct", "%"),
        ("extra time per read act, attempt_durability = durable", "durable_read", "extra_median_ms", "ms"),
        ("extra time per read act, durable, in one call (propose_and_commit)", "durable_one_call", "extra_median_ms", "ms"),
    ]
    key = {"read": "read", "write": "write", "non_agent": "non_agent_pct", "durable_read": "durable_read",
           "durable_one_call": "durable_one_call"}
    lines = ["| what | threshold | measured (median) | verdict |", "|---|---|---|---|"]
    for label, part, field, unit in rows:
        value, limit = result[part][field], THRESHOLDS[key[part]]
        lines.append(f"| {label} | <= {limit} {unit} | **{value} {unit}** | {'meets' if value <= limit else 'FAILS'} |")
    table = "\n".join(lines)
    (OUT / "result.json").write_text(json.dumps(result, indent=2))
    (OUT / "result.md").write_text(table + "\n")
    print()
    print(table)
    print()
    print(f"read act: gate {result['read']['gate_median_ms']} ms vs direct {result['read']['direct_median_ms']} ms; "
          f"the gate's own work inside the server: {result['read']['gate_work_in_server_median_ms']} ms")
    print("non-agent pairs (loss %): " + ", ".join(str(p["loss_pct"]) for p in result["non_agent"]["pairs"]))
    print(f"{result['machine']['postgres'].split(' on ')[0]} · {result['machine']['cpu']} · "
          f"data dir on {result['machine']['filesystem_of_data_dir']}")
    print(f"full result: {OUT / 'result.json'}")


if __name__ == "__main__":
    sys.exit(main())
