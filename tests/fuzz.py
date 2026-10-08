#!/usr/bin/env python3
# Copyright 2026 Manuel Reyes Bravo
# SPDX-License-Identifier: Apache-2.0
#
# Fuzz the gate the way an adversary would, with volume the 164 hand-written attacks do not
# have. Three properties, checked from a superuser's side of the database after every input:
#
#   1. DIRECT EXECUTION CHANGES NOTHING. In an agent session SQL does not execute, only the
#      verbs. So the full fingerprint -- catalog (tables, columns, constraints, triggers,
#      policies), the role's attributes, and EVERY ROW of both tables -- must be IDENTICAL after
#      any statement the agent runs directly.
#   2. A COMMITTED PROPOSAL STAYS IN BOUNDS -- the surface the two 0.2.1 bugs lived on. When
#      propose() accepts a statement, the fuzzer COMMITS it as the agent (whose tenant is set on
#      the role, so a write actually runs under RLS) and checks that the catalog, the role and
#      ANOTHER tenant are untouched and that no more than max_rows rows changed -- where "how many
#      rows changed" is MEASURED by diffing per-row hashes from the superuser, never read from the
#      number the gate reports (the 0.2.1 CTE bug reported 1 while deleting 8). The agent may
#      change its own tenant; that is reset between inputs. A teeth check proves a plain one-row
#      write really commits and is measured as exactly one row, so this oracle cannot pass vacuously.
#   3. propose() REFUSES THE OBVIOUS -- a word-list heuristic. DROP, GRANT, COPY, a second
#      statement, a writing CTE and the like should come back ok:false.
#
# And after every input the server is still alive; if the agent's backend went away the run
# reconnects and counts it. A reconnect is not a failure: an agent is no superuser and has no
# pg_signal_backend, so the only backend it can ever terminate is its own -- benign and expected.
# The failure signal is reaching the server too little (then the run proved nothing), not
# reconnecting.
#
# WHAT THIS DOES NOT CATCH, plainly. The dangerous FUNCTIONS split in two and the gate treats them
# differently (measured directly): the ones the agent may not execute -- the file and large-object
# functions lo_import, lo_export, pg_read_file, pg_stat_file, pg_ls_dir -- fail to plan and are
# REFUSED at propose, which the word list asserts. The ones it may call (pg_sleep,
# pg_terminate_backend, pg_cancel_backend) are ACCEPTED and run at commit, where they abort on a
# privilege or a timeout (pg_terminate_backend -> SQLSTATE 42501, pg_sleep -> 57014) and never
# apply -- bounded by property 2, not refused at propose. What the row/catalog oracle does NOT see:
# a function whose side effect leaves no row in the fingerprinted tables -- pg_notify, nextval,
# pg_advisory_lock -- runs as a "read" and is counted as one. Three teeth checks run first every
# time -- a known change must move the fingerprint, propose() must refuse a known DROP and GRANT,
# and a plain one-row write must commit and measure as exactly one row -- so no oracle passes
# vacuously; and a k=1..8 differential oracle proves the max_rows boundary on each run.
#
#   make fuzz PG_CONFIG=/path/to/pg_config            # default 3000 inputs
#   FUZZ_ITERS=20000 FUZZ_SEED=1 make fuzz            # longer, reproducible
#   FUZZ_NO_GATE=1 make fuzz                          # negative control: no gate, escapes expected
#
# The inputs are generated from dangerous templates, mutations of them, and random bytes, so a
# run is reproducible only with its seed, and it refuses any database not named gate_fuzz unless
# FUZZ_FORCE=1. The seed is printed for a clean or local run, but WITHHELD from the public CI
# output of a run that found a real escape -- there it would be a ready reproducer of a bug that
# is not yet fixed; reproduce locally instead. Facts are measured by the database, never asserted.
import hashlib
import hmac
import os
import random
import re
import sys
from collections import Counter

import psycopg

DSN = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("FUZZ_DSN", "")
AGENT = "fuzz_agent"
ITERS = int(os.environ.get("FUZZ_ITERS", "3000"))
IN_CI = bool(os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS"))
RUN_ID = os.environ.get("GITHUB_RUN_ID", "")
# Where the seed comes from, in order: an explicit FUZZ_SEED always wins (reproducing a known
# run). Otherwise, if a repo SECRET (FUZZ_SEED_KEY) and the CI run id are both present, derive the
# seed as HMAC(secret, run_id): the public log names only the run id, and whoever holds the secret
# recomputes the exact seed -- so a withheld seed still leaves the MAINTAINER a reproducer, not the
# public a ready exploit. Failing both, a random seed (printed, since nothing could recompute it).
_explicit, _key = os.environ.get("FUZZ_SEED"), os.environ.get("FUZZ_SEED_KEY")
if _explicit:
    SEED, SEED_SOURCE = int(_explicit), "explicit"
elif _key and RUN_ID:
    # The full 256-bit digest is the seed: public (run_id, seed) pairs from clean runs then reveal
    # nothing usable about the key, and recovering a random 32-byte key offline is infeasible.
    SEED = int.from_bytes(hmac.new(_key.encode(), RUN_ID.encode(), hashlib.sha256).digest(), "big")
    SEED_SOURCE = "hmac"
else:
    SEED, SEED_SOURCE = random.randrange(1 << 30), "random"
rng = random.Random(SEED)

# Statements an agent must never get to run, directly or through propose(). Each is a thing
# plain SQL can do that the gate exists to stop.
DANGEROUS = [
    "drop table shop.orders",
    "drop table shop.customers cascade",
    "truncate shop.orders",
    "truncate shop.customers, shop.orders",
    "delete from shop.orders",
    "delete from shop.customers",
    "update shop.customers set email = 'x'",
    "alter table shop.orders drop column total",
    "alter table shop.customers add column pwd text",
    "create table shop.evil (x int)",
    "create index on shop.orders (total)",
    "grant all on all tables in schema shop to fuzz_agent",
    "grant fuzz_agent to postgres",
    "alter role fuzz_agent superuser",
    "alter role fuzz_agent createrole",
    "revoke select on shop.orders from fuzz_agent",
    "do $$ begin perform 1; end $$",
    "call nope()",
    "copy shop.orders to stdout",
    "copy shop.orders from stdin",
    "prepare p as select 1",
    "vacuum shop.orders",
    "reindex table shop.orders",
    "cluster shop.orders",
    "comment on table shop.orders is 'x'",
    "alter system set work_mem = '1GB'",
    "set role postgres",
    "reset role",
    "select 1; drop table shop.orders",
    "select 1 \\g drop table shop.orders",
    "with d as (delete from shop.orders returning *) select count(*) from d",
    "with u as (update shop.customers set email='x' returning 1) select * from u",
    "insert into shop.orders select * from shop.orders",
    "update shop.customers set email = 'x' where set_config('app.tenant_id','2',true) is not null",
    "select set_config('app.tenant_id','2',false)",
    "select shop.customers.email from shop.customers where set_config('app.tenant_id','2',true) is null",
    "drop extension pg_agent_gate",
    "alter extension pg_agent_gate update",
    "select pg_catalog.pg_read_file('/etc/passwd')",
    "create function f() returns void language plpgsql as $$ begin end $$",
    "merge into shop.orders using shop.orders s on true when matched then delete",
    "lock shop.orders in access exclusive mode",
    "notify x",
    "listen x",
    # Dangerous FUNCTIONS, two kinds. The agent CANNOT execute the file/large-object ones below
    # (lo_import, lo_export, pg_read_file, pg_stat_file, pg_ls_dir), so the gate refuses them at
    # propose -- DANGER_WORDS asserts that. The ones it CAN call (pg_sleep, pg_terminate_backend,
    # pg_cancel_backend) are accepted and exercised at commit, where they abort (permission or
    # timeout), bounded by the agent's own privileges -- never refused at propose.
    "select pg_terminate_backend(pid) from pg_stat_activity",
    "select pg_cancel_backend(pid) from pg_stat_activity",
    "select pg_sleep(10)",
    "select lo_import('/etc/passwd')",
    "select lo_export(1, '/tmp/x')",
    "select pg_read_file('/etc/passwd')",
    "select pg_stat_file('/etc/passwd')",
    "select pg_ls_dir('/')",
]

# A few legitimate statements: the agent still cannot run these DIRECTLY (the gate blocks all
# direct execution), but propose() should ACCEPT them -- so they must not count as a refusal
# bug, only as "did direct execution stay inert".
SAFE_DML = [
    "update shop.customers set email = 'a@b.example' where id = 1",
    "delete from shop.orders where id = 1",
    "insert into shop.customers (id, tenant, name, email) values (99, 1, 'z', 'z@one.example')",
    "select count(*) from shop.orders",
]

SNIPPETS = ["shop.orders", "shop.customers", "set_config", "app.tenant_id", "drop", "--",
            "/*", "*/", ";", "$$", "\\g", "returning", "with", "'", '"', "\x00", "superuser",
            "pg_", "0x", "\\x", "union", "::regrole", "()", "\n", "\t", chr(0x1b)]


def mutate(s):
    for _ in range(rng.randint(1, 4)):
        k = rng.random()
        if k < 0.25 and len(s) > 1:          # cut a slice
            i = rng.randrange(len(s)); s = s[:i] + s[i + rng.randint(1, 5):]
        elif k < 0.5:                        # splice in a snippet
            i = rng.randrange(len(s) + 1); s = s[:i] + rng.choice(SNIPPETS) + s[i:]
        elif k < 0.7:                        # duplicate the statement
            s = s + rng.choice(["; ", " ", "\n"]) + s
        elif k < 0.85 and len(s) > 1:        # flip a byte to junk
            i = rng.randrange(len(s)); s = s[:i] + chr(rng.randint(1, 0x10FFFF)) + s[i + 1:]
        else:                                # change case
            s = s.swapcase()
    return s


def gen():
    k = rng.random()
    if k < 0.45:
        return rng.choice(DANGEROUS)
    if k < 0.80:
        return mutate(rng.choice(DANGEROUS + SAFE_DML))
    if k < 0.90:
        return "".join(rng.choice(SNIPPETS) for _ in range(rng.randint(1, 30)))
    return bytes(rng.randrange(256) for _ in range(rng.randint(0, 64))).decode("latin-1")


# Words whose presence makes an input one the gate MUST refuse at propose. MERGE, UPDATE, DELETE
# and INSERT are deliberately absent: they are the data changes the gate exists to allow (bounded
# by max_rows at commit), not refuse. So are "superuser" and "function": gaining superuser or
# defining a function is always an ALTER, CREATE or DROP -- already listed -- so as bare words they
# would only match a harmless identifier (a column or alias named "superuser"/"function"), the
# false positive the parse-tree gate does not make (e.g. `select pg_sleep(10) superuser`).
DANGER_WORDS = ("drop", "truncate", "alter", "create", "grant", "revoke", "copy", "do ",
                "call", "prepare", "vacuum", "reindex", "cluster", "comment", "lock",
                "listen", "notify", "set_config", "set role", "reset", "security", "extension",
                "pg_read_file", "pg_stat_file", "pg_ls", "lo_import", "lo_export")


def looks_dangerous(s):
    # Classify on the statement with its SQL comments AND string literals removed: a dangerous
    # word inside a comment or a string (an email 'zsuperuser@x', the text 'drop it') is inert,
    # and the gate -- which judges the parsed tree, not the text -- correctly allows it. Matching
    # the raw text would be a false positive, the naive mistake the gate does not make.
    stripped = re.sub(r"--[^\n]*", " ", s)
    stripped = re.sub(r"/\*.*?\*/", " ", stripped, flags=re.S)
    stripped = re.sub(r"\$\$.*?\$\$", " ", stripped, flags=re.S)   # dollar-quoted strings
    stripped = re.sub(r"'(?:[^']|'')*'", " ", stripped)            # single-quoted strings
    low = stripped.lower()
    if ";" in stripped.strip().rstrip(";"):   # more than one statement
        return True
    if "with" in low and ("delete" in low or "update" in low or "insert" in low):
        return True
    return any(w in low for w in DANGER_WORDS)


SCHEMA = """
drop schema if exists shop cascade;
create schema shop authorization fuzz_agent;
create table shop.customers (id int primary key, tenant int not null, name text, email text);
create table shop.orders (id int primary key, tenant int not null, customer int references shop.customers(id) on delete cascade, total numeric);
insert into shop.customers values (1,1,'Ana','ana@one.example'),(2,1,'Bruno','bruno@one.example'),
                                  (3,2,'Iris','iris@two.example'),(4,2,'Juan','juan@two.example');
insert into shop.orders select g,1,1+g%2,g*10 from generate_series(1,8) g;
-- A TENANT-2 child of a TENANT-1 parent. Deleting customer 1 cascades into this tenant-2 row (the
-- breach fixed in 0.2.2), so the gate must refuse the corpus `delete from shop.customers` at
-- propose. If it ever stops refusing, this row moves and safe_fp (tenant 2) catches it.
insert into shop.orders values (9, 2, 1, 90);
alter table shop.customers enable row level security; alter table shop.customers force row level security;
alter table shop.orders enable row level security;    alter table shop.orders force row level security;
-- USING alone: for an ALL policy Postgres reuses it as the write check, so a cross-tenant INSERT/UPDATE is refused too (same shape as tests/rls_isolation.sh).
create policy t on shop.customers using (tenant = current_setting('app.tenant_id')::int);
create policy t on shop.orders    using (tenant = current_setting('app.tenant_id')::int);
alter table shop.customers owner to fuzz_agent; alter table shop.orders owner to fuzz_agent;
"""

# The catalog and the role: these must NEVER change from anything an agent does -- directly
# or through a committed proposal. (No DDL, no new grant, no superuser.)
_CATALOG_ROLE = """
  select 'c:'||relname||':'||relkind::text from pg_class join pg_namespace n on n.oid=relnamespace where nspname='shop'
  union all select 'a:'||attrelid::regclass::text||':'||attname||':'||atttypid::regtype::text
             from pg_attribute where attrelid in (select c.oid from pg_class c join pg_namespace n on n.oid=c.relnamespace where nspname='shop') and attnum>0 and not attisdropped
  union all select 'k:'||conname||':'||contype::text from pg_constraint where connamespace=(select oid from pg_namespace where nspname='shop')
  union all select 'g:'||tgname from pg_trigger where tgrelid in (select c.oid from pg_class c join pg_namespace n on n.oid=c.relnamespace where nspname='shop')
  union all select 'p:'||polname from pg_policy
  union all select 'r:'||rolname||':'||rolsuper::text||':'||rolcreaterole::text||':'||rolcreatedb::text from pg_roles where rolname='fuzz_agent'
  union all select 'm:'||r.rolname from pg_auth_members am join pg_roles m on m.oid=am.member join pg_roles r on r.oid=am.roleid where m.rolname='fuzz_agent'
"""
# All rows of both tables. The agent MAY change its own tenant's rows (a committed write within
# max_rows), so the FULL fingerprint is for direct execution, where nothing may change at all.
_ALL_DATA = """
  union all select 'd:customers:'||coalesce(string_agg(
      c.id||':'||c.tenant||':'||coalesce(c.name,'')||':'||coalesce(c.email,''), '|' order by c.id), '') from shop.customers c
  union all select 'd:orders:'||coalesce(string_agg(
      o.id||':'||o.tenant||':'||coalesce(o.customer::text,'')||':'||coalesce(o.total::text,''), '|' order by o.id), '') from shop.orders o
"""
# Only ANOTHER tenant's rows. A committed proposal must never touch tenant 2.
_SAFE_DATA = """
  union all select 'd2:customers:'||coalesce(string_agg(
      c.id||':'||c.tenant||':'||coalesce(c.name,'')||':'||coalesce(c.email,''), '|' order by c.id), '') from shop.customers c where c.tenant=2
  union all select 'd2:orders:'||coalesce(string_agg(
      o.id||':'||o.tenant||':'||coalesce(o.customer::text,'')||':'||coalesce(o.total::text,''), '|' order by o.id), '') from shop.orders o where o.tenant=2
"""
FULL_FP = "select md5(string_agg(x, '|' order by x)) from (" + _CATALOG_ROLE + _ALL_DATA + ") s(x)"
SAFE_FP = "select md5(string_agg(x, '|' order by x)) from (" + _CATALOG_ROLE + _SAFE_DATA + ") s(x)"
MAX_ROWS = 5

# Per-row state from the SUPERUSER's side (a superuser is not subject to RLS): primary key -> a
# hash of the whole row, for both tables. How many rows a committed proposal ACTUALLY changed is
# measured by diffing two of these -- keys whose hash moved, plus removed, plus added -- never
# taken from the gate's own rows_affected (the 0.2.1 CTE bug reported 1 while deleting 8).
ROW_STATE = """
  select 'c:'||id, md5(coalesce(tenant::text,'~')||'|'||coalesce(name,'~')||'|'||coalesce(email,'~')) from shop.customers
  union all
  select 'o:'||id, md5(coalesce(tenant::text,'~')||'|'||coalesce(customer::text,'~')||'|'||coalesce(total::text,'~')) from shop.orders
"""

# The dangerous functions the gate ACCEPTS at propose (the agent may execute them): they run at
# COMMIT, where they must abort (permission, timeout) or run as a harmless read, never apply a
# change. The file/large-object ones (lo_import, pg_read_file, ...) are NOT here: the agent cannot
# execute them, so they are refused at propose (asserted by DANGER_WORDS) and never reach commit.
DANGER_FN_RE = re.compile(r"pg_sleep|pg_terminate_backend|pg_cancel_backend", re.I)


def main():
    if not DSN:
        sys.exit("need a superuser DSN as argv[1] or FUZZ_DSN")
    # The seed is withheld from the START line in CI: whether this run found a real escape is not
    # known yet, and in CI the log is public. A clean run's seed is added to the summary at the end.
    print(f"fuzzing pg_agent_gate: {ITERS} inputs" + ("" if IN_CI else f", seed {SEED}"))
    if IN_CI and SEED_SOURCE == "random" and ITERS > 0:
        # Without the key the seed is random, and an escape's seed would be withheld with nothing
        # to recompute it from. Warn loudly rather than fail -- a fork lacks the secret by design.
        print("WARNING: FUZZ_SEED_KEY is not set; the seed is random. If this run finds an escape "
              "its seed is withheld and NOT reproducible. Set the repo secret to make it recoverable.")
    su = psycopg.connect(DSN, autocommit=True)

    # This is destructive -- it drops schema shop and the role fuzz_agent. Refuse any database
    # not named gate_fuzz unless forced, so a stray DSN cannot wipe a real schema.
    db = su.execute("select current_database()").fetchone()[0]
    if db != "gate_fuzz" and not os.environ.get("FUZZ_FORCE"):
        sys.exit(f"refusing to fuzz database {db!r}: this drops schema shop and the role {AGENT}. "
                 "Use a throwaway named 'gate_fuzz', or set FUZZ_FORCE=1 if you are sure.")

    def run_schema():
        for stmt in SCHEMA.split(";"):
            if stmt.strip():
                su.execute(stmt)

    su.execute(f"drop role if exists {AGENT}")  # noqa: S608 -- fixed identifier
    su.execute(f"create role {AGENT} login")
    su.execute(f"alter role {AGENT} set statement_timeout = '2000'")  # so a pg_sleep cannot hang the run
    su.execute(f"alter role {AGENT} set app.tenant_id = '1'")  # its tenant, set ON THE ROLE -- the ordinary multi-tenant setup (tests/rls_isolation.sh). Without it a committed DML errors under RLS and nothing would change.
    su.execute("create extension if not exists pg_agent_gate")
    run_schema()
    # FUZZ_NO_GATE leaves the role an ordinary owner (not an agent): a negative control where
    # escapes are EXPECTED, so without the gate a clean run is the failure.
    gate_on = not os.environ.get("FUZZ_NO_GATE")
    if gate_on:
        su.execute(f"select agent_gate.register_agent('fuzzer', '{AGENT}', 'fuzz target', p_max_rows => {MAX_ROWS})")
    else:
        print("NEGATIVE CONTROL: no gate -- escapes are expected")

    def full_fp():
        try:
            return su.execute(FULL_FP).fetchone()[0]
        except psycopg.Error:
            return None   # a catastrophic change -- e.g. a table the fingerprint reads was dropped

    def safe_fp():
        try:
            return su.execute(SAFE_FP).fetchone()[0]
        except psycopg.Error:
            return None

    def alive():
        try:
            return su.execute("select 1").fetchone()[0] == 1
        except psycopg.Error:
            return False

    def row_state():
        try:
            return dict(su.execute(ROW_STATE).fetchall())
        except psycopg.Error:
            return None   # a table the snapshot reads was dropped -- a catastrophic change

    def rows_changed(before, after):
        # Distinct rows that differ between two snapshots: modified + removed + added. A snapshot
        # that could not be read (None) means the world changed catastrophically -- count it as
        # over the limit so it is never mistaken for "nothing moved".
        if before is None or after is None:
            return MAX_ROWS + 1
        n = sum(1 for k, h in after.items() if before.get(k) != h)
        n += sum(1 for k in before if k not in after)
        return n

    baseline = full_fp()
    max_rows_oracle_fails = []   # exact k-sweep differential oracle (filled in the teeth phase)

    # Prove BOTH oracles have teeth every run. (a) The fingerprint must move for a known data
    # change and a known DDL, and come back. (b) propose() must actually REFUSE a known-dangerous
    # statement -- otherwise property 2 is vacuous and a gate that stopped refusing would pass.
    if gate_on:
        su.execute("update shop.customers set email = email || '.teeth' where id = 1")
        saw_update = full_fp() != baseline
        su.execute("update shop.customers set email = replace(email, '.teeth', '') where id = 1")
        restored = full_fp() == baseline
        su.execute("create table shop.teeth_check (x int)")
        saw_ddl = full_fp() != baseline
        su.execute("drop table shop.teeth_check")
        if not (saw_update and restored and saw_ddl and full_fp() == baseline):
            sys.exit("the fingerprint is BLIND: a known change did not move it -- the oracle has no teeth")
        probe = psycopg.connect(DSN, user=AGENT, autocommit=True)
        for danger in ("drop table shop.orders", "grant all on shop.orders to fuzz_agent"):
            r = probe.execute("select agent_gate.propose(%s, %s)", (danger, "teeth")).fetchone()[0]
            if not (isinstance(r, dict) and r.get("ok") is False):
                sys.exit(f"propose() did NOT refuse {danger!r} -- property 2 has no teeth")
        # (c) a plain one-row write must actually COMMIT and be MEASURED as exactly one row --
        # otherwise the commit path never runs under RLS (no tenant on the role) and the max_rows
        # oracle, measured or not, would pass vacuously on every proposal.
        before = row_state()
        # orders, not customers: customers is now referenced by a cascading FK, so a write to it is
        # (correctly) refused. orders is referenced by nothing, so a one-row write to it is allowed.
        r = probe.execute("select agent_gate.propose(%s, %s)",
                          ("update shop.orders set total = total + 1 where id = 1", "teeth")).fetchone()[0]
        if not (isinstance(r, dict) and r.get("ok") is True and r.get("proposal") is not None):
            sys.exit("propose() refused a plain one-row UPDATE -- cannot exercise the commit path")
        probe.execute("select agent_gate.commit(%s)", (r["proposal"],))
        moved = rows_changed(before, row_state())
        if moved != 1:
            sys.exit(f"a committed one-row UPDATE was measured as {moved} rows, not 1 -- the commit "
                     "oracle is blind (tenant context on the role? RLS?)")
        # (d) an EXACT differential oracle for the two 0.2.1 surfaces, for a known count k and the
        # agent's own tenant (orders are all tenant 1), every k from 1 to 8 -- nothing random, so
        # the boundary is proved each run instead of waiting for the generator to stumble onto it.
        # A plain write (update, insert) must be KEPT and move exactly k at k <= MAX_ROWS, and ABORT
        # and move 0 above it. A data-modifying CTE must be REFUSED outright and never apply at any
        # k -- that is the other 0.2.1 fix, and a CTE that got kept would be its regression.
        for k in range(1, 9):
            for name, tmpl, is_cte in (
                    ("update", "update shop.orders set total = total + 1 where id <= {k}", False),
                    ("delete", "delete from shop.orders where id <= {k}", False),
                    ("insert", "insert into shop.orders select 100+g, 1, 1, g from generate_series(1,{k}) g", False),
                    ("upsert", "insert into shop.orders select 100+g, 1, 1, g from generate_series(1,{k}) g on conflict (id) do update set total = excluded.total", False),
                    ("update-from", "update shop.orders o set total = total + 1 from shop.customers c where c.id = o.customer and o.id <= {k}", False),
                    ("cte-delete", "with d as (delete from shop.orders where id <= {k} returning 1) select count(*) from d", True)):
                run_schema()
                before = row_state()
                pr = probe.execute("select agent_gate.propose(%s, %s)", (tmpl.format(k=k), "k-sweep")).fetchone()[0]
                outcome = "not-committed"
                if isinstance(pr, dict) and pr.get("ok") is True and pr.get("proposal") is not None:
                    cr = probe.execute("select agent_gate.commit(%s)", (pr["proposal"],)).fetchone()[0]
                    outcome = cr.get("outcome") if isinstance(cr, dict) else "?"
                moved = rows_changed(before, row_state())
                if is_cte:
                    if outcome == "kept" or moved != 0:
                        max_rows_oracle_fails.append(f"k={k} {name}: a writing CTE applied (outcome={outcome} moved={moved}) -- it must be refused")
                elif k <= MAX_ROWS:
                    if not (outcome == "kept" and moved == k):
                        max_rows_oracle_fails.append(f"k={k} {name}: expected kept & {k} rows, got outcome={outcome} moved={moved}")
                else:
                    if outcome == "kept" or moved != 0:
                        max_rows_oracle_fails.append(f"k={k} {name}: expected abort & 0 rows, got outcome={outcome} moved={moved}")
        # (e) anything whose effect the gate cannot see or bound must be REFUSED at propose: an
        # inbound cascading FK or a user trigger (0.2.2 -- the referential action ran as the owner
        # outside RLS and deleted a tenant-2 child), and a user function that is volatile or SECURITY
        # DEFINER (0.2.3 -- an opaque body may write uncounted or run as its owner). Build each and
        # assert refusal.
        run_schema()
        su.execute("create table shop.child (id int primary key, parent int references shop.customers(id) on delete cascade)")
        su.execute("create function shop.tf() returns trigger language plpgsql as $$ begin return new; end $$")
        su.execute("create trigger ct after insert on shop.child for each row execute function shop.tf()")
        su.execute("create function shop.wf() returns int language plpgsql volatile as $$ begin insert into shop.orders values (501,1,1,1); return 1; end $$")
        su.execute("create function shop.sd() returns int language sql security definer as $$ select 1 $$")
        su.execute(f"grant execute on function shop.wf(), shop.sd() to {AGENT}")
        for why, danger in (("inbound cascade", "delete from shop.customers where id = 1"),
                            ("user trigger", "insert into shop.child values (1, 1)"),
                            ("opaque volatile function", "select shop.wf()"),
                            ("security definer function", "select shop.sd()")):
            pr = probe.execute("select agent_gate.propose(%s, %s)", (danger, "amplification check")).fetchone()[0]
            if isinstance(pr, dict) and pr.get("ok") is True:
                max_rows_oracle_fails.append(f"amplification ({why}): propose ACCEPTED {danger!r} -- it must be refused")
        # the allow-list must NOT reopen the 0.2.2 breach: a cascade into an RLS child runs as the
        # table owner outside RLS, so it is unsafe even when the parent is allow-listed. orders (the
        # cascade child of customers) has RLS, so delete-from-customers STAYS refused after allow_write.
        su.execute("select agent_gate.allow_write('fuzzer', 'shop.customers', 'must not make a cross-tenant cascade safe')")
        pr = probe.execute("select agent_gate.propose(%s, %s)",
                           ("delete from shop.customers where id = 1", "amplification check")).fetchone()[0]
        if isinstance(pr, dict) and pr.get("ok") is True:
            max_rows_oracle_fails.append("allow-list reopened the breach: a cascade into an RLS child was ACCEPTED after allow_write")
        su.execute("select agent_gate.disallow_write('fuzzer', 'shop.customers')")
        # (f) allow_write relaxes propose for a table with a legitimate (updated_at-style) trigger,
        # but the commit backstop still bounds the TOTAL rows the trigger moves: with MAX_ROWS=5,
        # k=2 is 2 updates + 2 trigger inserts = 4 (kept), k=3 is 6 (aborted by the backstop).
        su.execute("create table shop.log (id serial primary key, m text)")
        su.execute("create table shop.items (id int primary key, t int not null, n int)")
        su.execute("insert into shop.items select g, 1, g from generate_series(1,8) g")
        su.execute("create function shop.au() returns trigger language plpgsql as $$ begin insert into shop.log(m) values ('u'); return new; end $$")
        su.execute("create trigger au after update on shop.items for each row execute function shop.au()")
        su.execute(f"alter table shop.log owner to {AGENT}")
        su.execute(f"alter table shop.items owner to {AGENT}")
        su.execute("select agent_gate.allow_write('fuzzer', 'shop.items', 'audit trigger is fine')")
        for k, want in ((2, "kept"), (3, "aborted")):
            pr = probe.execute("select agent_gate.propose(%s, %s)",
                               (f"update shop.items set n = n + 1 where id <= {k}", "backstop check")).fetchone()[0]
            got = "refused-at-propose"
            if isinstance(pr, dict) and pr.get("ok") is True and pr.get("proposal") is not None:
                cr = probe.execute("select agent_gate.commit(%s)", (pr["proposal"],)).fetchone()[0]
                got = cr.get("outcome") if isinstance(cr, dict) else "?"
            if got != want:
                max_rows_oracle_fails.append(f"backstop/allow-list k={k}: expected {want}, got {got}")
        su.execute("select agent_gate.disallow_write('fuzzer', 'shop.items')")
        # a SECURITY DEFINER trigger is NOT allow-listable (it runs as its owner): even allow-listed,
        # a write to its table stays refused.
        su.execute("create table shop.sditems (id int primary key, n int)")
        su.execute("insert into shop.sditems values (1, 1)")
        su.execute("create function shop.ausd() returns trigger language plpgsql security definer as $$ begin insert into shop.log(m) values ('sd'); return new; end $$")
        su.execute("create trigger ausd after update on shop.sditems for each row execute function shop.ausd()")
        su.execute(f"alter table shop.sditems owner to {AGENT}")
        su.execute("select agent_gate.allow_write('fuzzer', 'shop.sditems', 'should NOT help: trigger is SECURITY DEFINER')")
        pr = probe.execute("select agent_gate.propose(%s, %s)",
                           ("update shop.sditems set n = n + 1 where id = 1", "backstop check")).fetchone()[0]
        if isinstance(pr, dict) and pr.get("ok") is True:
            max_rows_oracle_fails.append("allow-list accepted a SECURITY DEFINER trigger table -- it must stay refused")
        su.execute("select agent_gate.disallow_write('fuzzer', 'shop.sditems')")
        # (g) an amplifier on an INHERITANCE CHILD or a RULE refuses a write to the table, and
        # discover agrees with propose (both go through _unsafe_amplifier).
        run_schema()
        su.execute("create table shop.par (id int primary key, t int not null)")
        su.execute("create table shop.kid (primary key (id)) inherits (shop.par)")
        su.execute("create function shop.kt() returns trigger language plpgsql as $$ begin return new; end $$")
        su.execute("create trigger kt before insert or update or delete on shop.kid for each row execute function shop.kt()")
        su.execute("create table shop.rlog (x int)")
        su.execute("create table shop.ruled (id int primary key, t int not null)")
        su.execute("create rule r as on update to shop.ruled do also insert into shop.rlog values (1)")
        su.execute("create table shop.plainz (id int primary key, t int not null)")
        for tbl in ("par", "kid", "rlog", "ruled", "plainz"):
            su.execute(f"alter table shop.{tbl} owner to {AGENT}")
        want = {# update/delete on an inheritance parent DOES reach kid's rows, so kid's
                # trigger genuinely fires -- the gate refuses, and the amplification is real.
                "update shop.par set t = t": False,
                "delete from shop.par": False,
                # conservative over-refusal: in CLASSIC inheritance an INSERT to the parent is
                # not routed down to kid, so kid's trigger would not fire -- the gate refuses
                # anyway, because kid (an inheritance child) carries a trigger and the walker
                # does not match the trigger's event to the statement. With a PARTITIONED parent
                # an INSERT WOULD route to a partition and fire it, so there it is not merely
                # conservative.
                "insert into shop.par values (1,1)": False,
                "update shop.ruled set t = t": False,           # has a DO ALSO rule
                "insert into shop.plainz values (1,1)": True}   # nothing on it
        for sql, want_ok in want.items():
            pr = probe.execute("select agent_gate.propose(%s, %s)", (sql, "parity check")).fetchone()[0]
            if (isinstance(pr, dict) and pr.get("ok") is True) != want_ok:
                max_rows_oracle_fails.append(f"parity propose {sql!r}: expected ok={want_ok}")
        disc = probe.execute("select agent_gate.discover(%s)", ("shop",)).fetchone()[0]
        refused = {r["relation"].split(".")[-1].strip('"')
                   for r in (disc.get("relations") or []) if r.get("write_refused")}
        for tbl, should in (("par", True), ("ruled", True), ("plainz", False)):
            if (tbl in refused) != should:
                max_rows_oracle_fails.append(f"parity discover shop.{tbl}: write_refused={tbl in refused}, expected {should}")
        run_schema(); baseline = full_fp()
        probe.close()

    agent = [psycopg.connect(DSN, user=AGENT, autocommit=True)]

    def reconnect():
        try:
            agent[0].close()
        except Exception:
            pass
        agent[0] = psycopg.connect(DSN, user=AGENT, autocommit=True)

    # Escapes, kept in separate buckets so the category survives into the CI summary even when the
    # inputs are hidden there. propose/commit splits three ways: the word list should have refused,
    # a commit that moved protected state, and a commit over max_rows (the measured check).
    # accepted/committed count how much the run actually exercised the two verbs.
    direct_bypass, crashes = [], []
    word_miss, protected, over_rows = [], [], []
    reached = client_rejected = reconnects = accepted = 0
    # commit() never raises on a bad statement -- it catches PostgreSQL's error and returns an
    # outcome ("kept" applied a write, "read" ran a read, "aborted" ran and PostgreSQL raised,
    # "refused" the gate stopped it). Count those, and separately the dangerous FUNCTIONS, so the
    # run shows they abort or read -- never "kept" -- instead of hiding behind one total.
    outcomes = Counter()
    danger_outcomes = Counter()
    danger_sqlstate = Counter()   # SQLSTATE of aborted dangerous-function commits: 42501
                                  # (insufficient_privilege) is the win, 57014 a timeout
    danger_kept = []              # a dangerous FUNCTION that APPLIED a change -- a real escape
    for i in range(ITERS):
        payload = gen()

        # 1. direct execution must change nothing. Count whether it reached the server, and if
        #    the agent's own backend went away, reconnect so later iterations still test.
        try:
            with agent[0].cursor() as c:
                c.execute(payload)
                reached += 1
                try:
                    c.fetchall()
                except psycopg.Error:
                    pass
        except psycopg.OperationalError:
            reconnects += 1; reconnect()        # the backend went away (e.g. terminated)
        except psycopg.Error:
            reached += 1                         # the server rejected it -- it still saw it
        except Exception:
            client_rejected += 1                 # psycopg refused to send it (e.g. a NUL byte)
        if not alive():
            crashes.append(payload); break
        if full_fp() != baseline:
            direct_bypass.append(payload)
            run_schema(); baseline = full_fp()  # restore and keep going

        # 2. propose() must refuse the dangerous (a word-list heuristic), and -- the surface the
        #    0.2.1 bugs actually lived on -- a proposal that IS accepted must, once COMMITTED,
        #    leave the catalog, the role and another tenant untouched and touch no more than
        #    max_rows rows. The agent may change its OWN tenant, so that is reset afterwards.
        pid = None
        try:
            with agent[0].cursor() as c:
                result = c.execute("select agent_gate.propose(%s, %s)", (payload, "fuzz")).fetchone()[0]
            ok = isinstance(result, dict) and result.get("ok") is True
            pid = result.get("proposal") if isinstance(result, dict) else None
        except psycopg.OperationalError:
            ok = False; reconnects += 1; reconnect()
        except (psycopg.Error, Exception):
            ok = False
        if ok:
            accepted += 1
            if looks_dangerous(payload):
                word_miss.append(payload)

        if ok and pid is not None:
            safe_before = safe_fp()
            rows_before = row_state()
            cres = None
            try:
                with agent[0].cursor() as c:
                    cres = c.execute("select agent_gate.commit(%s)", (pid,)).fetchone()[0]
            except psycopg.OperationalError:
                reconnects += 1; reconnect()
            except (psycopg.Error, Exception):
                pass
            if isinstance(cres, dict):   # commit() returned an outcome rather than raising
                oc = cres.get("outcome", "?")
                outcomes[oc] += 1
                if DANGER_FN_RE.search(payload):
                    danger_outcomes[oc] += 1
                    if oc == "kept":                 # a dangerous function applied a change: ESCAPE
                        danger_kept.append("dangerous function applied a change: " + payload)
                    elif oc == "aborted":
                        err = cres.get("error")
                        ss = err.get("sqlstate") if isinstance(err, dict) else None
                        if ss:
                            danger_sqlstate[ss] += 1
            if safe_fp() != safe_before:   # a committed proposal must never touch catalog/role/tenant 2
                protected.append("commit changed protected state: " + payload)
            # MEASURE how many rows actually changed, from the superuser's snapshot -- never trust
            # cres["rows_affected"], the gate's own number (the 0.2.1 CTE reported 1, deleted 8).
            moved = rows_changed(rows_before, row_state())
            if moved > MAX_ROWS:   # the max_rows guarantee, checked against what the database shows
                said = cres.get("rows_affected") if isinstance(cres, dict) else None
                over_rows.append(f"commit changed {moved} rows (gate reported {said}), over {MAX_ROWS}: " + payload)
            run_schema(); baseline = full_fp()  # a kept write changed the agent's own tenant; reset

        if not alive():
            crashes.append(payload); break
        if full_fp() != baseline:   # anything else must not have changed the world
            direct_bypass.append("after propose: " + payload)
            run_schema(); baseline = full_fp()

        if (i + 1) % 500 == 0:
            pc = len(word_miss) + len(protected) + len(over_rows) + len(danger_kept)
            print(f"  {i + 1}/{ITERS}  direct={len(direct_bypass)} propose/commit={pc} crashes={len(crashes)}")

    propose_commit = len(word_miss) + len(protected) + len(over_rows) + len(danger_kept)
    print("\n--- result ---")
    print(f"inputs generated:       {ITERS}")
    print(f"reached the server:     {reached}  (rejected by the client, e.g. a NUL byte: {client_rejected})")
    print(f"proposals accepted:     {accepted}   committed: {sum(outcomes.values())}")
    print(f"    commit outcomes: kept {outcomes['kept']} · read {outcomes['read']} · "
          f"aborted {outcomes['aborted']} · refused {outcomes['refused']}")
    if danger_outcomes:
        df = " · ".join(f"{k} {v}" for k, v in sorted(danger_outcomes.items()))
        print(f"    dangerous-function commits: {df}   (a 'kept' is an escape, enforced below)")
        if danger_sqlstate:
            ss = " · ".join(f"{k} {v}" for k, v in sorted(danger_sqlstate.items()))
            print(f"        aborted by SQLSTATE: {ss}   (42501 = permission denied, 57014 = timeout)")
    print(f"agent reconnections:    {reconnects}")
    print(f"server crashes:         {len(crashes)}")
    print(f"max_rows differential oracle (k=1..8): {'PASS' if not max_rows_oracle_fails else str(len(max_rows_oracle_fails)) + ' FAILED'}")
    print(f"direct-execution escapes: {len(direct_bypass)}")
    print(f"propose/commit escapes:   {propose_commit}")
    # Per category, so the CI summary shows WHICH oracle fired even though the inputs are hidden.
    print(f"    word list should have refused:   {len(word_miss)}")
    print(f"    commit moved protected state:    {len(protected)}")
    print(f"    commit over max_rows (measured): {len(over_rows)}")
    print(f"    dangerous function applied (kept): {len(danger_kept)}")

    # A public CI log is readable by anyone with a GitHub account, so in CI print only WHICH escape
    # (its position within its category, never the iteration) and never the fuzz input. The k-sweep
    # oracle carries no fuzz input (a fixed k and shape), so it is printed in full even in CI.
    for label, items in (("CRASH", crashes), ("DIRECT ESCAPE", direct_bypass), ("WORD-LIST MISS", word_miss),
                         ("PROTECTED-STATE", protected), ("OVER-MAX-ROWS", over_rows), ("DANGER-FN KEPT", danger_kept)):
        for idx, s in enumerate(items[:10], 1):
            print(f"  {label} {idx} of {len(items)}" + ("" if IN_CI else f": {s!r}"))
    for fail in max_rows_oracle_fails[:48]:   # 6 shapes x k=1..8
        print(f"  MAX-ROWS ORACLE: {fail}")

    escapes = len(crashes) + len(direct_bypass) + propose_commit + len(max_rows_oracle_fails)
    # Health: did the run actually exercise the gate? The one failure signal is reaching the server
    # too little -- then it proved nothing. Reconnections are NOT a failure: an agent is no
    # superuser and has no pg_signal_backend, so the only backend it can terminate is its own,
    # which is benign; a reconnect storm would itself starve `reached`, which is what we gate on.
    # (Measured: 0 reconnections over 5000 inputs -- a self-terminate aborts on another backend's
    # permission error before reaching its own pid.)
    too_few_reached = reached < ITERS // 2
    if too_few_reached:
        print(f"  UNHEALTHY: only {reached}/{ITERS} inputs reached the server")
    healthy = not too_few_reached

    # On a real escape in public CI the SEED is withheld -- printed, it would hand anyone a ready
    # reproducer of an unfixed bug. The maintainer does not lose the reproducer: an HMAC-derived
    # seed is recomputed from the run id (named below) with the repo secret; only a random seed has
    # nothing to recompute it from, and there the fallback is to re-run locally. A clean or local
    # run, and the negative control, print the seed outright (harmless provenance).
    reveal_seed = not (gate_on and escapes and IN_CI)
    if not gate_on:
        # Negative control: escapes are the PASS; a clean run means the oracle is blind.
        verdict = (f"NEGATIVE CONTROL: {escapes} escape(s) found, as expected" if escapes
                   else "NEGATIVE CONTROL FAILED: no escapes without the gate -- the oracle is blind")
        ok_exit = escapes > 0 and healthy
    elif escapes == 0:
        verdict = "CLEAN: nothing escaped"
        ok_exit = healthy
    elif reveal_seed:
        verdict = f"FOUND {escapes} escape(s) -- reproduce with FUZZ_SEED={SEED}"
        ok_exit = False
    elif SEED_SOURCE == "hmac":
        verdict = (f"FOUND {escapes} escape(s) -- seed withheld; recompute it from GITHUB_RUN_ID={RUN_ID} "
                   "with the repo's FUZZ_SEED_KEY, then FUZZ_SEED=<it> make fuzz")
        ok_exit = False
    else:
        verdict = f"FOUND {escapes} escape(s) -- seed withheld in public CI; re-run `make fuzz` locally"
        ok_exit = False
    print(f"\n{verdict}" + (f" (seed {SEED})" if reveal_seed else ""))

    # The public summary carries the numbers and the seed, never an escaping input.
    gh_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if gh_summary:
        danger_line = ""
        if danger_outcomes:
            danger_line = f"- dangerous-function commits: {dict(danger_outcomes)} (a 'kept' is an escape)"
            if danger_sqlstate:
                danger_line += f"; aborted SQLSTATE {dict(danger_sqlstate)}"
            danger_line += "\n"
        oracle_line = ("- max_rows differential oracle (k=1..8): PASS\n" if not max_rows_oracle_fails
                       else f"- max_rows differential oracle (k=1..8): {len(max_rows_oracle_fails)} FAILED\n")
        keywarn_line = ("- ⚠️ FUZZ_SEED_KEY unset: seed random, an escape would be unreproducible\n"
                        if IN_CI and SEED_SOURCE == "random" and ITERS > 0 else "")
        with open(gh_summary, "a") as f:
            f.write(
                f"### fuzz{f' (seed {SEED})' if reveal_seed else ''}\n\n"
                f"- inputs: {ITERS} — reached the server: {reached}, client-rejected: {client_rejected}\n"
                f"- proposals accepted: {accepted} · committed: {sum(outcomes.values())} "
                f"(kept {outcomes['kept']}, read {outcomes['read']}, aborted {outcomes['aborted']}, "
                f"refused {outcomes['refused']}) · reconnections: {reconnects}\n"
                f"{danger_line}"
                f"{oracle_line}"
                f"- crashes: {len(crashes)} · direct escapes: {len(direct_bypass)} · propose/commit escapes: {propose_commit}\n"
                f"- by category — word-list miss: {len(word_miss)} · moved protected state: {len(protected)} · over max_rows: {len(over_rows)} · danger-fn kept: {len(danger_kept)}\n"
                f"{keywarn_line}"
                f"- **{verdict}**\n"
            )
    sys.exit(0 if ok_exit else 1)


if __name__ == "__main__":
    main()
