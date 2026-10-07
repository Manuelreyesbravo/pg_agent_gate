#!/usr/bin/env python3
# Copyright 2026 Manuel Reyes Bravo
# SPDX-License-Identifier: Apache-2.0
#
# Fuzz the gate the way an adversary would, with volume the 164 hand-written attacks do not
# have. Two properties, checked from a superuser's side of the database after every input:
#
#   1. DIRECT EXECUTION CHANGES NOTHING -- the strong oracle. In an agent session SQL does not
#      execute, only the verbs. So a fingerprint of the catalog (tables, columns, constraints,
#      triggers, policies), the agent role's attributes, and EVERY ROW of both tables (so an
#      update of the agent's own tenant is caught too) must be IDENTICAL after any statement the
#      agent runs directly. Any change is a bypass of the one guarantee the extension exists for.
#   2. propose() REFUSES THE DANGEROUS -- a heuristic. A statement that drops, truncates, grants,
#      alters, creates, copies, calls, does, prepares, chains two statements, writes in a CTE, or
#      moves a setting its policies read should come back ok:false.
#
# And after every input: the server is still alive, and if the agent's own backend went away
# the run reconnects and counts it, so a killed session cannot turn into a silent "clean".
#
# WHAT THIS DOES NOT CATCH, said plainly. Property 2 is a word list, not a parser: it does not
# flag dangerous FUNCTIONS (pg_terminate_backend, pg_sleep, lo_import, dblink, pg_read_*). That
# is on purpose -- those resolve as reads, so propose() accepts them BY DESIGN; the damage, if
# any, is bounded by the agent's own privileges at commit (not a superuser, no pg_signal_backend,
# no server-file read) and by property 1. They are in the corpus, exercised, not expected to be
# refused. The real guarantee is property 1; property 2 is a convenience. A teeth check runs
# first every time (a known change must move the fingerprint) so a clean run is never vacuous.
#
#   make fuzz PG_CONFIG=/path/to/pg_config            # default 3000 inputs
#   FUZZ_ITERS=20000 FUZZ_SEED=1 make fuzz            # longer, reproducible
#   FUZZ_NO_GATE=1 make fuzz                          # negative control: no gate, escapes expected
#
# The inputs are generated from dangerous templates, mutations of them, and random bytes, so a
# run is reproducible only with its seed (printed at the top), and it refuses any database not
# named gate_fuzz unless FUZZ_FORCE=1. Facts are measured by the database, never asserted.
import os
import random
import re
import sys

import psycopg

DSN = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("FUZZ_DSN", "")
AGENT = "fuzz_agent"
ITERS = int(os.environ.get("FUZZ_ITERS", "3000"))
SEED = int(os.environ.get("FUZZ_SEED", str(random.randrange(1 << 30))))
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
    # Dangerous FUNCTIONS. These resolve as reads, so propose() may accept them -- that is by
    # design: the damage, if any, is bounded by the agent's own privileges at commit (it is not
    # a superuser, has no pg_signal_backend, cannot read server files) and by the fingerprint
    # oracle below. They are here to be EXERCISED end to end, not to be refused at propose.
    "select pg_terminate_backend(pid) from pg_stat_activity",
    "select pg_cancel_backend(pid) from pg_stat_activity",
    "select pg_sleep(10)",
    "select lo_import('/etc/passwd')",
    "select lo_export(1, '/tmp/x')",
    "select pg_read_server_files from pg_roles",
    "select dblink('host=x', 'select 1')",
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


# Words whose presence makes an input one the gate MUST refuse at propose. MERGE, UPDATE,
# DELETE and INSERT are deliberately absent: they are the data changes the gate exists to
# allow (bounded by max_rows at commit), not refuse.
DANGER_WORDS = ("drop", "truncate", "alter", "create", "grant", "revoke", "copy", "do ",
                "call", "prepare", "vacuum", "reindex", "cluster", "comment", "lock",
                "listen", "notify", "set_config", "set role", "reset", "security",
                "extension", "pg_read_file", "pg_ls", "function", "superuser")


def looks_dangerous(s):
    # Classify on the statement with its SQL comments removed: a dangerous word that lives
    # only inside a `-- ...` or `/* ... */` comment is inert, and the gate -- which judges the
    # parsed tree, not the text -- correctly allows it. Matching the raw text would be a false
    # positive, the naive mistake the gate does not make.
    stripped = re.sub(r"--[^\n]*", " ", s)
    stripped = re.sub(r"/\*.*?\*/", " ", stripped, flags=re.S)
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
create table shop.orders (id int primary key, tenant int not null, customer int references shop.customers, total numeric);
insert into shop.customers values (1,1,'Ana','ana@one.example'),(2,1,'Bruno','bruno@one.example'),
                                  (3,2,'Iris','iris@two.example'),(4,2,'Juan','juan@two.example');
insert into shop.orders select g,1,1+g%2,g*10 from generate_series(1,8) g;
alter table shop.customers enable row level security; alter table shop.customers force row level security;
alter table shop.orders enable row level security;    alter table shop.orders force row level security;
create policy t on shop.customers using (tenant = current_setting('app.tenant_id')::int);
create policy t on shop.orders    using (tenant = current_setting('app.tenant_id')::int);
alter table shop.customers owner to fuzz_agent; alter table shop.orders owner to fuzz_agent;
"""

FINGERPRINT = """
select md5(string_agg(x, '|' order by x)) from (
  select 'c:'||relname||':'||relkind::text from pg_class join pg_namespace n on n.oid=relnamespace where nspname='shop'
  union all select 'a:'||attrelid::regclass::text||':'||attname||':'||atttypid::regtype::text
             from pg_attribute where attrelid in (select c.oid from pg_class c join pg_namespace n on n.oid=c.relnamespace where nspname='shop') and attnum>0 and not attisdropped
  union all select 'k:'||conname||':'||contype::text from pg_constraint where connamespace=(select oid from pg_namespace where nspname='shop')
  union all select 'g:'||tgname from pg_trigger where tgrelid in (select c.oid from pg_class c join pg_namespace n on n.oid=c.relnamespace where nspname='shop')
  union all select 'p:'||polname from pg_policy
  union all select 'r:'||rolname||':'||rolsuper::text||':'||rolcreaterole::text||':'||rolcreatedb::text from pg_roles where rolname='fuzz_agent'
  union all select 'm:'||r.rolname from pg_auth_members am join pg_roles m on m.oid=am.member join pg_roles r on r.oid=am.roleid where m.rolname='fuzz_agent'
  -- Every row of both tables, every column, so ANY change a bypass could make -- including an
  -- update of the agent's own tenant -- moves the fingerprint. A superuser sees past RLS.
  union all select 'd:customers:'||coalesce(string_agg(
      c.id||':'||c.tenant||':'||coalesce(c.name,'')||':'||coalesce(c.email,''), '|' order by c.id), '')
    from shop.customers c
  union all select 'd:orders:'||coalesce(string_agg(
      o.id||':'||o.tenant||':'||coalesce(o.customer::text,'')||':'||coalesce(o.total::text,''), '|' order by o.id), '')
    from shop.orders o
) s(x)
"""


def main():
    if not DSN:
        sys.exit("need a superuser DSN as argv[1] or FUZZ_DSN")
    print(f"fuzzing pg_agent_gate: {ITERS} inputs, seed {SEED}")
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
    su.execute("create extension if not exists pg_agent_gate")
    run_schema()
    # FUZZ_NO_GATE leaves the role an ordinary owner (not an agent): a negative control that
    # proves the oracle has teeth -- without the gate, direct DROPs and the rest MUST escape.
    if not os.environ.get("FUZZ_NO_GATE"):
        su.execute(f"select agent_gate.register_agent('fuzzer', '{AGENT}', 'fuzz target', p_max_rows => 5)")
    else:
        print("NEGATIVE CONTROL: no gate -- escapes are expected")

    def fingerprint():
        try:
            return su.execute(FINGERPRINT).fetchone()[0]
        except psycopg.Error:
            return None   # a catastrophic change -- e.g. a table the fingerprint reads was dropped

    def alive():
        try:
            return su.execute("select 1").fetchone()[0] == 1
        except psycopg.Error:
            return False

    baseline = fingerprint()

    # Prove the oracle has TEETH every run, not only when FUZZ_NO_GATE is set by hand: as a
    # superuser, make a change the fingerprint must see (an update, then a new table) and undo
    # it. If the fingerprint does not move, it is blind and a clean run would mean nothing.
    if not os.environ.get("FUZZ_NO_GATE"):
        su.execute("update shop.customers set email = email || '.teeth' where id = 1")
        saw_update = fingerprint() != baseline
        su.execute("update shop.customers set email = replace(email, '.teeth', '') where id = 1")
        restored = fingerprint() == baseline
        su.execute("create table shop.teeth_check (x int)")
        saw_ddl = fingerprint() != baseline
        su.execute("drop table shop.teeth_check")
        if not (saw_update and restored and saw_ddl and fingerprint() == baseline):
            sys.exit("the fingerprint is BLIND: a known change did not move it -- the oracle has no teeth")

    agent = [psycopg.connect(DSN, user=AGENT, autocommit=True)]

    def reconnect():
        try:
            agent[0].close()
        except Exception:
            pass
        agent[0] = psycopg.connect(DSN, user=AGENT, autocommit=True)

    direct_bypass, propose_bypass, crashes = [], [], []
    reached = client_rejected = reconnects = 0
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
        if fingerprint() != baseline:
            direct_bypass.append(payload)
            run_schema(); baseline = fingerprint()  # restore and keep going

        # 2. propose() must refuse the dangerous. This half is a heuristic (see the docstring);
        #    the fingerprint above is the part that holds whatever the word list misses.
        try:
            with agent[0].cursor() as c:
                row = c.execute("select agent_gate.propose(%s, %s)", (payload, "fuzz")).fetchone()
            ok = isinstance(row[0], dict) and row[0].get("ok") is True
        except psycopg.OperationalError:
            ok = False; reconnects += 1; reconnect()
        except (psycopg.Error, Exception):
            ok = False
        if ok and looks_dangerous(payload):
            propose_bypass.append(payload)
        if not alive():
            crashes.append(payload); break
        if fingerprint() != baseline:   # propose itself must not change the world
            direct_bypass.append("via propose: " + payload)
            run_schema(); baseline = fingerprint()

        if (i + 1) % 500 == 0:
            print(f"  {i + 1}/{ITERS}  direct_bypass={len(direct_bypass)} propose_bypass={len(propose_bypass)} crashes={len(crashes)}")

    print("\n--- result ---")
    print(f"inputs generated:       {ITERS}")
    print(f"reached the server:     {reached}  (rejected by the client, e.g. a NUL byte: {client_rejected})")
    print(f"agent reconnections:    {reconnects}  (the agent's backend went away this many times)")
    print(f"server crashes:         {len(crashes)}")
    print(f"direct-execution escapes: {len(direct_bypass)}")
    print(f"propose() accepted a dangerous statement: {len(propose_bypass)}")
    for label, items in (("CRASH", crashes), ("DIRECT ESCAPE", direct_bypass), ("PROPOSE ESCAPE", propose_bypass)):
        for s in items[:10]:
            print(f"  {label}: {s!r}")

    bad = len(crashes) + len(direct_bypass) + len(propose_bypass)
    verdict = "CLEAN: nothing escaped" if bad == 0 else f"FOUND {bad} escape(s) -- see the job log, not this summary"
    print(f"\n{verdict} (seed {SEED})")

    # A public summary carries the numbers and the seed, but NEVER the escaping inputs: one
    # could disclose a bypass, so those stay only in the login-gated job log.
    gh_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if gh_summary:
        with open(gh_summary, "a") as f:
            f.write(
                f"### fuzz (seed {SEED})\n\n"
                f"- inputs: {ITERS} — reached the server: {reached}, client-rejected: {client_rejected}\n"
                f"- agent reconnections: {reconnects}\n"
                f"- crashes: {len(crashes)} · direct-execution escapes: {len(direct_bypass)} · "
                f"propose escapes: {len(propose_bypass)}\n"
                f"- **{verdict}**\n"
            )
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
