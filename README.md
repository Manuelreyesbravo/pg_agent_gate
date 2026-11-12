# pg_agent_gate

[![verify](https://github.com/Manuelreyesbravo/pg_agent_gate/actions/workflows/verify.yml/badge.svg)](https://github.com/Manuelreyesbravo/pg_agent_gate/actions/workflows/verify.yml)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![PostgreSQL 18 and 19](https://img.shields.io/badge/PostgreSQL-18%20%7C%2019-336791.svg)

**Agents propose, PostgreSQL decides.**

Teams are connecting AI agents to production PostgreSQL. The agent gets a role
and a connection, and from then on PostgreSQL cannot tell it from the
application: when the model hallucinates a `DELETE` without a `WHERE`, a
`DROP TABLE`, or a read of another customer's rows, the database runs it.

`pg_agent_gate` is an extension that makes the database tell the difference.
In a session that belongs to an agent, **SQL does not execute**. The agent may
only *propose* one statement; PostgreSQL verifies it against itself, shows its
exact effect, and keeps it only if every guard agrees. It is enforced by hooks
inside the server, so there is no client, driver or protocol path around it.

**No MCP server required.** The gate lives in the database, so an agent reaches it over
`psql`, a driver or direct SQL — there is nothing to put in front of it (see
[a client that only speaks MCP](#for-a-client-that-only-speaks-mcp-a-shim-with-no-power)).
A small, free model operating it live, verified end to end:
**[see the demo ▶](https://manuelreyesbravo.github.io/agent-gate-demo/)**.

**Contents:** [See it in one minute](#see-it-in-one-minute) ·
[Verify it yourself](#verify-it-yourself) · [How it works](#how-it-works) ·
[The seven verbs](#the-seven-verbs) · [Setup](#setup) ·
[Run the two side by side](#run-the-two-side-by-side) ·
[The pipe: what JSON costs](#the-pipe-what-json-costs) ·
[A client that only speaks MCP](#for-a-client-that-only-speaks-mcp-a-shim-with-no-power) ·
[Measured](#measured) · [What it costs](#what-it-costs) · [Threat model](#threat-model) ·
[What it does not cover](#what-it-does-not-cover)

## See it in one minute

```
make demo PG_CONFIG=/path/to/pg_config
```

The same role, with the same privileges, first as an ordinary user and then
registered as an agent. After every attempt a superuser prints the database:

```
WITHOUT the gate: an ordinary role, the way an agent connects today
     database now: customers: 4 · orders: 8
  1. the model 'cleans up' the orders:        DELETE FROM orders
     database now: customers: 4 · orders: 0
  2. the model 'fixes' the schema:             DROP TABLE customers CASCADE
     database now: customers: TABLE GONE · orders: 8
  3. the model reads another customer's data:  set_config('app.tenant_id', '2') + SELECT
     Iris|iris@TWO.example
     Juan|juan@TWO.example

WITH the gate: the same role, registered as an agent (max_rows 5, no DDL)
  1. DELETE FROM orders, typed directly
     ERROR:  pg_agent_gate: this session belongs to agent "assistant": it proposes, it does not execute
  2. DROP TABLE customers CASCADE, typed directly
     ERROR:  pg_agent_gate: this session belongs to agent "assistant": it proposes, it does not execute
  3. set_config to tenant 2, typed directly
     ERROR:  pg_agent_gate: this session belongs to agent "assistant": it proposes, it does not execute
     database now: customers: 4 · orders: 8

  ...and the same three, PROPOSED through the gate:
  1. propose + commit:  DELETE FROM orders   (8 rows, the agent may touch 5)
     commit: aborted -- it touched 8 rows, more than this agent may change in one statement
  2. propose:  DROP TABLE customers
     refused at propose -- kind_allowed: T_DropStmt changes the schema or the server, and this agent is not allowed DDL
  3. propose:  a read that moves the tenant from inside the statement
     refused at propose -- keeps_its_context: set_config() would change, while the proposal runs, a parameter ...
     database now: customers: 4 · orders: 8

  ...while legitimate work still goes through, and is seen before it is kept:
  dry_run (nothing kept):
     "rows": [{"after": {..., "email": "ana@new.example"}, "before": {..., "email": "ana@one.example"}}]
  commit:
     kept, Ana's email is now ana@new.example
```

A small, free model doing this live — fork-and-run, with the scored report:
**[agent-gate-demo](https://github.com/Manuelreyesbravo/agent-gate-demo)** ·
**[see a live run](https://manuelreyesbravo.github.io/agent-gate-demo/)**.

### Try it with no Rust or PostgreSQL installed

`make demo` needs PostgreSQL 18+, Rust and cargo-pgrx. To see the same with/without-gate
demo with none of that, run it in a throwaway container — the extension is built into the
image, and it needs only Docker or Podman:

```
make docker-demo        # builds the image from this repo and runs the demo
```

or pull the prebuilt image instead of building it:

```
docker run --rm ghcr.io/manuelreyesbravo/pg_agent_gate-demo
```

The image is `linux/amd64`; on an Apple-silicon Mac it runs under emulation.

## Verify it yourself

Every claim in this README has a test that attacks it on purpose and checks the
database from a superuser's side -- not the gate's own answer:

```
make verify PG_CONFIG=/path/to/pg_config     # your PostgreSQL 18+, a throwaway cluster
make clean-machine                           # the same, in a fresh container that only gets git HEAD
```

| suite | what it attacks | checks |
|---|---|---|
| `adversarial.sh` | every channel a session can type, and what can be slipped past `propose` | 59 |
| `hostile.sh` | garbage into the verbs, the record rewritten, the world moved between propose and commit | 40 |
| `privileges.sh` | the privilege boundary between agents, roles and the record | 31 |
| `rls_isolation.sh` | moving the context a row-level policy reads: `SET`, startup parameters, `set_config` | 22 |
| `dump_restore.sh` | the record across `pg_dump` and restore | 10 |
| `upgrade.sh` | an installation of the oldest schema, upgraded | 13 |
| `flushes.sh` | the WAL flushes each act pays against its durability | 8 |
| `plan_time.sh` | what runs while the gate verifies and plans | 45 |
| `pg_temp.sh` | a temporary catalog of the agent hiding what a write sets off; an assertion's path left in the session | 18 |
| `rollback.sh` | what a rollback takes from the record | 12 |
| `audit3.sh` | the third audit: fast-path, the gate's path, foreign proposals, DDL, roles, 2PC, dump | 18 |
| `audit4.sh` | the rest of it: settings between dry_run and commit, side effects of a read, a reused name, record size | 18 |
| `isolation.sh` | one proposal committed twice under REPEATABLE READ / SERIALIZABLE | 5 |
| `session_preload.sh` | a client parameter taking a per-session load out from behind the gate | 4 |
| `approvals.sh` | an agent that needs an approver committing its own proposal | 7 |
| `budget.sh` | a write split into slices that each fit `max_rows` (0.4.0) | 21 |
| `membership.sh` | another role becoming the agent with `SET ROLE` (0.4.1) | 16 |
| `audit5.sh` | SQL passed as text, `CREATE TABLE AS` over a writing CTE, functions the agent can alter or with a `SET` clause (0.4.3) | 44 |
| `audit6.sh` | code the tree does not show: a range type's support function, a domain's `CHECK`, an aggregate, a DDL's `DEFAULT`; large objects; a foreign key over `citext` (0.4.3) | 44 |
| `audit7.sh` | a verb's parameter of an agent's domain, a temporary table under a DBA's helper, a `DROP ... CASCADE` or `ALTER TYPE` reaching a DBA's table, a read that ends another session, code handed to a `NOINHERIT` role; and a module's `SET` parameter, an event trigger, `MERGE`, `lo_get()`, intagg, `serial` (0.4.3) | 58 |
| `audit8.sh` | an extension's C function in an agent's domain `CHECK`, `CREATE OR REPLACE FUNCTION` under a DBA's index, an index or `DETACH` reaching a DBA's partition; a `varchar[]` argument, a read-only transaction (0.4.3) | 43 |
| `audit9.sh` | a volatile function in a DBA's column `DEFAULT`, an `UPDATE` that moves rows between partitions, a pool's `DISCARD ALL` (0.4.3) | 44 |
| pgrx unit tests | the verbs, from inside the server | 13 |

For 0.4.3, the suites above: **580 checks passed, 0 failed** on PostgreSQL 18.6 with its
contrib modules and pgvector, and **578 passed, 0 failed** on 19 (19beta2, and again 19rc1 on
2026-11-12), whose builds had no pgcrypto for two of `audit9.sh`'s checks; `make verify` adds
the 13 pgrx unit tests, which pass on both. A case whose module is missing does not run, and
`make verify` says so in its summary ("N passed, 0 failed, M skipped"). The fresh Debian
container receiving only what git has committed runs the same suites, with 18 and the newest
19 from PGDG (19rc1 as of 2026-11-12). CI runs the same container for 18 and 19 on every push.
`VERIFY_DRIVERS=1` adds real pgjdbc and node-pg sessions.

Those 580 are the hand-written suites above. The amplification class that `0.2.2` and `0.2.3`
closed -- a writing CTE, a cascading foreign key, a trigger, a rule, an opaque (volatile or
`SECURITY DEFINER`) function, and the commit-time row-count backstop and per-agent allow-list
that back them -- is guarded by **`make fuzz`**, not by `make verify`. Its teeth build each of
those and assert the gate refuses or aborts it (and that `discover` says the same thing
`propose` does, through the one shared function), and a `k=1..8` differential oracle checks
`max_rows` against the row count a superuser actually measures. `make fuzz` also throws
generated and mutated adversarial SQL at the gate and checks, from a superuser's side: nothing
the agent runs directly changes the database, and every proposal the gate *accepts*, once
**committed**, leaves the catalog, the role and another tenant untouched and stays within
`max_rows` -- the surface the two 0.2.1 bugs lived on. Two teeth checks run first so neither
half can pass vacuously (a known change must move the fingerprint; `propose` must refuse a
known `DROP` and `GRANT`), and run against the `v0.2.0` tag the fuzzer reports the historical
`set_config` hole. **CI runs `FUZZ_ITERS=0 make fuzz` -- the teeth and the oracle, no
generation -- on every push, in the required `end-to-end` job**; the generative fuzz
(`FUZZ_ITERS` > 0) runs weekly. Each tooth asserts WHICH check refuses a statement (via
`failed_check`), not merely that one did, so it cannot pass unless the right check fired -- a
refusal by a parse error or a missing privilege does not count. That is the structural guard
against a vacuous pass. As a spot negative control (measured 2026-10-08), disabling
`no_amplification` turns `FUZZ_ITERS=0` red: 9 checks fail (the cascade and trigger teeth, the
allow-list breach checks, the discover/propose parity). `tests/fuzz.py` says plainly what it does
and does not catch.

Two of these suites were green while a hole was open: see
[what found the 0.2.1 fixes](#what-found-the-021-fixes). A green suite is a
claim about the cases it has, which is why the threat model below says what is
not covered.

## How it works

Today an LLM agent reaches PostgreSQL through an MCP server that holds a
connection, hands the model a list of tools, and runs whatever the model asks.
The model decides; the server obeys. Every guarantee lives in that server's
code, outside the database, and the database never learns what was checked.

`pg_agent_gate` moves the decision into PostgreSQL. An agent does not run SQL.
It has seven verbs, and in a session that belongs to an agent **it cannot do
anything else** -- not `DELETE`, not `DO`, not `COPY`, not `PREPARE`. The
database verifies every proposal against itself, runs it with the agent's own
privileges, and keeps the record.

```
discover  ->  propose  ->  dry_run  ->  commit
          ->  propose_and_commit           (both in one call)
                                         acts, whoami
```

## What an agent sees

```sql
-- what may I touch? derived from the live catalog and MY privileges
SELECT agent_gate.discover('customers');

-- propose one statement: nothing runs
SELECT agent_gate.propose(
  'update customers set plan = ''pro'' where id = $1::int',
  'upgrade the customer who asked for it',
  ARRAY['1']);
--  {"proposal": 42, "ok": true, "kind": "write", "estimated_rows": 1,
--   "checks": [{"check": "parses",           "passed": true, ...},
--              {"check": "single_statement", "passed": true, ...},
--              {"check": "kind_allowed",     "passed": true, ...},
--              ... no_writing_cte, keeps_its_context, no_amplification, no_opaque_function ...
--              {"check": "resolves",         "passed": true,
--               "detail": "the planner resolved every table, column, type and function without executing ..."}]}

-- see the exact effect, then nothing is kept
SELECT agent_gate.dry_run(42);
--  {"outcome": "rolled_back", "rows_affected": 1,
--   "rows": [{"before": {"id": 1, "plan": "free"}, "after": {"id": 1, "plan": "pro"}}]}

-- make it real, if every guard still agrees
SELECT agent_gate.commit(42);
--  {"outcome": "kept", "rows_affected": 1, ...}
```

Anything else, from that session:

```
=> delete from customers where id > 0;
ERROR:  pg_agent_gate: this session belongs to agent "billing": it proposes, it does not execute
DETAIL:  DELETE does not reach the database from an agent session
HINT:  Call agent_gate.propose(sql, intent), then agent_gate.dry_run(proposal) or agent_gate.commit(proposal) -- or agent_gate.propose_and_commit(sql, intent) for both in one call.
```

## Run the two side by side

```
make contrast PG_CONFIG=/path/to/pg_config
```

The same `DROP TABLE` that an ordinary connection runs -- and the table is gone,
irreversibly -- the gate refuses, with the reason. And where an ordinary server
hands back a row count *after* it ran, the gate returns the catalog the agent
may touch, every check with its verdict, and the exact before/after of the
change, *before* anything is kept. The piece you take out returned a result; the
piece in its place returns a decision you can see.

## The seven verbs

| verb | does |
|---|---|
| `discover(filter, max_objects)` | tables, views and functions the agent has privileges on, with columns, types, keys, constraints and comments. Objects owned by extensions are left out. Includes a fingerprint, so a client can tell the schema changed |
| `propose(sql, intent, params)` | verifies one statement and records it. Runs nothing -- except an `allow_ddl` agent's DDL, which is verified by running it in a subtransaction that is rolled back |
| `dry_run(proposal)` | runs it inside a subtransaction and rolls it back: rows touched, before/after of every row of a write, whether bound assertions would still hold |
| `commit(proposal)` | verifies again, runs it and keeps it if every guard agrees. A proposal is committed at most once |
| `propose_and_commit(sql, intent, params)` | `propose` then `commit` in ONE call, so in one transaction: the same checks (verified at propose and again at execution), the same record, one commit instead of two. No `dry_run` in between -- for a statement whose effect the agent has already seen, or a read. Returns `{outcome, proposal, commit}`; a statement that does not verify never reaches execution (`refused_at_propose`, `commit` null) |
| `acts(max_acts)` | what this agent proposed and did, with every execution and why anything was refused |
| `whoami()` | which agent this session is, whether the gate is enforced in it, and how durable attempts are |

## Verification

Nothing is reimplemented. Each check is PostgreSQL itself:

1. **parses** -- PostgreSQL's own raw parser accepts it.
2. **single_statement** -- exactly one, so what was verified is what runs.
   `select 1; delete ...` dies here.
3. **kind_allowed** -- read, write or DDL, against what the agent may do.
   Transaction control is refused: the gate owns the transaction.
4. **no_writing_cte** -- PostgreSQL's analyzer and rewriter build the query
   tree (every table, column, type, operator and function must exist and fit,
   or the proposal fails `resolves` right here), and a CTE that changes data
   is refused. `max_rows` counts the rows of
   the statement, and a write hidden in a CTE under a `SELECT count(*)` is
   counted as one row: before 0.2.1 it deleted every row under a limit of 5.
   Propose each write as its own statement.
5. **keeps_its_context** -- `set_config()` anywhere in that tree (the `WHERE`,
   the `FROM`, a subquery, a CTE, an expanded view, schema-qualified or not) is
   refused. Inside the statement it moves, while the statement runs, the
   parameter a row-level policy reads; before 0.2.1,
   `... where set_config('app.tenant_id', '2', true) is not null` read another
   tenant's rows. Since 0.4.2 the same holds below the tree: in an agent's session,
   while its SQL runs, `set_config()` does not start wherever it is reached -- the
   SQL a function receives as text, the body of another function, a `CHECK`, a
   default, a domain's `CHECK`, an aggregate's transition function. **Code is judged
   where it starts (0.4.3):** the executor asks the gate before it runs any function,
   built-ins included, and the function manager asks for every user function C code
   calls through a cache -- a range type's support function, an RI check, a trigger
   (`tests/audit5.sh`, `tests/audit6.sh`). **In the whole session, and the context is the
   gate's (second review of 0.4.3):** a verb's parameter bound as an agent's domain ran the
   domain's `CHECK` before any verb started and switched the tenant for the rest of the session.
   The floor now stands in every agent session, not only while its SQL runs; a verb's argument
   must be of a built-in type; and the session's context -- `role`, `session_authorization`,
   `row_security`, `session_replication_role`, `search_path` and every placeholder parameter
   such as `app.tenant_id` -- is remembered when the session starts and checked when every verb
   starts, after the agent's SQL ran, and before a row is returned or a change kept. If it moved,
   the verb refuses (`tests/audit7.sh`).
6. **no_amplification**, **no_hidden_sql**, **no_opaque_function** -- on the same
   tree: a write whose cascade, trigger or rule the gate cannot vouch for; a call
   to a function that runs SQL it receives as text (`query_to_xml()` and the rest
   of the `*_to_xml()` family, `ts_stat()`, `ts_rewrite()`, tablefunc's
   `crosstab()` and `connectby()`, dblink), whose query no check sees (0.4.2); and
   a call to a user function that is volatile or `SECURITY DEFINER`, that the agent
   can alter -- its `STABLE` or `IMMUTABLE` is then its own claim -- or whose `SET`
   clause moves the context a policy reads: a placeholder -- a custom parameter no loaded
   module defines, such as `app.tenant_id` --, `agent_gate.*`, `role`,
   `session_authorization`, `row_security` or `session_replication_role` (`work_mem`, `jit`,
   `plan_cache_mode`, `search_path`, and a module's own parameter -- `pg_trgm.*`, `hnsw.*`,
   `plpgsql.*`: defined by a loaded module, or named after an installed extension -- only say
   how the body runs, and pass). An aggregate is judged by the functions it
   runs, its transition function first: `pg_proc` marks every aggregate `IMMUTABLE`
   (0.4.3). A function that runs SQL from a text, one the agent can alter and one with
   such a `SET` clause are also stopped wherever they are reached in an agent's session,
   as a `SECURITY DEFINER` one is since 0.2.7. Whose function it is, is asked of the
   agent's own role, not of the role PostgreSQL runs an RI check as (0.4.3), and by
   membership: a function the agent handed to a role it belongs to without `INHERIT` is
   still its own. **read_changes_nothing** / **changes_only_rows** -- a built-in that
   changes state outside the rows the gate counts is refused: in a read, any; in a write
   or a DDL, those that are not how a write numbers its rows, locks them until commit or
   tells a listener (`nextval()`, transaction advisory locks, `pg_notify()`). Which
   built-ins change state is PostgreSQL's own marking, not a list of what is forbidden:
   a `VOLATILE` built-in changes state unless it is on a reviewed list of those that only
   read, wait or draw a random number (`random()`, `clock_timestamp()`, `pg_sleep()`,
   `currval()`, `lo_get()`, sizes and statistics, ...), so a signal or administration
   function nobody named is refused by default -- `pg_terminate_backend()` passed as a
   read before (second review of 0.4.3). A `LANGUAGE internal` function is the built-in
   it names, and is judged as that one. The same rule stops them wherever they are
   reached: a domain's `CHECK` that called `nextval()` made a read advance a sequence.
   For an `allow_ddl` agent, the query of a `CREATE TABLE AS`, `SELECT INTO` or
   `CREATE MATERIALIZED VIEW` gets checks 4 to 6 too (0.4.2): up to 0.4.1 it was
   only run, and over a CTE that deletes it deleted rows no limit counted.
7. **resolves** -- only now `EXPLAIN` plans it, for the estimate. **The order is
   a guarantee (0.2.6):** planning runs functions -- it folds an `IMMUTABLE` call
   with constant arguments and estimates a `STABLE` one by calling it -- so up
   to 0.2.5, where `EXPLAIN` came first, a `SECURITY DEFINER` function ran as its
   owner before `no_opaque_function` refused it, and what it raised (a secret)
   came back in the check's detail. Now every refusal is decided on the analyzed
   tree, which runs nothing (`tests/plan_time.sh` counts the calls); and since
   0.2.7 a `SECURITY DEFINER` function reached through a body the tree does not
   show -- a wrapper the planner folds -- is stopped before it runs.
   `estimated_rows` is given only when the agent could read in full every
   relation the analyzed tree AND the plan touch: `SELECT` on the whole table and
   no row-level security hiding rows from it. The statistics are gathered beneath
   the policy and beneath a view, and the estimate told another tenant's frequent
   value (34 rows) from an absent one (1) -- through the table (0.2.6), through a
   SQL function the planner inlines after the tree was built, and through a view
   that isolates tenants without row-level security (both 0.2.8). It errs on the
   withholding side: `SELECT` on a partitioned parent without its partitions, or on
   some columns only, withholds the estimate too, although nothing would leak. The agent's SQL
   never runs in a parallel worker (0.2.8): the backend runs the whole plan, where
   the gate's hooks see it. DDL (for agents allowed it) is verified instead by running
   it in a subtransaction that is rolled back -- as execution, under the same floor,
   and judged as a read: proposing changes nothing, so a DDL that would advance a
   sequence while it is only being checked is refused (0.4.3). A sequence the DDL itself
   creates may number its new column (`serial`, like an identity column: the rollback
   takes the sequence with it), one that existed before may not; a DBA's event-trigger
   code is judged as the DDL it runs for. **An agent's DDL changes only what the agent
   owns** (second review of 0.4.3): every object PostgreSQL drops for it -- by name,
   through a `CASCADE`, or as the owner of the schema -- must be one the agent could drop
   by name; a type it alters must not be what another role's table, domain or function is
   made of, and a function it redefines must not be what another role's index, constraint,
   generated column, view or function is built on (third review); what it creates -- an index
   or a trigger PostgreSQL makes on every partition of its table -- and a table it detaches
   must be its own; and it creates no temporary object, because PostgreSQL searches the temporary
   schema first for relation and type names and an agent's temporary table answered for a
   name a DBA's policy helper did not qualify.

Checks 4 and 5 were found by an LLM proposing through the gate against a
two-tenant database, with a superuser comparing the database before and after
every case -- not by the suites in `tests/`, which were green with both holes
open. Both now have cases there (`adversarial.sh`, `rls_isolation.sh`) that are
red against 0.2.0.

`commit` verifies **again**: a verification is a statement about the database
at a moment. A proposal older than `agent_gate.proposal_ttl_seconds` (900) is
refused outright.

## Execution

* Runs with the **agent's own privileges**. The gate adds verification; `GRANT`
  is still the authorization.
* Inside a subtransaction, decided **after** it runs:
  * a write touching more rows than the agent's `max_rows` is undone -- counted over
    everything the statement changed, triggers and functions included; a DDL's count
    is what it changed in tables that existed before it (0.4.3);
  * deferred constraints are fired **inside the gate** (`SET CONSTRAINTS ALL
    IMMEDIATE`), not at the caller's commit where nobody is watching;
  * assertions bound to the agent (from
    [pg_living_assertions](https://pgxn.org/dist/pg_living_assertions/)) are
    run after the change: `broken` or `erroring` undoes it -- a check that
    cannot run is not a check that passed.
* A read's subtransaction is **always** rolled back: a read has nothing to keep.

## The record

`agent_gate_internal.proposals` and `.executions` are append-only (triggers
refuse `UPDATE` and `DELETE`) and survive `pg_dump`. Each execution says its
outcome -- `kept`, `read`, `rolled_back`, `aborted` or `refused` -- and the last
two must say why (a `CHECK`). Writes keep the before/after of up to 50 rows.
**Reads keep nothing but counts**: copying what an agent read into an audit
table would copy the data itself.

Only the gate writes the record. The writing functions are `SECURITY DEFINER`
and first ask the gate whether the caller is the gate's own code -- a flag no
SQL can set, kept down while the agent's own SQL runs. A proposal cannot forge
its history; an agent calling those functions by name is refused by the hook.

**What a rollback takes, the server log keeps.** The record is written in the
caller's transaction, and an agent session may control its transaction (a driver
such as psycopg opens `BEGIN` by itself). So `ROLLBACK`, `ROLLBACK TO SAVEPOINT`,
or a session that disconnects without `COMMIT` takes those rows with it -- a
refused attempt and a read included. The gate cannot keep a row its caller rolls
back, and refusing transaction blocks would break every driver that opens one.
Instead, when an abort takes rows from the record, each one is written to the
server log at `LOG` -- outside every transaction, never sent to the agent's
session -- on one line, with the agent's text JSON-escaped:

```
LOG:  pg_agent_gate: rolled back with the transaction, so not in the record: proposal 1 of agent rollback (role ...): kind=ddl ok=false intent="probe one" sql="drop table shop.orders"
```

`acts()` and the tables show what was committed; the server log shows what an
abort took (since 0.2.10, from an external audit of 0.2.8; `tests/rollback.sh`).
A server crash before the log line is written loses it, as it would lose any.

### How durable the record is

`agent_gate.attempt_durability` (superuser-only):

* **A change the gate keeps is always committed with the durability the server
  is configured with.** That flush also carries the record of the proposal that
  led to it, which sits earlier in the WAL: no change exists on disk without
  its proposal and its execution next to it.
* **`fast` (default):** the record of an *attempt* -- a proposal, a dry run, a
  read, a refusal, anything that changed no data -- rides on an asynchronous
  commit. A server crash inside the WAL writer's window can lose the record of
  an attempt that changed nothing. (pgaudit's log is not fsynced either.)
* **`durable`:** every record pays its own flush -- so `propose` + `commit` pay
  two, and `propose_and_commit` pays **one**: the proposal and its execution ride
  on the same commit. Counted, not inferred: `tests/flushes.sh` reads the WAL
  fsyncs of client backends from `pg_stat_io` around 50 acts of every kind, and
  gets exactly 2.00 and 1.00 per act (0.00 for a fast read, 1.00 for any kept
  change).

Never relaxed in a transaction that had already written something before the
first verb ran: those writes are not the gate's to relax.

## Setup

PostgreSQL **18 or later** (`dry_run` uses `RETURNING old/new`). Built with
[pgrx](https://github.com/pgcentralfoundation/pgrx) 0.19.2; the test suite
passes on 18 and 19 (tested on 18.6 and 19rc1). `Cargo.lock` is committed, so a build
from a tag uses the crates its suites ran against.

```sh
cargo install cargo-pgrx --version 0.19.2 --locked
cargo pgrx init --pg18 /path/to/pg_config     # --pg19 for 19; registers it, downloads nothing
cargo pgrx install --release --pg-config /path/to/pg_config
```

```ini
# postgresql.conf -- recommended
shared_preload_libraries = 'pg_agent_gate'
```

```sql
CREATE EXTENSION pg_agent_gate;

CREATE ROLE billing_agent LOGIN;               -- never a superuser
GRANT USAGE ON SCHEMA public TO billing_agent;
GRANT SELECT, UPDATE ON customers TO billing_agent;

SELECT agent_gate.register_agent(
  'billing', 'billing_agent', 'answers billing questions and upgrades plans',
  p_max_rows => 50, p_allow_ddl => false);

-- optional: every write this agent keeps must leave this assertion holding
SELECT agent_gate.bind_assertion('billing', 'no_customer_without_plan');
```

`register_agent` sets `agent_gate.agent` on the role. If the library is not in
`shared_preload_libraries`, it also sets `session_preload_libraries` on that
role, so the gate is loaded before the agent's first statement. That setting
replaces any `session_preload_libraries` the role already had: add other
libraries back after registering (`ALTER ROLE ... SET session_preload_libraries
= 'pg_agent_gate, other'`). It refuses superuser roles: a superuser can unset a
superuser-only setting, and an agent that can leave the gate is not behind it.
For the same reason it refuses `REPLICATION` and `BYPASSRLS` roles, and members
(direct or inherited) of a superuser, of such a role, or of `pg_write_all_data`,
`pg_execute_server_program` or `pg_write_server_files`. A session loaded this
way ends (FATAL) if its client set any `agent_gate.*` parameter at startup. It
takes effect on the role's **next** connection.

## For a client that only speaks MCP: a shim with no power

The gate is in the database, so there is nothing to put in front of it -- an
agent reaches it through `psql`, a driver, or direct SQL, and it is governed all
the same. You do not need an MCP server, and that is the point: the piece that
used to hold the connection and run what the model asked is gone.

For a client that only speaks MCP, `gated-mcp/` fills the gap without bringing
that power back. It is a small Bun + Hono server exposing six of the verbs as six
MCP tools (`propose_and_commit`, added in 0.2.5, is not exposed there yet) over Streamable HTTP, and it connects **as the agent role**, so it is
not where the gate lives -- replace it with anything and it still can only call
the verbs. It is a compatibility layer, not the product. Six tools, never one
per table: what the agent may touch comes from `discover`.

```sh
cd gated-mcp && bun install
AGENT_GATE_DATABASE_URL=postgres://billing_agent@localhost/app bun run src/index.ts
# POST http://127.0.0.1:7878/mcp   (set AGENT_GATE_TOKEN to require a bearer token)
```

It speaks two protocol eras on the same endpoint, chosen by what each request
says: the **2026-07-28** revision -- stateless; `MCP-Protocol-Version`,
`Mcp-Method` and `Mcp-Name` must match the body or the request gets 400 and
`-32020` before it reaches the database; an unsupported version gets 400 and
`-32022`; `server/discover` and `tools/list` carry `ttlMs` and `cacheScope` --
and the **2025-11-25** `initialize` handshake most clients still run. `GET` and
`DELETE` get 405.

Bound to loopback, `Host` and `Origin` are checked on every request and a
foreign one gets 403 before the token and before the database: any web page can
make a browser post to localhost. Bound elsewhere, set
`AGENT_GATE_ALLOWED_HOSTS` and `AGENT_GATE_ALLOWED_ORIGINS`.

Besides the six tools it offers **resources and prompts, and they add no
power**. The resources -- `agent-gate://catalog`, `agent-gate://whoami`,
`agent-gate://acts` and the template `agent-gate://relation/{schema}/{name}` --
are read by calling a verb as the agent role, never with a query of their own:
the catalog as a resource is identical to what `discover` returns, and a
relation the agent was not granted answers `-32602`, not its content. The
prompts, `change_data` and `investigate`, carry no data: they teach a model the
gate's loop. What a resource contains depends on the agent's grants, so it is
marked `cacheScope: private`.

Checked against clients nobody here wrote: `test/clients.mjs` drives the gate
end to end with the official `@modelcontextprotocol/client` 2.0.0 pinned to
2026-07-28 and with `@modelcontextprotocol/sdk` 1.30.0, and checks from a
superuser connection that only the committed change happened;
`test/transport.mjs` checks the transport MUSTs with plain `fetch`; and the
official `@modelcontextprotocol/conformance` suite runs against it.

One command runs all of it -- a throwaway cluster, an agent registered behind
the gate, gated-mcp started as that role, and every suite against it:

```sh
make mcp PG_CONFIG=/path/to/pg_config     # needs node and bun on PATH
```

CI (`.github/workflows/verify.yml`, the `end-to-end` job) runs that same command
on every commit, so "a real MCP client can only operate the gate" is re-proved,
not just asserted.

## The pipe: what JSON costs

MCP is JSON-RPC, and JSON has no 64-bit integer, no exact decimal and no binary.
An agent that reaches the database through it moves its data over that pipe; one
that reaches the gate over a native connection does not. The gate's guarantee is
identical either way -- the same verbs, the same verification -- so what you
weigh is the pipe. `make transfer` measures it on a replica of a real workload
(a 64-bit id, exact money, binary, arrays, nested documents, at volume):

```
make transfer PG_CONFIG=/path/to/pg_config
```

| the same data | native, PostgreSQL's own protocol | forced through JSON |
|---|---|---|
| the id `9007199254740993` | exact | `9007199254740992` -- a JSON number is an IEEE double |
| `numeric(40,12)` | exact | lost, unless it travels as a string |
| 256 bytes of binary | 256 bytes, raw | 348 bytes of base64 text (+35%) |
| the whole set | its typed, binary self | larger, every number and key as text |

None of it is real data; it is there so you can run it. The fidelity loss is
shown live, by parsing the value with the same JSON a client would use.

## Measured

With real sessions of an agent role, both wire protocols, against PostgreSQL
19beta2 **built without assertions** (September-October 2026; the commit that
first measured each row is in its last column) -- a throwaway cluster from the same
binaries the extension is installed into (`tests/cluster.sh`), loading it from
`cargo pgrx package`. Each attack counts only if the error is **the gate's**
(a PostgreSQL permission error proves nothing about the gate), and a separate
superuser connection then checks that nothing changed. Every criterion was
declared before the code that it measures.

| criterion | threshold | measured | first measured |
|---|---|---|---|
| raw SQL executed from an agent session: `SELECT`/`INSERT`/`UPDATE`/`DELETE`, `DO`, `CALL`, `PREPARE`, `EXPLAIN ANALYZE`, writing CTE next to a verb, foreign function next to a verb or as its argument, subquery as argument, reading or forging the record, `LOCK`, `CREATE`, `SET ROLE`, `COPY`, extended protocol, cursor | 0 | **0 of 20, no side effect** | e05e20e, 2026-09-14 |
| raw SQL executed after an error inside the gate (error escaping a verb, error inside execution, cancellation mid-act, rollback in an explicit transaction) | 0 | **0 of 4** | e05e20e, 2026-09-14 |
| invented proposals refused at `propose`: missing table/column/function, wrong literal type, operator without a type, unbound parameter, hidden second statement, broken syntax, transaction control, DDL without permission | 100% | **17 of 17, no side effect** | dfdd949, 2026-09-15 |
| **control**: correct proposals pass and do exactly what they say | 100% | **10 of 10** | dfdd949, 2026-09-15 |
| **control**: a kept change survives an immediate shutdown (no checkpoint) with its proposal and its execution | 100% | **10 of 10** | dfdd949, 2026-09-15 |
| every channel a session can type, tried on purpose (`tests/adversarial.sh`): two statements in one query, `PREPARE`/`EXECUTE`, a cursor, `COPY TO`/`FROM PROGRAM`, `DO`, `CALL`, `EXPLAIN ANALYZE`, `CREATE TABLE`/`FUNCTION`, `SELECT INTO`, a writing CTE, a function as a verb argument, a subselect of what it was not granted, `SET ROLE`, `SET SESSION AUTHORIZATION`, `RESET ALL`, `DISCARD ALL`, `VACUUM`, `CHECKPOINT`, `LISTEN`/`NOTIFY`, `lo_export`, a function as the argument of `propose_and_commit`, and a replication connection | 0 | **0 of 24 had any effect** | 48170cc, 2026-10-08 |
| what can be slipped past `propose` (`tests/adversarial.sh`): two statements, a second one hidden after a comment, DDL without permission, `COPY TO PROGRAM`, `SELECT INTO`, `FOR UPDATE` and a write beyond `max_rows`, two writing CTEs under a `SELECT`, an expired verification, another agent's proposal -- and each of the first nine again through `propose_and_commit` | 0 | **0 of 20** | 48170cc, 2026-10-08 |
| **control**: an agent still runs `whoami`, `discover`, proposes, sees before/after in `dry_run`, commits a read and a write, is refused a second commit, and reads its `acts`; in one call, reads rows and keeps a write that shows in `acts` | 100% | **15 of 15** | 48170cc, 2026-10-08 |
| garbage into `propose` and `commit` (`tests/hostile.sh`): malformed SQL, unbalanced parentheses, an unterminated comment and dollar quote, a NUL byte, 500 levels of nesting, 100 KB of SQL, 500 parameters, fewer parameters than placeholders, a type that does not exist, invalid UTF-8, a 10 KB identifier, an empty proposal, ids that do not exist, an endless query | 0 crashes | **0 of 16, same postmaster** | 4c3eeb4, 2026-09-15 |
| the record rewritten (`tests/hostile.sh`): `DELETE`, `TRUNCATE`, disabling the triggers and dropping them, as the agent and as the owner | 0 | **0 of 7** | 4c3eeb4, 2026-09-15 |
| the world moved between `propose` and `commit` (`tests/hostile.sh`): table renamed, column dropped, privilege revoked, row gone, a bound assertion broken meanwhile, two sessions at once, and the same proposal committed twice at once | 100% | **9 of 9** | 4c3eeb4, 2026-09-15 |
| **control**: what an owner's trigger, `SECURITY DEFINER` function and view do on the agent's behalf is what this README says | 100% | **5 of 5** | 4c3eeb4, 2026-09-15 |


Those counts are the ones measured then. The cases behind every row are in
`tests/adversarial.sh` and `tests/hostile.sh`, which `make verify` runs: on
2026-11-12 they passed in full on 18.6 and 19rc1, for 0.4.3 plus this README.

**Two of those rows found real defects, which is why they exist.** `TRUNCATE`
emptied the whole record: the append-only triggers were `FOR EACH ROW`, and
`TRUNCATE` fires no row trigger, so the history could be erased in one statement
with nothing disabled and nothing said. And two concurrent `commit`s of the same
proposal both ran it -- each transaction read `committed` from its own snapshot,
where the other had not committed yet, so a write was applied twice. On a balance
that is a double charge. Both are fixed (0.2.0): statement-level triggers for
`TRUNCATE`, and the proposal's row is locked while a commit decides.

### What found the 0.2.1 fixes

Not these suites: they were green with both holes open. What found them, on
2026-10-06 against 0.2.0, was an LLM (a Qwen3-8B with a SQL adapter) proposing
through the gate against a two-tenant database with row-level security --
legitimate tasks, destructive ones written by the model and injected by hand, raw
SQL in the agent's session, and attempts to cross tenants -- with a superuser
comparing the database before and after every case, and the same cases run by an
identical role that was not an agent, to prove the cases were dangerous at all.
That run used a private harness and data whose results are not in this
repository, so no counts from it are claimed here; what it found is pinned by
cases that are in the suites:

1. **A CTE that writes dodged `max_rows`.** The limit counted the rows of the
   outer statement, so `with d as (delete ...) select count(*) from d` deleted
   12 rows under a limit of 5.
2. **`set_config()` inside a proposal moved the tenant.** The session allowlist
   judged `SET` and the startup parameters, but while the gate runs a proposal
   its hooks step aside, so `... where set_config('app.tenant_id', '2', true) is
   not null` read the other tenant's rows.

Since 0.2.1 both are refused at `propose` (checks 5 and 6 above), and both have
cases in the suites that are red against 0.2.0.

## What it costs

```
make bench PG_CONFIG=/path/to/pg_config
```

`tests/bench.py` on the throwaway cluster. "Directly" means an **identical role**
-- same grants, same statement, same parameters -- that is not registered as an
agent; never a superuser. Each of `ITER` iterations (300) runs both paths back to
back, alternating which goes first; the throughput test runs `PAIRS` (7) alternating
pairs of `pgbench -S` restarts of `SECONDS` (15) each, preloaded and bare, and
reports the median loss with every pair shown. It prints medians with p25/p75 and
writes them to `target/bench/result.json`. The thresholds were declared before the
code, and the run says whether each one holds:

| what `make bench` measures | threshold |
|---|---|
| extra time per read act (`propose` + `commit`) over the same query directly | <= 10 ms |
| extra time per kept write over the same `UPDATE` directly, which pays its own durable commit | <= 5 ms |
| throughput lost by sessions that are **not** agents when the library is preloaded | <= 3% |
| extra time per read act with `attempt_durability = durable` | <= 10 ms |
| the same durable read act in ONE call (`propose_and_commit`) | <= 10 ms |

This README publishes no timing of its own: one machine's numbers are not yours, so
run it where the gate will run.

**Where the time goes.** The gate's own work inside the server -- parse, plan, the
amplification and function checks, run, decide -- is a part of an act; most of the
rest is the record: every act is a proposal and an execution written to append-only
tables, in their own commits. That is not overhead to optimize away; it is what makes
an agent's actions auditable. With `durable` every one of those records pays its own
flush, and a flush is the disk: `propose` + `commit` pay two, `propose_and_commit`
writes both records in one commit and pays one (counted by `tests/flushes.sh`). A
durable act costs about the gate's own work plus one or two flushes, so its number
is mostly the disk's, and only as good as the disk it was taken on.

Two of the checks scale with the catalog: the commit backstop reads the transaction's
tuple statistics (twice per kept write), and `no_amplification` walks the inheritance
of the target. On a database with thousands of tables, expect the per-act cost to
grow; run `make bench` against your own schema. Build PostgreSQL without
`--enable-cassert` for it (pgrx's own instance has assertions on, which inflates
every number).

## Upgrading

**Copying a new `.so` does not upgrade anything.** Most of what this extension
guarantees lives in its SQL -- the triggers that keep the record append-only, the
functions that write it -- and that SQL runs once, inside `CREATE EXTENSION`. A
database where the extension already exists keeps the old schema until you say:

```
ALTER EXTENSION pg_agent_gate UPDATE;
```

That is not hypothetical. 0.2.0 closes two defects that live in the SQL, and
while preparing it the new library was loaded into a live database whose schema
stayed at 0.1.0: the `TRUNCATE` hole was still open, and the library was calling
a two-argument `_load_proposal` that did not exist there, so every commit an
agent made would have failed. Nothing broke only because that database had no
agents registered yet.

`tests/upgrade.sh` measures the upgrade against the real old schema, kept in
`tests/fixtures/` byte for byte, rather than against a freshly built one: an
extension is installed clean once and upgraded for the rest of its life, and
until now only the case that happens once was being tested.

## Notes for extension authors

* **pgrx's `SpiClient::update` assigns a transaction id before running
  anything** (it calls `GetCurrentTransactionId()` to mark the transaction
  mutable). A transaction with an id writes a commit record, and a durable
  commit record is an fsync. The first version of this extension used it for
  internal reads: every `discover` paid a flush, and the question "did this
  transaction already write?" answered itself yes by being asked. Reads here
  go through `SpiClient::select`; that question is asked with
  `GetTopTransactionIdIfAny()`.
* **`CREATE EXTENSION` does not grant `USAGE` on the extension's schema.** An
  agent could not even propose until the script granted it.

## Threat model

**The adversary is the agent.** A model that hallucinates, a model that was
prompt-injected, or a fully hostile client: it holds a connection as its role
and can send anything the wire protocol carries -- any statement, any startup
parameter, the extended protocol, a cursor, garbage.

**Where the line is.** The gate bounds what the agent *names* -- the statement it
proposes and the rows that statement changes -- plus the row count. What a DBA
attaches to a table (a trigger, a `CHECK` or `DEFAULT`, a generated column, a
view) is trusted code that runs with its own rules: the gate refuses the nested
*utility* such code fires (0.2.4) and counts the rows it writes, but it does not
read a definer function's body or re-decide what a view may show.

**What the gate guarantees against it**, each with a suite above:

* nothing the session types executes except the seven verbs;
* a proposal runs only after PostgreSQL's parser, planner, analyzer and
  rewriter accept it as one statement of a kind the agent may run;
* a write that touches more than `max_rows` rows, or breaks a bound assertion,
  is undone; and its writes over a window stay within its budget (0.4.0); an
  `allow_ddl` agent's `CREATE TABLE AS` or `SELECT INTO` cannot carry a write
  (0.4.2), and the rows a DDL's default, constraint or index expression changes in
  other tables are counted like a write's (0.4.3);
* a read changes nothing the record would not show: no sequence, lock or large
  object, wherever the code that would change it sits (0.4.3);
* no other role can become it: with the library in `shared_preload_libraries`, an
  agent role has no members, so no session but its own login can `SET ROLE` into
  it (0.4.1) -- connect each agent, or each seat of a broker, as its own role.
  With only the per-role `session_preload_libraries` that `register_agent` sets,
  the sessions of other roles do not load the gate, and a superuser's session
  that has not loaded it can still `GRANT` the agent role to another (measured on
  18.6, 2026-11-12): don't, or preload it;
* the context its row-level policies read cannot be moved -- not by `SET`, not
  at connection start, not by `set_config()` inside a proposal: in the statement,
  in SQL passed to a function as text, in a function's body, a constraint or a
  default (0.4.2), a domain's `CHECK` or a type's support function (0.4.3), nor by a
  function's `SET` clause (0.4.2);
* everything it proposed and did is recorded append-only, including why
  anything was refused.

**What it trusts, and is out of scope:**

* **superusers**, and whoever can edit `postgresql.conf` or restart the server:
  they can unload the gate. That is why `register_agent` refuses a superuser
  role -- an agent that can leave the gate is not behind it;
* **the DBA's grants**: `GRANT` is still the authorization. The gate adds
  verification, it does not invent privileges or take them away;
* **the functions and views the agent is granted**: they run with their own
  rules (see below);
* the operating system and the server binaries.

**What it does not protect, by design: intent.** A well-formed statement,
within the agent's privileges and under `max_rows`, runs. Measured: asked to
"set every customer's plan to free", the model wrote
`UPDATE ... WHERE plan <> 'free'`, which touched 2 rows under a limit of 5, and
the gate kept it -- correctly, by its contract. Bound the blast radius with a
small `max_rows`, bind assertions that must keep holding, and put a human on
`dry_run` for writes that matter.

## What it does not cover

Said here so nobody learns it the hard way:

* **A function's body is trusted to be what the function is marked.** The gate
  does not read a body. It judges each function where it starts (0.4.3): wherever
  reached in an agent's session, it stops `set_config()`, a function that runs
  SQL from a text, a built-in that changes state outside counted rows, a function
  the agent can alter (its marking is then its own claim) and one whose `SET` clause
  moves the context a policy reads. What remains is a DBA's function marked `STABLE`
  or `IMMUTABLE` that writes: it runs, and only the row-count backstop of a write or
  a DDL sees what it changed. PostgreSQL grants `EXECUTE` on every new function to
  `PUBLIC`, so not granting is not enough: `REVOKE EXECUTE ... FROM PUBLIC` on
  any function an agent must not reach.
* **Built-ins reached from C code are not judged one by one.** PostgreSQL looks a
  built-in up by a fast path that asks no hook. The executor's hook still sees every
  built-in an expression calls; what C code calls through a cache (the type cache,
  an RI check, index support) is chosen by DDL only a superuser runs -- operator
  classes, base types -- or, for a range type's support function, has a signature no
  built-in that changes state has.
* **Code an `allow_ddl` agent plants runs for whoever uses its objects.** Its
  functions never start in its own (or any agent's) session, but a human or an
  application that inserts into its table, casts to its domain or builds on its range
  type runs them with their own rights -- PostgreSQL's rule for any role that may
  create objects. Keep agents' schemas out of other roles' paths. In an agent's own
  session, what its objects call is its code (third review of 0.4.3): a `VOLATILE`
  function of another role's that an object of the agent's calls -- a domain's `CHECK`, a
  default, an index, a trigger -- is judged as the statement's own call. Native code (C,
  an untrusted language) is refused in every statement, so a C trigger function from
  contrib on an agent's table refuses its writes; SQL and PL/pgSQL are refused in reads
  and run in writes -- but a `DEFAULT` of the agent's own table that an `INSERT` relies on
  is written into the statement by the rewriter, and is judged there as the statement's own
  call: `no_opaque_function` refuses a volatile user function in it. Two more edges: the
  judgment is by function, not by call site,
  so once an agent's object calls a DBA's function every call of it in that agent's
  sessions is judged so; and it knows what PostgreSQL records in `pg_depend` -- a
  PL/pgSQL body records nothing, so a DBA's function that an agent's PL/pgSQL function
  calls is never reached that way (the agent's function never starts), and a call the
  DBA's own PL/pgSQL body makes stays the DBA's.
* **A persistent object of the agent can still answer for a name a DBA's code does not
  qualify.** An agent creates no temporary object (0.4.3), so `pg_temp` answers for
  nothing; but a schema the agent can create in, searched before the DBA's -- `ALTER ROLE
  agent SET search_path = agent_schema, public`, or a schema named after the agent's role
  under the default `"$user", public` -- puts the agent's table or type ahead of the DBA's
  in the agent's own session, and a policy helper that names `tenant_of` unqualified reads
  the agent's. A function is not affected (one the agent can alter never starts). Name
  tables in policy helpers with their schema, or pin `SET search_path = public, pg_temp` on
  them, and put an agent's schema after the DBA's.
* **The built-ins are classified by PostgreSQL's marking and one reviewed list.** A
  `VOLATILE` built-in that a later PostgreSQL adds is refused until it is reviewed (closed);
  the list was derived on 18.6 and 19beta2 (`verify.rs`, `state_change`). A built-in that
  PostgreSQL marks `STABLE` or `IMMUTABLE` is trusted not to change state.
* **The context is what the session started with.** The placeholders and the named
  parameters; a module's own parameter is not part of it (a value the role gives one before
  the module loads may be respelled when it does). The gate refuses rather than resets: a
  session whose context moved is refused until it `RESET`s or reconnects.
  pg_living_assertions 0.5.5's `run()` left the assertion's `search_path` in the session
  (fixed in its 0.5.6), so under 0.5.5 a write with a bound assertion is refused.
* **A module's parameter in a DBA's `SET` clause passes once the module defines it**, or
  when it is named after an installed extension (`pg_trgm.*`, `plpgsql.*`). One that is
  neither when the function is judged -- `hnsw.*` before anything loaded `vector` in that
  session -- is refused as a placeholder would be (closed).

* **Without the library loaded before the agent's first statement, the gate
  fails open.** `whoami()` reports `enforced`. Use `shared_preload_libraries`.
* **Existing connections** of a role are not behind the gate until they
  reconnect.
* **A dump of the database does not carry who is an agent.** `register_agent`
  marks the role (`ALTER ROLE ... SET agent_gate.agent`), and roles belong to
  the cluster: `pg_dump` leaves the mark out, `pg_dumpall --globals-only` has
  it. Restored into a server without the globals, the record still says the
  role is an agent while the role is outside the gate. The record itself does
  survive `pg_dump`; `tests/dump_restore.sh` checks both halves.
* **An agent session may change only the session parameters on an allowlist**:
  client formatting and time limits, which is what a driver sets on its own
  (`application_name`, `client_encoding`, `DateStyle`, `statement_timeout`,
  the transaction characteristics, and a few more). `SHOW` and transaction
  control pass, and so do `DISCARD` and `DEALLOCATE` (a pool's reset, which puts the
  session's own state back); everything else is refused, including `role`,
  `session_authorization`, every `agent_gate.*` setting even if someone granted
  `SET ON PARAMETER` on it, and -- the reason it is an allowlist and not a list
  of forbidden names -- whatever the application decides with. A row-level
  policy over `current_setting('app.tenant_id')` is the ordinary way to
  separate tenants, and no denylist can name the parameters an application
  invents: measured, an agent could point that policy at another tenant and the
  same read returned the other tenant's row (`tests/rls_isolation.sh`).
  **An agent's context is set on its role** (`ALTER ROLE ... SET`), and a DBA
  who needs one more parameter adds it to `agent_gate.settable` -- which is
  saying, out loud, that no policy of theirs stands on it.
* **The allowlist also covers parameters set when the connection starts.** A
  startup parameter -- libpq's `PGOPTIONS`, the `options` property of pgjdbc
  and node-pg -- is not a statement and reaches no hook, and a value the client
  sets at startup outranks the one on the role. Measured with pgjdbc 42.7.13,
  node-pg 8.23.0 and libpq before this was covered: `options=-c
  app.tenant_id=2` and the agent read the other tenant's row
  (`tests/drivers.sh`). An agent session that started with a parameter outside
  the allowlist now fails closed: every statement it sends is refused. What the
  drivers send on their own (`client_encoding`, `DateStyle`, `TimeZone`,
  `extra_float_digits`, `application_name`, a `statement_timeout` in `options`)
  is on the list and keeps working. `TimeZone` (and `DateStyle`, `IntervalStyle`) are
  inputs to a policy too: one that compares with `current_date`, or casts to `date` or
  `timestamp`, reads the session's zone, so an agent that sets `TimeZone` sees what a
  policy dates in another zone -- measured, a row embargoed until tomorrow, of its own
  tenant. Write such a policy with `timestamptz` and an explicit zone (`now() AT TIME
  ZONE 'UTC'`, a `date` column compared in that zone): the allowlist keeps `TimeZone`,
  because every driver sends it.
  `search_path` is deliberately not on it, so
  a driver configured with a default schema will be refused: pgjdbc's connection
  code sends `currentSchema` as the startup parameter `search_path` (read in
  the driver, not measured here). Set the agent's schema on its role instead.
* **The fast-path function-call protocol** (`PQfn`) skips the parser. Since
  0.2.12 an agent session answers it only for the verbs: any other function
  reached that way -- large objects, `pg_read_file` -- is refused by the
  object-access hook before it runs.
* **What dry_run showed is what commit keeps (0.2.14).** The session settings that
  decide how a statement reads its literals and writes its values -- `DateStyle`,
  `IntervalStyle`, `TimeZone`, `standard_conforming_strings`, `extra_float_digits`,
  `bytea_output` -- are recorded at `propose`, and `dry_run` and `commit` refuse if
  any changed since. Measured on 0.2.13: `dry_run` showed March 4, the session set
  `DateStyle = 'ISO, DMY'`, and `commit` kept April 3.
* **A read changes nothing (0.2.14).** A `read` that calls a built-in which changes
  state outside the rows it returns -- `nextval`, `setval`, the `pg_advisory_*` locks,
  large objects, `pg_notify`, `setseed`, WAL and statistics functions -- is refused;
  until 0.2.13 one advanced a sequence 100,000 times and the record said `read`. In a
  write they are allowed (an INSERT's default calls `nextval`). A user function that
  is STABLE but calls one of them is not seen: its body is not in the statement.
* **A reused agent name starts clean (0.2.14).** A proposal made under an earlier
  registration of the same name answers like another agent's, and `acts()` shows only
  the current registration's.
* **The record takes bounded input (0.2.14):** `agent_gate.max_proposal_bytes` (1 MB,
  SQL plus parameters) and `agent_gate.max_intent_bytes` (64 kB), superuser-only. The
  record stays append-only with no retention helper: reclaiming space still means
  disabling its triggers by hand.
* **The verbs run only under READ COMMITTED (0.2.12).** At a stricter level the
  gate would read the proposal and the record from an old snapshot; measured on
  0.2.11, four REPEATABLE READ sessions each kept the same proposal. A verb
  called at another level is refused. Two-phase commit (`PREPARE TRANSACTION`)
  is refused in an agent session.
* **With `attempt_durability = fast`, a crash can lose records of attempts**
  that changed nothing. Never of changes.
* **`lastval()` names the gate's own sequence in an agent's session.** Each verb draws from
  the record's sequences after the agent's statement, so `SELECT lastval()` (PHP PDO's
  `lastInsertId()` with no sequence name) is refused for lack of privilege on the gate's
  sequence. `INSERT ... RETURNING` and `currval('the_sequence')` give the agent's own value.
* **`dry_run` is a rollback, not a sandbox.** Sequence values, session advisory
  locks, and anything outside the transaction (`dblink`, untrusted languages)
  are not undone.
* **A row-level policy that calls a `SECURITY DEFINER` function refuses every
  proposal on its table.** The common membership helper (`USING (is_member(tenant))`,
  `SECURITY DEFINER` so it can read the membership table) is in the analyzed tree --
  the rewriter adds the policy's qual -- so `no_opaque_function` refuses the statement,
  and since 0.2.7 the function-manager hook would stop it anyway. That is the price of
  the rule, not an accident: write such a policy over a `security_invoker` helper or a
  plain subquery on a table the agent may read, or the table is out of the agent's reach.
* **An opaque user function is refused (0.2.3).** A statement that calls a user
  function which is volatile or `SECURITY DEFINER` is refused at `propose`
  (`no_opaque_function`): its body is not in the analyzed tree, so it could write
  rows no one counts or run as its owner outside the agent's tenant. Built-ins
  (`pg_catalog`, e.g. `gen_random_uuid()`) and non-volatile, non-`SECURITY DEFINER`
  user functions pass. There is no allow-list for functions in 0.2.3, so a volatile
  helper that does not write should be marked `STABLE` or `IMMUTABLE`. Measured
  (`tests/hostile.sh`): such a function inside a WRITE is refused and writes nothing.
* **`no_opaque_function` walks the proposal's query tree, not every place a function can hide --
  this is a class, not a fixed list.** It follows direct calls, operators, `= ANY`/`IN`,
  aggregates and window functions in the statement itself. It does NOT follow a function reached
  any other way: through a row comparison (`RowCompareExpr`), an aggregate's own transition or
  final functions, an I/O or user cast, or a function the *catalog* attaches rather than the
  statement -- a column `DEFAULT`, a `CHECK` or domain constraint, a generated column, an
  expression index, or the body of a view or another function the statement touches. (The
  rewriter does write a column `DEFAULT` into an `INSERT`, or an `UPDATE`'s `SET c = DEFAULT`; since
  the fourth review of 0.4.3 the walker sets it apart when it is exactly the catalog's `DEFAULT` of
  a table the agent cannot alter and not something the agent wrote, so a DBA's
  `gen_random_bytes()` or order-number `DEFAULT` no longer refuses the agent's `INSERT`. That is
  the owner's code, judged by the floor when it runs, like a `CHECK`. A `DEFAULT` of the agent's
  own table is still walked as its call.) For ordinary
  DML done this way the commit backstop still counts the rows against `max_rows` (bounded in COUNT,
  though not in tenant or privilege -- like an allow-listed trigger, a row written this way is
  counted but not tenant-filtered). A nested UTILITY is worse than uncounted: `pg_stat_xact`
  ignores `TRUNCATE`, so the backstop could not bound a `TRUNCATE`, `GRANT`, `ALTER` or `DROP` a
  function fires. **0.2.4 refuses any utility a trigger, constraint or function reaches while the
  gate runs the verified statement** (on the gate's own execution flag, not `current_user` --
  inside a `SECURITY DEFINER` function the agent is already the owner). Measured: a `CHECK` whose
  function `TRUNCATE`d a table ran on a plain `INSERT` the agent proposed -- before 0.2.4 the table
  was emptied and kept; now the same statement aborts and the table is intact. The window spans the
  gate's own `SET CONSTRAINTS`, so a utility fired by a DEFERRED constraint trigger is caught too;
  the one utility the gate runs on purpose (an `allow_ddl` agent's own DDL, and the `SET
  CONSTRAINTS`) is exempted, so it still goes through. This refuses ALL nested utility, benign
  included -- a trigger that does `NOTIFY`, `SET LOCAL`, `LOCK TABLE`, `CALL` or `CREATE TEMP TABLE`
  makes the statement abort (`pg_notify()` called as a function is fine). **A `SECURITY DEFINER`
  function reached through any of these positions is stopped before it runs (0.2.7).** Every
  `SECURITY DEFINER` call goes through PostgreSQL's `fmgr_security_definer`, which calls the
  function-manager hook before the body; while SQL the agent wrote is running (verification, the
  verified statement, its deferred constraints, an allowed DDL) the gate refuses there, however the
  call was reached -- another function, a `CHECK` or domain constraint, a default, a generated
  column, an expression index, a trigger, or the planner folding an `IMMUTABLE` wrapper at
  `propose`. Measured on 0.2.6: such a wrapper verified and ran its `SECURITY DEFINER` callee at
  `propose` and again at `commit`; now neither, and the write a `CHECK` reached that way is not kept
  (`tests/plan_time.sh`). There is no allow-list for it. What this does NOT stop, because it is not
  a `SECURITY DEFINER` call: a non-`SECURITY DEFINER` function in those positions (it runs with the
  agent's rights; if it writes, the commit backstop counts the rows), a referential action, which
  runs as the table owner by its own mechanism, and a view without `security_invoker` (below).
* **A cascade, trigger or rule that amplifies a write is refused (0.2.2/0.2.3).**
  Its extra rows run as the table owner, outside the agent's `max_rows` and -- for a
  referential action -- its tenant. `agent_gate.allow_write(agent, table)` re-permits
  one table, but only for what the gate can check: a trigger whose own function is not
  `SECURITY DEFINER`. A cascade and a rule are NOT allow-listable in 0.2.3 (making some
  cascades safe needs a recursive closure over the cascade edges, and lands in 0.2.4),
  and a SECURITY DEFINER trigger never is. The commit backstop still counts every
  amplified row against `max_rows` (it over-counts, the safe side). A row an `UPDATE` moves to
  another partition is a delete and an insert in those counters. Since the fourth review of 0.4.3
  it is counted once: no more rows than the statement can only have moved -- what it named minus
  the updates, and no more than the inserts and deletes in its target's leaves -- are taken off.
  Before, an `UPDATE` of a partition key was refused above half of `max_rows`. A `MERGE` that moves
  rows, and a tree with a foreign or non-heap leaf, are still counted twice. It reads
  `pg_stat_xact_user_tables`, which counts USER TABLES only -- not foreign tables, large
  objects, sequences, or effects outside the transaction; a `TRUNCATE` it does not count is
  instead refused as a nested utility (0.2.4). "What the gate can check" is the honest bound: a non-SECURITY DEFINER
  trigger can still fire a cascade of its own that runs as a table owner outside RLS -- the gate
  does not see the body. (A `SECURITY DEFINER` function it calls is stopped since 0.2.7.) Its rows are
  counted (so the limit holds) but not tenant-filtered. Allow-listing a trigger is a
  risk the DBA accepts for that one table; the backstop is the floor under it, not RLS.
* **A view is checked with its owner's privileges unless it was created with
  `security_invoker`.** An agent granted `SELECT` on such a view reads the
  tables behind it, including ones it has no privilege on at all: measured, a
  secret came through that way. That is PostgreSQL, not the gate -- the gate
  verifies the proposal, it does not re-decide what a view may show. `discover`
  lists the view, because the agent was granted it, and not the table behind.
* **`EXPLAIN` folds constant calls to immutable functions.** A DBA's function
  falsely marked `IMMUTABLE` runs at `propose` (with the guards above in place:
  no `set_config()`, no `SECURITY DEFINER` under it). Marking functions honestly
  is a prerequisite for the DBA's functions; a function the agent can alter is
  refused whatever it is marked (0.4.2).
* **The record is transactional.** Inside an explicit transaction that the
  caller rolls back, the record rolls back too; so does a `propose_and_commit`
  that is cancelled, or that fails outside the gate's own subtransaction, where
  `propose` + `commit` would have kept the proposal. Every verdict is also written
  to the server log, which does not roll back -- the verdict (agent, proposal id,
  kind, outcome) -- and since 0.2.10 so is every row a rollback takes, statement
  and intent included. **The server log can hold what an agent wrote:** the gate's
  rollback lines, and PostgreSQL's own `log_statement` or
  `log_min_duration_statement` if configured, which log the `agent_gate.propose(...)`
  call verbatim. A value passed as a parameter shows as `$1` in the statement; a
  literal in the SQL shows as written.
* **Parameters travel as text.** Cast them in the SQL (`$1::int`). A `varchar[]` -- what
  pgjdbc binds for a `String[]` -- is accepted as the parser coerces it (0.4.3).
* **The verbs do not run in a read-only transaction (0.4.3).** Every proposal, a read too,
  is written to the record first, so a `READ ONLY` transaction (pgjdbc's `setReadOnly(true)`)
  and a hot standby are refused, saying so.
* **A cast that runs a function around a verb's argument is refused (0.2.15).**
  Only the implicit cast the parser inserts to coerce a constant to the verb's own
  parameter type, through a built-in function, passes. An explicit cast, an I/O
  conversion cast, or a cast through a user function would run that function while
  the executor evaluates the argument -- before verification raises the proposal
  flag, so the definer guard would not see it -- and is refused at parse time. Pass
  such values as parameters, or cast them inside the proposed SQL (`$1::int`), where
  verification covers them.
* **`allow_ddl` is schema power, not a bigger `max_rows`.** An agent allowed DDL runs
  any `CREATE`, `ALTER` or `DROP` its grants permit; the change is verified by running
  it in a rolled-back subtransaction and kept only if that succeeds, but `max_rows`
  does not bound what it does to the agent's own tables: a granted `DROP TABLE` is
  kept, and an `ALTER COLUMN ... TYPE ... USING` rewrites every row of one with 0 rows
  counted. The query of a `CREATE TABLE AS`, `SELECT INTO` or `CREATE MATERIALIZED
  VIEW` is checked like a read before it runs (0.4.2), so it cannot carry a writing
  CTE, and a function the agent creates never starts in an agent's session. An expression
  a DDL evaluates -- a `DEFAULT` filled in by `ALTER TABLE`, a `CHECK`, an index
  expression -- runs under the same floor, and what it changes in tables that existed
  before the DDL counts against `max_rows` and the budget (0.4.3). A sequence it
  advances at commit is not undone. What PostgreSQL drops or alters for it is judged by
  owner, not counted: an object of a role whose privileges the agent has is its own, and
  an object with no owner of its own that a type's drop takes with it (a cast, a
  transform) is not judged. A DDL that creates a sequence may draw from it at propose; if
  it also draws from one that existed before (`ADD COLUMN s serial, ADD COLUMN n bigint
  DEFAULT nextval('public.s')`) it is refused after the trial, and the values it drew are
  gone, as any rolled-back `nextval()` leaves them -- and so is the value a DBA's DDL-audit
  event trigger draws for each trial. That judgment reads the sequences the transaction
  holds locked, so one locked earlier in the same transaction refuses a `serial` (closed).
  Grant DDL narrowly, and leave `allow_ddl => false` unless a specific agent needs it.

## License
Apache License 2.0 -- see [LICENSE](LICENSE). Copyright 2026 Manuel Reyes Bravo.

The name is not licensed with the code: see [TRADEMARK.md](TRADEMARK.md).
Security reports: [SECURITY.md](SECURITY.md). Contributions:
[CONTRIBUTING.md](CONTRIBUTING.md).

