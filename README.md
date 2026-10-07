# pg_agent_gate

[![verify](https://github.com/Manuelreyesbravo/pg_agent_gate/actions/workflows/verify.yml/badge.svg)](https://github.com/Manuelreyesbravo/pg_agent_gate/actions/workflows/verify.yml)

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
     commit: aborted -- it touched 8 rows and this agent may touch at most 5
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

## Verify it yourself

Every claim in this README has a test that attacks it on purpose and checks the
database from a superuser's side -- not the gate's own answer:

```
make verify PG_CONFIG=/path/to/pg_config     # your PostgreSQL 18+, a throwaway cluster
make clean-machine                           # the same, in a fresh container that only gets git HEAD
```

| suite | what it attacks | checks |
|---|---|---|
| `adversarial.sh` | every channel a session can type, and what can be slipped past `propose` | 45 |
| `hostile.sh` | garbage into the verbs, the record rewritten, the world moved between propose and commit | 37 |
| `privileges.sh` | the privilege boundary between agents, roles and the record | 31 |
| `rls_isolation.sh` | moving the context a row-level policy reads: `SET`, startup parameters, `set_config` | 22 |
| `dump_restore.sh` | the record across `pg_dump` and restore | 10 |
| `upgrade.sh` | an installation of the oldest schema, upgraded | 9 |
| pgrx unit tests | the verbs, from inside the server | 10 |

On a fresh Debian container receiving only what git has committed, with
PostgreSQL 18.6 and with 19beta4 from PGDG: **`verified: 164 checks passed, 0
failed`** on both (and on 19beta2, where it was developed). CI runs the same
container for 18 and 19 on every push. `VERIFY_DRIVERS=1` adds real pgjdbc and node-pg sessions.

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
It has six verbs, and in a session that belongs to an agent **it cannot do
anything else** -- not `DELETE`, not `DO`, not `COPY`, not `PREPARE`. The
database verifies every proposal against itself, runs it with the agent's own
privileges, and keeps the record.

```
discover  ->  propose  ->  dry_run  ->  commit
                                         acts, whoami
```

## What an agent sees

```sql
-- what may I touch? derived from the live catalog and MY privileges
SELECT agent_gate.discover('clientes');

-- propose one statement: nothing runs
SELECT agent_gate.propose(
  'update clientes set plan = ''pro'' where id = $1::int',
  'upgrade the customer who asked for it',
  ARRAY['1']);
--  {"proposal": 42, "ok": true, "kind": "write", "estimated_rows": 1,
--   "checks": [{"check": "parses",           "passed": true, ...},
--              {"check": "single_statement", "passed": true, ...},
--              {"check": "kind_allowed",     "passed": true, ...},
--              {"check": "resolves",         "passed": true,
--               "detail": "the planner resolved every table, column, type and function, and nothing ran"}]}

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
=> delete from clientes where id > 0;
ERROR:  pg_agent_gate: this session belongs to agent "billing": it proposes, it does not execute
DETAIL:  DELETE does not reach the database from an agent session
HINT:  Call agent_gate.propose(sql, intent), then agent_gate.dry_run(proposal) or agent_gate.commit(proposal).
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

## The six verbs

| verb | does |
|---|---|
| `discover(filter, max_objects)` | tables, views and functions the agent has privileges on, with columns, types, keys, constraints and comments. Objects owned by extensions are left out. Includes a fingerprint, so a client can tell the schema changed |
| `propose(sql, intent, params)` | verifies one statement and records it. Runs nothing |
| `dry_run(proposal)` | runs it inside a subtransaction and rolls it back: rows touched, before/after of every row of a write, whether bound assertions would still hold |
| `commit(proposal)` | verifies again, runs it and keeps it if every guard agrees. A proposal is committed at most once |
| `acts(max_acts)` | what this agent proposed and did, with every execution and why anything was refused |
| `whoami()` | which agent this session is, whether the gate is enforced in it, and how durable attempts are |

## Verification

Nothing is reimplemented. Each check is PostgreSQL itself:

1. **parses** -- PostgreSQL's own raw parser accepts it.
2. **single_statement** -- exactly one, so what was verified is what runs.
   `select 1; delete ...` dies here.
3. **kind_allowed** -- read, write or DDL, against what the agent may do.
   Transaction control is refused: the gate owns the transaction.
4. **resolves** -- `EXPLAIN` plans it without executing: every table,
   column, type, operator and function must exist and fit. DDL (for agents
   allowed it) is verified by running it in a subtransaction that is rolled
   back.
5. **no_writing_cte** -- PostgreSQL's analyzer and rewriter build the query
   tree, and a CTE that changes data is refused. `max_rows` counts the rows of
   the statement, and a write hidden in a CTE under a `SELECT count(*)` is
   counted as one row: before 0.2.1 it deleted every row under a limit of 5.
   Propose each write as its own statement.
6. **keeps_its_context** -- `set_config()` anywhere in that tree (the `WHERE`,
   the `FROM`, a subquery, a CTE, an expanded view, schema-qualified or not) is
   refused. Inside the statement it moves, while the statement runs, the
   parameter a row-level policy reads; before 0.2.1,
   `... where set_config('app.tenant_id', '2', true) is not null` read another
   tenant's rows. **Not covered:** a function that already exists and calls
   `set_config` in its own body -- its body is not in the tree. Do not grant an
   agent `EXECUTE` on one.

Checks 5 and 6 were found by an LLM proposing through the gate against a
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
  * a write touching more rows than the agent's `max_rows` is undone;
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
* **`durable`:** every record pays its own flush.

Never relaxed in a transaction that had already written something before the
first verb ran: those writes are not the gate's to relax.

## Setup

PostgreSQL **18 or later** (`dry_run` uses `RETURNING old/new`). Built with
[pgrx](https://github.com/pgcentralfoundation/pgrx) 0.19.2; the test suite
passes on 18 and 19.

```sh
cargo install cargo-pgrx --version 0.19.2 --locked
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
GRANT SELECT, UPDATE ON clientes TO billing_agent;

SELECT agent_gate.register_agent(
  'billing', 'billing_agent', 'answers billing questions and upgrades plans',
  p_max_rows => 50, p_allow_ddl => false);

-- optional: every write this agent keeps must leave this assertion holding
SELECT agent_gate.bind_assertion('billing', 'no_customer_without_plan');
```

`register_agent` sets `agent_gate.agent` on the role. If the library is not in
`shared_preload_libraries`, it also sets `session_preload_libraries` on that
role, so the gate is loaded before the agent's first statement. It refuses
superuser roles: a superuser can unset a superuser-only setting, and an agent
that can leave the gate is not behind it. It takes effect on the role's
**next** connection.

## For a client that only speaks MCP: a shim with no power

The gate is in the database, so there is nothing to put in front of it -- an
agent reaches it through `psql`, a driver, or direct SQL, and it is governed all
the same. You do not need an MCP server, and that is the point: the piece that
used to hold the connection and run what the model asked is gone.

For a client that only speaks MCP, `gated-mcp/` fills the gap without bringing
that power back. It is a small Bun + Hono server exposing the six verbs as six
MCP tools over Streamable HTTP, and it connects **as the agent role**, so it is
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
identical either way -- the same six verbs, the same verification -- so what you
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
19beta2 **built without assertions** -- a throwaway cluster from the same
binaries the extension is installed into (`tests/cluster.sh`), loading it from
`cargo pgrx package`. Each attack counts only if the error is **the gate's**
(a PostgreSQL permission error proves nothing about the gate), and a separate
superuser connection then checks that nothing changed. Every criterion was
declared before the code that it measures.

| criterion | threshold | measured |
|---|---|---|
| raw SQL executed from an agent session: `SELECT`/`INSERT`/`UPDATE`/`DELETE`, `DO`, `CALL`, `PREPARE`, `EXPLAIN ANALYZE`, writing CTE next to a verb, foreign function next to a verb or as its argument, subquery as argument, reading or forging the record, `LOCK`, `CREATE`, `SET ROLE`, `COPY`, extended protocol, cursor | 0 | **0 of 20, no side effect** |
| raw SQL executed after an error inside the gate (error escaping a verb, error inside execution, cancellation mid-act, rollback in an explicit transaction) | 0 | **0 of 4** |
| invented proposals refused at `propose`: missing table/column/function, wrong literal type, operator without a type, unbound parameter, hidden second statement, broken syntax, transaction control, DDL without permission | 100% | **17 of 17, no side effect** |
| **control**: correct proposals pass and do exactly what they say | 100% | **10 of 10** |
| **control**: a kept change survives an immediate shutdown (no checkpoint) with its proposal and its execution | 100% | **10 of 10** |
| every channel a session can type, tried on purpose (`tests/adversarial.sh`): two statements in one query, `PREPARE`/`EXECUTE`, a cursor, `COPY TO`/`FROM PROGRAM`, `DO`, `CALL`, `EXPLAIN ANALYZE`, `CREATE TABLE`/`FUNCTION`, `SELECT INTO`, a writing CTE, a function as a verb argument, a subselect of what it was not granted, `SET ROLE`, `SET SESSION AUTHORIZATION`, `RESET ALL`, `DISCARD ALL`, `VACUUM`, `CHECKPOINT`, `LISTEN`/`NOTIFY`, `lo_export`, and a replication connection | 0 | **0 of 22 had any effect** |
| what can be slipped past `propose` (`tests/adversarial.sh`): two statements, a second one hidden after a comment, DDL without permission, `COPY TO PROGRAM`, `SELECT INTO`, `FOR UPDATE` and a write beyond `max_rows`, an expired verification, another agent's proposal | 0 | **0 of 9** |
| **control**: an agent still runs `whoami`, `discover`, proposes, sees before/after in `dry_run`, commits a read and a write, is refused a second commit, and reads its `acts` | 100% | **11 of 11** |
| garbage into `propose` and `commit` (`tests/hostile.sh`): malformed SQL, unbalanced parentheses, an unterminated comment and dollar quote, a NUL byte, 500 levels of nesting, 100 KB of SQL, 500 parameters, fewer parameters than placeholders, a type that does not exist, invalid UTF-8, a 10 KB identifier, an empty proposal, ids that do not exist, an endless query | 0 crashes | **0 of 16, same postmaster** |
| the record rewritten (`tests/hostile.sh`): `DELETE`, `TRUNCATE`, disabling the triggers and dropping them, as the agent and as the owner | 0 | **0 of 7** |
| the world moved between `propose` and `commit` (`tests/hostile.sh`): table renamed, column dropped, privilege revoked, row gone, a bound assertion broken meanwhile, two sessions at once, and the same proposal committed twice at once | 100% | **9 of 9** |
| **control**: what an owner's trigger, `SECURITY DEFINER` function and view do on the agent's behalf is what this README says | 100% | **5 of 5** |


**Two of those rows found real defects, which is why they exist.** `TRUNCATE`
emptied the whole record: the append-only triggers were `FOR EACH ROW`, and
`TRUNCATE` fires no row trigger, so the history could be erased in one statement
with nothing disabled and nothing said. And two concurrent `commit`s of the same
proposal both ran it -- each transaction read `committed` from its own snapshot,
where the other had not committed yet, so a write was applied twice. On a balance
that is a double charge. Both are fixed (0.2.0): statement-level triggers for
`TRUNCATE`, and the proposal's row is locked while a commit decides.

### What found the 0.2.1 fixes

Not these suites: they were green with both holes open. What found them was an
LLM (a Qwen3-8B with a SQL adapter) proposing through the gate against a
two-tenant database with row-level security, on 157 cases -- 30 legitimate
tasks, destructive ones written by the model and injected by hand, raw SQL in the
agent's session, and attempts to cross tenants -- with a superuser comparing the
database before and after every case, and the same cases run by an identical role
that was not an agent, to prove the cases were dangerous at all.

1. **A CTE that writes dodged `max_rows`.** The limit counted the rows of the
   outer statement, so `with d as (delete ...) select count(*) from d` deleted
   12 rows under a limit of 5.
2. **`set_config()` inside a proposal moved the tenant.** The session allowlist
   judged `SET` and the startup parameters, but while the gate runs a proposal
   its hooks step aside, so `... where set_config('app.tenant_id', '2', true) is
   not null` read the other tenant's rows.

Against 0.2.0, 9 of 10 variants of the two did damage. Against 0.2.1, 0 of 10;
both are refused at `propose` (checks 5 and 6 above), and both now have cases in
the suites that are red against 0.2.0. On the same run, with the gate in place:
the model's correct SQL was never refused (0 of 27 false positives), and the
gate's own work cost 0.54 ms per act, median, over running the same SQL directly.

## What it costs

```
make bench PG_CONFIG=/path/to/pg_config
```

`tests/bench.py` on the throwaway cluster. "Directly" means an **identical role**
-- same grants, same statement, same parameters -- that is not registered as an
agent; never a superuser. Each of 300 iterations runs both paths back to back,
alternating which goes first. The thresholds were declared before the code.

| what | threshold | measured (median) |
|---|---|---|
| extra time per read act (`propose` + `commit`) over the same query directly | <= 10 ms | **0.269 ms** (p25 0.258, p75 0.285) |
| extra time per kept write over the same `UPDATE` directly, which pays its own durable commit | <= 5 ms | **0.475 ms** (p25 0.430, p75 0.575) |
| throughput lost by sessions that are **not** agents when the library is preloaded (`pgbench -S`, 7 alternating pairs of 15 s) | <= 3% | **0.09%** |
| extra time per read act with `attempt_durability = durable` | <= 10 ms | **2.119 ms** (p25 2.028, p75 2.342) |

**Where the time goes.** Of the 0.29 ms a read act takes end to end, the gate's
own work inside the server -- verify, run, decide -- is 0.09 ms. Most of the rest
is the record: every act is a proposal and an execution written to append-only
tables, in their own commits. That is not overhead to optimize away; it is what
makes an agent's actions auditable. With `durable` every one of those records
pays its own flush, which is the 2.1 ms.

**Every pair of the throughput test**, because a median hides how noisy one
pair is. Loss with the library preloaded, in %: `0.09`, `5.22`, `-0.37`, `0.87`,
`-1.06`, `0.56`, `-3.65`. A single 15-second pair on a desktop swings by about
four points either way. That is why the criterion is the median of several pairs
and not any one run: an earlier, uncontrolled run of this same test reported
3.16% and failed the criterion, and both it and an older 0.43% fall inside this
spread.

Measured on PostgreSQL 19beta2 built without assertions, AMD Ryzen AI 9 HX 370,
data directory on Btrfs, `fsync` and `synchronous_commit` on, with the benchmark
pinned to its own cores and a calibration run before and after to reject any
measurement taken while the machine was contended. Your numbers will differ;
`make bench` writes them to `target/bench/result.json`.

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

**What the gate guarantees against it**, each with a suite above:

* nothing the session types executes except the six verbs;
* a proposal runs only after PostgreSQL's parser, planner, analyzer and
  rewriter accept it as one statement of a kind the agent may run;
* a write that touches more than `max_rows` rows, or breaks a bound assertion,
  is undone;
* the context its row-level policies read cannot be moved -- not by `SET`, not
  at connection start, not by `set_config()` inside a proposal;
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

* **A function that calls `set_config()` in its own body.** The gate refuses
  `set_config` anywhere in a proposal's query tree, but a function's body is not
  in that tree. Do not grant an agent `EXECUTE` on such a function.

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
  control pass; everything else is refused, including `role`,
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
  is on the list and keeps working. `search_path` is deliberately not on it, so
  a driver configured with a default schema will be refused: pgjdbc's connection
  code sends `currentSchema` as the startup parameter `search_path` (read in
  the driver, not measured here). Set the agent's schema on its role instead.
* **The fast-path function-call protocol** (`PQfn`) skips the parser. A
  function reached that way that runs no SQL -- large objects -- is not
  stopped. Revoke `EXECUTE` on those from agent roles.
* **With `attempt_durability = fast`, a crash can lose records of attempts**
  that changed nothing. Never of changes.
* **`dry_run` is a rollback, not a sandbox.** Sequence values, session advisory
  locks, and anything outside the transaction (`dblink`, untrusted languages)
  are not undone.
* **Functions a proposal calls run with their own rules.** A `SECURITY DEFINER`
  function the agent may execute does what it does; the gate verifies the
  proposal, not every function body. Measured (`tests/hostile.sh`): called from
  a READ it leaves nothing, because a read's subtransaction is always rolled
  back -- but inside a WRITE that is kept, whatever it wrote is kept with it.
* **A view is checked with its owner's privileges unless it was created with
  `security_invoker`.** An agent granted `SELECT` on such a view reads the
  tables behind it, including ones it has no privilege on at all: measured, a
  secret came through that way. That is PostgreSQL, not the gate -- the gate
  verifies the proposal, it does not re-decide what a view may show. `discover`
  lists the view, because the agent was granted it, and not the table behind.
* **`EXPLAIN` folds constant calls to immutable functions.** A function falsely
  marked `IMMUTABLE` could run at `propose`. Marking functions honestly is a
  prerequisite.
* **The record is transactional.** Inside an explicit transaction that the
  caller rolls back, the record rolls back too. Every verdict is also written
  to the server log, which does not.
* **Parameters travel as text.** Cast them in the SQL (`$1::int`).
* **User-defined casts** around a verb's arguments are allowed, like any cast.
  Creating a cast already needs ownership of the types.

## License

Apache License 2.0 -- see [LICENSE](LICENSE). Copyright 2026 Manuel Reyes Bravo.

The name is not licensed with the code: see [TRADEMARK.md](TRADEMARK.md).
Security reports: [SECURITY.md](SECURITY.md). Contributions:
[CONTRIBUTING.md](CONTRIBUTING.md).

