# pg_agent_gate

**Agents propose, PostgreSQL decides.**

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
   column, type, operator and function must exist and fit. A `SELECT` whose
   CTE writes is reclassified as a write. DDL (for agents allowed it) is
   verified by running it in a subtransaction that is rolled back.

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

## gated-mcp: an MCP server that cannot execute anything

For clients that only speak MCP. `gated-mcp/` is a small Bun + Hono server
exposing the six verbs as six MCP tools over Streamable HTTP. Unlike an
ordinary MCP server for PostgreSQL, it holds no power of its own: it connects
**as the agent role**, so it is not where the gate lives -- replace it with
anything and it still can only call the verbs. Six tools, never one per table:
what the agent may touch comes from `discover`.

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
| extra time per read (`propose` + `commit`) over running the query directly, default settings | <= 10 ms | **0.41 ms** |
| extra time per kept write over the same `UPDATE` run directly (which pays its own durable commit) | <= 5 ms | **0.41 ms** |
| throughput lost by preloading the library in sessions that are not agents (`pgbench -S`, median of 5 alternating pairs) | <= 3% | **0.43%** |
| extra time per read with `attempt_durability = durable` | <= 10 ms | **14.7 ms -- fails** |

The last row is the first cost criterion, kept with the semantics it was
declared with. On the test machine one `fdatasync` costs about 5 ms (Btrfs with
copy-on-write), and with every record durable a read act pays two. The default
does not, and the crash control above is what shows it gave nothing up for it.

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

## What it does not cover

Said here so nobody learns it the hard way:

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
  proposal, not every function body.
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

PostgreSQL License.
