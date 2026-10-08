# Changelog

## 0.2.2 -- 2026-10-07

A cross-tenant breach, the same shape as the 0.2.1 bugs -- the gate counted the
top-level statement and the real effect was larger -- but worse, because the
extra effect also escaped row-level security. Found by the fuzzer's cascade
probe against a two-tenant database with a superuser watching.

* **A referential action amplified a write across tenants.** A referential
  action (ON DELETE/UPDATE CASCADE, SET NULL, SET DEFAULT) runs as the table
  owner and does NOT force RLS. A tenant-1 agent deleting a tenant-1 parent
  cascade-deleted a **tenant-2** child row it could never have named -- the gate
  reported one row and kept it (measured). New check `no_amplification`: a write
  whose target table has an inbound cascading foreign key is refused at
  `propose`, naming it. The same check also refuses a target that carries a user
  trigger or a rule: those amplify the row COUNT past `max_rows` (a normal
  trigger runs as the invoker, so RLS still applies to it; only a SECURITY
  DEFINER one would cross a tenant -- rules were not measured, refused
  conservatively). Inheritance and partition children of the target are included,
  and a lookup that fails refuses rather than passes (fail closed).
* Regression: `tests/fuzz.py` fixes a tenant-2 child of a tenant-1 parent into
  the schema (so `safe_fp` covers the whole class), an amplification teeth check
  (cascade and trigger), and a k=1..8 differential oracle for `max_rows` -- all
  run on every push via `FUZZ_ITERS=0`. Red against 0.2.1.
* Not yet covered (0.2.3): a volatile or SECURITY DEFINER function that writes,
  which is a read at `propose`. No schema changes; the upgrade script only moves
  the version.

## 0.2.1 -- 2026-10-06

Two holes, found by an LLM proposing through the gate against a two-tenant
database while every suite was green. Both now refused at `propose`, failing
closed, and both have regression cases that are red against 0.2.0.

* **A CTE that writes dodged `max_rows`.** The limit counted the rows of the
  outer statement only; `with d as (delete ...) select count(*) from d` deleted
  12 rows under a limit of 5. New check `no_writing_cte`.
* **`set_config()` inside a proposal moved the tenant** a row-level policy reads
  (`... where set_config('app.tenant_id', '2', true) is not null` read another
  tenant's rows). Matched by OID anywhere in the analyzed and rewritten tree.
  New check `keeps_its_context`.
* `make verify`, `make clean-machine` (CI: PostgreSQL 18 and 19), `make demo`,
  `make bench`; README with the threat model and the measured cost.
* License changed from the PostgreSQL License to the Apache License 2.0.
* No schema changes; the upgrade script only moves the version.

## 0.2.0 -- 2026-09-15

* `TRUNCATE` could empty the append-only record (row triggers do not fire on
  it): statement-level triggers now refuse it.
* Two concurrent `commit`s of the same proposal both ran it: the proposal's row
  is now locked while a commit decides.
* **An agent could move what its row-level policies read**: session parameters
  are now an allowlist (client formatting and time limits, plus
  `agent_gate.settable`), and startup parameters (`options=-c ...`) are judged
  by the same list.
* An agent could leave the gate with one mistaken `GRANT`; the record's writers
  now ask the gate whether the caller is the gate's own code.
* `attempt_durability`: the record of an attempt that changed nothing may ride
  an asynchronous commit (`fast`, default); a kept change is always as durable
  as the server. Reads no longer assign a transaction id, so they stop paying a
  flush.
* Sessions that are not agents take a path through the hooks that allocates
  nothing.
* `gated-mcp/`: an MCP server that connects as the agent role and can only call
  the verbs, speaking the 2026-07-28 and 2025-11-25 protocol revisions.
* The suites claim their database and role names instead of dropping whatever
  is there; `tests/adversarial.sh` tries every channel a session can type.

## 0.1.0 -- 2026-09-14

First version: an agent session can only call six verbs (`discover`,
`propose`, `dry_run`, `commit`, `acts`, `whoami`); PostgreSQL verifies each
proposal with its own parser and planner, runs it with the agent's privileges,
bounds it by `max_rows` and bound assertions, and records everything
append-only.
