# Changelog

## 0.2.4 -- unreleased

A runtime fix for an uncounted write reached through an unseen function, plus test and docs
hardening from the adversarial review of 0.2.3.

* **The gate now refuses a nested utility statement (fixes an uncounted write via an unseen
  function).** `no_opaque_function` walks the proposal's query tree, not a function the catalog
  attaches (a `CHECK`, `DEFAULT`, generated column, expression index, domain constraint, or view
  body). Measured: a `CHECK` whose `SECURITY DEFINER` function `TRUNCATE`d a table ran on a plain
  `INSERT` an agent proposed -- the walker did not see it, and `pg_stat_xact` does not count
  `TRUNCATE`, so the backstop let it through and the table was emptied, kept. Fix: while the gate
  runs the one verified statement, any utility a trigger, constraint or function reaches from there
  -- `TRUNCATE`, `GRANT`, `ALTER`, `DROP` -- is refused, on the gate's own execution flag, NOT on
  `current_user` (inside a `SECURITY DEFINER` function the agent is already the owner). Measured
  again: the same `CHECK` now aborts and the table is intact. Regression in `tests/fuzz.py`. The
  DISCLOSURE half of the class -- a `SECURITY DEFINER` function in a READ returning rows the agent
  cannot see -- is a read, not a utility, so this does not close it; it still waits on the walker
  resolving those positions at `propose`.
* **An amplification tooth in 0.2.2/0.2.3 passed for the wrong reason.** The fuzzer's trigger
  tooth asserted only that `insert into shop.child` was refused -- and it was, but at `resolves`
  (the agent held no INSERT on the table), never reaching `no_amplification`. The check it was
  meant to exercise did not run; the tooth was vacuous. The v0.2.3 tag shipped with it. The teeth
  now assert WHICH check refuses, so a refusal by a parse error or a missing privilege no longer
  counts, and the agent is granted the privilege. Surfaced by the review of the 0.2.3 release.
* The discover/propose parity now covers allow-listed tables (non-SECURITY DEFINER: writable and
  not refused; SECURITY DEFINER: refused by both). Docs: the walker's unreached-function gap is
  named as a class; "bounded by the backstop" is qualified to count, not tenant or privilege
  (and `TRUNCATE` reached that way, once uncounted, is now refused outright, per the fix above).

## 0.2.3 -- 2026-10-08

Closes the rest of the amplification class 0.2.2 opened, and makes the result usable.

* **An opaque user function amplifies a write the same way a cascade did.** A SELECT may
  call a user function whose body the gate cannot see: a volatile one may write rows no one
  counts, a SECURITY DEFINER one runs as its owner, outside the agent's tenant. New propose
  check `no_opaque_function`: a statement calling a user function that is volatile or
  SECURITY DEFINER is refused, naming it. Built-ins (pg_catalog) and non-volatile,
  non-SECURITY DEFINER user functions pass.
* **A commit-time backstop, so the limit counts the real effect.** Even a propose that
  passes is measured: the transaction's tuple operations on user tables over the statement
  (`pg_stat_xact_user_tables`, both snapshots in the one subtransaction) must not exceed
  `max_rows`, so a trigger, cascade, rule or function that moves more rows than the
  statement names aborts the kept set. It counts tuple operations, so it over-counts (the
  safe side -- rows a trigger writes then rolls back in its own EXCEPTION still count), and
  it does not see TRUNCATE (blocked as DDL at the top level; a TRUNCATE nested in a function
  the walker does not see is addressed in 0.2.4). The gate's own bookkeeping is excluded.
* **A per-agent allow-list, so a legitimate trigger is not a wall.** `agent_gate.allow_write
  (agent, relation)` lets an agent write a table that carries an `updated_at` or audit trigger
  that is NOT `SECURITY DEFINER`: it relaxes `no_amplification` for that one case only, never
  the limit -- the backstop still counts every amplified row. A cascading foreign key, a rule,
  or a `SECURITY DEFINER` trigger is NOT allow-listable in 0.2.3 (the recursive closure that
  makes some cascades safe lands in 0.2.4); `allow_write` records the entry but its result says
  `still_refused` with the object. `discover` reports `write_refused` on each table the agent
  may not write and why, through the same function `propose` uses, so the two never disagree.
* Regression in `tests/fuzz.py` (the amplification teeth also build a volatile writer and a
  SECURITY DEFINER function and assert both refused) runs on every push. Schema change: the
  `allowlist` table and the two functions; the upgrade script creates them and redefines
  `_agent`.

## 0.2.2 -- 2026-10-07

A cross-tenant breach, the same shape as the 0.2.1 bugs -- the gate counted the
top-level statement and the real effect was larger -- but worse, because the
extra effect also escaped row-level security. Reported during adversarial
review of the gate and confirmed by measuring the real cross-tenant row count
from a superuser against a two-tenant database; the case is now a regression in
the fuzzer (`tests/fuzz.py`).

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
* Published as [GHSA-89xf-63fg-xx5h](https://github.com/Manuelreyesbravo/pg_agent_gate/security/advisories/GHSA-89xf-63fg-xx5h)
  (CVSS 3.1: 9.6, Critical). Upgrade from any version before 0.2.2.

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
