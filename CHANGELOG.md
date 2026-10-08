# Changelog

## 0.2.8 -- unreleased

From an external audit of 0.2.7 (e600647), each item re-measured here before it was changed.

* **`estimated_rows` still told another tenant's frequent value, through two paths (medium).**
  0.2.6 withheld it when row-level security was active on a relation of the analyzed tree. The
  planner inlines a SQL function (`STABLE`, `SECURITY INVOKER`, `RETURNS SETOF`) AFTER that tree is
  built, so its table was not judged: `select * from shop.orders_by_secret('hot-b')` was estimated
  at 34 against 1 for an absent value, and two such calls joined at 1156. And a view that isolates
  tenants with a `WHERE` and no row-level security at all gave 34 too: the agent reads the view,
  the estimate counts the table behind it. Now the estimate is given only when the agent could read
  in full every relation the tree AND the plan touch (`EXPLAIN (VERBOSE)` names each scan's schema):
  `SELECT` on the whole table, and no row-level security hiding rows from it. A name that does not
  resolve, or a lookup that fails, withholds it. A view over a table the agent may read keeps its
  estimate (checked, so a `null` cannot mean the gate stopped estimating).
* **The agent's SQL no longer runs in parallel workers.** The function-manager hook keys on a
  counter that lives in the backend; a worker has its own, at zero. The audit marked this
  unmeasured; measured here, a worker of an agent session was refused anyway -- it inherits
  `agent_gate.agent`, so the session hooks refused the function body it parsed and any plan fragment
  that read a table. No leak, but by accident, and it broke a plain parallel `CREATE TABLE AS` of an
  `allow_ddl` agent. `verify` now sets `max_parallel_workers` (and the per-gather and maintenance
  limits, so `EXPLAIN` shows the plan that runs) to 0 for the rest of the agent's transaction: the
  backend runs the whole plan, the hook stops a `SECURITY DEFINER` function there, and the plain
  `CREATE TABLE AS` of 200000 rows is kept.
* **README:** a row-level policy that calls a `SECURITY DEFINER` function (the usual membership
  helper) refuses every proposal on its table -- it was already so before 0.2.7, now written down as
  the price of the rule.
* **`tests/plan_time.sh`**: eleven more checks. Against 0.2.7, the four estimate checks fail (34, 1156,
  34 -- the sublink one reads 1, and is kept for the rule) and so do the two parallel ones; the
  controls -- the inlined helper does tell hot from absent as the agent, a parallel worker does run
  that SELECT outside the gate, a readable view keeps its estimate -- pass on both.
* **Not changed:** the audit's note that `register_agent` "fails in silence" with a short
  description. It raises (`CHECK (length(description) >= 10)`); a script that does not stop on
  errors keeps going with the role unregistered, and `whoami()` says `is_agent: false`.

## 0.2.7 -- unreleased

The case 0.2.6 measured and left open, closed as a class and not as the one case.

* **A `SECURITY DEFINER` function reached through a body the gate cannot see no longer runs.**
  `no_opaque_function` refuses a `SECURITY DEFINER` function the statement calls, but its walker
  sees the statement's tree, not the body of another function, a `CHECK` or domain constraint, a
  default, a generated column, an expression index or a trigger. Measured on 0.2.6: an `IMMUTABLE`,
  non-`SECURITY DEFINER` wrapper over one verified and ran it at `propose` (the planner folds the
  wrapper) and again at `commit`; one over a function that raised returned its owner's secret; and
  a `CHECK` that reached one through a wrapper kept the write. The gate now installs PostgreSQL's
  function-manager hook (`fmgr_hook`): every `SECURITY DEFINER` call passes through
  `fmgr_security_definer`, which calls it before the body runs, and while SQL the agent wrote is
  running -- verification, the verified statement, its deferred constraints, an allowed DDL -- the
  gate refuses there with `42501`, naming the function. On 0.2.7 the counter does not move, the
  secret does not travel, and the `CHECK`'s write is not kept. The gate's own `SECURITY DEFINER`
  functions never run inside that window, so there is no exemption; there is no allow-list either.
  Outside an agent's SQL the hook is one atomic load.
* **Not covered, and said in the README:** a non-`SECURITY DEFINER` function in those positions
  (it runs with the agent's rights; what it writes, the commit backstop counts), a referential
  action (it runs as the table owner by its own mechanism, not as a `SECURITY DEFINER` call) and a
  view without `security_invoker`.
* **`tests/plan_time.sh`** gains eight checks, all red against 0.2.6, and two that must stay green:
  a wrapper with no `SECURITY DEFINER` under it still verifies and runs, and -- the control of the
  instrument -- the superuser calling the wrapper moves the counter. Writing them found that the
  `CHECK` case passed against 0.2.6 for the wrong reason: with `INSERT` alone the commit aborted on
  `permission denied`, because the gate appends `RETURNING to_jsonb(old/new)` to a write it runs. The
  agent there now holds `SELECT` too. (That an agent with `INSERT` but no `SELECT` passes `propose`
  and fails every `commit` is a separate rough edge, not changed here.)
* **`tests/fuzz.py`: the nested-utility teeth test their own mechanism again.** Their `CHECK` and
  trigger functions were `SECURITY DEFINER`, so on 0.2.7 the new hook stopped them before the
  `TRUNCATE` or `GRANT` was reached, and the four teeth that assert the reason "nested utility"
  failed -- with the outcome still `aborted` and nothing kept, but a tooth that names a mechanism
  must exercise it. The functions are now ordinary, and the agent holds the privileges they use, so
  without the nested-utility refusal the `TRUNCATE` and the `GRANT` would succeed. The
  `SECURITY DEFINER` shape stays as its own tooth for the hook.

## 0.2.6 -- unreleased

Two findings, both measured against 0.2.5 on PostgreSQL 18.6 with the extension built and
installed, and both red in the new suite before the fix (`tests/plan_time.sh`).

* **A function the gate refuses no longer runs while it is being verified (high).** The `resolves`
  check was an `EXPLAIN`, and it came before the tree walk that refuses an opaque function. Planning
  runs functions: it constant-folds an `IMMUTABLE` call with constant arguments and estimates a
  `STABLE` one by calling it. So `propose('... where secret = vault.peek()')`, with `vault.peek()`
  `IMMUTABLE SECURITY DEFINER`, ran the function as its owner and only then was refused by
  `no_opaque_function` -- measured: a non-transactional counter moved once per refused proposal, 5
  of 5, `propose_and_commit` included. A function that raised returned its owner's secret verbatim
  in the `resolves` detail the agent receives (`[P0001] leak: s3cr3t-from-vault`), under a check
  whose text said "nothing ran". Now every refusal (`no_writing_cte`, `keeps_its_context`,
  `no_amplification`, `no_opaque_function`) is decided on the analyzed and rewritten tree, which
  runs nothing, and the planner only sees what passed: the counter stays at 0 and the refusal names
  the function, not what it would have raised. A name or type that does not resolve still fails
  `resolves`, now at the analyzer. The order of the checks in the verdict changed accordingly.
  Privileges are still the first thing a proposal fails on: the analyzer does not check them (the
  `EXPLAIN` did, at executor start), so the gate now runs the executor's own `ExecCheckPermissions`
  on every analyzed query. Without it -- measured on the first cut of this fix -- an agent with no
  grant on a table was told which trigger writing it fires before its `permission denied`.
* **`estimated_rows` is withheld under row-level security (medium-low).** The estimate comes from
  statistics gathered over the whole table, beneath the policy. Measured with an agent of tenant 1
  on a table of 100 tenants: a value only tenant 2 has, 5000 times, was estimated at 34 rows; an
  absent value at 1. The agent cannot run `EXPLAIN` itself, so the gate was the only channel. It is
  now `null` whenever PostgreSQL's `row_security_active()` is true for a relation the statement
  touches (a superuser, a `BYPASSRLS` role and an owner without `FORCE` keep it), and `null` if that
  lookup fails. Without row-level security the estimate is unchanged -- the suite checks that too,
  or a `null` would only say the gate stopped estimating.
* **Still open, and now documented as such:** a non-volatile, non-`SECURITY DEFINER` user function
  passes `no_opaque_function` and its body is not walked, so a `SECURITY DEFINER` call INSIDE it runs
  -- at `commit`, as in 0.2.5, and also at `propose` when the planner folds the wrapper. Measured:
  an `IMMUTABLE` wrapper over `vault.peek()` is accepted and runs it at propose and at commit. It is
  the class the README already lists ("the body of a view or another function the statement
  touches"); the cure is not to grant an agent `EXECUTE` on such a wrapper.
* **`tests/plan_time.sh` (new suite in `make verify`).** Its counter is a sequence, because a
  function marked `IMMUTABLE` cannot `INSERT` and a table would be rolled back with the `EXPLAIN`'s
  subtransaction -- either would read 0 whether the body ran or not. Its controls: the superuser
  calls the function once and the counter must move; as the agent, the planner must tell the hot
  value from an absent one; and the table without row-level security must keep its estimate.

## 0.2.5 -- unreleased

A seventh verb, so a durable act pays one flush instead of two.

* **`propose_and_commit(sql, intent[, params])`: propose + commit in one call (schema change:
  `pg_agent_gate--0.2.4--0.2.5.sql`).** With `attempt_durability = durable` every record pays its
  own flush, and an act is two records in two transactions: counted from `pg_stat_io`, exactly
  2.00 WAL fsyncs per act, so a durable act costs mostly the disk's flushes. The new verb writes
  the proposal and its execution in ONE transaction: 1.00 fsync per act. Measured on the same
  btrfs NVMe in two states the same day (20 clean rounds each, interleaved, PostgreSQL 19beta2
  without assertions): with `fdatasync` at 0.88 ms, 2.65 -> 1.68 ms (-36.7% [35.0..38.0]); with it
  at 3.9 ms under sustained I/O, 10.86 ms [95% CI 9.30..12.56] -- straddling the 10 ms criterion
  -> 5.06 ms [4.87..5.36], under it with the whole interval (-53.4% [44.3..60.0]).
  It is `propose` then `commit`, not a shortcut: the same `execute`, so the statement is verified
  at propose and again at execution, under the same row limit, backstop, assertions and record.
  What it gives up is the `dry_run` in between, and -- one transaction cuts both ways -- a call
  cancelled or failing outside the gate's subtransaction leaves neither row, where two calls
  would have kept the proposal (the server log keeps the verdict). The two-call flow is unchanged.
* **`tests/flushes.sh` (new suite in `make verify`)** counts the WAL flushes an act pays instead
  of inferring them from a timing: fast read 0, any kept change 1, durable two calls 2, durable one
  call 1 -- reads and kept writes, two calls and one. The durable two-call case is the control of
  the instrument: blind to this backend's fsyncs, it would read 0 there and fail.
* **Every attack in `tests/adversarial.sh` that goes through `propose` now also goes through
  `propose_and_commit`**, judged the same way, by the world a superuser reads afterwards; plus a
  session attack (a function as its argument) and four controls. `tests/fuzz.py` sends every
  generated input through it as well, under the same oracles, and adds its own: a proposal that
  did not verify never reaches execution.
* **`tests/upgrade.sh` now compares the upgraded schema with a fresh install**, function by
  function (arguments, result, strictness, volatility), and an agent registered before the
  upgrade uses the new verb. The first version of that comparison passed an upgrade script that
  forgot the verb: both sides returned the same ERROR (`text || "char"` is ambiguous) and two
  equal errors compared equal. Caught by its negative control; the check now needs the fresh
  side to be a real list that names this version's verb, and the control was run both ways.
* `make bench` has a fifth row, the durable read act in one call, with the same 10 ms threshold
  declared before it was measured; the README's table is one clean run of all five (the run
  before it was flagged by the calibration sentinel and repeated), and the section now shows the
  durable act on a fast and a slow disk, because that number is mostly the disk's. A cost
  measured on an `--enable-cassert` build (pgrx's own instance) is not comparable: it inflates
  every row.

## 0.2.4 -- 2026-10-08

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
  `current_user` (inside a `SECURITY DEFINER` function the agent is already the owner). The window
  spans the gate's own `SET CONSTRAINTS` too, so a utility fired by a DEFERRED constraint trigger
  is caught; the gate exempts the one utility it runs on purpose (the verified DDL for an
  `allow_ddl` agent, and the `SET CONSTRAINTS` itself) with a one-shot allowance, and lets
  sub-commands through. Measured: the `CHECK`-`TRUNCATE` and a deferred-trigger `TRUNCATE` now
  abort and the table is intact, a benign `CHECK` and an `allow_ddl` agent's own `CREATE INDEX`
  stay kept, and the session recovers after the abort. **Behaviour change:** ANY nested utility is
  now refused, benign ones included -- a trigger that does `NOTIFY`, `SET LOCAL`, `LOCK TABLE`,
  `CALL` or `CREATE TEMP TABLE` makes the statement abort (`pg_notify()` as a function still
  works). Regression in `tests/fuzz.py`. The DISCLOSURE half of the class -- a `SECURITY DEFINER`
  function in a READ returning rows the agent cannot see -- is a read, not a utility, so this does
  not close it; it still waits on the walker resolving those positions at `propose`.
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
