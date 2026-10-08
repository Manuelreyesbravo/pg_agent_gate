// Copyright 2026 Manuel Reyes Bravo
// SPDX-License-Identifier: Apache-2.0

//! The counters that decide whether SQL may run in an agent session, and the
//! facts about the current transaction that decide how durable a record is.
//!
//! THREE COUNTERS, AND KEPT APART ON PURPOSE:
//!
//! * `TRUSTED`  -- the gate's own SQL is running (its record, `discover`).
//! * `PROPOSAL` -- SQL the AGENT wrote is running (verification, execution).
//! * `CHECKING` -- the gate is checking bound assertions after a change.
//!
//! With a single counter, a proposal could call the functions that write the
//! record and forge its own history: the record functions ask for `TRUSTED`
//! AND NOT `PROPOSAL`, so SQL the agent wrote can never satisfy them.
//!
//! A counter left up is a gate left open, in silence. Two things bring them
//! down: the guards' `Drop` (pgrx turns a PostgreSQL ERROR into an unwind that
//! runs it) and, as the second line, a transaction-abort callback that zeroes
//! all three.
//!
//! TWO TRANSACTION FACTS, for `agent_gate.attempt_durability = fast`:
//!
//! * `FOREIGN_WRITES` -- the transaction had already written something when
//!   the first verb ran. Relaxing its commit would relax writes the gate never
//!   saw, so a record in such a transaction is never relaxed.
//! * `KEPT_CHANGE` -- the gate kept a change in this transaction. From then on
//!   every record rides on the durable commit that change needs.
//!
//! Both are forgotten when the transaction ends, however it ends.
//!
//! WHAT AN ABORT TAKES FROM THE RECORD (0.2.10). The record is written in the caller's
//! transaction, and transaction control is allowed in an agent session -- a driver
//! opens BEGIN by itself. So ROLLBACK, ROLLBACK TO SAVEPOINT, or a session that leaves
//! without COMMIT takes rows of the record with it, refused attempts included (found
//! by an external audit of 0.2.8). The gate cannot keep a row its caller rolls back.
//! It remembers, per nesting level, each row it wrote; a commit forgets them, and an
//! abort writes the ones it takes to the server log -- outside every transaction, at
//! LOG, which the agent's session does not receive. The record's own rows are never
//! written inside one of the gate's internal subtransactions, so an abort of those
//! never matches one.

use pgrx::prelude::*;
use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering::SeqCst};

thread_local! {
    /// Rows the record wrote in this transaction, by the nesting level they were written at.
    static UNCOMMITTED: RefCell<Vec<(i32, String)>> = const { RefCell::new(Vec::new()) };
}

/// The record wrote a row; `line` says what it was, on one line, if it has to be told.
pub(crate) fn written_to_record(line: String) {
    let level = unsafe { pg_sys::GetCurrentTransactionNestLevel() };
    UNCOMMITTED.with(|u| u.borrow_mut().push((level, line)));
}

/// An abort at `level` takes every row written at that level or deeper: say so in the log.
fn lost_to_abort(level: i32, with: &str) {
    let lost: Vec<String> = UNCOMMITTED.with(|u| {
        let mut u = u.borrow_mut();
        let (lost, kept): (Vec<_>, Vec<_>) = u.drain(..).partition(|(l, _)| *l >= level);
        *u = kept;
        lost.into_iter().map(|(_, line)| line).collect()
    });
    for line in lost {
        log!("pg_agent_gate: rolled back with {with}, so not in the record: {line}");
    }
}

static TRUSTED: AtomicU32 = AtomicU32::new(0);
static PROPOSAL: AtomicU32 = AtomicU32::new(0);
static CHECKING: AtomicU32 = AtomicU32::new(0);
// Set ONLY while the gate runs the one verified statement (and fires its deferred constraints).
// Any utility that happens then -- a TRUNCATE, GRANT, ALTER or DROP from a trigger, constraint or
// function the statement reached, which the propose-time walker does not see -- is nested and is
// refused. GATE_UTILITY is how the gate exempts the one utility IT runs on purpose (the verified
// DDL itself for an allow_ddl agent, or its own SET CONSTRAINTS): a one-shot allowance.
static EXECUTING: AtomicU32 = AtomicU32::new(0);
static GATE_UTILITY: AtomicU32 = AtomicU32::new(0);

static TXN_SEEN: AtomicBool = AtomicBool::new(false);
static TXN_FOREIGN_WRITES: AtomicBool = AtomicBool::new(false);
static TXN_KEPT_CHANGE: AtomicBool = AtomicBool::new(false);

pub(crate) fn sql_may_run() -> bool {
    TRUSTED.load(SeqCst) > 0 || PROPOSAL.load(SeqCst) > 0 || CHECKING.load(SeqCst) > 0
}

/// The record functions call this. Only the gate's own SQL, never the agent's.
pub(crate) fn internal_call_allowed() -> bool {
    TRUSTED.load(SeqCst) > 0 && PROPOSAL.load(SeqCst) == 0 && CHECKING.load(SeqCst) == 0
}

pub(crate) fn checking() -> bool {
    CHECKING.load(SeqCst) > 0 && PROPOSAL.load(SeqCst) == 0
}

pub(crate) fn proposal_running() -> bool {
    PROPOSAL.load(SeqCst) > 0
}

pub(crate) struct Guard(&'static AtomicU32);

impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.0.fetch_update(SeqCst, SeqCst, |v| Some(v.saturating_sub(1)));
    }
}

fn enter(counter: &'static AtomicU32) -> Guard {
    counter.fetch_add(1, SeqCst);
    Guard(counter)
}

pub(crate) fn trusted() -> Guard {
    enter(&TRUSTED)
}

/// True while the gate is running the one verified statement -- so a nested utility
/// statement (from a trigger, constraint or function it reaches) can be refused.
pub(crate) fn executing() -> bool {
    EXECUTING.load(SeqCst) > 0
}

/// Guard for the executing window. On both entry and exit it clears GATE_UTILITY, so an
/// allowance that was granted but never consumed (the statement never reached the utility hook)
/// cannot outlive the window and be taken by a later nested utility.
pub(crate) struct ExecGuard;

impl Drop for ExecGuard {
    fn drop(&mut self) {
        let _ = EXECUTING.fetch_update(SeqCst, SeqCst, |v| Some(v.saturating_sub(1)));
        GATE_UTILITY.store(0, SeqCst);
    }
}

pub(crate) fn executing_verified() -> ExecGuard {
    GATE_UTILITY.store(0, SeqCst);
    EXECUTING.fetch_add(1, SeqCst);
    ExecGuard
}

/// The gate signals that the NEXT utility it runs (the verified DDL, or SET CONSTRAINTS) is its
/// own and must pass even inside the executing window.
pub(crate) fn allow_gate_utility() {
    GATE_UTILITY.fetch_add(1, SeqCst);
}

/// Consume one gate-utility allowance; true if there was one to consume.
pub(crate) fn take_gate_utility() -> bool {
    GATE_UTILITY
        .fetch_update(SeqCst, SeqCst, |v| if v > 0 { Some(v - 1) } else { None })
        .is_ok()
}

pub(crate) fn proposal() -> Guard {
    enter(&PROPOSAL)
}

pub(crate) fn checking_assertions() -> Guard {
    enter(&CHECKING)
}

pub(crate) fn txn_seen() -> bool {
    TXN_SEEN.load(SeqCst)
}

pub(crate) fn mark_txn_seen(foreign_writes: bool) {
    TXN_SEEN.store(true, SeqCst);
    TXN_FOREIGN_WRITES.store(foreign_writes, SeqCst);
}

pub(crate) fn txn_foreign_writes() -> bool {
    TXN_FOREIGN_WRITES.load(SeqCst)
}

pub(crate) fn mark_kept_change() {
    TXN_KEPT_CHANGE.store(true, SeqCst);
}

pub(crate) fn txn_kept_change() -> bool {
    TXN_KEPT_CHANGE.load(SeqCst)
}

fn reset_counters() {
    TRUSTED.store(0, SeqCst);
    PROPOSAL.store(0, SeqCst);
    CHECKING.store(0, SeqCst);
}

fn forget_transaction() {
    TXN_SEEN.store(false, SeqCst);
    TXN_FOREIGN_WRITES.store(false, SeqCst);
    TXN_KEPT_CHANGE.store(false, SeqCst);
}

/// Counters reset only on a TOP-LEVEL abort: a subtransaction abort happens
/// inside the gate's own verbs, while they still legitimately hold a counter.
/// The transaction facts are forgotten at every end of a transaction.
#[pg_guard]
pub(crate) unsafe extern "C-unwind" fn on_xact_event(
    event: pg_sys::XactEvent::Type,
    _arg: *mut std::ffi::c_void,
) {
    use pg_sys::XactEvent::*;
    if event == XACT_EVENT_ABORT {
        lost_to_abort(0, "the transaction");
    }
    if event == XACT_EVENT_COMMIT || event == XACT_EVENT_PREPARE {
        UNCOMMITTED.with(|u| u.borrow_mut().clear());
    }
    if event == XACT_EVENT_ABORT || event == XACT_EVENT_PARALLEL_ABORT {
        reset_counters();
    }
    if event == XACT_EVENT_COMMIT
        || event == XACT_EVENT_PARALLEL_COMMIT
        || event == XACT_EVENT_ABORT
        || event == XACT_EVENT_PARALLEL_ABORT
        || event == XACT_EVENT_PREPARE
    {
        forget_transaction();
    }
}

/// A savepoint rolled back takes the rows written inside it; one released hands them to
/// its parent. Called while the subtransaction is still the current one.
#[pg_guard]
pub(crate) unsafe extern "C-unwind" fn on_subxact_event(
    event: pg_sys::SubXactEvent::Type,
    _my_subid: pg_sys::SubTransactionId,
    _parent_subid: pg_sys::SubTransactionId,
    _arg: *mut std::ffi::c_void,
) {
    use pg_sys::SubXactEvent::*;
    let level = pg_sys::GetCurrentTransactionNestLevel();
    if event == SUBXACT_EVENT_ABORT_SUB {
        lost_to_abort(level, "a savepoint");
    } else if event == SUBXACT_EVENT_COMMIT_SUB {
        UNCOMMITTED.with(|u| {
            for (l, _) in u.borrow_mut().iter_mut() {
                if *l >= level {
                    *l = level - 1;
                }
            }
        });
    }
}
