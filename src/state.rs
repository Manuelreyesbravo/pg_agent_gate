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

use pgrx::prelude::*;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering::SeqCst};

static TRUSTED: AtomicU32 = AtomicU32::new(0);
static PROPOSAL: AtomicU32 = AtomicU32::new(0);
static CHECKING: AtomicU32 = AtomicU32::new(0);

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
