//! The counters that decide whether SQL may run in an agent session.
//!
//! THREE, AND KEPT APART ON PURPOSE:
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

use pgrx::prelude::*;
use std::sync::atomic::{AtomicU32, Ordering::SeqCst};

static TRUSTED: AtomicU32 = AtomicU32::new(0);
static PROPOSAL: AtomicU32 = AtomicU32::new(0);
static CHECKING: AtomicU32 = AtomicU32::new(0);

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

fn reset() {
    TRUSTED.store(0, SeqCst);
    PROPOSAL.store(0, SeqCst);
    CHECKING.store(0, SeqCst);
}

/// Only the TOP-LEVEL abort resets. A subtransaction abort happens inside the
/// gate's own verbs, while they are still running and legitimately hold a
/// counter up.
#[pg_guard]
pub(crate) unsafe extern "C-unwind" fn on_xact_event(
    event: pg_sys::XactEvent::Type,
    _arg: *mut std::ffi::c_void,
) {
    if event == pg_sys::XactEvent::XACT_EVENT_ABORT
        || event == pg_sys::XactEvent::XACT_EVENT_PARALLEL_ABORT
    {
        reset();
    }
}
