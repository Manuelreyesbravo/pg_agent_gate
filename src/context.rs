// Copyright 2026 Manuel Reyes Bravo
// SPDX-License-Identifier: Apache-2.0

//! THE AGENT'S CONTEXT IS AN INVARIANT THE GATE OWNS (0.4.3, second review).
//!
//! A row-level policy reads the session's context -- `current_setting('app.tenant_id')`, who is
//! acting, whether policies apply, how names resolve -- and an agent's context is set on its role.
//! Every review found another way to move it while the gate was looking elsewhere: SET (0.2.x),
//! a startup parameter (0.2.12), set_config() in the statement (0.2.1), in a body or a text
//! (0.4.2), and, in the review of 0.4.3, in a domain's CHECK that ran while a verb's parameter was
//! BOUND, before any verb started -- the tenant stayed switched for the rest of the session.
//!
//! The floor now stands for the whole session (state::floor_applies), and this is the check that
//! does not depend on finding the next path: the context the session STARTED with is remembered
//! before the first statement of the agent's is judged, and every verb checks it is still the
//! same when it starts, after it ran the agent's SQL, and before it hands back a row. If it moved,
//! the verb refuses: inside the statement's subtransaction, so the move is undone with it; at the
//! start of a verb, so a session whose context moved outside the gate does nothing until it
//! reconnects or RESETs.
//!
//! The context is: role, session_authorization, row_security, session_replication_role,
//! search_path, and every PLACEHOLDER -- a custom parameter no loaded module defines, which is where
//! an application keeps its context (`app.tenant_id`) -- less what the allowlist lets the agent
//! set itself. A module's own parameter is how its code runs, as in verify::set_clause_allowed. A
//! placeholder created later (one that did not exist when the session started) is a move too,
//! unless it is empty: that is looked for after the agent's SQL ran, the rest at every check.

use pgrx::prelude::*;
use std::cell::RefCell;
use std::ffi::{CStr, CString};

/// A parameter of the context, with the value the session started with.
struct Param {
    c_name: CString,
    name: String,
    value: Option<String>,
}

thread_local! {
    static BASELINE: RefCell<Option<Vec<Param>>> = const { RefCell::new(None) };
}

const NAMED: &[&str] = &[
    "role",
    "session_authorization",
    "row_security",
    "session_replication_role",
    "search_path",
];

unsafe fn value_of(name: &CStr) -> Option<String> {
    let v = pg_sys::GetConfigOption(name.as_ptr(), true, false);
    (!v.is_null()).then(|| CStr::from_ptr(v).to_string_lossy().into_owned())
}

/// A placeholder: a custom parameter no loaded module defines -- where an application keeps its
/// context. A module's own parameter is how its code runs, and a placeholder the session started
/// with becomes one when the module loads (its value may then be spelled differently).
unsafe fn is_placeholder(name: &CStr) -> bool {
    (pg_sys::GetConfigOptionFlags(name.as_ptr(), true) as u32 & pg_sys::GUC_CUSTOM_PLACEHOLDER) != 0
}

/// Every parameter of the context as it is now: the named ones and every placeholder, less what
/// the allowlist lets the agent set. Sorts all of GUC (get_guc_variables), so it is taken when the
/// session starts and after the agent's SQL ran, not at every check.
unsafe fn context_now() -> Vec<Param> {
    let mut count: std::ffi::c_int = 0;
    let vars = pg_sys::get_guc_variables(&mut count);
    let mut out = Vec::new();
    if vars.is_null() {
        return out;
    }
    for i in 0..count.max(0) as usize {
        let g = *vars.add(i);
        if g.is_null() || (*g).name.is_null() {
            continue;
        }
        let raw = CStr::from_ptr((*g).name);
        let named = NAMED
            .iter()
            .any(|n| raw.to_bytes().eq_ignore_ascii_case(n.as_bytes()));
        if !named && ((*g).flags as u32 & pg_sys::GUC_CUSTOM_PLACEHOLDER) == 0 {
            continue;
        }
        let name = String::from_utf8_lossy(raw.to_bytes()).to_lowercase();
        if crate::settable(&name) {
            continue;
        }
        out.push(Param {
            c_name: raw.to_owned(),
            name,
            value: value_of(raw),
        });
    }
    pg_sys::pfree(vars.cast());
    out
}

/// Remember the context, once per session, before anything of the agent's runs: the hooks call
/// this first thing in an agent session (after it, one thread-local check).
pub(crate) fn remember() {
    BASELINE.with(|b| {
        if b.borrow().is_none() {
            *b.borrow_mut() = Some(unsafe { context_now() });
        }
    });
}

/// The first parameter of the context that is not what the session started with, or None.
/// `new_too`: also look for a placeholder that did not exist then and has a value now.
pub(crate) fn moved(new_too: bool) -> Option<String> {
    if !crate::agent_is_set() {
        return None;
    }
    remember();
    BASELINE.with(|b| {
        let b = b.borrow();
        let base = b.as_ref()?;
        for p in base {
            let named = NAMED.contains(&p.name.as_str());
            // A placeholder that a module now defines is that module's parameter (see is_placeholder).
            if !named
                && unsafe { !is_placeholder(&p.c_name) }
                && unsafe { value_of(&p.c_name) }.is_some()
            {
                continue;
            }
            if unsafe { value_of(&p.c_name) } != p.value {
                return Some(p.name.clone());
            }
        }
        if !new_too {
            return None;
        }
        unsafe { context_now() }
            .into_iter()
            .find(|n| {
                n.value.as_deref().is_some_and(|v| !v.is_empty())
                    && !base.iter().any(|p| p.name == n.name)
            })
            .map(|n| n.name)
    })
}

/// Refuse if the context moved: an ERROR, so a subtransaction it is raised in takes the move back.
/// `new_too` after the agent's SQL ran (see moved()).
pub(crate) fn require(new_too: bool) {
    if let Some(name) = moved(new_too) {
        pgrx::pg_sys::panic::ErrorReport::new(
            pgrx::pg_sys::errcodes::PgSqlErrorCode::ERRCODE_INSUFFICIENT_PRIVILEGE,
            format!(
                "pg_agent_gate: this agent session's context moved: {name} is not what the session started with"
            ),
            "pg_agent_gate",
        )
        .set_detail(
            "An agent's context is set on its role, and the gate checks it before and after every verb. \
             Something changed it outside the verbs' checks; nothing the agent proposed is kept or returned \
             under a context it was not given.",
        )
        .set_hint("RESET ALL, or reconnect.")
        .report(pgrx::pg_sys::elog::PgLogLevel::ERROR);
    }
}
