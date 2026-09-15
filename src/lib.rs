//! pg_agent_gate -- agents propose, PostgreSQL decides.
//!
//! An agent connected to this database does not run SQL. It has six verbs:
//! `discover` what it may touch, `propose` one statement, `dry_run` it to see
//! the exact effect, `commit` it, read its own `acts`, and ask `whoami`.
//! PostgreSQL verifies every proposal against itself before anything runs,
//! executes it with the agent's own privileges, and keeps the record.
//!
//! The part plain SQL cannot do -- and the reason this is an extension with a
//! shared library and not a schema -- lives in `hooks.rs`: a session that
//! belongs to an agent cannot run anything except those verbs.

use pgrx::guc::{GucContext, GucFlags, GucRegistry, GucSetting};
use pgrx::prelude::*;
use std::ffi::CString;

mod exec;
mod hooks;
mod schema;
mod state;
mod verbs;
mod verify;

::pgrx::pg_module_magic!(name, version);

/// Which agent this session belongs to. SUSET on purpose: it is set on the
/// role by `agent_gate.register_agent()`, and an agent able to unset it would
/// be an agent able to leave the gate.
pub(crate) static AGENT: GucSetting<Option<CString>> = GucSetting::<Option<CString>>::new(None);

/// Rows a verb hands back. Anything beyond is reported as truncated, never
/// dropped in silence.
pub(crate) static MAX_RESULT_ROWS: GucSetting<i32> = GucSetting::<i32>::new(100);

/// A verification is a statement about the database at a moment. After this
/// many seconds it is no longer allowed to stand in for a fresh one.
pub(crate) static PROPOSAL_TTL_SECONDS: GucSetting<i32> = GucSetting::<i32>::new(900);

static mut PRELOADED: bool = false;

pub(crate) fn current_agent() -> Option<String> {
    AGENT.get().and_then(|c| c.into_string().ok()).filter(|s| !s.is_empty())
}

pub(crate) fn preloaded() -> bool {
    unsafe { PRELOADED }
}

#[pg_guard]
pub extern "C-unwind" fn _PG_init() {
    GucRegistry::define_string_guc(
        c"agent_gate.agent",
        c"The agent this session belongs to.",
        c"Set on the role by agent_gate.register_agent(). While set, the session can only call the gate's verbs.",
        &AGENT,
        GucContext::Suset,
        GucFlags::default(),
    );
    GucRegistry::define_int_guc(
        c"agent_gate.max_result_rows",
        c"Rows a verb returns to the agent.",
        c"Anything beyond is reported as truncated, never dropped in silence.",
        &MAX_RESULT_ROWS,
        0,
        100_000,
        GucContext::Suset,
        GucFlags::default(),
    );
    GucRegistry::define_int_guc(
        c"agent_gate.proposal_ttl_seconds",
        c"How long a verification stays valid.",
        c"After this the proposal must be made again: the database may have changed under it.",
        &PROPOSAL_TTL_SECONDS,
        1,
        86_400,
        GucContext::Suset,
        GucFlags::default(),
    );
    unsafe {
        pg_sys::MarkGUCPrefixReserved(c"agent_gate".as_ptr());
        PRELOADED = pg_sys::process_shared_preload_libraries_in_progress;
        hooks::install();
        pg_sys::RegisterXactCallback(Some(state::on_xact_event), std::ptr::null_mut());
    }
}

#[cfg(any(test, feature = "pg_test"))]
#[pg_schema]
mod tests {
    use pgrx::prelude::*;

    fn id(v: &serde_json::Value) -> i64 {
        v["proposal"].as_i64().unwrap_or_else(|| panic!("no proposal id in {v}"))
    }

    #[pg_test]
    fn a_write_is_verified_previewed_and_kept() {
        Spi::run("create table gate_t (id int primary key, plan text not null)").unwrap();
        Spi::run("insert into gate_t values (1, 'free'), (2, 'pro')").unwrap();

        let p = crate::verbs::propose("update gate_t set plan = 'pro' where id = 1", "upgrade client 1", None).0;
        assert_eq!(p["ok"], true, "{p}");
        assert_eq!(p["kind"], "write", "{p}");

        let d = crate::verbs::dry_run(id(&p)).0;
        assert_eq!(d["outcome"], "rolled_back", "{d}");
        assert_eq!(d["rows"][0]["before"]["plan"], "free", "{d}");
        assert_eq!(d["rows"][0]["after"]["plan"], "pro", "{d}");
        let after_dry: Option<String> = Spi::get_one("select plan from gate_t where id = 1").unwrap();
        assert_eq!(after_dry.as_deref(), Some("free"), "a dry run kept something");

        let c = crate::verbs::commit(id(&p)).0;
        assert_eq!(c["outcome"], "kept", "{c}");
        assert_eq!(c["rows_affected"], 1, "{c}");
        let after_commit: Option<String> = Spi::get_one("select plan from gate_t where id = 1").unwrap();
        assert_eq!(after_commit.as_deref(), Some("pro"));

        let again = crate::verbs::commit(id(&p)).0;
        assert_eq!(again["outcome"], "refused", "a proposal was committed twice: {again}");
    }

    #[pg_test]
    fn what_a_model_invents_dies_at_propose() {
        Spi::run("create table gate_u (id int primary key)").unwrap();
        for sql in [
            "select nope from gate_u",
            "select * from gate_nowhere",
            "select gate_no_such_function(id) from gate_u",
            "select 1; select 2",
            "selec 1",
            "begin",
        ] {
            let p = crate::verbs::propose(sql, "a false proposal", None).0;
            assert_eq!(p["ok"], false, "{sql} passed verification: {p}");
        }
    }

    #[pg_test]
    fn a_read_returns_rows_and_keeps_nothing() {
        Spi::run("create table gate_r (id int primary key, n int)").unwrap();
        Spi::run("insert into gate_r select g, g * 10 from generate_series(1, 3) g").unwrap();
        let p = crate::verbs::propose("select id, n from gate_r where n > $1::int order by id", "list big ones", Some(vec![Some("10".into())])).0;
        assert_eq!(p["ok"], true, "{p}");
        let c = crate::verbs::commit(id(&p)).0;
        assert_eq!(c["outcome"], "read", "{c}");
        assert_eq!(c["rows"][0]["n"], 20, "{c}");
        assert_eq!(c["rows_returned"], 2, "{c}");
    }

    #[pg_test]
    fn a_row_limit_aborts_and_keeps_nothing() {
        Spi::run("create table gate_l (id int primary key)").unwrap();
        Spi::run("insert into gate_l select generate_series(1, 1500)").unwrap();
        let p = crate::verbs::propose("delete from gate_l", "clear the table", None).0;
        assert_eq!(p["ok"], true, "{p}");
        let c = crate::verbs::commit(id(&p)).0;
        assert_eq!(c["outcome"], "aborted", "{c}");
        let left: Option<i64> = Spi::get_one("select count(*) from gate_l").unwrap();
        assert_eq!(left, Some(1500), "an aborted commit kept rows");
    }
}

/// This module is required by `cargo pgrx test` invocations.
/// It must be visible at the root of your extension crate.
#[cfg(test)]
pub mod pg_test {
    pub fn setup(_options: Vec<&str>) {}

    #[must_use]
    pub fn postgresql_conf_options() -> Vec<&'static str> {
        vec!["shared_preload_libraries = 'pg_agent_gate'"]
    }
}
