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

/// How durable the record of an ATTEMPT is -- a proposal, a dry run, a read, a
/// refusal: anything that changed no data. A change the gate keeps is always
/// committed with the server's configured durability, and its flush carries the
/// proposal that led to it. SUSET: the DBA decides, never the agent.
///
/// * `fast` (default): attempts ride on an asynchronous commit. A server crash
///   inside the walwriter's window can lose the record of an attempt that
///   changed nothing. pgaudit's log is not fsynced either.
/// * `durable`: every record pays its own flush.
#[allow(non_camel_case_types)]
#[derive(pgrx::PostgresGucEnum, Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum AttemptDurability {
    fast,
    durable,
}

pub(crate) static ATTEMPT_DURABILITY: GucSetting<AttemptDurability> =
    GucSetting::<AttemptDurability>::new(AttemptDurability::fast);

pub(crate) fn attempts_fast() -> bool {
    ATTEMPT_DURABILITY.get() == AttemptDurability::fast
}

pub(crate) fn attempt_durability_name() -> &'static str {
    match ATTEMPT_DURABILITY.get() {
        AttemptDurability::fast => "fast",
        AttemptDurability::durable => "durable",
    }
}

static mut PRELOADED: bool = false;

pub(crate) fn current_agent() -> Option<String> {
    AGENT.get().and_then(|c| c.into_string().ok()).filter(|s| !s.is_empty())
}

/// The hooks run on EVERY statement of EVERY session once the library is
/// preloaded, and almost none of those sessions belong to an agent. This asks
/// the question without allocating: is the setting's C string non-empty?
/// Only when it is does a hook pay for `current_agent()`.
pub(crate) fn agent_is_set() -> bool {
    unsafe {
        let value = *AGENT.as_ptr();
        !value.is_null() && *value != 0
    }
}

pub(crate) fn preloaded() -> bool {
    unsafe { PRELOADED }
}

/// Session parameters an agent session may change, and nothing else.
///
/// It is an ALLOWLIST and that is the whole point. The rule used to name what was
/// forbidden -- `role`, `session_authorization`, `agent_gate.*` -- and an
/// application parameter is in no such list: a row-level policy written over
/// `current_setting('app.tenant_id')`, the ordinary way to separate tenants, could
/// be pointed at another tenant by the agent itself (measured; tests/rls_isolation.sh).
/// No list of forbidden names can cover parameters the application invents.
///
/// What is here is what a driver sets on its own: output formatting and time
/// limits. `search_path` is deliberately absent -- it changes how a proposal
/// resolves its names -- and so is anything that decides what rows exist. A DBA
/// who needs more adds it to `agent_gate.settable`.
pub(crate) const SETTABLE_BY_AGENTS: &[&str] = &[
    "application_name",
    "bytea_output",
    "client_encoding",
    "client_min_messages",
    "datestyle",
    "default_transaction_deferrable",
    "default_transaction_isolation",
    "default_transaction_read_only",
    "extra_float_digits",
    "idle_in_transaction_session_timeout",
    "intervalstyle",
    "lock_timeout",
    "session characteristics",
    "standard_conforming_strings",
    "statement_timeout",
    "timezone",
    "transaction",
    "transaction_deferrable",
    "transaction_isolation",
    "transaction_read_only",
];

/// Extra session parameters an agent may change, comma separated. SUSET: adding
/// one is an act of administration, and it is the DBA saying "no policy of mine
/// stands on this".
pub(crate) static SETTABLE: GucSetting<Option<CString>> = GucSetting::<Option<CString>>::new(None);

pub(crate) fn settable(name: &str) -> bool {
    if SETTABLE_BY_AGENTS.contains(&name) {
        return true;
    }
    match SETTABLE.get().and_then(|c| c.into_string().ok()) {
        Some(extra) => extra.split(',').any(|p| p.trim().to_lowercase() == name),
        None => false,
    }
}

#[pg_guard]
pub extern "C-unwind" fn _PG_init() {
    GucRegistry::define_string_guc(
        c"agent_gate.settable",
        c"Extra session parameters an agent session may change, comma separated.",
        c"Beyond the built-in list of client formatting and timeouts. Anything a row-level policy or a function reads from current_setting() does not belong here.",
        &SETTABLE,
        GucContext::Suset,
        GucFlags::default(),
    );
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
    GucRegistry::define_enum_guc(
        c"agent_gate.attempt_durability",
        c"How durable the record of an attempt is (proposal, dry run, read, refusal).",
        c"fast: asynchronous commit, a crash can lose attempts that changed nothing. durable: every record pays its own flush. Kept changes are always as durable as the server is configured.",
        &ATTEMPT_DURABILITY,
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

    /// Regression: the gate used to append RETURNING whenever the proposal was
    /// a write, and a SELECT whose CTE writes is a write -- which produced
    /// `SELECT ... RETURNING`, a syntax error.
    #[pg_test]
    fn a_select_whose_cte_writes_is_a_write_and_is_kept() {
        Spi::run("create table gate_c (id int primary key, plan text not null)").unwrap();
        Spi::run("insert into gate_c values (1, 'free')").unwrap();
        let p = crate::verbs::propose(
            "with x as (update gate_c set plan = 'pro' where id = 1 returning id) select count(*) from x",
            "upgrade through a cte",
            None,
        )
        .0;
        assert_eq!(p["kind"], "write", "{p}");
        let c = crate::verbs::commit(id(&p)).0;
        assert_eq!(c["outcome"], "kept", "{c}");
        let plan: Option<String> = Spi::get_one("select plan from gate_c where id = 1").unwrap();
        assert_eq!(plan.as_deref(), Some("pro"));
    }

    /// A pg_test runs inside a transaction that has already written (it created
    /// tables). Relaxing that commit would relax writes the gate never saw.
    #[pg_test]
    fn a_transaction_that_already_wrote_is_never_relaxed() {
        Spi::run("create table gate_d (id int primary key)").unwrap();
        let before: Option<String> = Spi::get_one("select current_setting('synchronous_commit')").unwrap();
        let p = crate::verbs::propose("select id from gate_d", "a read in a transaction that wrote", None).0;
        assert_eq!(p["ok"], true, "{p}");
        let after: Option<String> = Spi::get_one("select current_setting('synchronous_commit')").unwrap();
        assert_eq!(after, before, "the gate relaxed a transaction that had already written");
    }

    /// Whatever lowered durability earlier in the transaction, a change the gate
    /// keeps is committed with the server's configured setting.
    #[pg_test]
    fn a_kept_change_restores_durability() {
        Spi::run("create table gate_k (id int primary key, plan text not null)").unwrap();
        Spi::run("insert into gate_k values (1, 'free')").unwrap();
        let configured: Option<String> = Spi::get_one("select reset_val from pg_settings where name = 'synchronous_commit'").unwrap();
        Spi::run("set local synchronous_commit = off").unwrap();
        let p = crate::verbs::propose("update gate_k set plan = 'pro' where id = 1", "a change after durability was lowered", None).0;
        let c = crate::verbs::commit(id(&p)).0;
        assert_eq!(c["outcome"], "kept", "{c}");
        let now: Option<String> = Spi::get_one("select current_setting('synchronous_commit')").unwrap();
        assert_eq!(now, configured, "a kept change did not restore the configured durability");
    }

    /// The positive half of the control, missing at first: the two tests above
    /// both run in transactions that already wrote, so they passed with the
    /// relaxation never happening at all. Found by the criteria harness, whose
    /// fast read cost the same as a durable one.
    #[pg_test]
    fn an_attempt_in_a_clean_transaction_is_relaxed() {
        let p = crate::verbs::propose("select 1", "an attempt before anything was written", None).0;
        assert_eq!(p["ok"], true, "{p}");
        let now: Option<String> = Spi::get_one("select current_setting('synchronous_commit')").unwrap();
        assert_eq!(now.as_deref(), Some("off"), "a clean attempt was not relaxed");
    }

    #[pg_test]
    fn whoami_reports_fast_attempts_by_default() {
        let w = crate::verbs::whoami().0;
        assert_eq!(w["attempt_durability"], "fast", "{w}");
        assert_eq!(w["enforced"], true, "{w}");
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
