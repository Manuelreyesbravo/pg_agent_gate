// Copyright 2026 Manuel Reyes Bravo
// SPDX-License-Identifier: Apache-2.0

//! The six verbs. They are the whole surface an agent has.
//!
//! They replace an MCP server's `tools/list` + `tools/call`, with one
//! difference that is the point of the extension: the agent never calls
//! anything that acts. It proposes; PostgreSQL verifies, runs and records.
//!
//! HOW DURABLE A RECORD IS (`agent_gate.attempt_durability`):
//!
//! * a KEPT CHANGE is committed with the durability the server is configured
//!   with, always. Its flush also carries the record of the proposal that led
//!   to it, which sits earlier in the WAL -- so no change exists on disk
//!   without its proposal and its execution next to it.
//! * an ATTEMPT -- a proposal, a dry run, a read, a refusal, an abort: nothing
//!   that changed data -- is committed asynchronously when the setting is
//!   `fast` (the default). A server crash inside the walwriter's window can
//!   lose it. With `durable` every record pays its own flush.
//! * never relaxed in a transaction that had written something before the
//!   first verb ran: those writes are not the gate's to relax.
//!
//! NO PHANTOM TRANSACTION IDS. pgrx's `SpiClient::update` asks PostgreSQL for
//! the current transaction id before running anything, which ASSIGNS one. A
//! transaction with an id writes a commit record, and a durable commit record
//! is an fsync. So the gate's reads go through read-only SPI, and whether the
//! transaction already wrote is asked in C without assigning anything. The
//! first version got both wrong: every `discover` and `acts` paid a flush, and
//! the question "did this transaction already write?" answered itself yes by
//! asking -- which is why attempts were never relaxed.

use crate::exec::{collect_rows, in_subxact, Rows};
use crate::hooks::VERBS;
use crate::state;
use crate::verify::{self, Kind};
use pgrx::datum::DatumWithOid;
use pgrx::prelude::*;
use pgrx::JsonB;
use serde_json::{json, Value};
use std::ffi::CStr;
use std::time::Instant;

/// Rows of a write kept in the record as before/after. Reads are never kept:
/// copying what an agent READ into an audit table would copy the data itself.
const SAMPLE_ROWS: usize = 50;

struct Identity {
    agent: String,
    is_agent: bool,
    role: String,
}

fn identity() -> Identity {
    let role = unsafe {
        let name = pg_sys::GetUserNameFromId(pg_sys::GetUserId(), false);
        CStr::from_ptr(name).to_string_lossy().into_owned()
    };
    match crate::current_agent() {
        Some(agent) => Identity { agent, is_agent: true, role },
        None => Identity { agent: format!("role:{role}"), is_agent: false, role },
    }
}

struct Config {
    max_rows: i64,
    allow_ddl: bool,
    bindings: Vec<String>,
    /// Relation OIDs this agent may write even though an amplifying object sits on them
    /// (agent_gate.allow_write). The propose check skips them; the backstop still counts them.
    allowed: Vec<u32>,
}

/// The gate's own SQL that WRITES the record. Read-write SPI: assigns a
/// transaction id, which a write needs anyway.
fn call_internal<T: FromDatum + IntoDatum>(query: &str, args: &[DatumWithOid]) -> Option<T> {
    let _gate = state::trusted();
    Spi::connect_mut(|client| {
        client
            .update(query, Some(1), args)
            .expect("pg_agent_gate: internal call failed")
            .first()
            .get::<T>(1)
            .expect("pg_agent_gate: internal call returned an unexpected type")
    })
}

/// The gate's own SQL that only READS. Read-only SPI: no transaction id, so no
/// commit record and no flush. The record functions called this way are
/// VOLATILE plpgsql, and read with a fresh snapshot inside.
fn read_internal<T: FromDatum + IntoDatum>(query: &str, args: &[DatumWithOid]) -> Option<T> {
    let _gate = state::trusted();
    Spi::connect(|client| {
        client
            .select(query, Some(1), args)
            .expect("pg_agent_gate: internal read failed")
            .first()
            .get::<T>(1)
            .expect("pg_agent_gate: internal read returned an unexpected type")
    })
}

fn config(who: &Identity) -> Config {
    if !who.is_agent {
        // A human or a service using the gate on purpose: the same checks, the
        // conservative limits, and no DDL.
        return Config { max_rows: 1000, allow_ddl: false, bindings: Vec::new(), allowed: Vec::new() };
    }
    let found: Option<JsonB> =
        read_internal("select agent_gate_internal._agent($1)", &[who.agent.clone().into()]);
    let Some(JsonB(agent)) = found.filter(|j| !j.0.is_null()) else {
        error!(
            "pg_agent_gate: this role is marked as agent \"{}\", but no agent by that name is registered",
            who.agent
        );
    };
    Config {
        max_rows: agent["max_rows"].as_i64().unwrap_or(0),
        allow_ddl: agent["allow_ddl"].as_bool().unwrap_or(false),
        bindings: agent["bindings"]
            .as_array()
            .map(|a| a.iter().filter_map(|b| b.as_str().map(str::to_string)).collect())
            .unwrap_or_default(),
        allowed: agent["allowed_writes"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_u64().map(|n| n as u32)).collect())
            .unwrap_or_default(),
    }
}

fn not_from_inside() {
    if state::proposal_running() || state::checking() {
        error!("pg_agent_gate: a proposal cannot call the gate from inside itself");
    }
}

/// Every verb that records starts here: no calls from inside a proposal, and
/// the first verb of a transaction notes whether something was already
/// written -- asked in C, because asking through read-write SPI assigns the
/// very transaction id the question is about.
fn begin_verb() {
    not_from_inside();
    if !state::txn_seen() {
        let already_wrote = unsafe { pg_sys::GetTopTransactionIdIfAny() } != pg_sys::TransactionId::INVALID;
        state::mark_txn_seen(already_wrote);
    }
}

/// The record of something that changed nothing may ride on an asynchronous
/// commit -- if the setting allows it and nothing in this transaction needs more.
fn relax_for_an_attempt() {
    debug1!(
        "pg_agent_gate: relax? fast={} seen={} foreign_writes={} kept_change={}",
        crate::attempts_fast(),
        state::txn_seen(),
        state::txn_foreign_writes(),
        state::txn_kept_change()
    );
    if crate::attempts_fast() && !state::txn_foreign_writes() && !state::txn_kept_change() {
        let _gate = state::trusted();
        Spi::run("SET LOCAL synchronous_commit = off")
            .expect("pg_agent_gate: could not relax the record of an attempt");
    }
}

/// A kept change gets the durability the server is configured with, whatever an
/// earlier verb of the same transaction relaxed or the session set.
fn restore_for_a_change() {
    state::mark_kept_change();
    let _gate = state::trusted();
    Spi::run("SET LOCAL synchronous_commit TO DEFAULT")
        .expect("pg_agent_gate: could not restore durability for a kept change");
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    DryRun,
    Commit,
}

impl Mode {
    fn as_str(self) -> &'static str {
        match self {
            Mode::DryRun => "dry_run",
            Mode::Commit => "commit",
        }
    }
}

/// What this agent may touch, derived from the live catalog and the agent's
/// own privileges -- never from a list someone keeps by hand.
#[pg_extern]
pub fn discover(filter: default!(Option<&str>, "NULL"), max_objects: default!(i32, 50)) -> JsonB {
    not_from_inside();
    let who = identity();
    // The agent cannot read the allow-list table, so the gate passes the relations it allowed as a
    // parameter; discover marks every other amplifying table as write_refused, with the reason.
    let allowed: Vec<i64> = config(&who).allowed.iter().map(|o| *o as i64).collect();
    let found: Option<JsonB> = read_internal(
        crate::schema::DISCOVER_SQL,
        &[filter.map(str::to_string).into(), max_objects.into(), allowed.into()],
    );
    let mut out = found.map(|j| j.0).unwrap_or_else(|| json!({}));
    out["agent"] = json!(who.agent);
    JsonB(out)
}

/// Propose one statement. Nothing runs: it is verified and recorded.
#[pg_extern]
pub fn propose(sql: &str, intent: &str, params: default!(Option<Vec<Option<String>>>, "NULL")) -> JsonB {
    begin_verb();
    if intent.trim().chars().count() < 3 {
        error!("pg_agent_gate: say what the proposal is for (intent); it stays in the record");
    }
    let who = identity();
    let cfg = config(&who);
    let verdict = verify::verify(sql, &params, cfg.allow_ddl, &cfg.allowed);
    let kind = verdict.kind.map(|k| k.as_str()).unwrap_or("unknown");

    relax_for_an_attempt();
    let id: i64 = call_internal(
        "select agent_gate_internal._record_proposal($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        &[
            who.agent.clone().into(),
            who.role.clone().into(),
            intent.to_string().into(),
            sql.to_string().into(),
            params.clone().into(),
            kind.to_string().into(),
            verdict.ok.into(),
            JsonB(verdict.checks_json()).into(),
            verdict.estimated_rows.into(),
        ],
    )
    .expect("pg_agent_gate: the proposal was not recorded");

    log!("pg_agent_gate: agent={} proposal={} kind={} ok={}", who.agent, id, kind, verdict.ok);

    JsonB(json!({
        "proposal": id,
        "ok": verdict.ok,
        "kind": verdict.kind.map(|k| k.as_str()),
        "checks": verdict.checks_json(),
        "estimated_rows": verdict.estimated_rows,
        "expires_in_seconds": crate::PROPOSAL_TTL_SECONDS.get(),
        "next": if verdict.ok {
            "agent_gate.dry_run(proposal) shows the exact effect; agent_gate.commit(proposal) makes it real"
        } else {
            "fix what failed and propose again"
        },
    }))
}

/// Run the proposal and undo it: the exact effect, before/after of every row,
/// and whether bound assertions would still hold. Nothing is kept.
#[pg_extern]
pub fn dry_run(proposal: i64) -> JsonB {
    begin_verb();
    JsonB(execute(proposal, Mode::DryRun))
}

/// Run the proposal and keep it, if every guard still agrees.
#[pg_extern]
pub fn commit(proposal: i64) -> JsonB {
    begin_verb();
    JsonB(execute(proposal, Mode::Commit))
}

/// What this agent proposed and did, newest first.
#[pg_extern]
pub fn acts(max_acts: default!(i32, 20)) -> JsonB {
    not_from_inside();
    let who = identity();
    let found: Option<JsonB> = read_internal(
        "select agent_gate_internal._acts($1, $2)",
        &[who.agent.into(), max_acts.into()],
    );
    JsonB(found.map(|j| j.0).unwrap_or_else(|| json!([])))
}

/// Who this session is, and whether the gate is actually enforced in it.
#[pg_extern]
pub fn whoami() -> JsonB {
    let who = identity();
    JsonB(json!({
        "agent": who.agent,
        "is_agent": who.is_agent,
        "role": who.role,
        "enforced": crate::hooks::installed(),
        "loaded_at_server_start": crate::preloaded(),
        "attempt_durability": crate::attempt_durability_name(),
        "verbs": VERBS,
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

/// The record functions ask this. True only for the gate's own SQL.
#[pg_extern]
fn _inside_gate() -> bool {
    state::internal_call_allowed()
}

/// The assertion runner asks this. True only while the gate checks assertions.
#[pg_extern]
fn _checking() -> bool {
    state::checking()
}

struct Outcome {
    rows: Rows,
    abort: Option<String>,
    assertions: Vec<Value>,
}

#[allow(clippy::too_many_arguments)]
fn record_execution(
    proposal: i64,
    mode: Mode,
    outcome: &str,
    reason: Option<String>,
    rows_affected: Option<i64>,
    rows_returned: Option<i32>,
    truncated: Option<bool>,
    assertions: Value,
    sample: Option<Value>,
    duration_ms: f64,
) -> Option<i64> {
    if outcome == "kept" {
        restore_for_a_change();
    } else {
        relax_for_an_attempt();
    }
    call_internal(
        "select agent_gate_internal._record_execution($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        &[
            proposal.into(),
            mode.as_str().to_string().into(),
            outcome.to_string().into(),
            reason.into(),
            rows_affected.into(),
            rows_returned.into(),
            truncated.into(),
            JsonB(assertions).into(),
            sample.map(JsonB).into(),
            duration_ms.into(),
        ],
    )
}

fn refuse_execution(who: &Identity, proposal: i64, mode: Mode, started: Instant, reason: String, checks: Value) -> Value {
    let ms = started.elapsed().as_secs_f64() * 1000.0;
    let execution = record_execution(proposal, mode, "refused", Some(reason.clone()), None, None, None, json!([]), None, ms);
    log!("pg_agent_gate: agent={} proposal={} mode={} outcome=refused", who.agent, proposal, mode.as_str());
    json!({
        "proposal": proposal,
        "mode": mode.as_str(),
        "outcome": "refused",
        "reason": reason,
        "checks": checks,
        "execution": execution,
        "duration_ms": ms,
    })
}

/// Tuple operations (insert + update + delete) this transaction has made to user tables outside
/// the gate's own schemas. Read before and after the statement inside the same subtransaction, the
/// difference is what the statement AND everything it fired -- triggers, cascades, rules, functions
/// -- changed, which `rows.processed` (the top-level count) misses. It counts tuples, so it
/// over-counts (the safe side), and does not see TRUNCATE (blocked as DDL). The gate's own
/// bookkeeping is excluded so its record does not inflate an agent's budget.
fn xact_tuples() -> Option<i64> {
    let _running = state::proposal();
    // None only on a real SPI failure: the coalesce guarantees a non-null value otherwise, so the
    // caller can tell "nothing changed" (Some(0)) from "could not measure" (None) and fail closed.
    Spi::get_one::<i64>(
        "select coalesce(sum(n_tup_ins + n_tup_upd + n_tup_del), 0)::bigint \
         from pg_catalog.pg_stat_xact_user_tables \
         where schemaname not in ('agent_gate', 'agent_gate_internal')",
    )
    .ok()
    .flatten()
}

fn execute(proposal: i64, mode: Mode) -> Value {
    let started = Instant::now();
    let who = identity();

    // A commit LOCKS the proposal's row while it decides; a dry run does not.
    // Without the lock two concurrent commits of the same proposal each read
    // 'committed' from their own snapshot, where the other had not committed
    // yet, and both ran it -- measured, the change was applied twice
    // (tests/hostile.sh). The locking path goes through read-write SPI because
    // a row lock needs a transaction id, which a commit is about to spend
    // anyway; reads keep using read-only SPI so they still spend none.
    let loaded: Option<JsonB> = if mode == Mode::Commit {
        call_internal("select agent_gate_internal._load_proposal($1, true)", &[proposal.into()])
    } else {
        read_internal("select agent_gate_internal._load_proposal($1)", &[proposal.into()])
    };
    let Some(JsonB(p)) = loaded.filter(|j| !j.0.is_null()) else {
        // Nothing to attach a record to: said to the caller and to the log.
        log!("pg_agent_gate: agent={} asked for proposal {} which does not exist", who.agent, proposal);
        return json!({ "proposal": proposal, "mode": mode.as_str(), "outcome": "refused", "reason": "no proposal with that id" });
    };

    if p["agent"].as_str() != Some(who.agent.as_str()) {
        let owner = p["agent"].as_str().unwrap_or("?").to_string();
        return refuse_execution(&who, proposal, mode, started, format!("the proposal belongs to {owner}"), json!(null));
    }
    if p["ok"].as_bool() != Some(true) {
        return refuse_execution(&who, proposal, mode, started, "the proposal did not pass verification".into(), json!(null));
    }
    let ttl = f64::from(crate::PROPOSAL_TTL_SECONDS.get());
    if p["age_seconds"].as_f64().unwrap_or(f64::MAX) > ttl {
        return refuse_execution(
            &who,
            proposal,
            mode,
            started,
            format!("the verification is older than {ttl} seconds: a verification is about the database at a moment, propose again"),
            json!(null),
        );
    }
    if mode == Mode::Commit && p["committed"].as_bool() == Some(true) {
        return refuse_execution(&who, proposal, mode, started, "it was already committed once".into(), json!(null));
    }

    let sql = p["sql"].as_str().unwrap_or_default().to_string();
    let params: Option<Vec<Option<String>>> = p["params"]
        .as_array()
        .map(|a| a.iter().map(|x| x.as_str().map(str::to_string)).collect());

    // The world may have changed since the proposal. Verify again, now.
    let cfg = config(&who);
    let verdict = verify::verify(&sql, &params, cfg.allow_ddl, &cfg.allowed);
    if !verdict.ok {
        let why = verdict.first_failure().map(|c| c.detail.clone()).unwrap_or_default();
        return refuse_execution(
            &who,
            proposal,
            mode,
            started,
            format!("it no longer verifies: {why}"),
            verdict.checks_json(),
        );
    }
    let kind = verdict.kind.expect("a passing verdict has a kind");
    let cap = crate::MAX_RESULT_ROWS.get().max(0) as usize;
    let statement = if verdict.append_returning {
        // On its own line: a trailing -- comment must not swallow it.
        format!("{}\nRETURNING to_jsonb(old) AS before, to_jsonb(new) AS after", verdict.statement)
    } else {
        verdict.statement.clone()
    };
    let args = verify::text_args(&params);
    let bindings = cfg.bindings.clone();
    let max_rows = cfg.max_rows;

    let result = in_subxact(
        || {
            let tup_before = xact_tuples();   // the backstop's starting point, inside this subxact
            // Hold the executing window across BOTH the verified statement and the gate's own SET
            // CONSTRAINTS below (where deferred constraint triggers fire): any utility a trigger,
            // constraint or function reaches is nested and refused, except the one the gate runs
            // on purpose, which it exempts with allow_gate_utility(). It is dropped before the
            // bound-assertion phase, which runs the gate's own pg_living_assertions code (and may
            // itself use utility) and is not the agent's statement.
            let exec_guard = state::executing_verified();
            let rows = {
                let _running = state::proposal();
                Spi::connect_mut(|client| {
                    // The verified statement is itself a utility only when it is DDL (an allow_ddl
                    // agent's CREATE INDEX, ...): exempt that one, so it is not refused as nested.
                    if kind == Kind::Ddl {
                        state::allow_gate_utility();
                    }
                    match kind {
                        // NOT `select`: read-only SPI runs on the snapshot of the
                        // statement that called the verb, and would not see what
                        // earlier statements of the same transaction wrote. A read
                        // cannot keep anything anyway: its subtransaction is
                        // always rolled back.
                        Kind::Read => {
                            client
                                .update(statement.as_str(), Some((cap + 1) as _), &args)
                                .expect("the read failed");
                        }
                        _ => {
                            client.update(statement.as_str(), None, &args).expect("the statement failed");
                        }
                    }
                    unsafe { collect_rows(cap) }
                })
            };

            let mut abort = None;
            if kind != Kind::Read {
                // Deferred constraints fire HERE, inside the gate, and not at the
                // caller's commit where nothing would be watching.
                {
                    let _running = state::proposal();
                    state::allow_gate_utility();   // SET CONSTRAINTS is the gate's own utility
                    Spi::run("SET CONSTRAINTS ALL IMMEDIATE").expect("constraints");
                }
                if kind == Kind::Write && rows.processed as i64 > max_rows {
                    abort = Some(format!(
                        "it touched {} rows and this agent may touch at most {}",
                        rows.processed, max_rows
                    ));
                } else if kind == Kind::Write {
                    // Backstop: the top-level count is not the whole story. Measure the tuples this
                    // transaction changed over the statement (triggers, cascades, rules, functions
                    // included) and abort if they exceed the limit -- the count check that catches an
                    // amplifier the propose checks did not, and what makes an allow-list safe. Fail
                    // CLOSED: if a snapshot could not be read, abort rather than assume zero.
                    match (tup_before, xact_tuples()) {
                        (Some(before), Some(after)) => {
                            let moved = after.saturating_sub(before);
                            if moved > max_rows {
                                abort = Some(format!(
                                    "it changed {moved} rows in all -- {} named plus more from a trigger, \
                                     cascade, rule or function -- and this agent may touch at most {max_rows}",
                                    rows.processed
                                ));
                            }
                        }
                        _ => {
                            abort = Some(
                                "the row-count backstop could not read the transaction's tuple \
                                 statistics, so this write cannot be proven bounded"
                                    .into(),
                            );
                        }
                    }
                }
            }

            // The verified statement and its deferred constraints are done; leave the executing
            // window before the gate's own assertion checks run.
            drop(exec_guard);

            let mut assertions = Vec::new();
            if abort.is_none() && kind != Kind::Read && !bindings.is_empty() {
                let _checking = state::checking_assertions();
                for name in &bindings {
                    let found: Option<JsonB> = Spi::connect_mut(|client| {
                        client
                            .update("select agent_gate_internal._run_assertion($1)", Some(1), &[name.clone().into()])
                            .expect("assertion")
                            .first()
                            .get::<JsonB>(1)
                            .expect("assertion result")
                    });
                    let r = found.map(|j| j.0).unwrap_or(Value::Null);
                    let st = r["state"].as_str().unwrap_or("erroring").to_string();
                    if abort.is_none() && (st == "broken" || st == "erroring") {
                        abort = Some(format!(
                            "after the change, assertion {name} is {st}: {}",
                            r["detail"].as_str().unwrap_or("")
                        ));
                    }
                    assertions.push(r);
                }
            }
            Outcome { rows, abort, assertions }
        },
        |o| mode == Mode::Commit && kind != Kind::Read && o.abort.is_none(),
    );

    let ms = started.elapsed().as_secs_f64() * 1000.0;
    // The hint is what an agent fixes a proposal from: it travels structured,
    // not only folded into the reason text.
    let mut error = None;
    let (outcome, reason, rows, processed, truncated, assertions) = match result {
        Err(f) => {
            error = Some(f.json());
            ("aborted", Some(format!("it ran and PostgreSQL raised {}", f.describe())), Vec::new(), None, None, Vec::new())
        }
        Ok(o) => {
            let outcome = if o.abort.is_some() {
                "aborted"
            } else if kind == Kind::Read {
                "read"
            } else if mode == Mode::Commit {
                "kept"
            } else {
                "rolled_back"
            };
            (outcome, o.abort, o.rows.rows, Some(o.rows.processed), Some(o.rows.truncated), o.assertions)
        }
    };

    let rows_affected = if kind == Kind::Read { None } else { processed.map(|n| n as i64) };
    let sample = if kind == Kind::Read { None } else { Some(Value::Array(rows.iter().take(SAMPLE_ROWS).cloned().collect())) };
    let execution = record_execution(
        proposal,
        mode,
        outcome,
        reason.clone(),
        rows_affected,
        Some(rows.len() as i32),
        truncated,
        Value::Array(assertions.clone()),
        sample,
        ms,
    );
    log!(
        "pg_agent_gate: agent={} proposal={} mode={} outcome={}",
        who.agent,
        proposal,
        mode.as_str(),
        outcome
    );

    json!({
        "proposal": proposal,
        "mode": mode.as_str(),
        "kind": kind.as_str(),
        "outcome": outcome,
        "reason": reason,
        "error": error,
        "rows_affected": rows_affected,
        "rows_returned": rows.len(),
        "truncated": truncated,
        "rows": rows,
        "assertions": assertions,
        "execution": execution,
        "duration_ms": ms,
        "note": if mode == Mode::DryRun {
            "nothing was kept; effects outside transactions (sequence values, session advisory locks) are not undone"
        } else {
            ""
        },
    })
}
