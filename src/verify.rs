//! Verification: every claim a proposal makes is checked against the database
//! itself, before anything runs.
//!
//! Nothing here is a reimplementation. The parser is PostgreSQL's parser, the
//! name and type resolution is PostgreSQL's planner (through EXPLAIN, which
//! plans and does not execute). What this file adds is the ORDER, the verdict
//! and the record of each check -- including the ones that passed, because
//! "what was checked" is the part the database never kept.

use crate::exec::in_subxact;
use crate::hooks::list_len;
use crate::state;
use pgrx::datum::{DatumWithOid, Json};
use pgrx::prelude::*;
use serde_json::{json, Value};
use std::ffi::CString;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Kind {
    Read,
    Write,
    Ddl,
}

impl Kind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Kind::Read => "read",
            Kind::Write => "write",
            Kind::Ddl => "ddl",
        }
    }
}

pub(crate) struct Check {
    pub name: &'static str,
    pub passed: bool,
    pub detail: String,
}

pub(crate) struct Verdict {
    pub ok: bool,
    pub kind: Option<Kind>,
    /// Exactly the statement the parser saw, without a trailing semicolon.
    pub statement: String,
    /// The TOP-LEVEL statement is INSERT, UPDATE, DELETE or MERGE without a
    /// RETURNING of its own, so the gate may add one to show before/after.
    ///
    /// Not the same as `kind == Write`, and the difference was a bug: a SELECT
    /// whose CTE writes IS a write, and `SELECT ... RETURNING` is a syntax
    /// error. Found by the control case of the criteria harness.
    pub append_returning: bool,
    pub estimated_rows: Option<f64>,
    pub checks: Vec<Check>,
}

impl Verdict {
    pub(crate) fn checks_json(&self) -> Value {
        Value::Array(
            self.checks
                .iter()
                .map(|c| json!({ "check": c.name, "passed": c.passed, "detail": c.detail }))
                .collect(),
        )
    }

    pub(crate) fn first_failure(&self) -> Option<&Check> {
        self.checks.iter().find(|c| !c.passed)
    }

    fn check(&mut self, name: &'static str, passed: bool, detail: impl Into<String>) {
        self.checks.push(Check { name, passed, detail: detail.into() });
    }
}

pub(crate) fn text_args(params: &Option<Vec<Option<String>>>) -> Vec<DatumWithOid<'static>> {
    params.iter().flatten().map(|p| DatumWithOid::from(p.clone())).collect()
}

struct Parsed {
    count: i32,
    tag: Option<pg_sys::NodeTag>,
    statement: String,
    append_returning: bool,
    select_into: bool,
    select_locks: bool,
}

pub(crate) fn verify(sql: &str, params: &Option<Vec<Option<String>>>, allow_ddl: bool) -> Verdict {
    let mut v = Verdict {
        ok: false,
        kind: None,
        statement: String::new(),
        append_returning: false,
        estimated_rows: None,
        checks: Vec::new(),
    };
    // Everything below runs SQL the agent wrote.
    let _running = state::proposal();

    // 1. PostgreSQL's own parser accepts it, and it is ONE statement.
    let text = match CString::new(sql) {
        Ok(t) => t,
        Err(_) => {
            v.check("parses", false, "the text contains a NUL byte");
            return v;
        }
    };
    let parsed = match in_subxact(|| unsafe { parse(sql, &text) }, |_| false) {
        Ok(p) => p,
        Err(f) => {
            v.check("parses", false, f.describe());
            return v;
        }
    };
    if parsed.count != 1 {
        v.check("parses", parsed.count > 0, "PostgreSQL's parser accepts the text");
        v.check(
            "single_statement",
            false,
            format!(
                "{} statements: a proposal is exactly one, so that what was verified is what runs",
                parsed.count
            ),
        );
        return v;
    }
    v.check("parses", true, "PostgreSQL's parser accepts it");
    v.check("single_statement", true, "exactly one statement");
    v.statement = parsed.statement;
    v.append_returning = parsed.append_returning;

    // 2. What kind of statement it is, and whether this agent may propose it.
    let tag = parsed.tag.expect("one statement has a tag");
    let mut kind = match tag {
        pg_sys::NodeTag::T_SelectStmt if parsed.select_into => Kind::Ddl,
        pg_sys::NodeTag::T_SelectStmt if parsed.select_locks => Kind::Write,
        pg_sys::NodeTag::T_SelectStmt => Kind::Read,
        pg_sys::NodeTag::T_InsertStmt
        | pg_sys::NodeTag::T_UpdateStmt
        | pg_sys::NodeTag::T_DeleteStmt
        | pg_sys::NodeTag::T_MergeStmt => Kind::Write,
        pg_sys::NodeTag::T_TransactionStmt => {
            v.check(
                "kind_allowed",
                false,
                "transaction control is the gate's job: a proposal is one statement the gate runs and keeps or undoes",
            );
            return v;
        }
        _ => Kind::Ddl,
    };
    if kind == Kind::Ddl && !allow_ddl {
        v.kind = Some(kind);
        v.check(
            "kind_allowed",
            false,
            format!("{tag:?} changes the schema or the server, and this agent is not allowed DDL"),
        );
        return v;
    }
    v.check("kind_allowed", true, format!("{} statement ({tag:?})", kind.as_str()));

    // 3. Names, types and functions resolve against the live catalog.
    match kind {
        Kind::Read | Kind::Write => {
            let explain = format!("EXPLAIN (FORMAT JSON) {}", v.statement);
            let args = text_args(params);
            match in_subxact(|| explain_plan(&explain, &args), |_| false) {
                Ok(plan) => {
                    let (rows, modifies) = read_plan(&plan);
                    if modifies && kind == Kind::Read {
                        // A SELECT whose CTE writes is a write.
                        kind = Kind::Write;
                    }
                    v.estimated_rows = rows;
                    v.check(
                        "resolves",
                        true,
                        "the planner resolved every table, column, type and function, and nothing ran",
                    );
                }
                Err(f) => {
                    v.kind = Some(kind);
                    v.check("resolves", false, f.describe());
                    return v;
                }
            }
        }
        Kind::Ddl => match in_subxact(|| run_statement(&v.statement), |_| false) {
            Ok(()) => v.check(
                "executes",
                true,
                "it ran inside a subtransaction that was rolled back: nothing was kept",
            ),
            Err(f) => {
                v.kind = Some(kind);
                v.check("executes", false, f.describe());
                return v;
            }
        },
    }

    v.kind = Some(kind);
    v.ok = true;
    v
}

unsafe fn parse(sql: &str, text: &CString) -> Parsed {
    let list = pg_sys::raw_parser(text.as_ptr(), pg_sys::RawParseMode::RAW_PARSE_DEFAULT);
    let count = list_len(list);
    let mut parsed = Parsed {
        count,
        tag: None,
        statement: String::new(),
        append_returning: false,
        select_into: false,
        select_locks: false,
    };
    if count != 1 {
        return parsed;
    }
    let raw = &*(pg_sys::list_nth(list, 0) as *mut pg_sys::RawStmt);
    let node = raw.stmt;
    let tag = (*node).type_;

    let start = raw.stmt_location.max(0) as usize;
    let end = if raw.stmt_len > 0 { start + raw.stmt_len as usize } else { sql.len() };
    parsed.statement = sql
        .get(start.min(sql.len())..end.min(sql.len()))
        .unwrap_or(sql)
        .trim()
        .trim_end_matches(';')
        .trim()
        .to_string();

    parsed.append_returning = match tag {
        pg_sys::NodeTag::T_InsertStmt => (*(node as *mut pg_sys::InsertStmt)).returningClause.is_null(),
        pg_sys::NodeTag::T_UpdateStmt => (*(node as *mut pg_sys::UpdateStmt)).returningClause.is_null(),
        pg_sys::NodeTag::T_DeleteStmt => (*(node as *mut pg_sys::DeleteStmt)).returningClause.is_null(),
        pg_sys::NodeTag::T_MergeStmt => (*(node as *mut pg_sys::MergeStmt)).returningClause.is_null(),
        _ => false,
    };
    if tag == pg_sys::NodeTag::T_SelectStmt {
        let s = &*(node as *mut pg_sys::SelectStmt);
        parsed.select_into = !s.intoClause.is_null();
        parsed.select_locks = !s.lockingClause.is_null();
    }
    parsed.tag = Some(tag);
    parsed
}

fn explain_plan(explain: &str, args: &[DatumWithOid<'static>]) -> Value {
    Spi::connect_mut(|client| {
        let plan: Option<Json> = client
            .update(explain, None, args)
            .expect("EXPLAIN failed")
            .first()
            .get::<Json>(1)
            .expect("EXPLAIN did not return json");
        plan.map(|j| j.0).unwrap_or(Value::Null)
    })
}

fn run_statement(statement: &str) {
    Spi::connect_mut(|client| {
        client.update(statement, None, &[]).expect("statement failed");
    })
}

/// (estimated rows the statement touches or returns, whether anything in the
/// plan modifies data)
fn read_plan(plan: &Value) -> (Option<f64>, bool) {
    let top = &plan[0]["Plan"];
    let rows = if top["Node Type"] == "ModifyTable" {
        top["Plans"][0]["Plan Rows"].as_f64()
    } else {
        top["Plan Rows"].as_f64()
    };
    (rows, modifies(top))
}

fn modifies(node: &Value) -> bool {
    node["Node Type"] == "ModifyTable"
        || node["Plans"].as_array().is_some_and(|children| children.iter().any(modifies))
}
