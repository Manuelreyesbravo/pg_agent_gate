// Copyright 2026 Manuel Reyes Bravo
// SPDX-License-Identifier: Apache-2.0

//! Verification: every claim a proposal makes is checked against the database
//! itself, before anything runs.
//!
//! Nothing here is a reimplementation. The parser is PostgreSQL's parser, the
//! name and type resolution is PostgreSQL's analyzer and rewriter, and the
//! estimate is PostgreSQL's planner (through EXPLAIN). What this file adds is
//! the ORDER, the verdict and the record of each check -- including the ones
//! that passed, because "what was checked" is the part the database never kept.
//!
//! The order is part of the guarantee. EXPLAIN does not execute the statement,
//! but planning it does run functions: it folds an IMMUTABLE call with constant
//! arguments and estimates a STABLE one by calling it. So every refusal is
//! decided on the analyzed tree, which runs nothing, and the planner only sees a
//! statement with nothing opaque left in it (0.2.6, tests/plan_time.sh).

use crate::exec::in_subxact;
use crate::hooks::list_len;
use crate::state;
use pgrx::datum::{DatumWithOid, Json};
use pgrx::prelude::*;
use serde_json::{json, Value};
use std::ffi::{c_void, CString};

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

/// `estimate`: whether to work out `estimated_rows`. Only `propose` reports it; `commit` verifies
/// again but returns no estimate, so it skips the VERBOSE plan and the privilege lookup that only
/// the estimate needs (measured: they were most of what 0.2.6-0.2.10 added to a commit).
pub(crate) fn verify(
    sql: &str,
    params: &Option<Vec<Option<String>>>,
    allow_ddl: bool,
    allowed: &[u32],
    estimate: bool,
) -> Verdict {
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
    keep_out_of_workers();

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
        // DDL IS AN ALLOWLIST (0.2.12): statements that change the schema, and nothing else. Every
        // other utility used to fall into "ddl" and run for an allow_ddl agent with no row limit: a DO
        // block deleted 50 rows under max_rows 5, a SET moved the tenant a row-level policy reads, SET
        // ROLE changed who was acting (external audit of 0.2.8, GATE-07). TRUNCATE empties a table
        // without counting a row, LOCK holds others, LISTEN/NOTIFY/LOAD/COPY reach outside: none of
        // them is a schema change, and what is not named here is refused.
        t if is_schema_change(t) => Kind::Ddl,
        other => {
            v.check(
                "kind_allowed",
                false,
                format!("{other:?} is not a change to the schema: an agent proposes reads, writes and -- if allowed -- DDL, nothing else"),
            );
            return v;
        }
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

    // 3. The analyzed and rewritten tree, BEFORE anything is planned. The order is the fix of
    // 0.2.6: up to 0.2.5 the EXPLAIN came first, and the planner constant-folds an IMMUTABLE call
    // with constant arguments -- and estimates a STABLE one -- by RUNNING it. A SECURITY DEFINER
    // function ran as its owner before no_opaque_function refused it, and what it raised came back
    // in the `resolves` detail (tests/plan_time.sh). The analyzer and the rewriter resolve names
    // and types, expand views and add row-level policies, and execute nothing; every refusal below
    // is decided on that tree, so a function the gate refuses is never called.
    //
    // What the tree shows and the plan does not. Two ways a proposal that resolves still escaped
    // the gate, both measured by the cycle harness of yggdrasil (its sql/139 and sql/141) with a
    // superuser watching:
    //   * a CTE that writes is not counted against max_rows -- the gate counts the rows of the
    //     OUTER statement, so `with d as (delete ...) select count(*) from d` deleted 12 rows
    //     under a limit of 5;
    //   * set_config() inside the statement moves, while it runs, a parameter the row-level
    //     policies read. The session allowlist judges SET and startup parameters, but the gate's
    //     own execution is where the hooks step aside, so
    //     `where set_config('app.tenant_id', '2', true) is not null` read another tenant's rows.
    // Both are refused, failing closed. set_config is matched by OID wherever it sits: where,
    // from, a sublink, a CTE, schema-qualified or not.
    // A user function's body is not in this tree, so it could call set_config or write rows no one
    // counts. If it is volatile or SECURITY DEFINER, no_opaque_function below refuses the statement.
    // CREATE TABLE AS and SELECT INTO -- and CREATE MATERIALIZED VIEW, the same node -- are DDL
    // that RUN a query, and up to 0.4.1 the DDL branch only ran it: its query was never walked. Over
    // a CTE that deletes, an allow_ddl agent deleted every row of a table with no max_rows, no budget
    // and no count, and the record said ddl (review of 2026-11-05). That query is now judged on its
    // analyzed and rewritten tree, like a read, before anything runs; the rest of a DDL still runs
    // in a subtransaction that is rolled back.
    let runs_a_query =
        kind == Kind::Ddl && (tag == pg_sys::NodeTag::T_CreateTableAsStmt || parsed.select_into);
    let mut tree_relations: Vec<pg_sys::Oid> = Vec::new();
    if kind != Kind::Ddl || runs_a_query {
        let n_params = params.as_ref().map_or(0, |p| p.len());
        let tree = match in_subxact(|| unsafe { analyze_tree(&v.statement, n_params) }, |_| false) {
            Ok(tree) => tree,
            Err(f) => {
                // A name or a type that does not resolve: the analyzer says so before the planner.
                v.kind = Some(kind);
                v.check("resolves", false, f.describe());
                return v;
            }
        };
        if tree.modifies && kind == Kind::Read {
            // A SELECT whose CTE writes is a write.
            kind = Kind::Write;
        }
        if tree.writing_cte {
            v.kind = Some(kind);
            v.check(
                "no_writing_cte",
                false,
                if runs_a_query {
                    "a CTE here changes data, and a CREATE TABLE AS or SELECT INTO is DDL, which \
                     counts no rows: propose the write as its own statement"
                } else {
                    "a CTE here changes data, and max_rows only counts the rows of the outer statement: \
                     propose each write as its own statement"
                },
            );
            return v;
        }
        v.check("no_writing_cte", true, "no CTE changes data: max_rows sees every row it touches");
        if tree.set_config {
            v.kind = Some(kind);
            v.check(
                "keeps_its_context",
                false,
                "set_config() would change, while the proposal runs, a parameter its row-level \
                 policies may read: an agent's context is set on its role",
            );
            return v;
        }
        v.check("keeps_its_context", true, "nothing in the statement calls set_config()");
        if kind != Kind::Ddl {
            // The allow-list does NOT skip the check -- it is consulted inside it, so an allowed
            // table still refuses an UNSAFE amplifier (a cascade the agent could not do directly,
            // a SECURITY DEFINER trigger, a rule). A blanket skip reopened the 0.2.2 breach.
            match amplifying_object(&tree.targets, allowed) {
                Err(why) => {
                    // Fail CLOSED: a lookup we could not complete is not "nothing to find".
                    v.kind = Some(kind);
                    v.check(
                        "no_amplification",
                        false,
                        format!("the catalog lookup for cascading keys, triggers and rules failed, \
                                 so this write cannot be proven bounded: {why}"),
                    );
                    return v;
                }
                Ok(Some(obj)) => {
                    v.kind = Some(kind);
                    v.check(
                        "no_amplification",
                        false,
                        format!(
                            "writing this table fires {obj}, whose effect the gate cannot check \
                             and which is not counted against max_rows. A non-SECURITY DEFINER \
                             trigger you accept can be allow-listed with agent_gate.allow_write; a \
                             cascade, a rule, or a SECURITY DEFINER trigger cannot be allow-listed \
                             in this version -- remove it or restructure the write"
                        ),
                    );
                    return v;
                }
                Ok(None) => {
                    if tree.modifies && tree.targets.is_empty() {
                        // A modifying statement whose target we could not resolve: refuse, do not run.
                        v.kind = Some(kind);
                        v.check(
                            "no_amplification",
                            false,
                            "this statement modifies data but its target relation could not be \
                             identified, so it cannot be checked for amplification",
                        );
                        return v;
                    }
                    v.check(
                        "no_amplification",
                        true,
                        "no unsafe cascade, trigger or rule on this write's target (or an \
                         inheritance child of it) can amplify it beyond the agent's reach",
                    );
                }
            }
        }
        // SQL IN A TEXT ARGUMENT (0.4.2, review of 2026-11-05). A built-in is vetted because it does
        // what its documentation says, and some say they run a query given as text: query_to_xml(),
        // ts_stat(), ts_rewrite(), the *_to_xml() family, tablefunc's crosstab(). That query is parsed
        // and run while the gate steps aside, so nothing above saw it: set_config() inside it moved
        // the tenant while the same statement read, and nextval() inside it advanced a sequence from
        // a read. The class is refused by what the function IS (its C entry point), not by its name:
        // see hidden_sql_function and the list in SQL_FROM_TEXT.
        match opaque_function(&tree.funcs) {
            Err(why) => {
                v.kind = Some(kind);
                v.check(
                    "no_opaque_function",
                    false,
                    format!("the catalog lookup for the statement's functions failed, so it \
                             cannot be proven safe: {why}"),
                );
                return v;
            }
            Ok(Some(Opaque::SqlFromText(f))) => {
                v.kind = Some(kind);
                v.check(
                    "no_hidden_sql",
                    false,
                    format!("the statement calls {f}, which parses and runs SQL it receives as text \
                             (or builds from a name) where no check of the gate sees it. It was refused \
                             before planning, so it did not run. Propose that query itself"),
                );
                return v;
            }
            Ok(Some(Opaque::Body(f))) => {
                v.check("no_hidden_sql", true, "no function that runs SQL from a text is called");
                v.kind = Some(kind);
                v.check(
                    "no_opaque_function",
                    false,
                    format!("the statement calls {f}; a user function that is volatile or \
                             SECURITY DEFINER, that this agent can alter, or whose SET clause sets a \
                             parameter an agent may not set, has a body or a context the gate cannot \
                             vouch for -- it may write rows no one counts, or run outside the agent's \
                             tenant. It was refused before planning, so it did not run"),
                );
                return v;
            }
            Ok(None) => {
                v.check("no_hidden_sql", true, "no function that runs SQL from a text is called");
                v.check(
                    "no_opaque_function",
                    true,
                    "every function called is a vetted built-in, or a user function that is \
                     neither volatile nor SECURITY DEFINER, is not this agent's to alter, and sets \
                     no parameter an agent may not set",
                );
            }
        }
        // A READ CHANGES NOTHING (0.2.14, external audit GATE-11). Built-ins are vetted above
        // because they do what their documentation says -- and some say they change state: a read
        // that called nextval() advanced a sequence 100,000 times and the record said outcome=read,
        // nothing changed. Those are refused in a read; in a write they are the write's business
        // (an INSERT's default calls nextval).
        if kind == Kind::Read {
            match stateful_builtin(&tree.funcs) {
                Err(why) => {
                    v.kind = Some(kind);
                    v.check(
                        "read_changes_nothing",
                        false,
                        format!("the catalog lookup for the statement's functions failed: {why}"),
                    );
                    return v;
                }
                Ok(Some(f)) => {
                    v.kind = Some(kind);
                    v.check(
                        "read_changes_nothing",
                        false,
                        format!("a read calls {f}, which changes state outside the rows it returns, \
                                 and the record would say nothing changed"),
                    );
                    return v;
                }
                Ok(None) => v.check(
                    "read_changes_nothing",
                    true,
                    "no built-in that changes state (sequences, advisory locks, large objects, \
                     notifications, the WAL) is called",
                ),
            }
        }
        if kind != Kind::Ddl {
            tree_relations = tree.relations;
        }
    }
    if kind == Kind::Ddl {
        match in_subxact(|| run_statement(&v.statement), |_| false) {
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
        }
    }

    // 4. The planner, last: only a statement with nothing opaque left in it gets here, so what
    // the EXPLAIN folds or estimates is a built-in or a vetted user function, run with the
    // agent's own rights.
    if kind != Kind::Ddl {
        // VERBOSE so that every scan names its schema: the estimate is judged on the relations the
        // PLAN reads, which can be more than the tree's (a SQL function the planner inlines).
        let explain = if estimate {
            format!("EXPLAIN (VERBOSE, FORMAT JSON) {}", v.statement)
        } else {
            format!("EXPLAIN (FORMAT JSON) {}", v.statement)
        };
        let args = text_args(params);
        match in_subxact(|| explain_plan(&explain, &args), |_| false) {
            Ok(plan) => {
                let (rows, modifies, plan_relations) = read_plan(&plan);
                if modifies && kind == Kind::Read {
                    kind = Kind::Write;
                }
                // The estimate comes from statistics gathered over the whole table, beneath
                // row-level security and beneath a view: an agent that sees none of a value's rows
                // would read how many another tenant has (measured: 34 against 1 for an absent
                // value). So it is given only when the agent could read in full every relation the
                // tree AND the plan touch -- the plan too, because the planner inlines a SQL
                // function after the tree was built (0.2.8: 34 through such a helper, 1156 through
                // two of them joined). Fail closed: a lookup that failed withholds it.
                if estimate {
                    let hidden = rows_hidden_from_agent(&tree_relations, &plan_relations).unwrap_or(true);
                    v.estimated_rows = if hidden { None } else { rows };
                }
                v.check(
                    "resolves",
                    true,
                    "the planner resolved every table, column, type and function without executing \
                     the statement; it was planned only after every check above passed",
                );
            }
            Err(f) => {
                v.kind = Some(kind);
                v.check("resolves", false, f.describe());
                return v;
            }
        }
    }

    v.kind = Some(kind);
    v.ok = true;
    v
}

/// What the analyzed and rewritten tree of a proposal holds that its plan does not say.
#[derive(Default)]
struct Tree {
    writing_cte: bool,
    set_config: bool,
    /// A data-modifying statement (INSERT/UPDATE/DELETE/MERGE) was seen. A locking read
    /// (SELECT ... FOR UPDATE) is a "write" to the gate but does not modify data, so it is not
    /// this -- and must not be refused for lacking a target.
    modifies: bool,
    /// Relations a modifying statement targets (its result relations), so the catalog can be asked
    /// whether writing them -- or an inheritance child of them -- fires a cascading foreign key, a
    /// user trigger or a rule whose effect is not counted against max_rows (and, for a referential
    /// action, runs as the table owner outside row-level security).
    targets: Vec<pg_sys::Oid>,
    /// Every function the statement calls (direct call, operator, aggregate, window). A USER
    /// function that is volatile or SECURITY DEFINER has a body the gate cannot see: it may write
    /// (uncounted, like a trigger) or run as its owner (outside the agent's tenant, like a cascade).
    funcs: Vec<pg_sys::Oid>,
    /// Every relation the statement reads or writes, in any query of the tree (views already
    /// expanded by the rewriter), so the catalog can be asked whether row-level security hides
    /// rows of one of them from this role -- and the plan's estimate, which counts them all, is
    /// withheld.
    relations: Vec<pg_sys::Oid>,
}

/// Record a Query's result relation. A data-modifying command sets `modifies`; a locking read does
/// not (it has no result relation), so it is not mistaken for a write with an unknown target.
unsafe fn collect_target(q: *mut pg_sys::Query, tree: &mut Tree) {
    // Privileges first, as when the EXPLAIN came first: it failed them at executor start, and the
    // analyzer that now runs before it does not check them. Without this an agent with no grant on
    // a table got the gate's reasoning about that table's triggers before its "permission denied"
    // (tests/plan_time.sh). The executor's own check, so a view's tables are checked as its owner;
    // it raises, and the caller reports it as `resolves`.
    pg_sys::ExecCheckPermissions((*q).rtable, (*q).rteperminfos, true);
    for i in 0..list_len((*q).rtable) {
        let rte = pg_sys::list_nth((*q).rtable, i) as *mut pg_sys::RangeTblEntry;
        if !rte.is_null()
            && (*rte).rtekind == pg_sys::RTEKind::RTE_RELATION
            && (*rte).relid != pg_sys::InvalidOid
        {
            tree.relations.push((*rte).relid);
        }
    }
    if matches!(
        (*q).commandType,
        pg_sys::CmdType::CMD_INSERT
            | pg_sys::CmdType::CMD_UPDATE
            | pg_sys::CmdType::CMD_DELETE
            | pg_sys::CmdType::CMD_MERGE
    ) {
        tree.modifies = true;
        if (*q).resultRelation > 0 {
            let rte = pg_sys::list_nth((*q).rtable, (*q).resultRelation - 1) as *mut pg_sys::RangeTblEntry;
            if !rte.is_null() && (*rte).relid != pg_sys::InvalidOid {
                tree.targets.push((*rte).relid);
            }
        }
    }
}

/// The first UNSAFE amplifier -- a cascade, a user trigger or a rule that writing a target (or an
/// inheritance child of one) fires and the gate cannot vouch for -- across the targets, or `None`.
/// The decision lives in ONE SQL function, agent_gate_internal._unsafe_amplifier, which `discover`
/// calls too, so the two never disagree. `Err` is a lookup that failed and must refuse, never pass.
fn amplifying_object(targets: &[pg_sys::Oid], allowed: &[u32]) -> Result<Option<String>, String> {
    if targets.is_empty() {
        return Ok(None);
    }
    let ids: Vec<i64> = targets.iter().map(|o| o.to_u32() as i64).collect();
    let allow: Vec<i64> = allowed.iter().map(|o| *o as i64).collect();
    // A scalar subquery, so the result is exactly one row: the first unsafe amplifier's name, or
    // NULL. Ok(Some)/Ok(None); only a real failure gives Err.
    crate::exec::get_one_prepared::<String>(
        "select (select x.label
                   from unnest($1::int8[]) t,
                        lateral (select agent_gate_internal._unsafe_amplifier(t::oid, $2::bigint[]) as label) x
                  where x.label is not null limit 1)",
        &[PgOid::BuiltIn(PgBuiltInOids::INT8ARRAYOID), PgOid::BuiltIn(PgBuiltInOids::INT8ARRAYOID)],
        &[ids.into(), allow.into()],
    )
}

/// The C entry points (prosrc of a LANGUAGE internal or C function) that parse and run SQL given
/// to them as text, or built from a name, through SPI -- where the hooks step aside, because the
/// statement that called them is already the gate's to run. Derived (0.4.2) from the PostgreSQL
/// source, not from a list of names: every SQL-callable function whose implementation reaches
/// SPI_execute, SPI_prepare or SPI_cursor_open/find with text it did not write itself.
///   * src/backend/utils/adt/xml.c: query_to_xml, query_to_xmlschema, query_to_xml_and_xmlschema
///     and cursor_to_xml, cursor_to_xmlschema (a query or a cursor given by the caller);
///     table_, schema_ and database_to_xml[schema|_and_xmlschema] (a SELECT built from a name).
///   * src/backend/utils/adt/tsvector_op.c: ts_stat1, ts_stat2 (ts_stat(query [, weights])).
///   * src/backend/utils/adt/tsquery_rewrite.c: tsquery_rewrite_query (ts_rewrite(tsquery, query)).
///   * contrib, installed as an extension: tablefunc's crosstab, crosstab_hash, connectby_text,
///     connectby_text_serial; xml2's xpath_table; every dblink_* entry point (already volatile).
/// The other users of SPI in the server are triggers (ri_triggers.c, tsvector_update_trigger, the
/// spi/tcn/lo contribs), which no statement calls, and ruleutils.c, whose queries are fixed catalog
/// reads (pg_get_ruledef, pg_get_viewdef). Checked against pg_proc of PostgreSQL 18.6 and 19beta2:
/// `select oid::regprocedure from pg_proc where prolang in (12, 13) and prosrc = any(...)`.
pub(crate) const SQL_FROM_TEXT: &[&str] = &[
    "query_to_xml",
    "query_to_xmlschema",
    "query_to_xml_and_xmlschema",
    "cursor_to_xml",
    "cursor_to_xmlschema",
    "table_to_xml",
    "table_to_xmlschema",
    "table_to_xml_and_xmlschema",
    "schema_to_xml",
    "schema_to_xmlschema",
    "schema_to_xml_and_xmlschema",
    "database_to_xml",
    "database_to_xmlschema",
    "database_to_xml_and_xmlschema",
    "ts_stat1",
    "ts_stat2",
    "tsquery_rewrite_query",
    "crosstab",
    "crosstab_hash",
    "connectby_text",
    "connectby_text_serial",
    "xpath_table",
];

/// Whether a C entry point (with its language) is one of SQL_FROM_TEXT. LANGUAGE internal is 12 and
/// C is 13, fixed in pg_language.dat; nothing else can name a C symbol.
pub(crate) fn runs_sql_from_text(prolang: u32, prosrc: &str) -> bool {
    (prolang == 12 || prolang == 13) && (SQL_FROM_TEXT.contains(&prosrc) || prosrc.starts_with("dblink"))
}

/// A parameter a function's SET clause may set and still be vouched for: one an agent may set
/// itself, or search_path, which only names where the function's own body looks (the usual
/// hardening of a function, and the gate's own functions carry it).
pub(crate) fn set_clause_allowed(name: &str) -> bool {
    let name = name.trim().to_lowercase();
    name == "search_path" || crate::settable(&name)
}

pub(crate) enum Opaque {
    /// A function that runs SQL from a text: `no_hidden_sql`.
    SqlFromText(String),
    /// A user function whose body or context the gate cannot vouch for: `no_opaque_function`.
    Body(String),
}

/// The first function the statement calls that the gate cannot vouch for, or `None`:
///   * one that runs SQL from a text (SQL_FROM_TEXT), built-in or not;
///   * a USER function -- created after initdb, OID >= FirstNormalObjectId, so an extension
///     installed into pg_catalog is not taken for a built-in -- that is
///       - SECURITY DEFINER (it runs as its owner, outside the agent's tenant, like a cascade), or
///       - volatile (its body may write rows no one counted, like a trigger), or
///       - in an agent's session, ALTERABLE BY THE AGENT: owned by a role whose privileges it has
///         (0.4.2). Its STABLE or IMMUTABLE is then the adversary's own claim -- an allow_ddl agent
///         marked a plpgsql function that calls set_config() IMMUTABLE, and the planner ran it --
///         so it is opaque whatever it says, or
///       - one whose SET clause sets a parameter an agent may not set (0.4.2): the clause applies
///         while the body runs, so `SET app.tenant_id = '2'` reads the other tenant's rows.
/// Err = the lookup failed (refuse, fail closed).
fn opaque_function(funcs: &[pg_sys::Oid]) -> Result<Option<Opaque>, String> {
    if funcs.is_empty() {
        return Ok(None);
    }
    let ids: Vec<i64> = funcs.iter().map(|o| o.to_u32() as i64).collect();
    let symbols: Vec<String> = SQL_FROM_TEXT.iter().map(|s| s.to_string()).collect();
    let mut settable: Vec<String> = crate::SETTABLE_BY_AGENTS.iter().map(|s| s.to_string()).collect();
    settable.extend(crate::settable_extra());
    settable.push("search_path".into());
    let found = crate::exec::get_one_prepared::<String>(
        "select (
           select case when x.from_text then 'T' else 'B' end ||
                  n.nspname || '.' || p.proname || '()' ||
                  case when x.from_text then '' else ' (' || x.why || ')' end
             from pg_catalog.pg_proc p
             join pg_catalog.pg_namespace n on n.oid = p.pronamespace
             cross join lateral (
               select p.prolang in (12, 13)
                      and (p.prosrc = any($2::text[]) or p.prosrc like 'dblink%') as from_text,
                      case
                        when p.oid < 16384 then null
                        when p.prosecdef then 'security definer'
                        when p.provolatile = 'v' then 'volatile'
                        when $3 and pg_catalog.pg_has_role(p.proowner, 'USAGE')
                          then 'this agent can alter it, so what it is marked is its own claim'
                        else (select 'its SET clause sets ' || pg_catalog.split_part(c, '=', 1) ||
                                     ', which an agent may not set'
                                from pg_catalog.unnest(p.proconfig) c
                               where pg_catalog.lower(pg_catalog.split_part(c, '=', 1)) <> all($4::text[])
                               limit 1)
                      end as why) x
            where p.oid = any($1::int8[]::oid[])
              and (x.from_text or x.why is not null)
            order by x.from_text desc
            limit 1
         )",
        &[
            PgOid::BuiltIn(PgBuiltInOids::INT8ARRAYOID),
            PgOid::BuiltIn(PgBuiltInOids::TEXTARRAYOID),
            PgOid::BuiltIn(PgBuiltInOids::BOOLOID),
            PgOid::BuiltIn(PgBuiltInOids::TEXTARRAYOID),
        ],
        &[ids.into(), symbols.into(), crate::agent_is_set().into(), settable.into()],
    )?;
    Ok(found.map(|f| match f.split_at(1) {
        ("T", rest) => Opaque::SqlFromText(rest.to_string()),
        (_, rest) => Opaque::Body(rest.to_string()),
    }))
}

/// A built-in the statement calls that changes state outside the rows a read returns: sequences,
/// session advisory locks, large objects, notifications, the random seed, the WAL and statistics.
/// Ok(None) = none, Ok(Some(name)) = refuse naming it, Err = lookup failed (refuse, fail closed).
fn stateful_builtin(funcs: &[pg_sys::Oid]) -> Result<Option<String>, String> {
    if funcs.is_empty() {
        return Ok(None);
    }
    let ids: Vec<i64> = funcs.iter().map(|o| o.to_u32() as i64).collect();
    crate::exec::get_one_prepared::<String>(
        "select (
           select p.proname||'()'
             from pg_catalog.pg_proc p
             where p.oid = any($1::int8[]::oid[])
               and p.pronamespace = 'pg_catalog'::regnamespace
               and (p.proname in ('nextval', 'setval', 'setseed', 'pg_notify',
                                  'pg_logical_emit_message', 'pg_switch_wal',
                                  'pg_create_restore_point', 'pg_create_physical_replication_slot',
                                  'pg_create_logical_replication_slot', 'pg_drop_replication_slot',
                                  'pg_replication_origin_create', 'pg_replication_origin_drop')
                    or p.proname like 'pg\\_advisory\\_%'
                    or p.proname like 'pg\\_try\\_advisory\\_%'
                    or p.proname like 'pg\\_stat\\_reset%'
                    or p.proname like 'lo\\_%'
                    or p.proname in ('loread', 'lowrite'))
             limit 1
         )",
        &[PgOid::BuiltIn(PgBuiltInOids::INT8ARRAYOID)],
        &[ids.into()],
    )
}

/// Whether the current role could NOT read in full some relation the statement touches -- in the
/// analyzed tree (by OID) or in the plan (by schema and name). Not in full means: no SELECT on the
/// whole table (the agent reads it only through a view, or only some columns), row-level security
/// active for this role (PostgreSQL's row_security_active(), so a superuser, a BYPASSRLS role and an
/// owner without FORCE keep the estimate), or a plan relation whose name does not resolve. Err = the
/// lookup failed; the caller withholds the estimate (fail closed).
fn rows_hidden_from_agent(relations: &[pg_sys::Oid], plan_relations: &[(String, String)]) -> Result<bool, String> {
    if relations.is_empty() && plan_relations.is_empty() {
        return Ok(false);
    }
    let ids: Vec<i64> = relations.iter().map(|o| o.to_u32() as i64).collect();
    let schemas: Vec<String> = plan_relations.iter().map(|(s, _)| s.clone()).collect();
    let names: Vec<String> = plan_relations.iter().map(|(_, n)| n.clone()).collect();
    crate::exec::get_one_prepared::<bool>(
        "select exists (select 1 from (
             select r::oid as r from unnest($1::int8[]) r
             union all
             select pg_catalog.to_regclass(pg_catalog.format('%I.%I', s, n))::oid
               from unnest($2::text[], $3::text[]) as p(s, n)
           ) x
           where x.r is null
              or not pg_catalog.has_table_privilege(x.r, 'SELECT')
              or pg_catalog.row_security_active(x.r))",
        &[
            PgOid::BuiltIn(PgBuiltInOids::INT8ARRAYOID),
            PgOid::BuiltIn(PgBuiltInOids::TEXTARRAYOID),
            PgOid::BuiltIn(PgBuiltInOids::TEXTARRAYOID),
        ],
        &[ids.into(), schemas.into(), names.into()],
    )
    .map(|b| b.unwrap_or(true))
    .map_err(|e| e.to_string())
}

/// Keep the agent's SQL out of parallel workers, for the rest of its transaction. The hook that stops
/// a SECURITY DEFINER function keys on a counter that lives in this backend; a worker has its own, at
/// zero. Measured on 0.2.7: a worker of an agent session was refused anyway -- it inherits
/// agent_gate.agent, so the session hooks refused the function body it parsed and a plan fragment
/// that read a table -- which held by accident and broke a plain parallel CREATE TABLE AS of an
/// allow_ddl agent. With no workers the backend runs the whole plan, where the hook sees it, and that
/// statement goes through. max_parallel_workers is the guarantee (it caps what this backend may
/// launch, maintenance workers included); the other two keep the plan EXPLAIN shows the plan that
/// runs. LOCAL: undone when the transaction ends, and the agent cannot SET them back (allowlist).
fn keep_out_of_workers() {
    for name in [c"max_parallel_workers", c"max_parallel_workers_per_gather", c"max_parallel_maintenance_workers"] {
        // elevel 0 on a session source is ERROR: a setting that did not take fails the verb, closed.
        unsafe {
            pg_sys::set_config_option(
                name.as_ptr(),
                c"0".as_ptr(),
                pg_sys::GucContext::PGC_USERSET,
                pg_sys::GucSource::PGC_S_SESSION,
                pg_sys::GucAction::GUC_ACTION_LOCAL,
                true,
                0,
                false,
            );
        }
    }
}

/// Parses the (already verified, single) statement again, runs PostgreSQL's analyzer and
/// rewriter on it with the parameters typed as text -- the way EXPLAIN and the execution
/// receive them -- and walks every query the rewriter produced.
unsafe fn analyze_tree(statement: &str, n_params: usize) -> Tree {
    let text = CString::new(statement).expect("the statement was parsed from a NUL-free text");
    let raws = pg_sys::raw_parser(text.as_ptr(), pg_sys::RawParseMode::RAW_PARSE_DEFAULT);
    // The statement was already verified as one non-empty statement; re-parsing must
    // yield exactly that. Fail closed (the subtransaction catches a panic and verify
    // refuses) rather than indexing an empty list or dereferencing a null node.
    assert_eq!(list_len(raws), 1, "the verified statement re-parses to one statement");
    let raw = pg_sys::list_nth(raws, 0) as *mut pg_sys::RawStmt;
    assert!(!(*raw).stmt.is_null(), "the verified statement re-parses to a non-empty node");
    let types = vec![pg_sys::TEXTOID; n_params];
    let queries = pg_sys::pg_analyze_and_rewrite_fixedparams(
        raw,
        text.as_ptr(),
        types.as_ptr(),
        n_params as i32,
        std::ptr::null_mut(),
    );
    let mut tree = Tree::default();
    for i in 0..list_len(queries) {
        let q = pg_sys::list_nth(queries, i) as *mut pg_sys::Query;
        // A CREATE TABLE AS (SELECT INTO is analyzed into one) is a utility whose query the
        // analyzer has resolved but the rewriter has not: rewrite a copy, as EXPLAIN does, so views
        // are expanded and row-level policies added, and walk that.
        let ctas = (*q).commandType == pg_sys::CmdType::CMD_UTILITY
            && !(*q).utilityStmt.is_null()
            && (*(*q).utilityStmt).type_ == pg_sys::NodeTag::T_CreateTableAsStmt;
        let walked: Vec<*mut pg_sys::Query> = if ctas {
            let inner = (*((*q).utilityStmt as *mut pg_sys::CreateTableAsStmt)).query;
            assert!(
                !inner.is_null() && (*inner).type_ == pg_sys::NodeTag::T_Query,
                "the query of a CREATE TABLE AS is analyzed"
            );
            let rewritten = pg_sys::QueryRewrite(pg_sys::copyObjectImpl(inner as *const c_void) as *mut pg_sys::Query);
            (0..list_len(rewritten)).map(|j| pg_sys::list_nth(rewritten, j) as *mut pg_sys::Query).collect()
        } else {
            vec![q]
        };
        for q in walked {
            tree.writing_cte |= (*q).hasModifyingCTE;
            collect_target(q, &mut tree);
            pg_sys::query_tree_walker_impl(q, Some(walk), &mut tree as *mut Tree as *mut c_void, 0);
        }
        if tree.set_config {
            break;
        }
    }
    tree
}

/// Tree walker: stops (returns true) at the first set_config(); records a writing CTE in
/// any nested query and keeps walking, because set_config may still be further down.
#[pg_guard]
unsafe extern "C-unwind" fn walk(node: *mut pg_sys::Node, context: *mut c_void) -> bool {
    if node.is_null() {
        return false;
    }
    let tree = &mut *(context as *mut Tree);
    match (*node).type_ {
        pg_sys::NodeTag::T_FuncExpr => {
            let fe = node as *mut pg_sys::FuncExpr;
            tree.funcs.push((*fe).funcid);
            if (*fe).funcid == pg_sys::Oid::from(pg_sys::F_SET_CONFIG) {
                tree.set_config = true;
                return true;
            }
            pg_sys::expression_tree_walker_impl(node, Some(walk), context)
        }
        pg_sys::NodeTag::T_OpExpr | pg_sys::NodeTag::T_DistinctExpr | pg_sys::NodeTag::T_NullIfExpr => {
            tree.funcs.push((*(node as *mut pg_sys::OpExpr)).opfuncid);
            pg_sys::expression_tree_walker_impl(node, Some(walk), context)
        }
        pg_sys::NodeTag::T_ScalarArrayOpExpr => {
            // `x = ANY(...)`, `x IN (...)`: the operator's function, same as an OpExpr.
            tree.funcs.push((*(node as *mut pg_sys::ScalarArrayOpExpr)).opfuncid);
            pg_sys::expression_tree_walker_impl(node, Some(walk), context)
        }
        pg_sys::NodeTag::T_Aggref => {
            tree.funcs.push((*(node as *mut pg_sys::Aggref)).aggfnoid);
            pg_sys::expression_tree_walker_impl(node, Some(walk), context)
        }
        pg_sys::NodeTag::T_WindowFunc => {
            tree.funcs.push((*(node as *mut pg_sys::WindowFunc)).winfnoid);
            pg_sys::expression_tree_walker_impl(node, Some(walk), context)
        }
        pg_sys::NodeTag::T_Query => {
            let q = node as *mut pg_sys::Query;
            tree.writing_cte |= (*q).hasModifyingCTE;
            collect_target(q, tree);
            pg_sys::query_tree_walker_impl(q, Some(walk), context, 0)
        }
        _ => pg_sys::expression_tree_walker_impl(node, Some(walk), context),
    }
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
    if node.is_null() {
        // An empty statement (e.g. ";") parses to a single RawStmt whose node is
        // null. It runs nothing; report zero statements so verify refuses it as
        // "not exactly one statement" instead of dereferencing the null (crash).
        parsed.count = 0;
        return parsed;
    }
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
/// plan modifies data, the (schema, relation) of every relation the plan reads or writes)
fn read_plan(plan: &Value) -> (Option<f64>, bool, Vec<(String, String)>) {
    let top = &plan[0]["Plan"];
    let rows = if top["Node Type"] == "ModifyTable" {
        top["Plans"][0]["Plan Rows"].as_f64()
    } else {
        top["Plan Rows"].as_f64()
    };
    let mut relations = Vec::new();
    plan_relations(top, &mut relations);
    (rows, modifies(top), relations)
}

/// Every node that names a relation, sub-plans and init-plans included (they are under "Plans"). A
/// name without a schema is kept with an empty one: it does not resolve, and the estimate is
/// withheld rather than guessed.
fn plan_relations(node: &Value, out: &mut Vec<(String, String)>) {
    if let Some(name) = node["Relation Name"].as_str() {
        out.push((node["Schema"].as_str().unwrap_or("").to_string(), name.to_string()));
    }
    if let Some(children) = node["Plans"].as_array() {
        for child in children {
            plan_relations(child, out);
        }
    }
}

fn modifies(node: &Value) -> bool {
    node["Node Type"] == "ModifyTable"
        || node["Plans"].as_array().is_some_and(|children| children.iter().any(modifies))
}

/// The statements an allow_ddl agent may propose: they change the schema. An allowlist, so a
/// statement PostgreSQL adds later is refused until someone decides it belongs here.
fn is_schema_change(tag: pg_sys::NodeTag) -> bool {
    use pg_sys::NodeTag::*;
    matches!(
        tag,
        T_CreateStmt
            | T_CreateTableAsStmt
            | T_CreateSchemaStmt
            | T_CreateSeqStmt
            | T_CreateFunctionStmt
            | T_CreateTrigStmt
            | T_CreatePolicyStmt
            | T_CreateDomainStmt
            | T_CreateEnumStmt
            | T_CreateRangeStmt
            | T_CreateStatsStmt
            | T_CompositeTypeStmt
            | T_DefineStmt
            | T_ViewStmt
            | T_IndexStmt
            | T_RuleStmt
            | T_AlterTableStmt
            | T_AlterSeqStmt
            | T_AlterFunctionStmt
            | T_AlterEnumStmt
            | T_AlterDomainStmt
            | T_AlterPolicyStmt
            | T_AlterOwnerStmt
            | T_AlterObjectSchemaStmt
            | T_AlterStatsStmt
            | T_RenameStmt
            | T_DropStmt
            | T_CommentStmt
            | T_GrantStmt
    )
}
