// Copyright 2026 Manuel Reyes Bravo
// SPDX-License-Identifier: Apache-2.0

//! The gate itself: what plain SQL cannot do.
//!
//! A schema of functions can OFFER a safe path. It cannot make the unsafe path
//! disappear -- an agent holding a connection can always type `DELETE FROM`.
//! These hooks make it disappear: in a session that belongs to an agent, every
//! statement that reaches the parser must be `SELECT agent_gate.<verb>(...)`
//! with literals or parameters as arguments, transaction control, SHOW, or a SET
//! of a parameter on the allowlist (crate::SETTABLE_BY_AGENTS). The same allowlist
//! judges the parameters the session STARTED with: a startup parameter is not a
//! statement, so it is checked once, before the session's first statement is judged.
//! Everything else dies before it is planned.
//!
//! FOUR HOOKS, ONE RULE. `post_parse_analyze` is the gate. `ProcessUtility`
//! and `ExecutorStart` are the second line, for anything that reaches
//! execution without a fresh parse (a cached plan, a utility statement issued
//! from C). `fmgr_hook` is the floor under verification: while the agent's SQL
//! runs, no SECURITY DEFINER function starts, however it was reached (0.2.7).
//!
//! THE FLOOR: CODE IS JUDGED WHERE IT STARTS (0.4.3). The checks of verify.rs read the
//! statement's own tree, and the tree is not where all the code is: a domain's CHECK, a table's
//! CHECK or DEFAULT, an index expression, an aggregate's transition function, a range type's
//! subtype_diff, a trigger, another function's body. Each review found the next place (0.4.2:
//! SQL given as text, CHECK and DEFAULT; 0.4.3: domains, aggregates, a range type's support
//! function reached from the type cache). So the rule does not depend on finding them: while
//! the agent's SQL runs, every function is judged at the moment it starts, by one function,
//! `floor()`, on the two paths by which PostgreSQL starts a function --
//!   * the executor (`object_access`, OAT_FUNCTION_EXECUTE): every expression it evaluates,
//!     built-ins included, wherever the expression came from;
//!   * the function manager (`needs_floor` + `definer_guard`): a function C code calls through
//!     a cached FmgrInfo, with no executor around it -- the type cache, RI checks, triggers,
//!     index support. PostgreSQL asks `needs_fmgr_hook` when it looks such a function up, and
//!     calls `fmgr_hook` each time it starts. A built-in is looked up by the fast path that asks
//!     no hook; on these paths it is chosen by DDL only a superuser runs (operator classes, base
//!     types), or has a signature no built-in that changes state has (a range's subtype_diff).
//! What the floor stops is said in `floor()`; whose function it is, is judged against the AGENT'S
//! role -- the session's login role -- and never the current user, which PostgreSQL switches to a
//! table's owner for an RI check.
//!
//! THE COMMON CASE IS FREE. Once preloaded, these run on every statement of
//! every session, and almost none belong to an agent. Each hook first asks two
//! questions that allocate nothing -- is the gate's own SQL running, is the
//! agent setting non-empty -- and returns. Only an agent session pays for more.
//!
//! WHAT IT DOES NOT COVER, said here and in the README:
//! * the fast-path function-call protocol (PQfn) skips the parser; a function
//!   reached that way which runs no SQL (large objects) is not stopped. Revoke
//!   EXECUTE on those from the agent's role.
//! * without the library loaded before the agent's first statement the gate
//!   fails OPEN, like Landlock. `whoami()` reports whether it is enforced.

use crate::state;
use pgrx::pg_sys::elog::PgLogLevel;
use pgrx::pg_sys::errcodes::PgSqlErrorCode;
use pgrx::pg_sys::panic::ErrorReport;
use pgrx::prelude::*;
use std::ffi::{c_char, CStr};

pub(crate) const VERBS: &[&str] =
    &["discover", "propose", "dry_run", "commit", "propose_and_commit", "acts", "whoami"];

const SHAPE: &str = "an agent session may only run SELECT agent_gate.<verb>(...) with literals or parameters";

static mut PREV_POST_PARSE: pg_sys::post_parse_analyze_hook_type = None;
static mut PREV_PROCESS_UTILITY: pg_sys::ProcessUtility_hook_type = None;
static mut PREV_EXECUTOR_START: pg_sys::ExecutorStart_hook_type = None;
static mut PREV_FMGR: pg_sys::fmgr_hook_type = None;
static mut PREV_NEEDS_FMGR: pg_sys::needs_fmgr_hook_type = None;
static mut PREV_OBJECT_ACCESS: pg_sys::object_access_hook_type = None;
static mut INSTALLED: bool = false;

pub(crate) fn installed() -> bool {
    unsafe { INSTALLED }
}

pub(crate) unsafe fn install() {
    if INSTALLED {
        return;
    }
    PREV_POST_PARSE = pg_sys::post_parse_analyze_hook;
    pg_sys::post_parse_analyze_hook = Some(post_parse);
    PREV_PROCESS_UTILITY = pg_sys::ProcessUtility_hook;
    pg_sys::ProcessUtility_hook = Some(process_utility);
    PREV_EXECUTOR_START = pg_sys::ExecutorStart_hook;
    pg_sys::ExecutorStart_hook = Some(executor_start);
    PREV_FMGR = pg_sys::fmgr_hook;
    pg_sys::fmgr_hook = Some(definer_guard);
    PREV_NEEDS_FMGR = pg_sys::needs_fmgr_hook;
    pg_sys::needs_fmgr_hook = Some(needs_floor);
    PREV_OBJECT_ACCESS = pg_sys::object_access_hook;
    pg_sys::object_access_hook = Some(object_access);
    INSTALLED = true;
}

/// True only when the statement must be judged: an agent session, and none of
/// the gate's own SQL running. Allocation-free on the common path.
///
/// It is also where the SESSION is judged, before any of its statements: an agent
/// session that started with a parameter it may not hold -- `options=-c
/// app.tenant_id=2` -- would read under a context its role was not given, and no
/// statement of it shows that. Such a session fails closed: every statement is
/// refused, in all three hooks, because all three ask this first.
fn must_judge() -> bool {
    if state::sql_may_run() || !crate::agent_is_set() {
        return false;
    }
    if let Some(name) = crate::startup_parameter_not_settable() {
        refuse(&crate::current_agent().unwrap_or_default(), started_with(&name));
    }
    true
}

fn started_with(name: &str) -> String {
    format!(
        "the connection set {name} when it started (a startup parameter, such as libpq's PGOPTIONS or a driver's \
         `options`): an agent session may only start with client formatting and time limits. Its context is set \
         on its role, and a superuser can add a parameter to agent_gate.settable"
    )
}

pub(crate) unsafe fn list_len(list: *mut pg_sys::List) -> i32 {
    if list.is_null() {
        0
    } else {
        pg_sys::list_length(list)
    }
}

unsafe fn nth<T>(list: *mut pg_sys::List, i: i32) -> *mut T {
    pg_sys::list_nth(list, i) as *mut T
}

pub(crate) fn refuse(agent: &str, why: String) -> ! {
    ErrorReport::new(
        PgSqlErrorCode::ERRCODE_INSUFFICIENT_PRIVILEGE,
        format!("pg_agent_gate: this session belongs to agent \"{agent}\": it proposes, it does not execute"),
        "pg_agent_gate",
    )
    .set_detail(why)
    .set_hint(
        "Call agent_gate.propose(sql, intent), then agent_gate.dry_run(proposal) or \
         agent_gate.commit(proposal) -- or agent_gate.propose_and_commit(sql, intent) for both \
         in one call. agent_gate.discover() shows what this agent may touch.",
    )
    .report(PgLogLevel::ERROR);
    unreachable!()
}

// PostgreSQL 19 made the jumble state a const pointer in this hook.
#[cfg(feature = "pg18")]
type JumbleStatePtr = *mut pg_sys::JumbleState;
#[cfg(not(feature = "pg18"))]
type JumbleStatePtr = *const pg_sys::JumbleState;

#[pg_guard]
unsafe extern "C-unwind" fn post_parse(
    pstate: *mut pg_sys::ParseState,
    query: *mut pg_sys::Query,
    jstate: JumbleStatePtr,
) {
    if let Some(prev) = PREV_POST_PARSE {
        prev(pstate, query, jstate);
    }
    if query.is_null() || !must_judge() {
        return;
    }
    if let Some(agent) = crate::current_agent() {
        if let Err(why) = top_level_allowed(&*query) {
            refuse(&agent, why);
        }
    }
}

#[pg_guard]
#[allow(clippy::too_many_arguments)]
unsafe extern "C-unwind" fn process_utility(
    pstmt: *mut pg_sys::PlannedStmt,
    query_string: *const c_char,
    read_only_tree: bool,
    context: pg_sys::ProcessUtilityContext::Type,
    params: pg_sys::ParamListInfo,
    query_env: *mut pg_sys::QueryEnvironment,
    dest: *mut pg_sys::DestReceiver,
    qc: *mut pg_sys::QueryCompletion,
) {
    if !pstmt.is_null() && must_judge() {
        if let Some(agent) = crate::current_agent() {
            if let Err(why) = utility_allowed((*pstmt).utilityStmt) {
                refuse(&agent, why);
            }
        }
    }
    // A utility statement that fires while the gate is running a verified statement can only have
    // come from a trigger, constraint or function that statement reached -- a path the propose-time
    // walker does not see and that pg_stat_xact would not even count (a TRUNCATE, GRANT, ALTER or
    // DROP from there is uncounted and permanent). Refuse it, on the gate's own `executing` flag and
    // NOT on current_user (inside a SECURITY DEFINER function the agent is already the owner).
    if !pstmt.is_null() && state::executing() {
        // A SUBCOMMAND is part of a utility the gate is already running (e.g. the index an ALTER
        // TABLE builds), so it passes. The one utility the gate runs on purpose -- the verified
        // DDL for an allow_ddl agent, or its own SET CONSTRAINTS -- carries a one-shot allowance.
        // Anything else a trigger, constraint or function fires from here is nested and refused.
        if context != pg_sys::ProcessUtilityContext::PROCESS_UTILITY_SUBCOMMAND
            && !state::take_gate_utility()
        {
            let agent = crate::current_agent().unwrap_or_default();
            refuse(
                &agent,
                "a trigger, constraint or function reached by this statement tried to run a utility \
                 command (TRUNCATE, GRANT, a DDL, ...); the gate refuses nested utility"
                    .into(),
            );
        }
    }
    // AN AGENT ROLE HAS NO MEMBERS (0.4.1). The gate knows an agent session by agent_gate.agent,
    // which PostgreSQL applies when the agent role CONNECTS; a member of that role can SET ROLE
    // into it (or set_config('role', ...)) from a session of its own and have the agent's
    // privileges with no gate at all -- measured on 0.4.0: `SET ROLE seat; DELETE FROM t` took 20
    // rows past a max_rows of 2. Only members (and superusers, outside the gate by design) can do
    // that, so a statement that ADDS a membership in a registered agent role is refused, whatever
    // its form: GRANT, CREATE ROLE ... IN ROLE, ALTER GROUP ... ADD USER. Read before and after,
    // so an installation upgraded with memberships already in place can still administer its roles
    // while it revokes them (the upgrade warns); it only cannot add one.
    let watch = !pstmt.is_null() && changes_membership((*pstmt).utilityStmt);
    let before = if watch { agent_memberships() } else { None };
    match PREV_PROCESS_UTILITY {
        Some(prev) => prev(pstmt, query_string, read_only_tree, context, params, query_env, dest, qc),
        None => pg_sys::standard_ProcessUtility(
            pstmt,
            query_string,
            read_only_tree,
            context,
            params,
            query_env,
            dest,
            qc,
        ),
    }
    if let (Some(before), Some(after)) = (before, if watch { agent_memberships() } else { None }) {
        let added: Vec<&String> = after.iter().filter(|m| !before.contains(m)).collect();
        if !added.is_empty() {
            let added = added.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ");
            error!(
                "pg_agent_gate: this would make a role a member of an agent role ({added}); a member \
                 can SET ROLE into it in a session the gate does not watch. An agent role has no \
                 members: each agent, or each seat of a broker, logs in as its own role"
            );
        }
    }
}

/// A utility statement that can add a member to a role.
unsafe fn changes_membership(stmt: *mut pg_sys::Node) -> bool {
    !stmt.is_null()
        && matches!(
            (*stmt).type_,
            pg_sys::NodeTag::T_GrantRoleStmt | pg_sys::NodeTag::T_CreateRoleStmt | pg_sys::NodeTag::T_AlterRoleStmt
        )
}

/// Every membership in a registered agent role ('agent <- member'), or None where the extension
/// is not installed in this database at 0.4.1 or later: the library is loaded cluster-wide, the
/// record is per database, and a newer library over an older schema enforces what that schema has.
fn agent_memberships() -> Option<Vec<String>> {
    let installed: Option<bool> = Spi::get_one(
        "select to_regprocedure('agent_gate_internal._agent_memberships()') is not null",
    )
    .ok()
    .flatten();
    if installed != Some(true) {
        return None;
    }
    crate::verbs::read_internal::<Vec<String>>("select agent_gate_internal._agent_memberships()", &[])
}

#[pg_guard]
unsafe extern "C-unwind" fn executor_start(query_desc: *mut pg_sys::QueryDesc, eflags: i32) {
    if !query_desc.is_null() && must_judge() {
        if let Some(agent) = crate::current_agent() {
            let ps = (*query_desc).plannedstmt;
            if !ps.is_null()
                && ((*ps).commandType != pg_sys::CmdType::CMD_SELECT
                    || (*ps).hasModifyingCTE
                    || plan_reads_relations((*ps).rtable))
            {
                refuse(
                    &agent,
                    "the executor was asked to run a plan that did not come through the gate".into(),
                );
            }
        }
    }
    match PREV_EXECUTOR_START {
        Some(prev) => prev(query_desc, eflags),
        None => pg_sys::standard_ExecutorStart(query_desc, eflags),
    }
}

/// THE FLOOR UNDER no_opaque_function (0.2.7). The walker refuses a SECURITY DEFINER function the
/// STATEMENT calls, but not one reached through a body it cannot see: another function (an IMMUTABLE
/// wrapper passes the walker, and the planner even folds it at propose), a CHECK or domain
/// constraint, a column default the rewriter did not add, a generated column, an expression index,
/// a trigger. Measured on 0.2.6: an IMMUTABLE wrapper over a SECURITY DEFINER function verified and
/// ran it at propose and again at commit.
///
/// Every SECURITY DEFINER call goes through fmgr_security_definer, which calls this hook before the
/// body runs (fmgr.c; no needs_fmgr_hook required). While SQL the AGENT wrote is running -- the
/// PROPOSAL counter: verification, the verified statement, its deferred constraints, an allowed
/// DDL -- such a call is refused, however it was reached. The gate's own SECURITY DEFINER functions
/// never run then (the record functions refuse unless PROPOSAL is down, and no verb runs inside a
/// proposal), so there is no exemption to get wrong. The common path is one atomic load.
#[pg_guard]
unsafe extern "C-unwind" fn definer_guard(
    event: pg_sys::FmgrHookEventType::Type,
    flinfo: *mut pg_sys::FmgrInfo,
    private: *mut pg_sys::Datum,
) {
    if event == pg_sys::FmgrHookEventType::FHET_START && state::proposal_running() && !flinfo.is_null() {
        if let Some(name) = security_definer_name((*flinfo).fn_oid) {
            ErrorReport::new(
                PgSqlErrorCode::ERRCODE_INSUFFICIENT_PRIVILEGE,
                format!(
                    "pg_agent_gate: the proposal reached SECURITY DEFINER function {name}, which would run \
                     as its owner; it was stopped before it ran"
                ),
                "pg_agent_gate",
            )
            .set_detail(
                "it was reached through a body the gate cannot check -- another function, a constraint, a \
                 default, a generated column, an index expression or a trigger -- so its effect would be \
                 neither verified nor bound to the agent's tenant",
            )
            .set_hint("Do not place a SECURITY DEFINER function where an agent's statement reaches it.")
            .report(PgLogLevel::ERROR);
        }
        // THE FLOOR ON THE FUNCTION MANAGER'S PATH (0.4.3). A function C code calls through a cached
        // FmgrInfo never meets the executor's hook: an allow_ddl agent's own plpgsql function, set
        // as a range type's subtype_diff, ran from the type cache while a GiST index was built --
        // at propose it SET the tenant and raised the other tenant's row into the `executes`
        // detail; at commit it deleted 20 rows under a max_rows of 2 (review of 0.4.2). Such a
        // function reaches this hook because needs_floor() asked for it when it was looked up.
        if crate::agent_is_set() {
            if let Some(what) = floor((*flinfo).fn_oid) {
                stop(what);
            }
        }
    }
    if let Some(prev) = PREV_FMGR {
        prev(event, flinfo, private);
    }
}

/// needs_fmgr_hook: asked when a function that is not a fast-path built-in is looked up, for the
/// executor and for C code alike. In an agent's session, a user function the floor would stop is
/// routed through fmgr_security_definer, so that definer_guard sees each call however it is made.
/// The verdict is the function's own (its owner, its language, its SET clause), not the moment's,
/// because the lookup can be cached long before the call: the type cache keeps it for the session.
/// Only such functions pay for the detour; every other session pays one load.
#[pg_guard]
unsafe extern "C-unwind" fn needs_floor(oid: pg_sys::Oid) -> bool {
    if let Some(prev) = PREV_NEEDS_FMGR {
        if prev(oid) {
            return true;
        }
    }
    crate::agent_is_set()
        && oid.to_u32() >= pg_sys::FirstNormalObjectId
        && pg_sys::IsTransactionState()
        && user_verdict(oid).is_some()
}

fn stop(what: String) -> ! {
    ErrorReport::new(
        PgSqlErrorCode::ERRCODE_INSUFFICIENT_PRIVILEGE,
        format!("pg_agent_gate: the proposal reached {what}; it was stopped before it ran"),
        "pg_agent_gate",
    )
    .set_detail(
        "it was reached where the gate's checks do not look -- SQL given as text, the body of another \
         function, a constraint, a default, an index expression, a type's support function, an \
         aggregate or a trigger -- so its effect would be neither verified, counted, nor bound to the \
         agent's tenant",
    )
    .report(PgLogLevel::ERROR);
    unreachable!()
}

/// `schema.name` of the function if it is SECURITY DEFINER, else None. Read from the syscache: this
/// runs inside the function manager, where SPI is not an option.
unsafe fn security_definer_name(oid: pg_sys::Oid) -> Option<String> {
    let tup = pg_sys::SearchSysCache1(pg_sys::SysCacheIdentifier::PROCOID as _, pg_sys::Datum::from(oid));
    if tup.is_null() {
        return None;
    }
    let form = pg_sys::heap_tuple_get_struct::<pg_sys::FormData_pg_proc>(tup);
    let secdef = (*form).prosecdef;
    let nsp = (*form).pronamespace;
    let name = CStr::from_ptr((*form).proname.data.as_ptr()).to_string_lossy().into_owned();
    pg_sys::ReleaseSysCache(tup);
    if !secdef {
        return None;
    }
    let schema = pg_sys::get_namespace_name(nsp);
    let schema = if schema.is_null() { "?".into() } else { CStr::from_ptr(schema).to_string_lossy().into_owned() };
    Some(format!("{schema}.{name}()"))
}

unsafe fn plan_reads_relations(rtable: *mut pg_sys::List) -> bool {
    (0..list_len(rtable))
        .any(|i| (*nth::<pg_sys::RangeTblEntry>(rtable, i)).rtekind == pg_sys::RTEKind::RTE_RELATION)
}

unsafe fn top_level_allowed(q: &pg_sys::Query) -> Result<(), String> {
    match q.commandType {
        pg_sys::CmdType::CMD_UTILITY => utility_allowed(q.utilityStmt),
        pg_sys::CmdType::CMD_SELECT => select_allowed(q),
        pg_sys::CmdType::CMD_INSERT => Err("INSERT does not reach the database from an agent session".into()),
        pg_sys::CmdType::CMD_UPDATE => Err("UPDATE does not reach the database from an agent session".into()),
        pg_sys::CmdType::CMD_DELETE => Err("DELETE does not reach the database from an agent session".into()),
        pg_sys::CmdType::CMD_MERGE => Err("MERGE does not reach the database from an agent session".into()),
        _ => Err(SHAPE.into()),
    }
}

unsafe fn utility_allowed(stmt: *mut pg_sys::Node) -> Result<(), String> {
    if stmt.is_null() {
        return Err(SHAPE.into());
    }
    match (*stmt).type_ {
        pg_sys::NodeTag::T_VariableShowStmt => Ok(()),
        pg_sys::NodeTag::T_TransactionStmt => {
            // Not two-phase commit (0.2.12): a prepared transaction outlives the session, and when
            // ROLLBACK PREPARED later takes the agent's record with it, no callback of this backend
            // is there to write down what was lost (external audit of 0.2.8, GATE-12).
            let t = &*(stmt as *mut pg_sys::TransactionStmt);
            match t.kind {
                pg_sys::TransactionStmtKind::TRANS_STMT_PREPARE
                | pg_sys::TransactionStmtKind::TRANS_STMT_COMMIT_PREPARED
                | pg_sys::TransactionStmtKind::TRANS_STMT_ROLLBACK_PREPARED => Err(
                    "two-phase commit is not available to an agent session: a prepared transaction outlives it"
                        .into(),
                ),
                _ => Ok(()),
            }
        }
        pg_sys::NodeTag::T_VariableSetStmt => {
            let v = &*(stmt as *mut pg_sys::VariableSetStmt);
            let name = if v.name.is_null() {
                String::new()
            } else {
                CStr::from_ptr(v.name).to_string_lossy().to_lowercase()
            };
            // An ALLOWLIST, not a list of forbidden names: what an agent session
            // may change is client formatting and time limits (crate::SETTABLE_BY_AGENTS,
            // plus whatever a superuser added to agent_gate.settable). Everything
            // else is refused -- who is acting (`role`, `session_authorization`,
            // `agent_gate.*`), and, just as important, whatever the application
            // decides with: a policy over current_setting('app.tenant_id') is the
            // ordinary way to separate tenants, and no denylist can name the
            // parameters an application invents (measured; tests/rls_isolation.sh).
            //
            // A nameless statement -- RESET ALL, SET SESSION CHARACTERISTICS with no
            // parameter -- goes back to what the ROLE was given, which is where an
            // agent's context is supposed to come from, so it passes.
            if name.is_empty() || crate::settable(&name) {
                Ok(())
            } else {
                Err(format!(
                    "SET {name} is not one an agent session may change: an agent's context is set on its role, \
                     and a superuser can add a parameter to agent_gate.settable"
                ))
            }
        }
        other => Err(format!("{other:?} is not one of the gate's verbs ({})", VERBS.join(", "))),
    }
}

unsafe fn select_allowed(q: &pg_sys::Query) -> Result<(), String> {
    let decorated = q.hasSubLinks
        || q.hasModifyingCTE
        || q.hasAggs
        || q.hasWindowFuncs
        || q.hasTargetSRFs
        || q.hasForUpdate
        || q.hasRecursive
        || !q.cteList.is_null()
        || !q.setOperations.is_null()
        || !q.havingQual.is_null()
        || !q.groupClause.is_null()
        || !q.sortClause.is_null()
        || !q.distinctClause.is_null()
        || !q.windowClause.is_null()
        || !q.limitCount.is_null()
        || !q.limitOffset.is_null()
        || !q.rowMarks.is_null()
        || (!q.jointree.is_null() && !(*q.jointree).quals.is_null());
    if decorated {
        return Err(SHAPE.into());
    }

    // Either `SELECT agent_gate.verb(...)` or `SELECT * FROM agent_gate.verb(...)`.
    let from_function = match list_len(q.rtable) {
        0 => false,
        1 => {
            let rte = &*nth::<pg_sys::RangeTblEntry>(q.rtable, 0);
            if rte.rtekind != pg_sys::RTEKind::RTE_FUNCTION || list_len(rte.functions) != 1 {
                return Err(SHAPE.into());
            }
            let rtf = &*nth::<pg_sys::RangeTblFunction>(rte.functions, 0);
            verb_call(rtf.funcexpr)?;
            true
        }
        _ => return Err(SHAPE.into()),
    };

    let targets = list_len(q.targetList);
    if targets == 0 {
        return Err(SHAPE.into());
    }
    for i in 0..targets {
        let te = &*nth::<pg_sys::TargetEntry>(q.targetList, i);
        let expr = te.expr as *mut pg_sys::Node;
        if from_function {
            if expr.is_null() || (*expr).type_ != pg_sys::NodeTag::T_Var {
                return Err(SHAPE.into());
            }
        } else {
            verb_call(expr)?;
        }
    }
    Ok(())
}

unsafe fn verb_call(node: *mut pg_sys::Node) -> Result<(), String> {
    if node.is_null() || (*node).type_ != pg_sys::NodeTag::T_FuncExpr {
        return Err(SHAPE.into());
    }
    let f = &*(node as *mut pg_sys::FuncExpr);
    let gate = pg_sys::get_namespace_oid(c"agent_gate".as_ptr(), true);
    let name_ptr = pg_sys::get_func_name(f.funcid);
    let name = if name_ptr.is_null() {
        String::from("?")
    } else {
        CStr::from_ptr(name_ptr).to_string_lossy().into_owned()
    };
    if pg_sys::get_func_namespace(f.funcid) != gate || !VERBS.contains(&name.as_str()) {
        return Err(format!("{name}() is not one of the gate's verbs ({})", VERBS.join(", ")));
    }
    for i in 0..list_len(f.args) {
        simple_argument(nth::<pg_sys::Node>(f.args, i))?;
    }
    Ok(())
}

/// Literals and parameters, the relabels and array constructors the parser wraps
/// them in, and -- only -- the implicit cast the parser inserts to coerce a
/// constant to the verb's own parameter type through a built-in function. An
/// explicit cast, an I/O conversion cast, or any cast through a non-built-in
/// function is code of the agent's own choosing: it runs while this argument is
/// evaluated, before verify() raises the proposal flag, so the definer guard
/// would not see it. All of those are refused here.
unsafe fn simple_argument(node: *mut pg_sys::Node) -> Result<(), String> {
    const ARGS: &str = "arguments of a verb must be literals or parameters, not expressions that run code";
    if node.is_null() {
        return Err(ARGS.into());
    }
    match (*node).type_ {
        pg_sys::NodeTag::T_Const | pg_sys::NodeTag::T_Param => Ok(()),
        pg_sys::NodeTag::T_RelabelType => {
            simple_argument((*(node as *mut pg_sys::RelabelType)).arg as *mut pg_sys::Node)
        }
        pg_sys::NodeTag::T_ArrayExpr => {
            let a = &*(node as *mut pg_sys::ArrayExpr);
            for i in 0..list_len(a.elements) {
                simple_argument(nth::<pg_sys::Node>(a.elements, i))?;
            }
            Ok(())
        }
        pg_sys::NodeTag::T_FuncExpr => {
            let f = &*(node as *mut pg_sys::FuncExpr);
            let catalog = pg_sys::get_namespace_oid(c"pg_catalog".as_ptr(), false);
            if f.funcformat != pg_sys::CoercionForm::COERCE_IMPLICIT_CAST
                || pg_sys::get_func_namespace(f.funcid) != catalog
            {
                return Err(ARGS.into());
            }
            for i in 0..list_len(f.args) {
                simple_argument(nth::<pg_sys::Node>(f.args, i))?;
            }
            Ok(())
        }
        _ => Err(ARGS.into()),
    }
}

/// FAST PATH (0.2.12). A fast-path function call (libpq's PQfn) reaches no parser and no executor,
/// so none of the gate's other hooks saw it: an agent called set_config() through it and moved the
/// tenant its row-level policies read, and a role that could SET ROLE to a superuser cleared its own
/// agent mark and left the gate (external audit of 0.2.8, GATE-02). The function manager invokes
/// this hook for a fast-path call (tcop/fastpath.c), with no client query running. In an agent
/// session, outside the gate's own
/// work, only the verbs pass. The executor invokes the same hook for every function of a query; a
/// query in an agent session is already a verb call that post_parse admitted, and an implicit cast
/// of its arguments must not be refused, so only fast path is judged here.
#[pg_guard]
unsafe extern "C-unwind" fn object_access(
    access: pg_sys::ObjectAccessType::Type,
    class_id: pg_sys::Oid,
    object_id: pg_sys::Oid,
    sub_id: std::ffi::c_int,
    arg: *mut std::ffi::c_void,
) {
    // THE FLOOR UNDER no_hidden_sql, keeps_its_context AND no_opaque_function (0.4.2). The executor
    // invokes this hook for every function it is about to run -- built-ins included, unlike
    // fmgr_hook -- wherever the function sits: the statement, the SQL query_to_xml() parses from a
    // text, the body of another function, a CHECK constraint, a default, an index expression, the
    // planner folding an IMMUTABLE call. The checks of verify.rs see only the statement's own tree,
    // and the review of 2026-11-05 reached set_config() through the rest: query_to_xml() over a
    // text, a function marked STABLE that calls it, an allow_ddl agent's function in a CHECK of its
    // own table. So while the agent's SQL runs, in an agent's session, none of these starts.
    // Since 0.4.3 this is one of the floor's two paths (see the module comment and floor()): a
    // domain's CHECK and an aggregate's transition function come here too, and what C code calls
    // through a cache comes to definer_guard.
    if access == pg_sys::ObjectAccessType::OAT_FUNCTION_EXECUTE
        && state::proposal_running()
        && crate::agent_is_set()
    {
        if let Some(what) = floor(object_id) {
            stop(what);
        }
    }
    if access == pg_sys::ObjectAccessType::OAT_FUNCTION_EXECUTE && fastpath_call() && must_judge() {
        let (schema, name) = function_identity(object_id);
        if !(schema == "agent_gate" && VERBS.contains(&name.as_str())) {
            refuse(
                &crate::current_agent().unwrap_or_default(),
                format!("a fast-path function call reached {schema}.{name}(), and an agent session calls only the gate's verbs"),
            );
        }
    }
    if let Some(prev) = PREV_OBJECT_ACCESS {
        prev(access, class_id, object_id, sub_id, arg);
    }
}

/// WHAT THE FLOOR STOPS (0.4.3), named, or None. While the agent's SQL runs, a function that starts:
///   * set_config(), which moves a parameter the agent's row-level policies may read;
///   * one that runs SQL from a text (verify::SQL_FROM_TEXT), built-in or not;
///   * a built-in that changes state outside the rows the gate counts (verify::state_change):
///     a session advisory lock, a large object, setval(), the WAL -- in any statement; and
///     nextval(), a transaction advisory lock or a notification in a read, which changes nothing;
///   * a user function the agent can alter (owned by a role whose privileges the AGENT'S role
///     has) -- what it is marked is the adversary's own claim -- or whose SET clause sets a
///     parameter that carries the context a policy reads (verify::set_clause_allowed).
/// A volatile user function of the DBA's is not stopped here: one reached through a body is the
/// call the DBA placed there, and what it writes is counted (the backstop in verbs.rs, for a DDL
/// too since 0.4.3); the floor under SECURITY DEFINER is definer_guard. Read from the syscache:
/// this runs inside the executor and the function manager, where SPI is not an option.
unsafe fn floor(oid: pg_sys::Oid) -> Option<String> {
    if oid == pg_sys::Oid::from(pg_sys::F_SET_CONFIG) {
        return Some(
            "pg_catalog.set_config(), which would change a parameter the agent's row-level policies may read".into(),
        );
    }
    if oid.to_u32() >= pg_sys::FirstNormalObjectId {
        return user_verdict(oid);
    }
    match builtin_class(oid) {
        Builtin::Plain => None,
        Builtin::SqlFromText => {
            Some(format!("{}, which runs SQL it receives as text where no check of the gate sees it", function_name(oid)))
        }
        Builtin::ChangesState(crate::verify::StateChange::InARead)
            if matches!(state::running_kind(), state::RUNNING_WRITE | state::RUNNING_DDL) =>
        {
            None
        }
        Builtin::ChangesState(crate::verify::StateChange::InARead) if state::running_kind() == state::RUNNING_TRIAL => {
            Some(format!(
                "{}, which changes state, and proposing changes nothing: what a sequence gives out is not \
                 rolled back (an identity column numbers the rows of a new column without it)",
                function_name(oid)
            ))
        }
        Builtin::ChangesState(crate::verify::StateChange::InARead) => Some(format!(
            "{}, which changes state, and a read changes nothing",
            function_name(oid)
        )),
        Builtin::ChangesState(crate::verify::StateChange::Always) => Some(format!(
            "{}, which changes state outside the rows the gate counts",
            function_name(oid)
        )),
    }
}

#[derive(Clone, Copy)]
enum Builtin {
    Plain,
    SqlFromText,
    ChangesState(crate::verify::StateChange),
}

thread_local! {
    /// What each built-in is, by OID. A built-in (OID below FirstNormalObjectId) is fixed at initdb,
    /// so the answer is read once per backend: the executor asks for every function it starts, and
    /// 0.4.2 read the catalog -- and copied the whole body -- each time (~110x on a read whose
    /// plpgsql helper re-ran a query per row; review of 0.4.2).
    static BUILTINS: std::cell::RefCell<std::collections::HashMap<u32, Builtin>> =
        std::cell::RefCell::new(std::collections::HashMap::new());
}

unsafe fn builtin_class(oid: pg_sys::Oid) -> Builtin {
    if let Some(b) = BUILTINS.with(|m| m.borrow().get(&oid.to_u32()).copied()) {
        return b;
    }
    let tup = pg_sys::SearchSysCache1(pg_sys::SysCacheIdentifier::PROCOID as _, pg_sys::Datum::from(oid));
    if tup.is_null() {
        return Builtin::Plain;
    }
    let form = pg_sys::heap_tuple_get_struct::<pg_sys::FormData_pg_proc>(tup);
    let lang = (*form).prolang.to_u32();
    let in_catalog = (*form).pronamespace == pg_sys::Oid::from(pg_sys::PG_CATALOG_NAMESPACE);
    let name = CStr::from_ptr((*form).proname.data.as_ptr()).to_string_lossy().into_owned();
    let from_text = (lang == 12 || lang == 13) && prosrc_runs_sql(tup, lang);
    pg_sys::ReleaseSysCache(tup);
    let b = if from_text {
        Builtin::SqlFromText
    } else if let Some(c) = in_catalog.then(|| crate::verify::state_change(&name)).flatten() {
        Builtin::ChangesState(c)
    } else {
        Builtin::Plain
    };
    BUILTINS.with(|m| m.borrow_mut().insert(oid.to_u32(), b));
    b
}

/// The C entry point of an internal or C function, compared with SQL_FROM_TEXT. Only those two
/// languages name a C symbol in prosrc, so only they are read: a plpgsql body can be megabytes.
unsafe fn prosrc_runs_sql(tup: pg_sys::HeapTuple, lang: u32) -> bool {
    let mut isnull = false;
    let src = pg_sys::SysCacheGetAttr(
        pg_sys::SysCacheIdentifier::PROCOID as _,
        tup,
        pg_sys::Anum_pg_proc_prosrc as _,
        &mut isnull,
    );
    if isnull {
        return false;
    }
    let c = pg_sys::text_to_cstring(src.cast_mut_ptr::<pg_sys::text>());
    let runs = crate::verify::runs_sql_from_text(lang, &CStr::from_ptr(c).to_string_lossy());
    pg_sys::pfree(c.cast());
    runs
}

/// The floor's verdict on a USER function (OID >= FirstNormalObjectId): what it is, not where it
/// was reached. Used by both paths and by needs_floor, so it allocates nothing on a function it
/// lets through, except to read a C function's entry point or a SET clause that is there.
unsafe fn user_verdict(oid: pg_sys::Oid) -> Option<String> {
    let tup = pg_sys::SearchSysCache1(pg_sys::SysCacheIdentifier::PROCOID as _, pg_sys::Datum::from(oid));
    if tup.is_null() {
        return None;
    }
    let form = pg_sys::heap_tuple_get_struct::<pg_sys::FormData_pg_proc>(tup);
    let lang = (*form).prolang.to_u32();
    let owner = (*form).proowner;
    let from_text = (lang == 12 || lang == 13) && prosrc_runs_sql(tup, lang);
    // THE AGENT'S ROLE, not GetUserId() (0.4.3). An RI check runs as the referenced table's owner
    // (SetUserIdAndSecContext), and 0.4.2 asked whether THAT role could alter the function: a
    // superuser owner can alter every function, so citext's equality operator was "the agent's"
    // and every write to a table with a citext foreign key was refused (review of 0.4.2). The
    // agent is the session's login role: an agent session can SET neither ROLE nor SESSION
    // AUTHORIZATION (the allowlist), and an agent role has no members (0.4.1).
    let alterable = pg_sys::has_privs_of_role(pg_sys::GetSessionUserId(), owner);
    let bad_set = if from_text || alterable
        || pg_sys::heap_attisnull(tup, pg_sys::Anum_pg_proc_proconfig as _, std::ptr::null_mut())
    {
        None
    } else {
        let mut isnull = false;
        let d = pg_sys::SysCacheGetAttr(
            pg_sys::SysCacheIdentifier::PROCOID as _,
            tup,
            pg_sys::Anum_pg_proc_proconfig as _,
            &mut isnull,
        );
        if isnull {
            None
        } else {
            Vec::<Option<String>>::from_polymorphic_datum(d, false, pg_sys::TEXTARRAYOID)
                .unwrap_or_default()
                .into_iter()
                .flatten()
                .map(|c| c.split('=').next().unwrap_or_default().to_string())
                .find(|p| !crate::verify::set_clause_allowed(p))
        }
    };
    pg_sys::ReleaseSysCache(tup);
    if from_text {
        return Some(format!("{}, which runs SQL it receives as text where no check of the gate sees it", function_name(oid)));
    }
    if alterable {
        return Some(format!("{}, a function this agent can alter, so what it is marked is its own claim", function_name(oid)));
    }
    bad_set.map(|p| format!("{}, whose SET clause sets {p}, which carries the context a policy may read", function_name(oid)))
}

/// `schema.name()` of a function, for a refusal.
unsafe fn function_name(oid: pg_sys::Oid) -> String {
    let (schema, name) = function_identity(oid);
    format!("{schema}.{name}()")
}

/// A fast-path call: no client query is running (PostgresMain leaves debug_query_string NULL for a
/// function-call message, and sets it for every query, simple or extended), or the backend reports
/// STATE_FASTPATH. Either suffices, so the answer does not depend on track_activities.
unsafe fn fastpath_call() -> bool {
    if pg_sys::debug_query_string.is_null() {
        return true;
    }
    let be = pg_sys::MyBEEntry;
    !be.is_null() && (*be).st_state == pg_sys::BackendState::STATE_FASTPATH
}

/// (schema, name) of a function, from the syscache.
unsafe fn function_identity(oid: pg_sys::Oid) -> (String, String) {
    let tup = pg_sys::SearchSysCache1(pg_sys::SysCacheIdentifier::PROCOID as _, pg_sys::Datum::from(oid));
    if tup.is_null() {
        return ("?".into(), "?".into());
    }
    let form = pg_sys::heap_tuple_get_struct::<pg_sys::FormData_pg_proc>(tup);
    let nsp = (*form).pronamespace;
    let name = CStr::from_ptr((*form).proname.data.as_ptr()).to_string_lossy().into_owned();
    pg_sys::ReleaseSysCache(tup);
    let schema = pg_sys::get_namespace_name(nsp);
    let schema = if schema.is_null() { "?".into() } else { CStr::from_ptr(schema).to_string_lossy().into_owned() };
    (schema, name)
}
