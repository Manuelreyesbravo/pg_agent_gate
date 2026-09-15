//! The gate itself: what plain SQL cannot do.
//!
//! A schema of functions can OFFER a safe path. It cannot make the unsafe path
//! disappear -- an agent holding a connection can always type `DELETE FROM`.
//! These hooks make it disappear: in a session that belongs to an agent, every
//! statement that reaches the parser must be `SELECT agent_gate.<verb>(...)`
//! with literals or parameters as arguments, transaction control, SHOW, or a SET
//! that does not change who is acting (never role, session_authorization or
//! anything under agent_gate.*).
//! Everything else dies before it is planned.
//!
//! THREE HOOKS, ONE RULE. `post_parse_analyze` is the gate. `ProcessUtility`
//! and `ExecutorStart` are the second line, for anything that reaches
//! execution without a fresh parse (a cached plan, a utility statement issued
//! from C).
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

pub(crate) const VERBS: &[&str] = &["discover", "propose", "dry_run", "commit", "acts", "whoami"];

const SHAPE: &str = "an agent session may only run SELECT agent_gate.<verb>(...) with literals or parameters";

static mut PREV_POST_PARSE: pg_sys::post_parse_analyze_hook_type = None;
static mut PREV_PROCESS_UTILITY: pg_sys::ProcessUtility_hook_type = None;
static mut PREV_EXECUTOR_START: pg_sys::ExecutorStart_hook_type = None;
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
    INSTALLED = true;
}

/// True only when the statement must be judged: an agent session, and none of
/// the gate's own SQL running. Allocation-free on the common path.
fn must_judge() -> bool {
    !state::sql_may_run() && crate::agent_is_set()
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
         agent_gate.commit(proposal). agent_gate.discover() shows what this agent may touch.",
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
        pg_sys::NodeTag::T_TransactionStmt | pg_sys::NodeTag::T_VariableShowStmt => Ok(()),
        pg_sys::NodeTag::T_VariableSetStmt => {
            let v = &*(stmt as *mut pg_sys::VariableSetStmt);
            let name = if v.name.is_null() {
                String::new()
            } else {
                CStr::from_ptr(v.name).to_string_lossy().to_lowercase()
            };
            // Who is acting is not a setting an agent session changes. `role` and
            // `session_authorization` change the database user; `agent_gate.*` is
            // the mark itself and the gate's own knobs. Leaving the mark to the
            // superuser-only GUC context was not enough: PostgreSQL 15+ can GRANT
            // SET ON PARAMETER agent_gate.agent, and with that one mistaken grant
            // an agent ran `set agent_gate.agent = ''` and then raw SQL (measured,
            // tests/privileges.sh). One rule for the whole prefix, SET and RESET
            // alike, instead of a list of the knobs that happen to matter today.
            if name == "role" || name == "session_authorization" || name.starts_with("agent_gate.") {
                Err(format!("SET {name} would change who is acting; an agent session keeps its identity"))
            } else {
                Ok(())
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

/// Literals and parameters, and the casts the parser wraps them in. Anything
/// that could call a function of the agent's choosing is refused here.
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
        pg_sys::NodeTag::T_CoerceViaIO => {
            simple_argument((*(node as *mut pg_sys::CoerceViaIO)).arg as *mut pg_sys::Node)
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
            let cast = f.funcformat == pg_sys::CoercionForm::COERCE_EXPLICIT_CAST
                || f.funcformat == pg_sys::CoercionForm::COERCE_IMPLICIT_CAST;
            if !cast {
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
