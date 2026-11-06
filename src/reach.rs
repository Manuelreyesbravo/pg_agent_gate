// Copyright 2026 Manuel Reyes Bravo
// SPDX-License-Identifier: Apache-2.0

//! WHAT AN AGENT'S DDL REACHES (0.4.3, second review).
//!
//! An allow_ddl agent's DDL runs with the agent's rights, and PostgreSQL lets those rights reach
//! objects of other roles: the owner of a type or a schema may DROP it with CASCADE, which takes
//! every table built on it; the owner of a schema may drop any object in it; DROP DOMAIN ... CASCADE
//! drops a column of another role's table; ALTER TYPE ... RENAME VALUE changes what every row of
//! another role's table says. The review of 0.4.3 measured 70 rows of a DBA's tables gone and a
//! DBA's column dropped, each recorded as a DDL of 0 rows. And an agent's TEMPORARY table answers
//! first, in the agent's own session, for a name a DBA's policy helper does not qualify: PostgreSQL
//! searches pg_temp before the path for relations and types, whatever search_path says, and an
//! agent read another tenant's rows with no SET at all.
//!
//! ONE RULE: AN AGENT'S DDL AFFECTS ONLY WHAT THE AGENT OWNS. It is judged where PostgreSQL does the
//! work, not by reading the statement (which a CASCADE does not spell out):
//!   * every object PostgreSQL drops is judged as it is dropped (OAT_DROP, the object still in the
//!     catalog): one whose owner is not a role whose privileges the agent has stops the DDL --
//!     exactly what the agent could have dropped by name. An object with no owner of its own (a
//!     constraint, a default, a trigger, a rule, a policy) is judged by its table or its domain;
//!   * every type the DDL alters is noted (OAT_POST_ALTER) and, when the DDL has run, judged by what
//!     depends on it: a column, a table, a domain or a function of another role stops it. A GRANT,
//!     an ALTER ... OWNER or a COMMENT changes who may use a type, not what its values are;
//!   * every function the DDL redefines (CREATE OR REPLACE, ALTER FUNCTION) is noted and judged
//!     the same way (third review of 0.4.3): an index, a CHECK, a generated column, a view, a
//!     policy, a trigger or a function of another role's built on it stops it. CREATE OR REPLACE of
//!     an agent's IMMUTABLE function had left a DBA's expression index and stored column computing
//!     what the function no longer computes, and the DBA's own inserts failing its CHECK. A RENAME
//!     or a SET SCHEMA changes a name, not what is computed, and is not judged;
//!   * every relation, trigger, constraint, policy or rule the DDL creates must be the agent's: an
//!     index on an agent's partitioned table is created on every partition, and one built on a
//!     DBA's partition made the DBA's own inserts fail (third review). A trigger PostgreSQL makes
//!     for a foreign key (internal) is how a REFERENCES privilege the DBA granted works, and passes;
//!   * a table the DDL takes out of an inheritance tree (DETACH PARTITION, NO INHERIT) must be the
//!     agent's: detaching a DBA's partition from the agent's table rewrote the DBA's catalog row;
//!   * an object in the session's temporary schema stops it: an agent does not create temporary
//!     objects, so no name in the agent's session resolves to something the agent put first;
//!   * a sequence the DDL created may be numbered by it at propose -- serial, like an identity
//!     column, numbers a new column from a new sequence that the rollback of the trial takes with
//!     it -- and a sequence that existed before the DDL may not: what was taken from one is not
//!     given back (judged by the locks nextval() takes, see judge()).
//! The DBA's event-trigger code is not the agent's DDL (state::in_event_trigger): it is not watched.

use crate::state;
use pgrx::pg_sys::elog::PgLogLevel;
use pgrx::pg_sys::errcodes::PgSqlErrorCode;
use pgrx::pg_sys::panic::ErrorReport;
use pgrx::prelude::*;
use std::cell::RefCell;
use std::ffi::CStr;

thread_local! {
    /// Types the running DDL altered.
    static ALTERED: RefCell<Vec<u32>> = const { RefCell::new(Vec::new()) };
    /// Relations the running DDL created.
    static CREATED: RefCell<Vec<u32>> = const { RefCell::new(Vec::new()) };
    /// Triggers, constraints, policies and rules the running DDL created: (class, oid).
    static ATTACHED: RefCell<Vec<(u32, u32)>> = const { RefCell::new(Vec::new()) };
    /// Functions the running DDL created or redefined.
    static REDEFINED: RefCell<Vec<u32>> = const { RefCell::new(Vec::new()) };
    /// Tables the running DDL took out of an inheritance tree (the child of pg_inherits).
    static DISINHERITED: RefCell<Vec<u32>> = const { RefCell::new(Vec::new()) };
    /// Whether ALTERs are judged for this DDL (verify::Verdict::judge_alters).
    static JUDGE_ALTERS: RefCell<bool> = const { RefCell::new(true) };
    /// Whether an ALTER of a function is judged (verify::Verdict::judge_redefinitions).
    static JUDGE_REDEFINITIONS: RefCell<bool> = const { RefCell::new(true) };
    /// A nextval() started in the trial because the trial created a sequence.
    static NEXTVAL_ON_NEW: RefCell<bool> = const { RefCell::new(false) };
}

/// The gate is running an agent's DDL -- its trial at propose or its run at commit -- and not the
/// DBA's event-trigger code it fired.
pub(crate) fn watching() -> bool {
    state::proposal_running()
        && state::executing()
        && matches!(state::running_kind(), state::RUNNING_DDL | state::RUNNING_TRIAL)
        && !state::in_event_trigger()
}

/// Before the DDL runs: forget what the last one noted.
pub(crate) fn begin(judge_alters: bool, judge_redefinitions: bool) {
    ALTERED.with(|a| a.borrow_mut().clear());
    CREATED.with(|c| c.borrow_mut().clear());
    ATTACHED.with(|c| c.borrow_mut().clear());
    REDEFINED.with(|r| r.borrow_mut().clear());
    DISINHERITED.with(|d| d.borrow_mut().clear());
    JUDGE_ALTERS.with(|j| *j.borrow_mut() = judge_alters);
    JUDGE_REDEFINITIONS.with(|j| *j.borrow_mut() = judge_alters && judge_redefinitions);
    NEXTVAL_ON_NEW.with(|n| *n.borrow_mut() = false);
}

/// pg_inherits: PostgreSQL posts an ALTER of it, with the child's OID, when a table leaves its
/// parent (tablecmds.c RemoveInheritance). Not in pgrx's bindings; fixed since 8.x.
const INHERITS_RELATION: u32 = 2611;

pub(crate) fn altered(class: pg_sys::Oid, object: pg_sys::Oid) {
    if class == pg_sys::TypeRelationId && JUDGE_ALTERS.with(|j| *j.borrow()) {
        ALTERED.with(|a| a.borrow_mut().push(object.to_u32()));
    } else if class == pg_sys::ProcedureRelationId && JUDGE_REDEFINITIONS.with(|j| *j.borrow()) {
        REDEFINED.with(|r| r.borrow_mut().push(object.to_u32()));
    } else if class.to_u32() == INHERITS_RELATION {
        DISINHERITED.with(|d| d.borrow_mut().push(object.to_u32()));
    }
}

pub(crate) fn created(class: pg_sys::Oid, object: pg_sys::Oid) {
    if class == pg_sys::RelationRelationId {
        CREATED.with(|c| c.borrow_mut().push(object.to_u32()));
    } else if class == pg_sys::ProcedureRelationId {
        // CREATE OR REPLACE posts a CREATE for the function it replaces (pg_proc.c): a new one has
        // nothing built on it yet, so noting every one judges exactly the replaced.
        REDEFINED.with(|r| r.borrow_mut().push(object.to_u32()));
    } else if class == pg_sys::TriggerRelationId || ATTACHABLE.contains(&class.to_u32()) {
        ATTACHED.with(|a| a.borrow_mut().push((class.to_u32(), object.to_u32())));
    }
}

/// pg_constraint, pg_policy, pg_rewrite: not in pgrx's bindings; fixed since they were added.
const ATTACHABLE: [u32; 3] = [2606, 3256, 2618];

/// pg_depend and its index on (refclassid, refobjid, refobjsubid). Not in pgrx's bindings; fixed
/// since PostgreSQL 7.3.
const DEPEND_RELATION: u32 = 2608;
const DEPEND_REFERENCE_INDEX: u32 = 2674;

/// Whether an object the agent can alter -- owned by a role the agent's role is a member of, the
/// floor's own test of authorship (hooks::user_judgment) -- calls this function: depends on it in
/// pg_depend, as a domain's or a table's CHECK, a default, a generated column, an index, a policy,
/// a trigger, a view's rule, an operator, an aggregate, a range type or an SQL-body function does.
/// Read by an index scan, not SPI: the floor asks it inside the executor and the function manager.
pub(crate) unsafe fn called_by_agent_object(func: pg_sys::Oid) -> bool {
    let mut dependents: Vec<(pg_sys::Oid, pg_sys::Oid)> = Vec::new();
    let rel = pg_sys::table_open(pg_sys::Oid::from(DEPEND_RELATION), pg_sys::AccessShareLock as _);
    let mut keys: [pg_sys::ScanKeyData; 2] = std::mem::zeroed();
    let oideq = pg_sys::Oid::from(pg_sys::F_OIDEQ);
    let equal = pg_sys::BTEqualStrategyNumber as pg_sys::StrategyNumber;
    pg_sys::ScanKeyInit(&mut keys[0], 4, equal, oideq, pg_sys::Datum::from(pg_sys::ProcedureRelationId));
    pg_sys::ScanKeyInit(&mut keys[1], 5, equal, oideq, pg_sys::Datum::from(func));
    let scan = pg_sys::systable_beginscan(
        rel,
        pg_sys::Oid::from(DEPEND_REFERENCE_INDEX),
        true,
        std::ptr::null_mut(),
        2,
        keys.as_mut_ptr(),
    );
    let desc = (*rel).rd_att;
    loop {
        let tup = pg_sys::systable_getnext(scan);
        if tup.is_null() {
            break;
        }
        let mut isnull = false;
        let class = pg_sys::Oid::from(pg_sys::heap_getattr(tup, 1, desc, &mut isnull).value() as u32);
        let object = pg_sys::Oid::from(pg_sys::heap_getattr(tup, 2, desc, &mut isnull).value() as u32);
        dependents.push((class, object));
    }
    pg_sys::systable_endscan(scan);
    pg_sys::table_close(rel, pg_sys::AccessShareLock as _);
    let agent = pg_sys::GetSessionUserId();
    dependents
        .into_iter()
        .any(|(class, object)| object_owner(class, object, 0).is_some_and(|owner| pg_sys::is_member_of_role(agent, owner)))
}

/// The floor asks this when nextval() starts in the trial of a DDL (hooks::floor): allowed when the
/// trial created a sequence, and then judge() checks that no sequence that existed before was taken.
pub(crate) fn nextval_in_trial() -> bool {
    let created_sequence = CREATED.with(|c| {
        c.borrow().iter().any(|o| unsafe { pg_sys::get_rel_relkind(pg_sys::Oid::from(*o)) } as u8 == b'S')
    });
    if created_sequence {
        NEXTVAL_ON_NEW.with(|n| *n.borrow_mut() = true);
    }
    created_sequence
}

/// An object PostgreSQL is about to drop for the agent's DDL: None if it is the agent's to drop.
pub(crate) unsafe fn dropped(class: pg_sys::Oid, object: pg_sys::Oid, sub: std::ffi::c_int) -> Option<String> {
    let owner = object_owner(class, object, 0)?;
    if pg_sys::has_privs_of_role(pg_sys::GetSessionUserId(), owner) {
        return None;
    }
    let address = pg_sys::ObjectAddress { classId: class, objectId: object, objectSubId: sub };
    let what = pg_sys::getObjectDescription(&address, true);
    let what = if what.is_null() { "an object".into() } else { CStr::from_ptr(what).to_string_lossy().into_owned() };
    let who = pg_sys::GetUserNameFromId(owner, true);
    let who = if who.is_null() { format!("{}", owner.to_u32()) } else { CStr::from_ptr(who).to_string_lossy().into_owned() };
    Some(format!("it would drop {what}, which belongs to {who}"))
}

/// The owner of a catalog object, or of the table or domain an ownerless one belongs to. None: no
/// owner to judge (a cast, a transform: they belong to the types they convert).
unsafe fn object_owner(class: pg_sys::Oid, object: pg_sys::Oid, depth: u8) -> Option<pg_sys::Oid> {
    if depth > 2 || !pg_sys::is_objectclass_supported(class) {
        return None;
    }
    let owner_col = pg_sys::get_object_attnum_owner(class);
    let oid_col = pg_sys::get_object_attnum_oid(class);
    let rel = pg_sys::table_open(class, pg_sys::AccessShareLock as _);
    let tup = pg_sys::get_catalog_object_by_oid(rel, oid_col, object);
    let mut found: Option<(pg_sys::Oid, pg_sys::Oid)> = None; // (class, oid) of the owner or the parent
    if !tup.is_null() {
        let desc = (*rel).rd_att;
        let read = |col: i32| -> Option<pg_sys::Oid> {
            if col <= 0 {
                return None;
            }
            let mut isnull = false;
            let d = pg_sys::heap_getattr(tup, col, desc, &mut isnull);
            let o = pg_sys::Oid::from(d.value() as u32);
            (!isnull && o != pg_sys::InvalidOid).then_some(o)
        };
        if owner_col > 0 {
            found = read(owner_col as i32).map(|o| (pg_sys::InvalidOid, o));
        } else {
            for (col, parent) in [
                (c"conrelid", pg_sys::RelationRelationId),
                (c"contypid", pg_sys::TypeRelationId),
                (c"adrelid", pg_sys::RelationRelationId),
                (c"tgrelid", pg_sys::RelationRelationId),
                (c"ev_class", pg_sys::RelationRelationId),
                (c"polrelid", pg_sys::RelationRelationId),
            ] {
                if let Some(p) = read(pg_sys::SPI_fnumber(desc, col.as_ptr())) {
                    found = Some((parent, p));
                    break;
                }
            }
        }
        pg_sys::heap_freetuple(tup);
    }
    pg_sys::table_close(rel, pg_sys::AccessShareLock as _);
    match found {
        Some((c, o)) if c == pg_sys::InvalidOid => Some(o),
        Some((parent, p)) => object_owner(parent, p, depth + 1),
        None => None,
    }
}

/// The owner of the object (d.classid, d.objid), or of the table or the domain an ownerless one
/// belongs to; NULL when it has none to judge.
macro_rules! owner_of {
    () => {
        "case d.classid
       when 'pg_catalog.pg_class'::pg_catalog.regclass then
         (select c.relowner from pg_catalog.pg_class c where c.oid = d.objid)
       when 'pg_catalog.pg_type'::pg_catalog.regclass then
         (select y.typowner from pg_catalog.pg_type y where y.oid = d.objid)
       when 'pg_catalog.pg_proc'::pg_catalog.regclass then
         (select p.proowner from pg_catalog.pg_proc p where p.oid = d.objid)
       when 'pg_catalog.pg_operator'::pg_catalog.regclass then
         (select p.oprowner from pg_catalog.pg_operator p where p.oid = d.objid)
       when 'pg_catalog.pg_constraint'::pg_catalog.regclass then
         (select coalesce(c.relowner, y.typowner) from pg_catalog.pg_constraint k
            left join pg_catalog.pg_class c on c.oid = k.conrelid
            left join pg_catalog.pg_type y on y.oid = k.contypid where k.oid = d.objid)
       when 'pg_catalog.pg_attrdef'::pg_catalog.regclass then
         (select c.relowner from pg_catalog.pg_attrdef a
            join pg_catalog.pg_class c on c.oid = a.adrelid where a.oid = d.objid)
       when 'pg_catalog.pg_rewrite'::pg_catalog.regclass then
         (select c.relowner from pg_catalog.pg_rewrite r
            join pg_catalog.pg_class c on c.oid = r.ev_class where r.oid = d.objid)
       when 'pg_catalog.pg_trigger'::pg_catalog.regclass then
         (select c.relowner from pg_catalog.pg_trigger g
            join pg_catalog.pg_class c on c.oid = g.tgrelid where g.oid = d.objid)
       when 'pg_catalog.pg_policy'::pg_catalog.regclass then
         (select c.relowner from pg_catalog.pg_policy l
            join pg_catalog.pg_class c on c.oid = l.polrelid where l.oid = d.objid)
       when 'pg_catalog.pg_statistic_ext'::pg_catalog.regclass then
         (select x.stxowner from pg_catalog.pg_statistic_ext x where x.oid = d.objid)
       when 'pg_catalog.pg_amproc'::pg_catalog.regclass then
         (select f.opfowner from pg_catalog.pg_amproc a
            join pg_catalog.pg_opfamily f on f.oid = a.amprocfamily where a.oid = d.objid)
     end"
    };
}

/// Something of another role's built on one of `ids` (objects of the catalog `class`, pg_type or
/// pg_proc), directly or through others of the same class (a domain over the type, an SQL-body
/// function calling the function), described with its owner; '' if none.
macro_rules! foreign_dependent_sql {
    ($class:literal) => {
        concat!(
            "with recursive t(oid) as (
                 select pg_catalog.unnest($1::int8[]::oid[])
                 union
                 select d.objid from pg_catalog.pg_depend d join t on d.refobjid = t.oid
                  where d.refclassid = 'pg_catalog.", $class, "'::pg_catalog.regclass
                    and d.classid = 'pg_catalog.", $class, "'::pg_catalog.regclass)
             select coalesce((
               select pg_catalog.pg_describe_object(d.classid, d.objid, d.objsubid)
                      || ' (which belongs to ' || pg_catalog.pg_get_userbyid(o.owner) || ')'
                 from pg_catalog.pg_depend d
                 join t on d.refclassid = 'pg_catalog.", $class, "'::pg_catalog.regclass and d.refobjid = t.oid
                 cross join lateral (select ", owner_of!(), " as owner) o
                where o.owner is not null
                  and not pg_catalog.pg_has_role(session_user, o.owner, 'USAGE')
                limit 1), '')"
        )
    };
}

fn foreign_dependent(sql: &'static str, ids: &[i64]) -> Result<String, String> {
    if ids.is_empty() {
        return Ok(String::new());
    }
    Ok(crate::exec::get_one_prepared::<String>(
        sql,
        &[PgOid::BuiltIn(PgBuiltInOids::INT8ARRAYOID)],
        &[ids.to_vec().into()],
    )?
    .unwrap_or_default())
}

/// After the DDL has run, still inside its subtransaction: what it altered, created and took.
fn judge() -> Result<(), String> {
    let _running = state::proposal();
    let temp = crate::exec::get_one_prepared::<String>(
        "select coalesce((select x.what from (
                   select 'relation ' || c.relname as what from pg_catalog.pg_class c
                    where c.relnamespace = pg_catalog.pg_my_temp_schema()
                   union all
                   select 'type ' || t.typname from pg_catalog.pg_type t
                    where t.typnamespace = pg_catalog.pg_my_temp_schema()
                   union all
                   select 'function ' || p.proname from pg_catalog.pg_proc p
                    where p.pronamespace = pg_catalog.pg_my_temp_schema()
                   union all
                   select 'operator ' || o.oprname from pg_catalog.pg_operator o
                    where o.oprnamespace = pg_catalog.pg_my_temp_schema()) x limit 1), '')",
        &[],
        &[],
    )?
    .unwrap_or_default();
    if !temp.is_empty() {
        return Err(format!(
            "it would create the temporary {temp}: PostgreSQL searches the temporary schema first for \
             relations and types, so in this agent's session it would answer for a name a DBA's \
             function or policy does not qualify. An agent does not create temporary objects"
        ));
    }
    let altered: Vec<i64> = ALTERED.with(|a| a.borrow().iter().map(|o| *o as i64).collect());
    let foreign = foreign_dependent(foreign_dependent_sql!("pg_type"), &altered)?;
    if !foreign.is_empty() {
        return Err(format!(
            "{foreign} is made of a type it alters: a change to a type is a change to every value \
             stored in it"
        ));
    }
    let redefined: Vec<i64> = REDEFINED.with(|r| r.borrow().iter().map(|o| *o as i64).collect());
    let foreign = foreign_dependent(foreign_dependent_sql!("pg_proc"), &redefined)?;
    if !foreign.is_empty() {
        return Err(format!(
            "{foreign} is built on a function it redefines: what an index, a constraint or a stored \
             column holds was computed by the function as it was, and would no longer be what it \
             computes"
        ));
    }
    let mut classes: Vec<i64> = Vec::new();
    let mut objects: Vec<i64> = Vec::new();
    for (c, o) in CREATED
        .with(|c| c.borrow().iter().map(|o| (pg_sys::RelationRelationId.to_u32(), *o)).collect::<Vec<_>>())
        .into_iter()
        .chain(ATTACHED.with(|a| a.borrow().clone()))
    {
        classes.push(c as i64);
        objects.push(o as i64);
    }
    if !objects.is_empty() {
        let foreign = crate::exec::get_one_prepared::<String>(
            concat!(
                "select coalesce((
                   select pg_catalog.pg_describe_object(d.classid, d.objid, 0)
                          || ' (which belongs to ' || pg_catalog.pg_get_userbyid(o.owner) || ')'
                     from rows from (pg_catalog.unnest($1::int8[]::oid[]), pg_catalog.unnest($2::int8[]::oid[]))
                          as d(classid, objid)
                     cross join lateral (select ", owner_of!(), " as owner) o
                    where o.owner is not null
                      and not pg_catalog.pg_has_role(session_user, o.owner, 'USAGE')
                      and not coalesce((select g.tgisinternal from pg_catalog.pg_trigger g
                                         where d.classid = 'pg_catalog.pg_trigger'::pg_catalog.regclass
                                           and g.oid = d.objid), false)
                    limit 1), '')"
            ),
            &[PgOid::BuiltIn(PgBuiltInOids::INT8ARRAYOID), PgOid::BuiltIn(PgBuiltInOids::INT8ARRAYOID)],
            &[classes.into(), objects.into()],
        )?
        .unwrap_or_default();
        if !foreign.is_empty() {
            return Err(format!(
                "it would create {foreign}: an index or a trigger made on an agent's table is made on \
                 every partition of it too, and one of those is another role's table"
            ));
        }
    }
    let disinherited: Vec<i64> = DISINHERITED.with(|d| d.borrow().iter().map(|o| *o as i64).collect());
    if !disinherited.is_empty() {
        let foreign = crate::exec::get_one_prepared::<String>(
            "select coalesce((select c.oid::pg_catalog.regclass::text
                     || ' (which belongs to ' || pg_catalog.pg_get_userbyid(c.relowner) || ')'
                from pg_catalog.pg_class c
               where c.oid = any($1::int8[]::oid[])
                 and not pg_catalog.pg_has_role(session_user, c.relowner, 'USAGE') limit 1), '')",
            &[PgOid::BuiltIn(PgBuiltInOids::INT8ARRAYOID)],
            &[disinherited.into()],
        )?
        .unwrap_or_default();
        if !foreign.is_empty() {
            return Err(format!(
                "it would take {foreign} out of its parent: detaching a partition rewrites that table's \
                 own catalog row and its partition constraint"
            ));
        }
    }
    if NEXTVAL_ON_NEW.with(|n| *n.borrow()) {
        let created: Vec<i64> = CREATED.with(|c| c.borrow().iter().map(|o| *o as i64).collect());
        let taken = crate::exec::get_one_prepared::<String>(
            "select coalesce((select c.oid::pg_catalog.regclass::text
                 from pg_catalog.pg_locks l join pg_catalog.pg_class c on c.oid = l.relation
                where l.locktype = 'relation' and l.pid = pg_catalog.pg_backend_pid()
                  and c.relkind = 'S' and c.oid <> all($1::int8[]::oid[]) limit 1), '')",
            &[PgOid::BuiltIn(PgBuiltInOids::INT8ARRAYOID)],
            &[created.into()],
        )?
        .unwrap_or_default();
        if !taken.is_empty() {
            return Err(format!(
                "proposing it drew from {taken}, a sequence that existed before it, and what a sequence \
                 gives out is not given back: proposing changes nothing"
            ));
        }
    }
    Ok(())
}

/// judge(), raised as an error inside the DDL's subtransaction, so nothing it did is kept.
pub(crate) fn judge_or_refuse() {
    if let Err(why) = judge() {
        refuse(why);
    }
}

pub(crate) fn refuse(why: String) -> ! {
    ErrorReport::new(
        PgSqlErrorCode::ERRCODE_INSUFFICIENT_PRIVILEGE,
        format!("pg_agent_gate: an agent's DDL changes only what the agent owns: {why}"),
        "pg_agent_gate",
    )
    .set_detail(
        "PostgreSQL lets the owner of a type, a function or a schema drop or change what others built \
         on it (CASCADE, ALTER TYPE, CREATE OR REPLACE FUNCTION), and makes an index or a trigger of a \
         partitioned table on every partition; the gate judges each object the DDL reaches",
    )
    .report(PgLogLevel::ERROR);
    unreachable!()
}
