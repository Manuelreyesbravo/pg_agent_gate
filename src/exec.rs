// Copyright 2026 Manuel Reyes Bravo
// SPDX-License-Identifier: Apache-2.0

//! Running something inside a subtransaction and deciding AFTERWARDS whether
//! to keep it -- and turning SPI rows into JSON without hiding that there were
//! more.

use pgrx::pg_sys::panic::CaughtError;
use pgrx::datum::DatumWithOid;
use pgrx::prelude::*;
use serde_json::{json, Map, Value};
use std::ffi::CStr;
use std::panic::AssertUnwindSafe;

/// What PostgreSQL said when something failed, kept whole: the SQLSTATE, the
/// message, the detail and the hint. An agent fixes a proposal from the hint;
/// dropping it would leave the agent guessing.
pub(crate) struct Failure {
    pub sqlstate: String,
    pub message: String,
    pub detail: Option<String>,
    pub hint: Option<String>,
}

impl Failure {
    fn from_caught(e: CaughtError) -> Self {
        let r = match &e {
            CaughtError::PostgresError(r) | CaughtError::ErrorReport(r) => r,
            CaughtError::RustPanic { ereport, .. } => ereport,
        };
        Failure {
            sqlstate: sqlstate(r.sql_error_code() as i32),
            message: r.message().to_string(),
            detail: r.detail().map(str::to_string),
            hint: r.hint().map(str::to_string),
        }
    }

    pub(crate) fn describe(&self) -> String {
        let mut s = format!("[{}] {}", self.sqlstate, self.message);
        if let Some(d) = &self.detail {
            s.push_str(&format!(" -- {d}"));
        }
        if let Some(h) = &self.hint {
            s.push_str(&format!(" (hint: {h})"));
        }
        s
    }

    pub(crate) fn json(&self) -> Value {
        json!({
            "sqlstate": self.sqlstate,
            "message": self.message,
            "detail": self.detail,
            "hint": self.hint,
        })
    }
}

/// PostgreSQL packs a SQLSTATE into six bits per character.
fn sqlstate(code: i32) -> String {
    (0..5)
        .map(|i| ((((code >> (6 * i)) & 0x3F) as u8) + b'0') as char)
        .collect()
}

/// Runs `f` inside an internal subtransaction. If `f` raises, the error is
/// captured and the subtransaction rolled back. If it returns, `keep` decides:
/// release (the work stays) or roll back (it never happened).
///
/// The memory context and resource owner are restored by hand, as every
/// procedural language does around `BeginInternalSubTransaction`: without it
/// the caller's allocations would end up in a context that no longer exists.
pub(crate) fn in_subxact<T>(f: impl FnOnce() -> T, keep: impl FnOnce(&T) -> bool) -> Result<T, Failure> {
    unsafe {
        let old_context = pg_sys::CurrentMemoryContext;
        let old_owner = pg_sys::CurrentResourceOwner;
        pg_sys::BeginInternalSubTransaction(std::ptr::null());
        pg_sys::MemoryContextSwitchTo(old_context);

        let result: Result<T, Failure> = PgTryBuilder::new(AssertUnwindSafe(|| Ok(f())))
            .catch_others(|e| Err(Failure::from_caught(e)))
            .catch_rust_panic(|e| Err(Failure::from_caught(e)))
            .execute();

        let keep_it = match &result {
            Ok(value) => keep(value),
            Err(_) => false,
        };
        if keep_it {
            pg_sys::ReleaseCurrentSubTransaction();
        } else {
            pg_sys::RollbackAndReleaseCurrentSubTransaction();
        }
        pg_sys::MemoryContextSwitchTo(old_context);
        pg_sys::CurrentResourceOwner = old_owner;
        result
    }
}

pub(crate) struct Rows {
    /// What SPI reports as processed: rows touched by a write, rows fetched by
    /// a read.
    pub processed: u64,
    pub rows: Vec<Value>,
    /// True when more rows existed than were handed back.
    pub truncated: bool,
}

/// Reads the result of the SPI call that just ran. Must be called before any
/// other SPI call, while `SPI_tuptable` still belongs to it.
pub(crate) unsafe fn collect_rows(cap: usize) -> Rows {
    let processed = pg_sys::SPI_processed;
    let table = pg_sys::SPI_tuptable;
    if table.is_null() {
        return Rows { processed, rows: Vec::new(), truncated: false };
    }
    let tupdesc = (*table).tupdesc;
    let natts = (*tupdesc).natts;
    let available = (*table).numvals as usize;
    let take = available.min(cap);

    let mut rows = Vec::with_capacity(take);
    for i in 0..take {
        let tuple = *(*table).vals.add(i);
        let mut object = Map::new();
        for col in 1..=natts {
            let name_ptr = pg_sys::SPI_fname(tupdesc, col);
            let mut name = if name_ptr.is_null() {
                format!("column{col}")
            } else {
                CStr::from_ptr(name_ptr).to_string_lossy().into_owned()
            };
            if object.contains_key(&name) {
                name = format!("{name}_{col}");
            }
            let text_ptr = pg_sys::SPI_getvalue(tuple, tupdesc, col);
            let value = if text_ptr.is_null() {
                Value::Null
            } else {
                typed(pg_sys::SPI_gettypeid(tupdesc, col), &CStr::from_ptr(text_ptr).to_string_lossy())
            };
            object.insert(name, value);
        }
        rows.push(Value::Object(object));
    }
    Rows { processed, rows, truncated: available > take || processed as usize > take }
}

/// Numbers, booleans and JSON keep their type; everything else travels as its
/// text form. `numeric` stays text on purpose: a JSON number would round it.
fn typed(type_oid: pg_sys::Oid, text: &str) -> Value {
    use pg_sys::BuiltinOid as B;
    let is = |b: B| type_oid == b.value();
    if is(B::BOOLOID) {
        Value::Bool(text == "t")
    } else if is(B::INT2OID) || is(B::INT4OID) || is(B::INT8OID) {
        text.parse::<i64>().map(Value::from).unwrap_or_else(|_| Value::String(text.into()))
    } else if is(B::FLOAT4OID) || is(B::FLOAT8OID) {
        text.parse::<f64>()
            .ok()
            .and_then(serde_json::Number::from_f64)
            .map(Value::Number)
            .unwrap_or_else(|| Value::String(text.into()))
    } else if is(B::JSONOID) || is(B::JSONBOID) {
        serde_json::from_str(text).unwrap_or_else(|_| Value::String(text.into()))
    } else {
        Value::String(text.into())
    }
}

thread_local! {
    /// Plans of the gate's own fixed queries, prepared once per backend (SPI_keepplan). The plan
    /// cache revalidates them when the catalog changes, as it does for any prepared statement.
    static PLANS: std::cell::RefCell<std::collections::HashMap<&'static str, pgrx::spi::OwnedPreparedStatement>> =
        std::cell::RefCell::new(std::collections::HashMap::new());
}

/// One row, one column, from one of the gate's own FIXED queries -- never the agent's SQL --
/// with its plan prepared once per backend instead of on every call. Measured on the mind
/// (2026-10-08): planning the max_rows counter alone took ~2 ms, twice per commit. The plan is
/// taken out of the cache while it runs, so an error unwinding through here only costs a
/// re-prepare next time.
pub(crate) fn get_one_prepared<T: FromDatum + IntoDatum>(
    sql: &'static str,
    types: &[PgOid],
    args: &[DatumWithOid],
) -> Result<Option<T>, String> {
    Spi::connect(|client| {
        let plan = match PLANS.with(|p| p.borrow_mut().remove(sql)) {
            Some(plan) => plan,
            None => client.prepare(sql, types).map_err(|e| e.to_string())?.keep(),
        };
        let result = client
            .select(&plan, Some(1), args)
            .and_then(|t| t.first().get_one::<T>())
            .map_err(|e| e.to_string());
        PLANS.with(|p| p.borrow_mut().insert(sql, plan));
        result
    })
}
