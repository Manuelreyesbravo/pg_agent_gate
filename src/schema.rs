//! The record, the only functions allowed to write it, and the administration.
//!
//! The record lives in `agent_gate_internal`, which agents never touch
//! directly. It is written by SECURITY DEFINER functions that first ask the
//! gate whether the caller is the gate's own code (`agent_gate._inside_gate()`)
//! -- a flag no SQL can set, and one that is down while the agent's own SQL
//! runs. So a proposal cannot forge its history, and neither can an agent
//! calling those functions by name.

use pgrx::prelude::*;

extension_sql!(
    r#"
-- The verbs are reachable by any role: they run with the caller's own
-- privileges, so reaching them grants nothing. CREATE EXTENSION does not do
-- this by itself, and without it an agent cannot even propose -- found by the
-- criteria harness, whose attacks were being stopped by a schema permission
-- and not by the gate.
GRANT USAGE ON SCHEMA agent_gate TO PUBLIC;

CREATE SCHEMA agent_gate_internal;
COMMENT ON SCHEMA agent_gate_internal IS
    'pg_agent_gate: the record of what agents proposed and did. Agents never touch it directly.';
GRANT USAGE ON SCHEMA agent_gate_internal TO PUBLIC;

CREATE TABLE agent_gate_internal.agents (
    name          text PRIMARY KEY CHECK (name ~ '^[a-z][a-z0-9_]{0,62}$'),
    role          name NOT NULL UNIQUE,
    max_rows      integer NOT NULL DEFAULT 1000 CHECK (max_rows >= 0),
    allow_ddl     boolean NOT NULL DEFAULT false,
    description   text NOT NULL CHECK (length(description) >= 10),
    registered_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    registered_by name NOT NULL DEFAULT session_user
);

CREATE TABLE agent_gate_internal.proposals (
    id             bigserial PRIMARY KEY,
    agent          text NOT NULL,
    role           name NOT NULL,
    backend_pid    integer NOT NULL,
    intent         text NOT NULL,
    sql            text NOT NULL,
    params         text[],
    kind           text NOT NULL CHECK (kind IN ('read', 'write', 'ddl', 'unknown')),
    ok             boolean NOT NULL,
    checks         jsonb NOT NULL,
    estimated_rows double precision,
    proposed_at    timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX ON agent_gate_internal.proposals (agent, id DESC);

-- outcome: kept = committed; read = a read ran (a read keeps nothing by
-- construction); rolled_back = a dry run; aborted = it ran and a guard undid
-- it; refused = it never ran. The last two must say why.
CREATE TABLE agent_gate_internal.executions (
    id            bigserial PRIMARY KEY,
    proposal      bigint NOT NULL REFERENCES agent_gate_internal.proposals (id),
    mode          text NOT NULL CHECK (mode IN ('dry_run', 'commit')),
    outcome       text NOT NULL CHECK (outcome IN ('kept', 'read', 'rolled_back', 'aborted', 'refused')),
    reason        text,
    rows_affected bigint,
    rows_returned integer,
    truncated     boolean,
    assertions    jsonb NOT NULL DEFAULT '[]',
    sample        jsonb,
    duration_ms   double precision NOT NULL,
    started_at    timestamptz NOT NULL,
    CONSTRAINT a_refusal_or_abort_says_why CHECK ((outcome IN ('aborted', 'refused')) = (reason IS NOT NULL))
);
CREATE INDEX ON agent_gate_internal.executions (proposal);

CREATE TABLE agent_gate_internal.bindings (
    agent     text NOT NULL REFERENCES agent_gate_internal.agents (name) ON DELETE CASCADE,
    assertion text NOT NULL,
    bound_at  timestamptz NOT NULL DEFAULT clock_timestamp(),
    bound_by  name NOT NULL DEFAULT session_user,
    PRIMARY KEY (agent, assertion)
);
"#,
    name = "record",
    bootstrap
);

extension_sql!(
    r#"
-- THE RECORD IS NOT EDITED. A superuser can still disable these triggers for
-- retention; that is an act of administration, and it is not silent.
CREATE FUNCTION agent_gate_internal._append_only() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    RAISE EXCEPTION 'pg_agent_gate: % on % is not allowed: what agents proposed and did is append-only',
        TG_OP, TG_TABLE_NAME USING ERRCODE = 'insufficient_privilege';
END $$;
CREATE TRIGGER proposals_append_only BEFORE UPDATE OR DELETE ON agent_gate_internal.proposals
    FOR EACH ROW EXECUTE FUNCTION agent_gate_internal._append_only();
CREATE TRIGGER executions_append_only BEFORE UPDATE OR DELETE ON agent_gate_internal.executions
    FOR EACH ROW EXECUTE FUNCTION agent_gate_internal._append_only();

-- TRUNCATE FIRES NO FOR EACH ROW TRIGGER. Without these two the whole history
-- could be emptied in one statement, with nothing disabled and nothing said --
-- which is not the deliberate act of administration the paragraph above
-- describes, it is the opposite. The asymmetry (UPDATE and DELETE stopped,
-- TRUNCATE free) was an oversight, found by tests/hostile.sh.
CREATE TRIGGER proposals_no_truncate BEFORE TRUNCATE ON agent_gate_internal.proposals
    FOR EACH STATEMENT EXECUTE FUNCTION agent_gate_internal._append_only();
CREATE TRIGGER executions_no_truncate BEFORE TRUNCATE ON agent_gate_internal.executions
    FOR EACH STATEMENT EXECUTE FUNCTION agent_gate_internal._append_only();

CREATE FUNCTION agent_gate_internal._only_the_gate() RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF NOT agent_gate._inside_gate() THEN
        RAISE EXCEPTION 'pg_agent_gate: only the gate reads and writes its own record'
            USING ERRCODE = 'insufficient_privilege',
                  HINT = 'agent_gate.acts() shows what this agent did.';
    END IF;
END $$;

CREATE FUNCTION agent_gate_internal._record_proposal(
    p_agent text, p_role text, p_intent text, p_sql text, p_params text[],
    p_kind text, p_ok boolean, p_checks jsonb, p_estimated double precision)
RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, agent_gate_internal AS $$
DECLARE
    new_id bigint;
BEGIN
    PERFORM agent_gate_internal._only_the_gate();
    INSERT INTO agent_gate_internal.proposals
        (agent, role, backend_pid, intent, sql, params, kind, ok, checks, estimated_rows)
    VALUES (p_agent, p_role, pg_backend_pid(), p_intent, p_sql, p_params, p_kind, p_ok, p_checks, p_estimated)
    RETURNING id INTO new_id;
    RETURN new_id;
END $$;

CREATE FUNCTION agent_gate_internal._record_execution(
    p_proposal bigint, p_mode text, p_outcome text, p_reason text, p_rows_affected bigint,
    p_rows_returned integer, p_truncated boolean, p_assertions jsonb, p_sample jsonb,
    p_duration_ms double precision)
RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, agent_gate_internal AS $$
DECLARE
    new_id bigint;
BEGIN
    PERFORM agent_gate_internal._only_the_gate();
    INSERT INTO agent_gate_internal.executions
        (proposal, mode, outcome, reason, rows_affected, rows_returned, truncated,
         assertions, sample, duration_ms, started_at)
    VALUES (p_proposal, p_mode, p_outcome, p_reason, p_rows_affected, p_rows_returned, p_truncated,
            coalesce(p_assertions, '[]'), p_sample, p_duration_ms,
            clock_timestamp() - make_interval(secs => p_duration_ms / 1000.0))
    RETURNING id INTO new_id;
    RETURN new_id;
END $$;

CREATE FUNCTION agent_gate_internal._load_proposal(p_id bigint, p_lock boolean DEFAULT false)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, agent_gate_internal AS $$
BEGIN
    PERFORM agent_gate_internal._only_the_gate();
    -- TWO COMMITS OF THE SAME PROPOSAL AT THE SAME TIME BOTH RAN IT. 'committed'
    -- below is read from each transaction's own snapshot, and neither sees the
    -- other's commit yet, so both passed the check and the change was applied
    -- twice -- on a balance that is a double charge. Measured with two
    -- concurrent commits (tests/hostile.sh). Locking the row makes the second
    -- one wait and then see it kept. Only when the caller is about to execute:
    -- a dry run does not need it, and taking row locks on reads would assign a
    -- transaction id to every one of them.
    IF p_lock THEN
        PERFORM 1 FROM agent_gate_internal.proposals WHERE id = p_id FOR UPDATE;
    END IF;
    RETURN (
        SELECT jsonb_build_object(
                   'id', p.id, 'agent', p.agent, 'sql', p.sql, 'params', to_jsonb(p.params),
                   'ok', p.ok, 'kind', p.kind,
                   'age_seconds', extract(epoch FROM clock_timestamp() - p.proposed_at),
                   'committed', EXISTS (SELECT 1 FROM agent_gate_internal.executions e
                                        WHERE e.proposal = p.id AND e.mode = 'commit'
                                          AND e.outcome = 'kept'))
          FROM agent_gate_internal.proposals p
         WHERE p.id = p_id);
END $$;

CREATE FUNCTION agent_gate_internal._agent(p_name text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, agent_gate_internal AS $$
BEGIN
    PERFORM agent_gate_internal._only_the_gate();
    RETURN (
        SELECT jsonb_build_object(
                   'name', a.name, 'max_rows', a.max_rows, 'allow_ddl', a.allow_ddl,
                   'bindings', coalesce((SELECT jsonb_agg(b.assertion ORDER BY b.assertion)
                                           FROM agent_gate_internal.bindings b
                                          WHERE b.agent = a.name), '[]'))
          FROM agent_gate_internal.agents a
         WHERE a.name = p_name);
END $$;

CREATE FUNCTION agent_gate_internal._acts(p_agent text, p_limit integer) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, agent_gate_internal AS $$
BEGIN
    PERFORM agent_gate_internal._only_the_gate();
    RETURN coalesce((
        SELECT jsonb_agg(a ORDER BY (a ->> 'proposal')::bigint DESC)
          FROM (SELECT jsonb_build_object(
                         'proposal', p.id, 'proposed_at', p.proposed_at, 'intent', p.intent,
                         'kind', p.kind, 'ok', p.ok, 'sql', p.sql,
                         'executions', coalesce((
                             SELECT jsonb_agg(jsonb_strip_nulls(jsonb_build_object(
                                        'mode', e.mode, 'outcome', e.outcome, 'reason', e.reason,
                                        'rows_affected', e.rows_affected, 'at', e.started_at)) ORDER BY e.id)
                               FROM agent_gate_internal.executions e
                              WHERE e.proposal = p.id), '[]')) AS a
                  FROM agent_gate_internal.proposals p
                 WHERE p.agent = p_agent
                 ORDER BY p.id DESC
                 LIMIT greatest(least(p_limit, 500), 1)) recent), '[]');
END $$;

-- Runs a bound assertion as the extension owner: an agent usually cannot read
-- pg_living_assertions' tables, and the check must not depend on it. The four
-- states that matter to a commit: holds and unknown let it through; broken and
-- erroring stop it -- a check that cannot run is not a check that passed.
CREATE FUNCTION agent_gate_internal._run_assertion(p_name text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, agent_gate_internal AS $$
DECLARE
    st text;
    de text;
BEGIN
    IF NOT agent_gate._checking() THEN
        RAISE EXCEPTION 'pg_agent_gate: assertions are run by the gate, after a change'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF to_regnamespace('living_assertions') IS NULL THEN
        RETURN jsonb_build_object('assertion', p_name, 'state', 'erroring', 'detail',
            'pg_living_assertions is not installed: a bound assertion nobody can check is not one that passed');
    END IF;
    BEGIN
        EXECUTE 'SELECT state, detail FROM living_assertions.run($1)' INTO st, de USING p_name;
    EXCEPTION WHEN OTHERS THEN
        RETURN jsonb_build_object('assertion', p_name, 'state', 'erroring', 'detail', SQLERRM);
    END;
    RETURN jsonb_build_object('assertion', p_name, 'state', st, 'detail', de);
END $$;

-- ADMINISTRATION. Not verbs: an agent session cannot reach them.

CREATE FUNCTION agent_gate.register_agent(
    p_name text, p_role regrole, p_description text,
    p_max_rows integer DEFAULT 1000, p_allow_ddl boolean DEFAULT false)
RETURNS jsonb LANGUAGE plpgsql SET search_path = pg_catalog, agent_gate_internal AS $$
DECLARE
    role_name name;
    is_super  boolean;
    enforced  text;
BEGIN
    SELECT rolname, rolsuper INTO role_name, is_super FROM pg_roles WHERE oid = p_role;
    IF is_super THEN
        RAISE EXCEPTION 'pg_agent_gate: % is a superuser, and a superuser can unset agent_gate.agent', role_name
            USING HINT = 'An agent role that can leave the gate is not behind it. Use a role without SUPERUSER.';
    END IF;
    INSERT INTO agent_gate_internal.agents (name, role, max_rows, allow_ddl, description)
    VALUES (p_name, role_name, p_max_rows, p_allow_ddl, p_description);
    EXECUTE format('ALTER ROLE %I SET agent_gate.agent = %L', role_name, p_name);
    IF current_setting('shared_preload_libraries') ~ '(^|,)\s*"?pg_agent_gate"?\s*(,|$)' THEN
        enforced := 'shared_preload_libraries';
    ELSE
        EXECUTE format('ALTER ROLE %I SET session_preload_libraries = %L', role_name, 'pg_agent_gate');
        enforced := 'session_preload_libraries, set on the role';
    END IF;
    RETURN jsonb_build_object(
        'agent', p_name, 'role', role_name, 'max_rows', p_max_rows, 'allow_ddl', p_allow_ddl,
        'enforced_by', enforced,
        'takes_effect', 'on the next connection of that role; existing connections are not behind the gate');
END $$;

CREATE FUNCTION agent_gate.unregister_agent(p_name text) RETURNS jsonb
LANGUAGE plpgsql SET search_path = pg_catalog, agent_gate_internal AS $$
DECLARE
    role_name name;
BEGIN
    SELECT role INTO role_name FROM agent_gate_internal.agents WHERE name = p_name;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'pg_agent_gate: no agent named %', p_name;
    END IF;
    EXECUTE format('ALTER ROLE %I RESET agent_gate.agent', role_name);
    DELETE FROM agent_gate_internal.agents WHERE name = p_name;
    RETURN jsonb_build_object('agent', p_name, 'role', role_name,
        'effect', 'from its next connection the role is an ordinary role; its record stays');
END $$;

CREATE FUNCTION agent_gate.bind_assertion(p_agent text, p_assertion text) RETURNS jsonb
LANGUAGE plpgsql SET search_path = pg_catalog, agent_gate_internal AS $$
DECLARE
    st text;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM agent_gate_internal.agents WHERE name = p_agent) THEN
        RAISE EXCEPTION 'pg_agent_gate: no agent named %', p_agent;
    END IF;
    IF to_regnamespace('living_assertions') IS NULL THEN
        RAISE EXCEPTION 'pg_agent_gate: pg_living_assertions is not installed'
            USING HINT = 'A binding nobody can check would abort every write this agent commits.';
    END IF;
    EXECUTE 'SELECT living_assertions.state($1)' INTO st USING p_assertion;
    IF st IN ('unregistered', 'retired') THEN
        RAISE EXCEPTION 'pg_agent_gate: assertion % is %', p_assertion, st;
    END IF;
    INSERT INTO agent_gate_internal.bindings (agent, assertion) VALUES (p_agent, p_assertion)
    ON CONFLICT DO NOTHING;
    RETURN jsonb_build_object('agent', p_agent, 'assertion', p_assertion, 'state_now', st,
        'effect', 'every write this agent commits is checked against it before it is kept');
END $$;

CREATE FUNCTION agent_gate.unbind_assertion(p_agent text, p_assertion text) RETURNS boolean
LANGUAGE sql SET search_path = pg_catalog, agent_gate_internal AS $$
    WITH gone AS (DELETE FROM agent_gate_internal.bindings
                   WHERE agent = p_agent AND assertion = p_assertion RETURNING 1)
    SELECT EXISTS (SELECT 1 FROM gone);
$$;

REVOKE EXECUTE ON FUNCTION agent_gate.register_agent(text, regrole, text, integer, boolean) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION agent_gate.unregister_agent(text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION agent_gate.bind_assertion(text, text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION agent_gate.unbind_assertion(text, text) FROM PUBLIC;

-- The record survives pg_dump.
SELECT pg_catalog.pg_extension_config_dump('agent_gate_internal.agents', '');
SELECT pg_catalog.pg_extension_config_dump('agent_gate_internal.bindings', '');
SELECT pg_catalog.pg_extension_config_dump('agent_gate_internal.proposals', '');
SELECT pg_catalog.pg_extension_config_dump('agent_gate_internal.proposals_id_seq', '');
SELECT pg_catalog.pg_extension_config_dump('agent_gate_internal.executions', '');
SELECT pg_catalog.pg_extension_config_dump('agent_gate_internal.executions_id_seq', '');
"#,
    name = "record_functions",
    finalize
);

/// What an agent may touch, from the live catalog and the agent's privileges.
/// Objects that belong to extensions are left out: they are the database's
/// machinery, not the application an agent works on.
pub(crate) const DISCOVER_SQL: &str = r#"
with params as (
    select $1::text as f, greatest(coalesce($2::int, 50), 1) as lim
),
rels as (
    select c.oid, n.nspname, c.relname, c.relkind
      from pg_class c
      join pg_namespace n on n.oid = c.relnamespace
     cross join params p
     where c.relkind in ('r', 'p', 'v', 'm', 'f')
       and n.nspname not in ('pg_catalog', 'information_schema', 'agent_gate', 'agent_gate_internal')
       and n.nspname not like 'pg\_%'
       and has_schema_privilege(n.oid, 'USAGE')
       and has_table_privilege(c.oid, 'SELECT, INSERT, UPDATE, DELETE')
       and not exists (select 1 from pg_depend d
                        where d.classid = 'pg_class'::regclass and d.objid = c.oid and d.deptype = 'e')
       and (p.f is null
            or c.relname ilike '%' || p.f || '%'
            or n.nspname ilike '%' || p.f || '%'
            or coalesce(obj_description(c.oid, 'pg_class'), '') ilike '%' || p.f || '%')
),
rel_json as (
    select r.nspname, r.relname, jsonb_strip_nulls(jsonb_build_object(
        'relation', format('%I.%I', r.nspname, r.relname),
        'kind', case r.relkind when 'v' then 'view' when 'm' then 'materialized view'
                               when 'f' then 'foreign table' else 'table' end,
        'privileges', to_jsonb(array_remove(array[
            case when has_table_privilege(r.oid, 'SELECT') then 'select' end,
            case when has_table_privilege(r.oid, 'INSERT') then 'insert' end,
            case when has_table_privilege(r.oid, 'UPDATE') then 'update' end,
            case when has_table_privilege(r.oid, 'DELETE') then 'delete' end], null)),
        'comment', obj_description(r.oid, 'pg_class'),
        'columns', (select jsonb_agg(jsonb_strip_nulls(jsonb_build_object(
                        'name', a.attname,
                        'type', format_type(a.atttypid, a.atttypmod),
                        'not_null', a.attnotnull,
                        'default', pg_get_expr(ad.adbin, ad.adrelid),
                        'comment', col_description(r.oid, a.attnum))) order by a.attnum)
                      from pg_attribute a
                      left join pg_attrdef ad on ad.adrelid = a.attrelid and ad.adnum = a.attnum
                     where a.attrelid = r.oid and a.attnum > 0 and not a.attisdropped
                       and has_column_privilege(r.oid, a.attnum, 'SELECT, INSERT, UPDATE')),
        'primary_key', (select to_jsonb(array_agg(a.attname order by k.ord))
                          from pg_constraint co
                         cross join lateral unnest(co.conkey) with ordinality as k(attnum, ord)
                          join pg_attribute a on a.attrelid = co.conrelid and a.attnum = k.attnum
                         where co.conrelid = r.oid and co.contype = 'p'),
        'foreign_keys', (select jsonb_agg(jsonb_build_object('constraint', co.conname,
                                                             'definition', pg_get_constraintdef(co.oid))
                                          order by co.conname)
                           from pg_constraint co
                          where co.conrelid = r.oid and co.contype = 'f'),
        'checks', (select jsonb_agg(pg_get_constraintdef(co.oid) order by co.conname)
                     from pg_constraint co
                    where co.conrelid = r.oid and co.contype = 'c')
    )) as j
    from rels r
),
funcs as (
    select n.nspname, p.proname, jsonb_strip_nulls(jsonb_build_object(
        'function', p.oid::regprocedure::text,
        'returns', pg_get_function_result(p.oid),
        'kind', case p.prokind when 'p' then 'procedure' else 'function' end,
        'volatility', case p.provolatile when 'i' then 'immutable' when 's' then 'stable' else 'volatile' end,
        'comment', obj_description(p.oid, 'pg_proc'))) as j
      from pg_proc p
      join pg_namespace n on n.oid = p.pronamespace
     cross join params pa
     where p.prokind in ('f', 'p')
       and n.nspname not in ('pg_catalog', 'information_schema', 'agent_gate', 'agent_gate_internal')
       and n.nspname not like 'pg\_%'
       and has_schema_privilege(n.oid, 'USAGE')
       and has_function_privilege(p.oid, 'EXECUTE')
       and not exists (select 1 from pg_depend d
                        where d.classid = 'pg_proc'::regclass and d.objid = p.oid and d.deptype = 'e')
       and (pa.f is null
            or p.proname ilike '%' || pa.f || '%'
            or coalesce(obj_description(p.oid, 'pg_proc'), '') ilike '%' || pa.f || '%')
)
select jsonb_build_object(
    'relations', coalesce((select jsonb_agg(j order by nspname, relname)
                             from (select * from rel_json order by nspname, relname
                                    limit (select lim from params)) x), '[]'::jsonb),
    'relations_total', (select count(*) from rel_json),
    'functions', coalesce((select jsonb_agg(j order by nspname, proname)
                             from (select * from funcs order by nspname, proname
                                    limit (select lim from params)) y), '[]'::jsonb),
    'functions_total', (select count(*) from funcs),
    'fingerprint', md5(coalesce((select string_agg(j::text, '|' order by nspname, relname) from rel_json), '')
                       || '#'
                       || coalesce((select string_agg(j::text, '|' order by nspname, proname) from funcs), '')),
    'how', 'propose(sql, intent[, params]) -> dry_run(proposal) -> commit(proposal). '
           || 'Parameters travel as text: cast them in the SQL ($1::int).'
)
"#;
