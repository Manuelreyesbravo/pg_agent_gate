/* pg_agent_gate 0.3.0 -> 0.4.0 : a write budget per agent, on by default.
 *
 * max_rows bounds ONE proposal. An agent that loops can split a write it is refused into
 * several that each fit: measured (agent-gate-demo/compare, base Qwen3-8B, 0.3.0), a model
 * told "may touch at most 5" emptied a 6-row table in two legal commits (5 + 1). The
 * database decided each statement and none of their sum. Now it decides the sum too: every
 * agent has a budget of rows it may change per window, counted from the record of what it
 * already kept, and a commit that would pass it is aborted. Unset, the budget is max_rows
 * per hour -- safe by default; an administrator raises it with agent_gate.set_budget().
 *
 * This file is the upgrade path for existing installs. The same objects go into
 * the base schema (src/schema.rs extension_sql) for fresh installs.
 */

-- 1. The budget, per agent. Existing agents get their own max_rows per hour.
ALTER TABLE agent_gate_internal.agents
    ADD COLUMN max_rows_per_window integer,
    ADD COLUMN window_seconds integer NOT NULL DEFAULT 3600 CHECK (window_seconds > 0),
    -- Set by reset_budget(): what the agent kept before this does not count.
    ADD COLUMN budget_since timestamptz;
UPDATE agent_gate_internal.agents SET max_rows_per_window = max_rows;
ALTER TABLE agent_gate_internal.agents
    ALTER COLUMN max_rows_per_window SET NOT NULL,
    ADD CONSTRAINT agents_max_rows_per_window_check CHECK (max_rows_per_window >= 0);

DO $$
DECLARE
    names text;
BEGIN
    SELECT string_agg(format('%s (%s rows per hour)', name, max_rows_per_window), ', ' ORDER BY name)
      INTO names FROM agent_gate_internal.agents;
    IF names IS NOT NULL THEN
        RAISE NOTICE 'pg_agent_gate 0.4.0: every agent now has a write budget per window, set to its max_rows per hour: %', names
            USING HINT = 'Raise it where an agent legitimately writes more: SELECT agent_gate.set_budget(agent, rows, window_seconds).';
    END IF;
END $$;

-- 2. The rows a kept write really changed: what the backstop measures, cascades, triggers
--    and rules included. rows_affected stays the statement's own count; the budget sums this.
ALTER TABLE agent_gate_internal.executions
    ADD COLUMN rows_moved bigint;

-- 3. The budget reads the kept commits of the last window. Without this it would walk the
--    agent's whole history on every commit.
CREATE INDEX executions_kept_commit_at
    ON agent_gate_internal.executions (started_at) WHERE mode = 'commit' AND outcome = 'kept';

-- 4. _record_execution records rows_moved.
DROP FUNCTION agent_gate_internal._record_execution(bigint, text, text, text, bigint, integer, boolean,
                                                    jsonb, jsonb, double precision);
CREATE FUNCTION agent_gate_internal._record_execution(
    p_proposal bigint, p_mode text, p_outcome text, p_reason text, p_rows_affected bigint,
    p_rows_returned integer, p_truncated boolean, p_assertions jsonb, p_sample jsonb,
    p_duration_ms double precision, p_rows_moved bigint)
RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, agent_gate_internal, pg_temp AS $$
DECLARE
    new_id bigint;
BEGIN
    PERFORM agent_gate_internal._only_the_gate();
    INSERT INTO agent_gate_internal.executions
        (proposal, mode, outcome, reason, rows_affected, rows_returned, truncated,
         assertions, sample, duration_ms, started_at, approved_by, rows_moved)
    VALUES (p_proposal, p_mode, p_outcome, p_reason, p_rows_affected, p_rows_returned, p_truncated,
            coalesce(p_assertions, '[]'), p_sample, p_duration_ms,
            clock_timestamp() - make_interval(secs => p_duration_ms / 1000.0),
            (SELECT approver FROM agent_gate_internal.approvals WHERE proposal = p_proposal),
            p_rows_moved)
    RETURNING id INTO new_id;
    RETURN new_id;
END $$;

-- 5. What this agent may still write. With p_lock, the agent's row is locked first, so two
--    sessions of one agent cannot each read the same remainder and both spend it; the sum
--    then runs as its own statement, with a snapshot taken after the lock was granted, and
--    sees what the session that held it kept. FOR NO KEY UPDATE: foreign-key checks on the
--    agent (bindings, allowlist) do not wait on it.
CREATE FUNCTION agent_gate_internal._budget(p_agent text, p_lock boolean)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, agent_gate_internal, pg_temp AS $$
DECLARE
    v_budget integer;
    v_window integer;
    v_since  timestamptz;
    v_used   bigint;
BEGIN
    PERFORM agent_gate_internal._only_the_gate();
    IF p_lock THEN
        SELECT a.max_rows_per_window, a.window_seconds, a.budget_since INTO v_budget, v_window, v_since
          FROM agent_gate_internal.agents a WHERE a.name = p_agent
           FOR NO KEY UPDATE;
    ELSE
        SELECT a.max_rows_per_window, a.window_seconds, a.budget_since INTO v_budget, v_window, v_since
          FROM agent_gate_internal.agents a WHERE a.name = p_agent;
    END IF;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    SELECT coalesce(sum(coalesce(e.rows_moved, e.rows_affected, 0)), 0) INTO v_used
      FROM agent_gate_internal.executions e
      JOIN agent_gate_internal.proposals p ON p.id = e.proposal
     WHERE e.mode = 'commit' AND e.outcome = 'kept'
       AND e.started_at > greatest(clock_timestamp() - make_interval(secs => v_window),
                                   coalesce(v_since, '-infinity'))
       AND p.agent = p_agent;
    RETURN jsonb_build_object('budget', v_budget, 'used', v_used, 'window_seconds', v_window);
END $$;

-- 6. register_agent gains p_max_rows_per_window: NULL means max_rows, per p_window_seconds.
DROP FUNCTION agent_gate.register_agent(text, regrole, text, integer, boolean, boolean);
CREATE FUNCTION agent_gate.register_agent(
    p_name text, p_role regrole, p_description text,
    p_max_rows integer DEFAULT 1000, p_allow_ddl boolean DEFAULT false,
    p_requires_approval boolean DEFAULT false,
    p_max_rows_per_window integer DEFAULT NULL, p_window_seconds integer DEFAULT 3600)
RETURNS jsonb LANGUAGE plpgsql SET search_path = pg_catalog, agent_gate_internal, pg_temp AS $$
DECLARE
    role_name name;
    is_super  boolean;
    enforced  text;
    budget    integer := coalesce(p_max_rows_per_window, p_max_rows);
BEGIN
    SELECT rolname, rolsuper INTO role_name, is_super FROM pg_roles WHERE oid = p_role;
    IF is_super THEN
        RAISE EXCEPTION 'pg_agent_gate: % is a superuser, and a superuser can unset agent_gate.agent', role_name
            USING HINT = 'An agent role that can leave the gate is not behind it. Use a role without SUPERUSER.';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE oid = p_role AND (rolreplication OR rolbypassrls)) THEN
        RAISE EXCEPTION 'pg_agent_gate: % has REPLICATION or BYPASSRLS, which reach past the gate', role_name
            USING HINT = 'Use a role without REPLICATION and without BYPASSRLS.';
    END IF;
    IF EXISTS (
        WITH RECURSIVE up(r) AS (
            SELECT m.roleid FROM pg_auth_members m WHERE m.member = p_role
            UNION
            SELECT m.roleid FROM pg_auth_members m JOIN up ON m.member = up.r)
        SELECT 1 FROM up JOIN pg_roles r ON r.oid = up.r
         WHERE r.rolsuper OR r.rolreplication OR r.rolbypassrls
            OR r.rolname IN ('pg_write_all_data', 'pg_execute_server_program', 'pg_write_server_files'))
    THEN
        RAISE EXCEPTION 'pg_agent_gate: % is a member, directly or through other roles, of a superuser or of a role that reaches past the gate', role_name
            USING HINT = 'An agent role must not be able to SET ROLE out from behind the gate. Revoke those memberships.';
    END IF;
    INSERT INTO agent_gate_internal.agents
        (name, role, max_rows, allow_ddl, description, requires_approval, max_rows_per_window, window_seconds)
    VALUES (p_name, role_name, p_max_rows, p_allow_ddl, p_description, p_requires_approval, budget, p_window_seconds);
    EXECUTE format('ALTER ROLE %I SET agent_gate.agent = %L', role_name, p_name);
    IF current_setting('shared_preload_libraries') ~ '(^|,)\s*"?pg_agent_gate"?\s*(,|$)' THEN
        enforced := 'shared_preload_libraries';
    ELSE
        EXECUTE format('ALTER ROLE %I SET session_preload_libraries = %L', role_name, 'pg_agent_gate');
        enforced := 'session_preload_libraries, set on the role';
    END IF;
    RETURN jsonb_build_object(
        'agent', p_name, 'role', role_name, 'max_rows', p_max_rows, 'allow_ddl', p_allow_ddl,
        'requires_approval', p_requires_approval,
        'max_rows_per_window', budget, 'window_seconds', p_window_seconds,
        'enforced_by', enforced,
        'takes_effect', 'on the next connection of that role; existing connections are not behind the gate');
END $$;
REVOKE EXECUTE ON FUNCTION agent_gate.register_agent(text, regrole, text, integer, boolean, boolean, integer, integer) FROM PUBLIC;

-- 7. set_budget(): an administrator changes an agent's budget. Not a verb: an agent session
--    cannot reach it (EXECUTE revoked from PUBLIC, like register_agent).
CREATE FUNCTION agent_gate.set_budget(p_agent text, p_rows integer, p_window_seconds integer DEFAULT 3600)
RETURNS jsonb LANGUAGE plpgsql SET search_path = pg_catalog, agent_gate_internal, pg_temp AS $$
BEGIN
    UPDATE agent_gate_internal.agents
       SET max_rows_per_window = p_rows, window_seconds = p_window_seconds
     WHERE name = p_agent;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'pg_agent_gate: no agent named %', p_agent;
    END IF;
    RETURN jsonb_build_object('agent', p_agent, 'max_rows_per_window', p_rows,
                              'window_seconds', p_window_seconds,
                              'effect', 'the next commit of this agent is counted against it');
END $$;
REVOKE EXECUTE ON FUNCTION agent_gate.set_budget(text, integer, integer) FROM PUBLIC;

-- 8. reset_budget(): an administrator who has looked at what an agent did gives it its whole
--    budget back from now. Nothing in the record changes; the agent's row says since when the
--    budget counts, and by whom (a NOTICE names both). Not a verb.
CREATE FUNCTION agent_gate.reset_budget(p_agent text)
RETURNS jsonb LANGUAGE plpgsql SET search_path = pg_catalog, agent_gate_internal, pg_temp AS $$
DECLARE
    v_since timestamptz := clock_timestamp();
BEGIN
    UPDATE agent_gate_internal.agents SET budget_since = v_since WHERE name = p_agent;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'pg_agent_gate: no agent named %', p_agent;
    END IF;
    RAISE NOTICE 'pg_agent_gate: % reset the write budget of agent % at %', session_user, p_agent, v_since;
    RETURN jsonb_build_object('agent', p_agent, 'budget_since', v_since, 'reset_by', session_user);
END $$;
REVOKE EXECUTE ON FUNCTION agent_gate.reset_budget(text) FROM PUBLIC;
