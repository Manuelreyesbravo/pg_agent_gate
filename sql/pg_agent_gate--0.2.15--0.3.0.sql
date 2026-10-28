/* pg_agent_gate 0.2.15 -> 0.3.0 : human-in-the-middle approvals.
 *
 * Principle: the ownership rule does not change. An agent still commits its own
 * proposal; approval is a recorded consent that UNBLOCKS that commit. The guards
 * (max_rows, assertions, backstop) still run at commit. See control/gate-fase2/DESIGN.md.
 *
 * This file is the upgrade path for existing installs. The same objects go into
 * the base schema (src/schema.rs extension_sql) for fresh installs.
 */

-- 1. Per-agent flag.
ALTER TABLE agent_gate_internal.agents
    ADD COLUMN requires_approval boolean NOT NULL DEFAULT false;

-- 2. The approver group. A role may approve only if it is a member of this, and
--    only agent_gate.approve() is granted to it (below). NOLOGIN: it is a group.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_gate_approver') THEN
        CREATE ROLE agent_gate_approver NOLOGIN;
    END IF;
END $$;

-- 3. One recorded consent per proposal. Agents never touch this table.
CREATE TABLE agent_gate_internal.approvals (
    proposal    bigint PRIMARY KEY REFERENCES agent_gate_internal.proposals (id) ON DELETE CASCADE,
    approver    name NOT NULL,
    approved_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

-- 4. Who approved a kept commit (nullable; set by _record_execution from approvals).
ALTER TABLE agent_gate_internal.executions
    ADD COLUMN approved_by name;

-- 5. _load_proposal also tells the engine whether this proposal's agent requires
--    approval and whether an approval exists, so execute() can gate the commit.
CREATE OR REPLACE FUNCTION agent_gate_internal._load_proposal(p_id bigint, p_lock boolean DEFAULT false)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, agent_gate_internal, pg_temp AS $$
BEGIN
    PERFORM agent_gate_internal._only_the_gate();
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
                                          AND e.outcome = 'kept'),
                   'predates_agent', p.proposed_at < (SELECT a.registered_at FROM agent_gate_internal.agents a
                                                       WHERE a.name = p.agent),
                   'requires_approval', coalesce((SELECT a.requires_approval FROM agent_gate_internal.agents a
                                                   WHERE a.name = p.agent), false),
                   'approved', EXISTS (SELECT 1 FROM agent_gate_internal.approvals ap WHERE ap.proposal = p.id),
                   'settings_changed', (SELECT string_agg(format('%s (%s then, %s now)', k, p.settings ->> k, n.v), ', ' ORDER BY k)
                                          FROM jsonb_each_text(agent_gate_internal._session_settings()) AS n(k, v)
                                         WHERE p.settings IS NOT NULL AND p.settings ->> k IS DISTINCT FROM n.v))
          FROM agent_gate_internal.proposals p
         WHERE p.id = p_id);
END $$;

-- 6. A kept (or any) execution records who approved, looked up from approvals.
CREATE OR REPLACE FUNCTION agent_gate_internal._record_execution(
    p_proposal bigint, p_mode text, p_outcome text, p_reason text, p_rows_affected bigint,
    p_rows_returned integer, p_truncated boolean, p_assertions jsonb, p_sample jsonb,
    p_duration_ms double precision)
RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, agent_gate_internal, pg_temp AS $$
DECLARE
    new_id bigint;
BEGIN
    PERFORM agent_gate_internal._only_the_gate();
    INSERT INTO agent_gate_internal.executions
        (proposal, mode, outcome, reason, rows_affected, rows_returned, truncated,
         assertions, sample, duration_ms, started_at, approved_by)
    VALUES (p_proposal, p_mode, p_outcome, p_reason, p_rows_affected, p_rows_returned, p_truncated,
            coalesce(p_assertions, '[]'), p_sample, p_duration_ms,
            clock_timestamp() - make_interval(secs => p_duration_ms / 1000.0),
            (SELECT approver FROM agent_gate_internal.approvals WHERE proposal = p_proposal))
    RETURNING id INTO new_id;
    RETURN new_id;
END $$;

-- 7. register_agent gains p_requires_approval. Drop the old 5-arg signature and
--    recreate with the 6th, defaulted, parameter.
DROP FUNCTION agent_gate.register_agent(text, regrole, text, integer, boolean);
CREATE FUNCTION agent_gate.register_agent(
    p_name text, p_role regrole, p_description text,
    p_max_rows integer DEFAULT 1000, p_allow_ddl boolean DEFAULT false,
    p_requires_approval boolean DEFAULT false)
RETURNS jsonb LANGUAGE plpgsql SET search_path = pg_catalog, agent_gate_internal, pg_temp AS $$
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
    INSERT INTO agent_gate_internal.agents (name, role, max_rows, allow_ddl, description, requires_approval)
    VALUES (p_name, role_name, p_max_rows, p_allow_ddl, p_description, p_requires_approval);
    EXECUTE format('ALTER ROLE %I SET agent_gate.agent = %L', role_name, p_name);
    IF current_setting('shared_preload_libraries') ~ '(^|,)\s*"?pg_agent_gate"?\s*(,|$)' THEN
        enforced := 'shared_preload_libraries';
    ELSE
        EXECUTE format('ALTER ROLE %I SET session_preload_libraries = %L', role_name, 'pg_agent_gate');
        enforced := 'session_preload_libraries, set on the role';
    END IF;
    RETURN jsonb_build_object(
        'agent', p_name, 'role', role_name, 'max_rows', p_max_rows, 'allow_ddl', p_allow_ddl,
        'requires_approval', p_requires_approval, 'enforced_by', enforced,
        'takes_effect', 'on the next connection of that role; existing connections are not behind the gate');
END $$;
REVOKE EXECUTE ON FUNCTION agent_gate.register_agent(text, regrole, text, integer, boolean, boolean) FROM PUBLIC;

-- 8. approve(): an approver records consent for one proposal. It runs nothing.
--    SECURITY DEFINER so it can read the record and write approvals; the real
--    caller is session_user (the console logs in as an approver role, no SET ROLE).
CREATE FUNCTION agent_gate.approve(p_proposal bigint) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, agent_gate_internal, pg_temp AS $$
DECLARE
    v_approver name := session_user;
    v_agent    text;
    v_role     name;
    v_ok       boolean;
    v_req      boolean;
    v_kept     boolean;
BEGIN
    IF NOT pg_has_role(v_approver, 'agent_gate_approver', 'USAGE') THEN
        RAISE EXCEPTION 'pg_agent_gate: % is not a member of agent_gate_approver', v_approver
            USING HINT = 'Only an approver can approve a proposal.';
    END IF;
    SELECT p.agent, p.ok, a.role, a.requires_approval,
           EXISTS (SELECT 1 FROM agent_gate_internal.executions e
                   WHERE e.proposal = p.id AND e.mode = 'commit' AND e.outcome = 'kept')
      INTO v_agent, v_ok, v_role, v_req, v_kept
      FROM agent_gate_internal.proposals p
      JOIN agent_gate_internal.agents a ON a.name = p.agent
     WHERE p.id = p_proposal;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'pg_agent_gate: no proposal %, or its agent is no longer registered', p_proposal;
    END IF;
    IF NOT v_req THEN
        RAISE EXCEPTION 'pg_agent_gate: proposal % belongs to an agent that does not require approval', p_proposal;
    END IF;
    IF NOT v_ok THEN
        RAISE EXCEPTION 'pg_agent_gate: proposal % did not pass propose; there is nothing to approve', p_proposal;
    END IF;
    IF v_kept THEN
        RAISE EXCEPTION 'pg_agent_gate: proposal % was already committed', p_proposal;
    END IF;
    IF v_approver = v_role THEN
        RAISE EXCEPTION 'pg_agent_gate: an agent cannot approve its own proposal';
    END IF;
    INSERT INTO agent_gate_internal.approvals (proposal, approver)
    VALUES (p_proposal, v_approver)
    ON CONFLICT (proposal) DO NOTHING;
    RETURN jsonb_build_object('proposal', p_proposal, 'approved_by', v_approver,
        'effect', 'the owning agent can now commit this proposal; the guards still run at commit');
END $$;
REVOKE EXECUTE ON FUNCTION agent_gate.approve(bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION agent_gate.approve(bigint) TO agent_gate_approver;

-- 9. The approvals record survives pg_dump, like the rest of the record.
SELECT pg_catalog.pg_extension_config_dump('agent_gate_internal.approvals', '');
