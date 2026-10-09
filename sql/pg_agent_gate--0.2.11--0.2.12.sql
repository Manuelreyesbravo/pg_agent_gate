-- 0.2.11 -> 0.2.12
--
-- The third external audit (of 0.2.8), measured again on 0.2.11 and closed (tests/audit3.sh,
-- tests/isolation.sh, tests/session_preload.sh: every tooth red on 0.2.11 with its control green).
-- What lives in the library is described in CHANGELOG.md; what lives in the catalog is here:
--
--   * one kept commit per proposal is now a constraint (GATE-04): a unique partial index on
--     executions(proposal) where mode = 'commit' and outcome = 'kept'. Under REPEATABLE READ four
--     sessions each kept the same change, because _load_proposal's read used an old snapshot.
--   * register_agent refuses a role with REPLICATION or BYPASSRLS, and one that is a member --
--     directly or through other roles -- of a superuser or of such a role (GATE-10).
--   * the allow-list is dumped with the database (GATE-14).

-- An installation with two kept commits of one proposal (only possible through GATE-04) cannot take
-- the index, and the record is append-only: say which, rather than fail with a bare unique violation.
DO $$
DECLARE
    dup text;
BEGIN
    SELECT string_agg(proposal::text, ', ') INTO dup
      FROM (SELECT proposal FROM agent_gate_internal.executions
             WHERE mode = 'commit' AND outcome = 'kept' GROUP BY proposal HAVING count(*) > 1) d;
    IF dup IS NOT NULL THEN
        RAISE EXCEPTION 'pg_agent_gate: proposals committed more than once already: %', dup
            USING HINT = 'Those changes were applied more than once (GATE-04). Review them; the upgrade needs the record to hold one kept commit per proposal.';
    END IF;
END $$;

CREATE UNIQUE INDEX executions_one_kept_commit
    ON agent_gate_internal.executions (proposal) WHERE mode = 'commit' AND outcome = 'kept';

SELECT pg_catalog.pg_extension_config_dump('agent_gate_internal.allowlist', '');

CREATE OR REPLACE FUNCTION agent_gate.register_agent(
    p_name text, p_role regrole, p_description text,
    p_max_rows integer DEFAULT 1000, p_allow_ddl boolean DEFAULT false)
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
    -- Nor a role that reaches past the gate another way (0.2.12; external audit of 0.2.8, GATE-10):
    -- REPLICATION streams the WAL -- every table, in plain text -- over a protocol no hook sees;
    -- BYPASSRLS ignores the policies the gate's tenant isolation stands on; and membership, direct
    -- or through other roles, in a superuser or in such a role lets SET ROLE take the session out.
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
