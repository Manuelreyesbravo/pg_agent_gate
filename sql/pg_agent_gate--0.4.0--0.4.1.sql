/* pg_agent_gate 0.4.0 -> 0.4.1 : an agent role has no members.
 *
 * The gate knows a session belongs to an agent by agent_gate.agent, which register_agent sets
 * on the ROLE and PostgreSQL applies when that role CONNECTS. A session of another role that
 * SET ROLEs into the agent's (or set_config('role', ...)) gets the agent's privileges without
 * the setting: it is not behind the gate. Measured on 0.4.0: a broker role granted the agent
 * role ran `SET ROLE seat; DELETE FROM t` -- 20 rows, max_rows 2, nothing proposed, nothing
 * recorded. Only a member of a role (or a superuser, who is outside the gate by design) can
 * SET ROLE into it, so the rule that closes every such path is: an agent role has no members.
 * register_agent refuses a role that has any, and the library refuses any statement that
 * leaves a registered agent role with one (GRANT, CREATE ROLE ... IN ROLE, ALTER GROUP ...).
 *
 * This file is the upgrade path for existing installs. The same objects go into
 * the base schema (src/schema.rs extension_sql) for fresh installs.
 */

-- 1. Every membership in a registered agent role, as 'agent_role <- member' (empty when none).
--    The library reads it before and after every statement that can change role membership,
--    and refuses the statement if it ADDED one. Comparing, not just checking, is deliberate: an
--    installation upgraded with memberships already in place (warned below) can still administer
--    its roles while it revokes them; it only cannot add new ones.
--    Callable by every role, like the rest of the record's functions -- the library calls it from
--    the session of whoever runs CREATE or ALTER ROLE -- and answering only the gate itself.
CREATE FUNCTION agent_gate_internal._agent_memberships() RETURNS text[]
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, agent_gate_internal, pg_temp AS $$
BEGIN
    PERFORM agent_gate_internal._only_the_gate();
    RETURN (SELECT coalesce(array_agg(format('%I <- %I', a.role, r.rolname) ORDER BY a.role, r.rolname),
                            '{}')
              FROM agent_gate_internal.agents a
              JOIN pg_catalog.pg_roles ar ON ar.rolname = a.role
              JOIN pg_catalog.pg_auth_members am ON am.roleid = ar.oid
              JOIN pg_catalog.pg_roles r ON r.oid = am.member);
END $$;

-- 2. register_agent refuses a role that has members. The rest of it is unchanged from 0.4.0.
CREATE OR REPLACE FUNCTION agent_gate.register_agent(
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
    members   text;
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
    -- And nothing can SET ROLE INTO it (0.4.1): a member of the agent role would have its
    -- privileges in a session the gate does not watch.
    SELECT string_agg(format('%I', r.rolname), ', ' ORDER BY r.rolname) INTO members
      FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.member
     WHERE m.roleid = p_role;
    IF members IS NOT NULL THEN
        RAISE EXCEPTION 'pg_agent_gate: % has members (%), and a member can SET ROLE into it in a session the gate does not watch', role_name, members
            USING HINT = 'An agent role has no members: each agent (or each seat of a broker) logs in AS its own role. REVOKE those memberships first.';
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

-- 3. An installation that already has an agent role with members is not broken by the upgrade:
--    it is told, by name, what to revoke. The library refuses any NEW membership from now on.
DO $$
DECLARE
    found text[] := (SELECT coalesce(array_agg(format('%I <- %I', a.role, r.rolname) ORDER BY a.role, r.rolname), '{}')
                       FROM agent_gate_internal.agents a
                       JOIN pg_catalog.pg_roles ar ON ar.rolname = a.role
                       JOIN pg_catalog.pg_auth_members am ON am.roleid = ar.oid
                       JOIN pg_catalog.pg_roles r ON r.oid = am.member);
BEGIN
    IF cardinality(found) > 0 THEN
        RAISE WARNING 'pg_agent_gate 0.4.1: these agent roles have members, and a member can SET ROLE into them outside the gate: %',
            array_to_string(found, ', ')
            USING HINT = 'REVOKE those memberships; each agent logs in as its own role. New ones are refused from now on.';
    END IF;
END $$;
