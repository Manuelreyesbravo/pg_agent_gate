-- 0.2.2 -> 0.2.3
--
-- A real schema change this time. The library (verify.rs, verbs.rs) adds two things that need no
-- catalog change -- the no_opaque_function propose check, and a commit-time row-count backstop
-- (pg_stat_xact_user_tables delta vs max_rows) -- and one that does: a per-agent allow-list, so a
-- table with a legitimate trigger (updated_at, audit) can be written without the amplification
-- refusal, while the backstop still counts every amplified row against max_rows.
--
-- What 0.2.3 refuses or bounds, over 0.2.2:
--  * no_opaque_function: a statement calling a USER function that is volatile or SECURITY DEFINER
--    is refused -- its body is not in the analyzed tree, so it may write uncounted rows or run as
--    its owner outside the agent's tenant. Built-ins and pure user functions pass.
--  * the backstop: triggers, cascades, rules and functions can move more rows than the top-level
--    count names; the transaction's tuple operations on user tables are measured and the kept set
--    aborts if they exceed max_rows. It over-counts (the safe side) and does not see TRUNCATE.
--  * allow_write(agent, relation): relaxes no_amplification for one table, not the limit.

CREATE TABLE agent_gate_internal.allowlist (
    agent      text NOT NULL REFERENCES agent_gate_internal.agents (name) ON DELETE CASCADE,
    relid      oid  NOT NULL,
    note       text,
    allowed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    allowed_by name NOT NULL DEFAULT session_user,
    PRIMARY KEY (agent, relid)
);

-- The single decision shared by propose (verify.rs) and discover, so they never disagree: the
-- first unsafe amplifier (cascade or rule -- never allow-listable in 0.2.3; a user trigger unless
-- the target is allowed AND its function is not SECURITY DEFINER) reachable from a write, over
-- inheritance children, or NULL. Created before allow_write, which calls it.
CREATE FUNCTION agent_gate_internal._unsafe_amplifier(p_target oid, p_allowed bigint[])
RETURNS text LANGUAGE sql STABLE SET search_path = pg_catalog, agent_gate_internal AS $$
    WITH RECURSIVE d(oid) AS (
        SELECT p_target
        UNION
        SELECT i.inhrelid FROM pg_inherits i JOIN d ON i.inhparent = d.oid
    )
    SELECT label FROM (
        SELECT 'cascading foreign key '||co.conname AS label
          FROM pg_constraint co JOIN d ON d.oid = co.confrelid
         WHERE co.contype = 'f' AND (co.confdeltype IN ('c','n','d') OR co.confupdtype IN ('c','n','d'))
        UNION ALL
        SELECT 'trigger '||tg.tgname
          FROM pg_trigger tg JOIN d ON d.oid = tg.tgrelid
          JOIN pg_proc p ON p.oid = tg.tgfoid
         WHERE NOT tg.tgisinternal
           AND (p_target::bigint <> ALL (coalesce(p_allowed, '{}'::bigint[])) OR p.prosecdef)
        UNION ALL
        SELECT 'rule '||rw.rulename
          FROM pg_rewrite rw JOIN d ON d.oid = rw.ev_class
         WHERE rw.rulename <> '_RETURN'
    ) s LIMIT 1
$$;

CREATE FUNCTION agent_gate.allow_write(p_agent text, p_relation regclass, p_note text DEFAULT NULL)
RETURNS jsonb LANGUAGE plpgsql SET search_path = pg_catalog, agent_gate_internal AS $$
DECLARE
    still text;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM agent_gate_internal.agents WHERE name = p_agent) THEN
        RAISE EXCEPTION 'pg_agent_gate: no agent named %', p_agent;
    END IF;
    INSERT INTO agent_gate_internal.allowlist (agent, relid, note)
    VALUES (p_agent, p_relation::oid, p_note)
    ON CONFLICT (agent, relid) DO UPDATE SET note = EXCLUDED.note;
    still := agent_gate_internal._unsafe_amplifier(p_relation::oid, ARRAY[p_relation::oid]::bigint[]);
    RETURN jsonb_build_object('agent', p_agent, 'relation', p_relation::text, 'note', p_note,
        'still_refused', still,
        'effect', CASE WHEN still IS NULL
            THEN 'this agent may now propose writes to this table; the commit backstop still counts every row its trigger moves against max_rows'
            ELSE 'recorded, but writes to this table are STILL refused: '||still||' cannot be allow-listed -- remove it or restructure the write' END);
END $$;

CREATE FUNCTION agent_gate.disallow_write(p_agent text, p_relation regclass) RETURNS boolean
LANGUAGE sql SET search_path = pg_catalog, agent_gate_internal AS $$
    WITH gone AS (DELETE FROM agent_gate_internal.allowlist
                   WHERE agent = p_agent AND relid = p_relation::oid RETURNING 1)
    SELECT EXISTS (SELECT 1 FROM gone);
$$;

REVOKE EXECUTE ON FUNCTION agent_gate.allow_write(text, regclass, text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION agent_gate.disallow_write(text, regclass) FROM PUBLIC;

-- _agent now also reports the allow-list (DISCOVER_SQL's third parameter and config() read it).
CREATE OR REPLACE FUNCTION agent_gate_internal._agent(p_name text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, agent_gate_internal AS $$
BEGIN
    PERFORM agent_gate_internal._only_the_gate();
    RETURN (
        SELECT jsonb_build_object(
                   'name', a.name, 'max_rows', a.max_rows, 'allow_ddl', a.allow_ddl,
                   'bindings', coalesce((SELECT jsonb_agg(b.assertion ORDER BY b.assertion)
                                           FROM agent_gate_internal.bindings b
                                          WHERE b.agent = a.name), '[]'),
                   'allowed_writes', coalesce((SELECT jsonb_agg(w.relid::bigint ORDER BY w.relid)
                                           FROM agent_gate_internal.allowlist w
                                          WHERE w.agent = a.name), '[]'))
          FROM agent_gate_internal.agents a
         WHERE a.name = p_name);
END $$;
