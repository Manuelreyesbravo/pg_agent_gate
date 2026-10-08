-- 0.2.8 -> 0.2.9
--
-- Every function of the gate names pg_temp last in its search_path.
--
-- They all said `search_path = pg_catalog, agent_gate_internal` (or just pg_catalog), and
-- PostgreSQL searches an unnamed pg_temp FIRST for relations -- even before an explicitly
-- listed pg_catalog. _unsafe_amplifier runs in the agent's session, called by propose, and
-- read pg_constraint, pg_rewrite, pg_trigger, pg_proc and pg_inherits without a schema. An
-- allow_ddl agent may create temporary tables. Measured in tests/pg_temp.sh against 0.2.8:
--
--   * with an empty pg_temp.pg_constraint, no_amplification passed a delete whose foreign
--     key cascades: it was kept, and the cascade deleted, as the table owner, a row of a
--     table the agent holds no grant on;
--   * with an empty pg_temp.pg_rewrite, a delete under a DO ALSO rule was kept, and the
--     rule wrote, with its owner's rights, where the agent cannot;
--   * with pg_living_assertions 0.5.4, a temporary table named like the one a bound
--     assertion reads made the assertion hold, and an overdraft it forbids was kept.
--
-- _unsafe_amplifier now also names its catalogs by schema, and _run_assertion answers
-- `erroring` -- which stops the commit -- when pg_living_assertions is older than 0.5.5,
-- the first release that runs a check with pg_temp last. The other thirteen functions keep
-- their bodies; only their path changes. A fresh install and an upgraded one stay identical
-- (tests/upgrade.sh compares them).

CREATE OR REPLACE FUNCTION agent_gate_internal._unsafe_amplifier(p_target oid, p_allowed bigint[])
RETURNS text LANGUAGE sql STABLE SET search_path = pg_catalog, agent_gate_internal, pg_temp AS $$
    WITH RECURSIVE d(oid) AS (
        SELECT p_target
        UNION
        SELECT i.inhrelid FROM pg_catalog.pg_inherits i JOIN d ON i.inhparent = d.oid
    )
    SELECT label FROM (
        SELECT 'cascading foreign key '||co.conname AS label
          FROM pg_catalog.pg_constraint co JOIN d ON d.oid = co.confrelid
         WHERE co.contype = 'f' AND (co.confdeltype IN ('c','n','d') OR co.confupdtype IN ('c','n','d'))
        UNION ALL
        SELECT 'trigger '||tg.tgname
          FROM pg_catalog.pg_trigger tg JOIN d ON d.oid = tg.tgrelid
          JOIN pg_catalog.pg_proc p ON p.oid = tg.tgfoid
         WHERE NOT tg.tgisinternal
           AND (p_target::bigint <> ALL (coalesce(p_allowed, '{}'::bigint[])) OR p.prosecdef)
        UNION ALL
        SELECT 'rule '||rw.rulename
          FROM pg_catalog.pg_rewrite rw JOIN d ON d.oid = rw.ev_class
         WHERE rw.rulename <> '_RETURN'
    ) s LIMIT 1
$$;

CREATE OR REPLACE FUNCTION agent_gate_internal._run_assertion(p_name text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, agent_gate_internal, pg_temp AS $$
DECLARE
    st text;
    de text;
    la text;
    too_old boolean;
BEGIN
    IF NOT agent_gate._checking() THEN
        RAISE EXCEPTION 'pg_agent_gate: assertions are run by the gate, after a change'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF to_regnamespace('living_assertions') IS NULL THEN
        RETURN jsonb_build_object('assertion', p_name, 'state', 'erroring', 'detail',
            'pg_living_assertions is not installed: a bound assertion nobody can check is not one that passed');
    END IF;
    -- Before 0.5.5, pg_living_assertions applied an assertion's recorded search_path without
    -- naming pg_temp, so a temporary table of the session running the check -- here the
    -- agent's -- stood in for the table it reads, and an overdraft was kept under an
    -- assertion that forbade it (tests/pg_temp.sh). A check the agent can answer for is not
    -- one that passed. A version that does not parse is treated the same way.
    BEGIN
        SELECT extversion, string_to_array(extversion, '.')::int[] < '{0,5,5}'
          INTO la, too_old
          FROM pg_catalog.pg_extension WHERE extname = 'pg_living_assertions';
    EXCEPTION WHEN OTHERS THEN
        too_old := true;
    END;
    IF too_old IS NOT FALSE THEN
        RETURN jsonb_build_object('assertion', p_name, 'state', 'erroring', 'detail',
            format('pg_living_assertions %s predates 0.5.5: a temporary table of the agent could answer '
                   'for the table the assertion reads. Upgrade it: ALTER EXTENSION pg_living_assertions UPDATE',
                   coalesce(la, '?')));
    END IF;
    BEGIN
        EXECUTE 'SELECT state, detail FROM living_assertions.run($1)' INTO st, de USING p_name;
    EXCEPTION WHEN OTHERS THEN
        RETURN jsonb_build_object('assertion', p_name, 'state', 'erroring', 'detail', SQLERRM);
    END;
    RETURN jsonb_build_object('assertion', p_name, 'state', st, 'detail', de);
END $$;

-- Two functions whose bodies an older upgrade carried without the comments a fresh install has.
-- Same code; recreated so that an upgraded database is defined exactly as a fresh one, which
-- tests/upgrade.sh now compares function by function, body and search_path included.
CREATE OR REPLACE FUNCTION agent_gate.allow_write(p_agent text, p_relation regclass, p_note text DEFAULT NULL)
RETURNS jsonb LANGUAGE plpgsql SET search_path = pg_catalog, agent_gate_internal, pg_temp AS $$
DECLARE
    still text;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM agent_gate_internal.agents WHERE name = p_agent) THEN
        RAISE EXCEPTION 'pg_agent_gate: no agent named %', p_agent;
    END IF;
    INSERT INTO agent_gate_internal.allowlist (agent, relid, note)
    VALUES (p_agent, p_relation::oid, p_note)
    ON CONFLICT (agent, relid) DO UPDATE SET note = EXCLUDED.note;
    -- With this table allowed, is anything on it STILL unsafe? If so, allow_write did not help.
    still := agent_gate_internal._unsafe_amplifier(p_relation::oid, ARRAY[p_relation::oid]::bigint[]);
    RETURN jsonb_build_object('agent', p_agent, 'relation', p_relation::text, 'note', p_note,
        'still_refused', still,
        'effect', CASE WHEN still IS NULL
            THEN 'this agent may now propose writes to this table; the commit backstop still counts every row its trigger moves against max_rows'
            ELSE 'recorded, but writes to this table are STILL refused: '||still||' cannot be allow-listed -- remove it or restructure the write' END);
END $$;

CREATE OR REPLACE FUNCTION agent_gate_internal._load_proposal(p_id bigint, p_lock boolean DEFAULT false)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, agent_gate_internal, pg_temp AS $$
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

-- The rest keep their bodies; only their path gains pg_temp at the end.
ALTER FUNCTION agent_gate.disallow_write(text,regclass) SET search_path = pg_catalog, agent_gate_internal, pg_temp;
ALTER FUNCTION agent_gate.bind_assertion(text,text) SET search_path = pg_catalog, agent_gate_internal, pg_temp;
ALTER FUNCTION agent_gate.register_agent(text,regrole,text,integer,boolean) SET search_path = pg_catalog, agent_gate_internal, pg_temp;
ALTER FUNCTION agent_gate.unbind_assertion(text,text) SET search_path = pg_catalog, agent_gate_internal, pg_temp;
ALTER FUNCTION agent_gate.unregister_agent(text) SET search_path = pg_catalog, agent_gate_internal, pg_temp;
ALTER FUNCTION agent_gate_internal._acts(text,integer) SET search_path = pg_catalog, agent_gate_internal, pg_temp;
ALTER FUNCTION agent_gate_internal._agent(text) SET search_path = pg_catalog, agent_gate_internal, pg_temp;
ALTER FUNCTION agent_gate_internal._append_only() SET search_path = pg_catalog, pg_temp;
ALTER FUNCTION agent_gate_internal._only_the_gate() SET search_path = pg_catalog, pg_temp;
ALTER FUNCTION agent_gate_internal._record_execution(bigint,text,text,text,bigint,integer,boolean,jsonb,jsonb,double precision) SET search_path = pg_catalog, agent_gate_internal, pg_temp;
ALTER FUNCTION agent_gate_internal._record_proposal(text,text,text,text,text[],text,boolean,jsonb,double precision) SET search_path = pg_catalog, agent_gate_internal, pg_temp;
