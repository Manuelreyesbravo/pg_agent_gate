-- 0.2.13 -> 0.2.14
--
-- The rest of the third external audit (of 0.2.8), measured on 0.2.13 first (tests/audit4.sh: every
-- tooth red there with its control green). What lives in the library is in CHANGELOG.md; what lives
-- in the catalog is here:
--
--   * proposals.settings: the session settings that decide how a statement reads its literals and
--     writes its values, recorded at propose; _load_proposal names the ones that changed since, and
--     dry_run and commit refuse (GATE-09: dry_run showed March 4 and commit kept April 3).
--   * _load_proposal says whether a proposal predates the agent's current registration, and _acts
--     shows only the current one's (GATE-13: a reused name let a new role commit the old one's).
--
-- A proposal made before this upgrade has no recorded settings and is not compared; it expires with
-- agent_gate.proposal_ttl_seconds like any other.

ALTER TABLE agent_gate_internal.proposals ADD COLUMN settings jsonb;

CREATE OR REPLACE FUNCTION agent_gate_internal._session_settings() RETURNS jsonb
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT jsonb_build_object(
               'DateStyle', current_setting('DateStyle'),
               'IntervalStyle', current_setting('IntervalStyle'),
               'TimeZone', current_setting('TimeZone'),
               'standard_conforming_strings', current_setting('standard_conforming_strings'),
               'extra_float_digits', current_setting('extra_float_digits'),
               'bytea_output', current_setting('bytea_output'))
$$;
CREATE OR REPLACE FUNCTION agent_gate_internal._record_proposal(
    p_agent text, p_role text, p_intent text, p_sql text, p_params text[],
    p_kind text, p_ok boolean, p_checks jsonb, p_estimated double precision)
RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, agent_gate_internal, pg_temp AS $$
DECLARE
    new_id bigint;
BEGIN
    PERFORM agent_gate_internal._only_the_gate();
    -- The settings are read here, in the agent's own session: this function is SECURITY DEFINER,
    -- which changes the role and not the session's settings.
    INSERT INTO agent_gate_internal.proposals
        (agent, role, backend_pid, intent, sql, params, kind, ok, checks, estimated_rows, settings)
    VALUES (p_agent, p_role, pg_backend_pid(), p_intent, p_sql, p_params, p_kind, p_ok, p_checks, p_estimated,
            agent_gate_internal._session_settings())
    RETURNING id INTO new_id;
    RETURN new_id;
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
                                          AND e.outcome = 'kept'),
                   -- Made under an earlier registration of the same name (0.2.14): a name that
                   -- was unregistered and given to another role is not the same principal.
                   'predates_agent', p.proposed_at < (SELECT a.registered_at FROM agent_gate_internal.agents a
                                                       WHERE a.name = p.agent),
                   -- The settings that changed since it was verified, by name (0.2.14).
                   'settings_changed', (SELECT string_agg(format('%s (%s then, %s now)', k, p.settings ->> k, n.v), ', ' ORDER BY k)
                                          FROM jsonb_each_text(agent_gate_internal._session_settings()) AS n(k, v)
                                         WHERE p.settings IS NOT NULL AND p.settings ->> k IS DISTINCT FROM n.v))
          FROM agent_gate_internal.proposals p
         WHERE p.id = p_id);
END $$;
CREATE OR REPLACE FUNCTION agent_gate_internal._acts(p_agent text, p_limit integer) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, agent_gate_internal, pg_temp AS $$
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
                   -- Only this registration's acts (0.2.14): a reused name does not inherit them.
                   AND p.proposed_at >= (SELECT a.registered_at FROM agent_gate_internal.agents a
                                          WHERE a.name = p_agent)
                 ORDER BY p.id DESC
                 LIMIT greatest(least(p_limit, 500), 1)) recent), '[]');
END $$;
