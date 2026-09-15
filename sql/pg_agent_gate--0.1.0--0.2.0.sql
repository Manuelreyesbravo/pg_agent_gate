-- 0.1.0 -> 0.2.0
--
-- Two defects that live in this SQL and not in the library, so copying a new
-- .so does NOT apply them to a database where the extension already exists.
-- That is how it was found: with 0.2.0's library already loaded, the database
-- still had 0.1.0's schema -- no TRUNCATE triggers, and _load_proposal with one
-- argument while the library called the two-argument one. Every commit would
-- have died with 'function does not exist'.
--
-- 1. TRUNCATE FIRES NO FOR EACH ROW TRIGGER, so the whole record could be
--    emptied in one statement with nothing disabled and nothing said -- the
--    opposite of the deliberate act of administration the README describes.
-- 2. TWO CONCURRENT COMMITS OF THE SAME PROPOSAL BOTH RAN IT: 'committed' is
--    read from each transaction's own snapshot, where the other has not
--    committed yet. On a balance that is a double charge. The row is now locked
--    while a commit decides.

CREATE TRIGGER proposals_no_truncate BEFORE TRUNCATE ON agent_gate_internal.proposals
    FOR EACH STATEMENT EXECUTE FUNCTION agent_gate_internal._append_only();
CREATE TRIGGER executions_no_truncate BEFORE TRUNCATE ON agent_gate_internal.executions
    FOR EACH STATEMENT EXECUTE FUNCTION agent_gate_internal._append_only();

-- The old one-argument function is dropped rather than left alongside: the
-- library only ever calls one of the two shapes, and leaving a callable
-- unlocked path is how the defect would come back without anybody choosing it.
DROP FUNCTION IF EXISTS agent_gate_internal._load_proposal(bigint);

CREATE FUNCTION agent_gate_internal._load_proposal(p_id bigint, p_lock boolean DEFAULT false)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, agent_gate_internal AS $$
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
                                          AND e.outcome = 'kept'))
          FROM agent_gate_internal.proposals p
         WHERE p.id = p_id);
END $$;
