-- 0.2.4 -> 0.2.5
--
-- One catalog change: a seventh verb.
--
-- propose_and_commit(sql, intent[, params]) is propose followed by commit in ONE call, so in one
-- transaction. The proposal and its execution are written by the same commit, and with
-- attempt_durability = durable an act pays one WAL flush instead of two -- measured on 2026-10-08,
-- propose + commit pay exactly 2.00 fsyncs per act, 5.1 ms each on a btrfs NVMe, a floor of
-- 10.2 ms before the gate does any work. Its checks are commit's own: the statement is verified
-- at propose and again at execution. What it gives up is the dry_run in between.
--
-- The signature is the one pgrx generates for a fresh 0.2.5 install, so an upgraded database and
-- a new one carry the same function (tests/upgrade.sh compares them). The hooks recognise a verb
-- by schema and name, and the library that knows this name is the 0.2.5 one this script ships with.

CREATE FUNCTION agent_gate."propose_and_commit"(
	"sql" TEXT,
	"intent" TEXT,
	"params" TEXT[] DEFAULT NULL
) RETURNS jsonb
LANGUAGE c
AS 'MODULE_PATHNAME', 'propose_and_commit_wrapper';
