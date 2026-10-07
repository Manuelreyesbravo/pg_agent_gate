#!/usr/bin/env bash
# What the pipe costs: the same data through the native path and forced through JSON.
#
# The gate's guarantee is the same whether an agent reaches it over PostgreSQL's own
# protocol or through an MCP server -- a proposal is verified either way. What changes is
# the pipe. MCP is JSON-RPC: the result is JSON, and JSON has no 64-bit integer, no exact
# decimal and no binary. The native path is the database's own wire protocol: typed and
# binary. This measures the difference on a REPLICA of the conditions we run -- rich types
# and volume -- so anyone can run it; none of it is real data.
#
#   make transfer PG_CONFIG=/path/to/pg_config     # needs node on PATH for the JSON proof
#
# The comparison is deliberately FAIR to MCP: binary is counted as base64 (+33%), what a
# JSON protocol actually does, not as the hex that to_jsonb would use (+100%). Runs on the
# throwaway cluster of tests/cluster.sh (it builds the artifact if missing).
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
export PG_CONFIG=${PG_CONFIG:-pg_config}
export USER=${USER:-$(id -un)}
BIN=$("$PG_CONFIG" --bindir)
export PGHOST=$ROOT/.testcluster PGPORT=${GATE_PORT:-5499}
DB=gate_transfer
AGENT=etl_agent
ROWS=${ROWS:-5000}

command -v node >/dev/null || { echo "needs node on PATH for the JSON fidelity proof"; exit 2; }

MAJOR=$("$PG_CONFIG" --version | sed -E 's/^PostgreSQL ([0-9]+).*/\1/')
[ -f "target/release/pg_agent_gate-pg$MAJOR$("$PG_CONFIG" --pkglibdir)/pg_agent_gate.so" ] \
    || bash tests/cluster.sh package >/dev/null 2>&1 \
    || { echo "could not build the artifact: run tests/cluster.sh package"; exit 1; }
bash tests/cluster.sh init >/dev/null && bash tests/cluster.sh start >/dev/null || exit 1
trap 'bash tests/cluster.sh stop fast >/dev/null 2>&1 || true' EXIT

q()    { "$BIN/psql" -X -q -d "$DB" -tA -c "$1" 2>&1; }
agent(){ "$BIN/psql" -X -q -U "$AGENT" -d "$DB" -tA -c "$1" 2>&1; }

say()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
note() { printf '  \033[2m%s\033[0m\n' "$*"; }
row()  { printf '  %-34s %s\n' "$1" "$2"; }

BIGID=9007199254740993                       # 2^53 + 1: the first integer JSON cannot hold
AMOUNT=12345678901234567890.123456789012     # 20 digits, 12 decimals: no IEEE double holds this

"$BIN/psql" -X -q -d postgres -tA -c "create role $AGENT login" >/dev/null 2>&1
"$BIN/psql" -X -q -d postgres -tA -c "create database $DB owner $AGENT" >/dev/null 2>&1
q "create extension if not exists pg_agent_gate" >/dev/null
# A replica of the conditions we run: a 64-bit id past JSON's reach, exact money, a binary
# blob, an array and a nested document -- the types a real workload carries.
q "
  drop table if exists events;
  create table events (
    id        bigint primary key,
    amount    numeric(40,12) not null,
    blob      bytea not null,
    tags      text[] not null,
    doc       jsonb not null,
    ts        timestamptz not null default now()
  );
  insert into events
    select $BIGID + g,
           $AMOUNT,
           decode(repeat(md5(g::text), 16), 'hex'),          -- 256 bytes of binary per row
           array['tenant:'||(g%4), 'kind:event', 'v:'||g],
           jsonb_build_object('seq', g, 'nested', jsonb_build_object('a', g, 'b', g*2)),
           now() + (g || ' seconds')::interval
    from generate_series(0, $ROWS - 1) g;
  grant select, insert, update, delete on events to $AGENT;" >/dev/null


say "A REPLICA OF THE CONDITIONS WE RUN -- rich types and volume, so you can run it too"
note "$ROWS rows: a 64-bit id past 2^53, numeric(40,12), 256 bytes of binary each, an array, nested jsonb"


say "ONE VALUE, TYPED vs FORCED THROUGH JSON  (the pipe, not the gate)"
note "the same id and amount, read with their types -- and parsed the way a JSON-RPC client must"
row "native, typed  id (int8):"    "$(q "select id from events where id = $BIGID")  exact"
row "native, typed  amount:"       "$(q "select amount from events where id = $BIGID")  exact"
JSONV=$(printf '{"id": %s, "amount": %s}' "$BIGID" "$AMOUNT")
PARSED=$(printf '%s' "$JSONV" | node -e 'let s="";process.stdin.on("data",d=>s+=d);process.stdin.on("end",()=>{const o=JSON.parse(s);console.log(o.id+"\t"+o.amount)})')
row "through JSON    id:"           "$(echo "$PARSED" | cut -f1)  <- CORRUPTED (JSON number is an IEEE double)"
row "through JSON    amount:"       "$(echo "$PARSED" | cut -f2)  <- lost; it must travel as a string to survive"


say "ONE BLOB, BINARY vs BASE64  (what any JSON protocol must do to bytes)"
RAW=$(q "select octet_length(blob) from events where id = $BIGID")
B64=$(q "select octet_length(encode(blob, 'base64')) from events where id = $BIGID")
row "native, binary:"  "$RAW bytes, raw"
row "through JSON (base64):"  "$B64 bytes of text  (+$(( (B64 - RAW) * 100 / RAW ))%, and no longer bytes)"


say "THE WHOLE SET -- total bytes to move $ROWS rows"
note "same rows either way; JSON counts binary as base64 (fair), numbers and keys as text"
NATIVE=$(q "select sum(pg_column_size(e))::bigint from events e")
JSONSET=$(q "select sum(octet_length((to_jsonb(e) - 'blob' || jsonb_build_object('blob', encode(e.blob, 'base64')))::text))::bigint from events e")
row "native representation:"    "$(q "select pg_size_pretty($NATIVE::bigint)")"
row "JSON (binary as base64):"  "$(q "select pg_size_pretty($JSONSET::bigint)")  (+$(( (JSONSET - NATIVE) * 100 / NATIVE ))%)"


say "SAME GATE, EITHER PIPE -- the fatter pipe changes nothing about the guarantee"
q "select agent_gate.register_agent('etl', '$AGENT', 'moves events', p_max_rows => 100000)" >/dev/null
ID=$(agent "select agent_gate.propose('update events set amount = amount + 1 where id = $BIGID', 'adjust one event')" | sed -nE 's/.*"proposal": ?([0-9]+).*/\1/p' | head -1)
row "propose + commit over native:"  "$(agent "select agent_gate.commit($ID)" | sed -nE 's/.*"outcome": ?"([a-z]+)".*/\1/p' | head -1)  -- verified by PostgreSQL, same as through MCP"
echo
