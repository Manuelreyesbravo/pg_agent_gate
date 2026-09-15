// node-pg against the session allowlist. Run by tests/drivers.sh, which sets up the
// database and passes DEPS, DB, ROLE, MINE, THEIRS, GATE_HOST and PGPORT.
//
// Every attack reads through the gate on the SAME client that tried to move the
// tenant, because that is the only place it can come out wrong. A refusal counts only
// when it is the gate's own: its message starts with "pg_agent_gate:". node-pg puts
// only the primary message in e.message (the detail lives in e.detail), so that prefix
// is what is matched, never a phrase from the detail.
import { createRequire } from "node:module";

const need = (key, fallback) => {
  const v = process.env[key];
  if (v) return v;
  if (fallback !== undefined) return fallback;
  throw new Error(`missing environment variable ${key}`);
};

const pg = createRequire(`${need("DEPS")}/package.json`)("pg");
const base = {
  host: need("GATE_HOST", "localhost"),
  port: Number(need("PGPORT", "5499")),
  database: need("DB"),
  user: need("ROLE"),
};
const MINE = need("MINE");
const THEIRS = need("THEIRS");
const READ_SQL = "select body from docs order by 1";
const GATE = "pg_agent_gate:";

const text = (v) => (typeof v === "string" ? v : JSON.stringify(v));
const first = (result) => Object.values(result.rows[0] ?? {})[0];

function check(kind, what, ok, got) {
  console.log(`  ${ok ? "ok  " : "FAIL"} [${kind}] ${what}`);
  if (!ok) console.log(`       got: ${String(got).replace(/\n/g, " ")}`);
}

async function withClient(extra, body) {
  const client = new pg.Client({ ...base, ...extra });
  try {
    await client.connect();
    return await body(client);
  } catch (e) {
    return `error: ${e.message}`;
  } finally {
    await client.end().catch(() => {});
  }
}

async function attempt(client, sql) {
  try {
    await client.query(sql);
    return "accepted";
  } catch (e) {
    return `error: ${e.message}`;
  }
}

// Propose the read and commit it on THIS client. Passing values makes node-pg use the
// extended protocol with bound parameters.
async function read(client) {
  try {
    const proposed = first(await client.query("select agent_gate.propose($1, $2)", [READ_SQL, "read the documents I may read"]));
    const id = proposed?.proposal;
    if (id === undefined) return `no proposal id in: ${text(proposed)}`;
    return text(first(await client.query("select agent_gate.commit($1)", [id])));
  } catch (e) {
    return `error: ${e.message}`;
  }
}

const ownOnly = (got) => got.includes(MINE) && !got.includes(THEIRS);
const refusedByGate = (got) => got.startsWith("error") && got.includes(GATE);

// ------------------------------------------------------------------ attacks --
let got = await withClient({ options: "-c app.tenant_id=2" }, read);
check("attack", "node-pg: options=-c app.tenant_id at connect does not move the tenant",
  !got.includes(THEIRS) && (got.includes(MINE) || refusedByGate(got)), got);

got = await withClient({}, async (c) => `${await attempt(c, "set app.tenant_id = '2'")} | ${await read(c)}`);
check("attack", "node-pg: SET through client.query does not move the tenant", ownOnly(got), got);

got = await withClient({}, async (c) => {
  await c.query("begin");
  const tried = await attempt(c, "set local app.tenant_id = '2'");
  if (tried.startsWith("error")) await c.query("rollback");
  const r = await read(c);
  if (!tried.startsWith("error")) await c.query("commit").catch(() => {});
  const ok = !r.includes(THEIRS) && (r.includes(MINE) || refusedByGate(tried));
  return `${ok ? "PASS " : ""}${tried} | ${r}`;
});
check("attack", "node-pg: SET LOCAL inside a transaction does not move the tenant", got.startsWith("PASS "), got);

// -------------------------------------------------------------------- legit --
got = await withClient({}, async (c) => text(first(await c.query("select agent_gate.whoami()"))));
check("legit", "node-pg: connects as the agent and whoami answers", got.includes('"is_agent":true'), got);

got = await withClient({}, read);
check("legit", "node-pg: propose and commit with bound parameters read its own tenant", ownOnly(got), got);

got = await withClient({}, async (c) => {
  await c.query("begin");
  const w = text(first(await c.query("select agent_gate.whoami()")));
  await c.query("commit");
  return w;
});
check("legit", "node-pg: begin and commit around a verb", got.includes('"is_agent":true'), got);

got = await withClient({ options: "-c statement_timeout=5000" }, async (c) => text(first(await c.query("show statement_timeout"))));
check("legit", "node-pg: a statement_timeout passed through options still applies", got === "5s", got);

got = await withClient({ application_name: "gate-drivers-node" }, async (c) => text(first(await c.query("show application_name"))));
check("legit", "node-pg: application_name is set", got === "gate-drivers-node", got);
