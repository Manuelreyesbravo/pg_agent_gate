/**
 * Does a real MCP client operate the gate through gated-mcp -- a client nobody
 * here wrote, speaking the protocol its own way?
 *
 *   node test/clients.mjs 2026   @modelcontextprotocol/client 2.0.0, pinned to 2026-07-28
 *   node test/clients.mjs 2025   @modelcontextprotocol/sdk 1.30.0, the 2025-11-25 handshake
 *
 * Pinned and not `auto` on purpose: `auto` falls back to the 2025 handshake on
 * anything it does not recognise, so a server that got 2026-07-28 wrong would
 * still pass. A pin fails loudly.
 *
 * Needs gated-mcp running AS AN AGENT ROLE (GATED_MCP_URL) and a superuser
 * connection to the same database (GATE_SUPERUSER_URL): what changed is checked
 * from OUTSIDE the gate, not from what the gate says it did. The database holds
 * customers(id int primary key, plan text not null) with rows (1, 'free') and
 * (2, 'pro'), SELECT and UPDATE granted to the agent role.
 *
 * One `ok` / `FAIL` line per step.
 */
import postgres from "postgres";

const era = process.argv[2];
const url = new URL(process.env.GATED_MCP_URL ?? "http://127.0.0.1:7878/mcp");
if (!process.env.GATE_SUPERUSER_URL) {
  console.error("GATE_SUPERUSER_URL is required: what changed is checked from outside the gate");
  process.exit(2);
}
const su = postgres(process.env.GATE_SUPERUSER_URL, { max: 1, onnotice: () => {} });

let failures = 0;
function step(what, ok, detail) {
  console.log(`  ${ok ? "ok  " : "FAIL"} ${what}`);
  if (!ok) {
    failures++;
    // One line: a harness reads the indented line after a FAIL, and a multi-line
    // error (a zod report is several) would arrive cut at its first line.
    if (detail !== undefined) {
      const text = typeof detail === "string" ? detail : JSON.stringify(detail);
      console.log(`       ${text.replace(/\s+/g, " ").slice(0, 900)}`);
    }
  }
}

async function connect(errors) {
  if (era === "2026") {
    const { Client, StreamableHTTPClientTransport } = await import("@modelcontextprotocol/client");
    const client = new Client(
      { name: "gated-mcp-test", version: "0.1.0" },
      { versionNegotiation: { mode: { pin: "2026-07-28" } } },
    );
    const transport = new StreamableHTTPClientTransport(url);
    client.onerror = (e) => errors.push(String(e?.message ?? e));
    await client.connect(transport);
    return client;
  }
  if (era === "2025") {
    const { Client } = await import("@modelcontextprotocol/sdk/client/index.js");
    const { StreamableHTTPClientTransport } = await import("@modelcontextprotocol/sdk/client/streamableHttp.js");
    const client = new Client({ name: "gated-mcp-test", version: "0.1.0" });
    const transport = new StreamableHTTPClientTransport(url);
    client.onerror = (e) => errors.push(String(e?.message ?? e));
    await client.connect(transport);
    return client;
  }
  console.error("usage: node test/clients.mjs 2026|2025");
  process.exit(2);
}

// What a verb returned, whichever way the client exposes it.
function body(result) {
  if (result?.structuredContent && typeof result.structuredContent === "object") return result.structuredContent;
  const text = result?.content?.find?.((c) => c.type === "text")?.text;
  try {
    return JSON.parse(text);
  } catch {
    return { _text: text };
  }
}

async function main() {
  const intent = `upgrade customer 1 through the ${era} client`;
  // Setup from outside the gate, so every run starts from the same world.
  await su`update customers set plan = 'free' where id = 1`;

  const errors = [];
  let client;
  try {
    client = await connect(errors);
    step(`the ${era} client connects`, true);
  } catch (e) {
    step(`the ${era} client connects`, false, String(e?.message ?? e));
    return;
  }

  const tools = await client.listTools().catch((e) => ({ error: String(e?.message ?? e) }));
  const names = (tools.tools ?? []).map((t) => t.name).sort();
  step("it lists exactly the six verbs", JSON.stringify(names) === JSON.stringify(["acts", "commit", "discover", "dry_run", "propose", "whoami"]), tools.error ?? names);

  const call = (name, args = {}) => client.callTool({ name, arguments: args });

  const who = body(await call("whoami"));
  step("whoami says the connection is an agent behind an enforced gate", who?.is_agent === true && who?.enforced === true, who);

  const disc = await call("discover", { filter: "customers" });
  step("discover shows the table the agent was granted", JSON.stringify(body(disc)).includes("customers"), body(disc));

  const prop = body(await call("propose", { sql: "update customers set plan = 'pro' where id = 1", intent }));
  step("a correct proposal verifies", prop?.ok === true && Number.isInteger(prop?.proposal), prop);

  const dry = body(await call("dry_run", { proposal: prop?.proposal }));
  step("dry_run shows the effect and keeps nothing", dry?.outcome === "rolled_back" && dry?.rows_affected === 1, dry);

  const kept = body(await call("commit", { proposal: prop?.proposal }));
  step("commit keeps it", kept?.outcome === "kept", kept);

  const wrong = body(await call("propose", { sql: "update customers set plann = 'pro' where id = 2", intent: "a column that does not exist" }));
  step("a false proposal is refused by the gate, through the client", wrong?.ok === false, wrong);

  const refused = body(await call("commit", { proposal: wrong?.proposal }));
  step("and committing it is refused", refused?.outcome === "refused", refused);

  const acts = await call("acts", { max_acts: 50 });
  step("acts shows what this agent did", JSON.stringify(body(acts)).includes(intent), body(acts));

  let notAVerb;
  try {
    const r = await call("sql", { query: "delete from customers" });
    notAVerb = r?.isError === true;
  } catch {
    notAVerb = true;
  }
  step("a tool that is not a verb does not exist", notAVerb);

  const world = await su`select id, plan from customers order by id`;
  step(
    "from outside the gate, only the committed change happened",
    JSON.stringify(world.map((r) => [r.id, r.plan])) === JSON.stringify([[1, "pro"], [2, "pro"]]),
    world,
  );

  step("the client and its transport reported no errors", errors.length === 0, errors);

  await client.close().catch(() => {});
}

try {
  await main();
} catch (e) {
  step("the run finished without an unexpected exception", false, String(e?.stack ?? e));
} finally {
  await su.end({ timeout: 2 });
}
process.exit(failures ? 1 : 0);
