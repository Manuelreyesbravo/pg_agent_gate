/**
 * Resources and prompts through the official 2026-07-28 client -- and proof that
 * they add no power.
 *
 *   node test/resources.mjs
 *
 * gated-mcp exposes six tools and never more. Resources and prompts are other
 * ways to LOOK at what the verbs already give: every resource is read by calling
 * a verb as the agent role. Three cases here would break if a resource ever
 * grew a query of its own:
 *   * the catalog read as a resource is identical to the discover tool's answer;
 *   * a relation the agent was not granted answers -32602 (it does not exist for
 *     this agent), never its content;
 *   * reading resources and prompts leaves no new proposal in the record, checked
 *     from a superuser connection outside the gate.
 *
 * Needs GATED_MCP_URL (gated-mcp running as the agent role) and GATE_SUPERUSER_URL.
 * The database holds customers (granted) and secrets (not granted).
 * One `ok` / `FAIL` line per case.
 */
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import postgres from "postgres";

const url = new URL(process.env.GATED_MCP_URL ?? "http://127.0.0.1:7878/mcp");
if (!process.env.GATE_SUPERUSER_URL) {
  console.error("GATE_SUPERUSER_URL is required: what the reads did is checked from outside the gate");
  process.exit(2);
}
const su = postgres(process.env.GATE_SUPERUSER_URL, { max: 1, onnotice: () => {} });

let failures = 0;
function check(what, ok, detail) {
  console.log(`  ${ok ? "ok  " : "FAIL"} ${what}`);
  if (!ok) {
    failures++;
    if (detail !== undefined) {
      const text = typeof detail === "string" ? detail : JSON.stringify(detail);
      console.log(`       ${String(text).replace(/\s+/g, " ").slice(0, 900)}`);
    }
  }
}

const json = (contents) => {
  try {
    return JSON.parse(contents?.[0]?.text ?? "null");
  } catch {
    return null;
  }
};
const errorOf = async (promise) => {
  try {
    return { value: await promise };
  } catch (e) {
    return { code: e?.code, message: String(e?.message ?? e) };
  }
};
const proposals = async () => Number((await su`select count(*) as n from agent_gate_internal.proposals`)[0].n);

async function main() {
  const client = new Client(
    { name: "gated-mcp-resources-test", version: "0.1.0" },
    { versionNegotiation: { mode: { pin: "2026-07-28" } } },
  );
  await client.connect(new StreamableHTTPClientTransport(url));
  const before = await proposals();

  const caps = client.getServerCapabilities() ?? {};
  check("the server declares resources and prompts (and still tools)", !!caps.resources && !!caps.prompts && !!caps.tools, caps);

  const list = await errorOf(client.listResources());
  const uris = (list.value?.resources ?? []).map((r) => r.uri).sort();
  check("it lists the catalog, the identity and the history as resources",
    ["agent-gate://acts", "agent-gate://catalog", "agent-gate://whoami"].every((u) => uris.includes(u)), list.value ?? list);

  const templates = await errorOf(client.listResourceTemplates());
  check("it lists a template for one relation",
    (templates.value?.resourceTemplates ?? []).some((t) => t.uriTemplate === "agent-gate://relation/{schema}/{name}"), templates.value ?? templates);

  const catalog = await errorOf(client.readResource({ uri: "agent-gate://catalog" }));
  const tool = await client.callTool({ name: "discover", arguments: { max_objects: 500 } });
  const toolBody = tool.structuredContent ?? JSON.parse(tool.content?.[0]?.text ?? "null");
  check("NO POWER OF ITS OWN: the catalog as a resource is identical to the discover tool",
    catalog.value && JSON.stringify(json(catalog.value.contents)) === JSON.stringify(toolBody),
    { resource: json(catalog.value?.contents)?.fingerprint, tool: toolBody?.fingerprint, error: catalog.message });

  const who = await errorOf(client.readResource({ uri: "agent-gate://whoami" }));
  check("the identity resource says the connection is an agent behind the gate",
    json(who.value?.contents)?.is_agent === true && json(who.value?.contents)?.enforced === true, who.value ?? who);

  const rel = await errorOf(client.readResource({ uri: "agent-gate://relation/public/customers" }));
  check("a granted relation reads with its columns", JSON.stringify(json(rel.value?.contents) ?? "").includes("plan"), rel.value ?? rel);

  const secret = await errorOf(client.readResource({ uri: "agent-gate://relation/public/secrets" }));
  check("NO POWER OF ITS OWN: a relation without a GRANT answers -32602, not its content",
    secret.code === -32602 && !JSON.stringify(secret).includes("passphrase"), secret);

  const unknown = await errorOf(client.readResource({ uri: "agent-gate://nothing-here" }));
  check("an unknown resource answers -32602", unknown.code === -32602, unknown);

  const prompts = await errorOf(client.listPrompts());
  const names = (prompts.value?.prompts ?? []).map((p) => p.name).sort();
  check("it lists the two prompts", names.includes("change_data") && names.includes("investigate"), prompts.value ?? prompts);

  const goal = "move customer 7 to the pro plan";
  const got = await errorOf(client.getPrompt({ name: "change_data", arguments: { goal } }));
  const text = (got.value?.messages ?? []).map((m) => m.content?.text ?? "").join("\n");
  check("change_data carries the goal and the gate's loop",
    text.includes(goal) && ["discover", "propose", "dry_run", "commit"].every((v) => text.includes(v)), got.value ?? got);

  const missing = await errorOf(client.getPrompt({ name: "change_data", arguments: {} }));
  check("a prompt without its required argument answers -32602", missing.code === -32602, missing);

  const after = await proposals();
  check("NO POWER OF ITS OWN: reading resources and prompts left no new proposal in the record",
    after === before, { before, after });

  await client.close().catch(() => {});
}

try {
  await main();
} catch (e) {
  check("the run finished without an unexpected exception", false, String(e?.stack ?? e));
} finally {
  await su.end({ timeout: 2 });
}
process.exit(failures ? 1 : 0);
