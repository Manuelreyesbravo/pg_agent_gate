/**
 * gated-mcp -- the six verbs of pg_agent_gate, reachable by any MCP client.
 *
 * This is NOT where the gate lives. The gate is inside PostgreSQL: this process
 * connects AS THE AGENT ROLE, so even if this file were replaced by something
 * hostile it could only call the verbs -- the database refuses anything else.
 * That is the difference with an ordinary MCP server, which holds a connection
 * and runs what it is asked.
 *
 * SIX TOOLS AND NEVER MORE. They are the verbs, not a catalog of the schema:
 * what the agent may touch comes from `discover`, derived from the live catalog.
 * If this list ever grows toward one tool per table, gated-mcp became a catalog
 * and lost the point.
 *
 * RESOURCES AND PROMPTS ADD NO POWER. They are other ways to LOOK at what the
 * verbs already give: every resource is read by calling a verb as the agent role,
 * never with a query of its own, so a resource cannot show what `discover` would
 * not -- a relation without a GRANT does not exist here either. The prompts carry
 * no data at all: they teach a model the gate's loop. test/resources.mjs checks
 * all three halves from outside the gate.
 *
 * TWO ERAS ON ONE ENDPOINT, chosen per request by the MCP-Protocol-Version header
 * or the per-request _meta -- never guessed from the method:
 *   * 2026-07-28, stateless. Every request says its version, Mcp-Method and (for
 *     tools/call, resources/read, prompts/get) Mcp-Name; they must match the body
 *     or the request is refused with 400 and -32020 before anything reaches the
 *     database. That check is a security property, not tidiness: a proxy routing
 *     on the header and a server executing the body must see the same request.
 *   * 2025-11-25 and earlier, the initialize handshake -- what most clients run.
 *
 * DNS REBINDING. Bound to loopback, any web page can make a browser post here.
 * Host and Origin are checked on every request and a foreign one gets 403 before
 * the token and before the database. Bound elsewhere, set
 * AGENT_GATE_ALLOWED_HOSTS and AGENT_GATE_ALLOWED_ORIGINS.
 *
 * Measured, not assumed: test/clients.mjs (the official v2 client pinned to
 * 2026-07-28, and the v1 SDK), test/resources.mjs, test/transport.mjs (the MUSTs
 * with plain fetch), and the official conformance suite.
 */
import { Hono } from "hono";
import postgres from "postgres";

const VERSION = "0.1.0";
const MODERN = ["2026-07-28"];
const LEGACY = ["2025-11-25", "2025-06-18", "2025-03-26"];
const SUPPORTED = [...MODERN, ...LEGACY];
// The tool, template and prompt lists are the same for every caller and change
// only with a deploy. What a resource CONTAINS depends on the agent's grants.
const STATIC_TTL_MS = 3_600_000;
const CONTENT_TTL_MS = 60_000;
// Requests whose Mcp-Name header mirrors params.name or params.uri.
const NAMED = new Set(["tools/call", "resources/read", "prompts/get"]);

const url = process.env.AGENT_GATE_DATABASE_URL;
if (!url) {
  console.error("AGENT_GATE_DATABASE_URL is required, and it must connect as the agent role");
  process.exit(1);
}
const token = process.env.AGENT_GATE_TOKEN ?? "";
const port = Number(process.env.PORT ?? 7878);
const hostname = process.env.HOST ?? "127.0.0.1";

const LOOPBACK = new Set(["localhost", "127.0.0.1", "::1", "[::1]"]);
const boundToLoopback = LOOPBACK.has(hostname.toLowerCase());
const listFrom = (v: string | undefined) =>
  (v ?? "").split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
const allowedHosts = listFrom(process.env.AGENT_GATE_ALLOWED_HOSTS);
const allowedOrigins = listFrom(process.env.AGENT_GATE_ALLOWED_ORIGINS);
if (!boundToLoopback && allowedHosts.length === 0) {
  console.error(`warning: bound to ${hostname} with no AGENT_GATE_ALLOWED_HOSTS -- the Host header is not checked`);
}

// fetch_types would run a catalog query at connect time, and an agent session
// can only call the verbs: the gate would refuse it, correctly.
const sql = postgres(url, { max: 4, fetch_types: false, onnotice: () => {} });

type Args = Record<string, unknown>;
type Verb = {
  description: string;
  inputSchema: Record<string, unknown>;
  run: (a: Args) => Promise<unknown>;
};

const str = (v: unknown) => (typeof v === "string" ? v : null);
const int = (v: unknown) => (Number.isInteger(v) ? (v as number) : null);

// postgres.js without fetch_types cannot type a JS array and sends it joined
// ("basic,3"), which PostgreSQL rejects. The array travels as ONE text value in
// PostgreSQL's own array syntax and is cast in the SQL -- a cast of a
// parameter, which the gate accepts as a verb's argument.
const pgTextArray = (items: unknown[]) =>
  "{" +
  items
    .map((p) =>
      p === null || p === undefined ? "NULL" : `"${String(p).replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`,
    )
    .join(",") +
  "}";

async function one(query: Promise<Array<{ r: unknown }>>): Promise<unknown> {
  const rows = await query;
  return rows[0]?.r ?? null;
}

const VERBS: Record<string, Verb> = {
  discover: {
    description:
      "What this agent may touch: tables, views and functions it has privileges on, with columns, types, keys, " +
      "constraints and comments -- derived from the live catalog. Start here. Optional filter matches names and comments.",
    inputSchema: {
      type: "object",
      properties: {
        filter: { type: "string", description: "substring of a name or comment" },
        max_objects: { type: "integer", minimum: 1, maximum: 500 },
      },
      additionalProperties: false,
    },
    run: (a) => one(sql`select agent_gate.discover(${str(a.filter)}, ${int(a.max_objects) ?? 50}) as r`),
  },
  propose: {
    description:
      "Propose exactly one SQL statement. Nothing runs: PostgreSQL parses it, plans it, and checks it against what " +
      "this agent may do, and returns every check. Parameters travel as text: cast them in the SQL ($1::int). " +
      "Then dry_run(proposal) to see the exact effect, or commit(proposal) to make it real.",
    inputSchema: {
      type: "object",
      properties: {
        sql: { type: "string", description: "one statement" },
        intent: { type: "string", minLength: 3, description: "what it is for; stays in the record" },
        params: { type: "array", items: { type: ["string", "null"] } },
      },
      required: ["sql", "intent"],
      additionalProperties: false,
    },
    run: (a) => {
      const params = Array.isArray(a.params) ? pgTextArray(a.params) : null;
      return one(sql`select agent_gate.propose(${String(a.sql)}, ${String(a.intent)}, ${params}::text[]) as r`);
    },
  },
  dry_run: {
    description:
      "Run a verified proposal and undo it. Returns the exact effect: rows touched, the before and after of each " +
      "row for a write, and whether bound assertions would still hold. Nothing is kept.",
    inputSchema: {
      type: "object",
      properties: { proposal: { type: "integer" } },
      required: ["proposal"],
      additionalProperties: false,
    },
    run: (a) => one(sql`select agent_gate.dry_run(${int(a.proposal)}) as r`),
  },
  commit: {
    description:
      "Run a verified proposal and keep it, if it still verifies and every guard agrees (row limit, constraints, " +
      "bound assertions). A read returns its rows. A proposal is committed at most once.",
    inputSchema: {
      type: "object",
      properties: { proposal: { type: "integer" } },
      required: ["proposal"],
      additionalProperties: false,
    },
    run: (a) => one(sql`select agent_gate.commit(${int(a.proposal)}) as r`),
  },
  acts: {
    description: "What this agent proposed and did, newest first, with every execution and why anything was refused.",
    inputSchema: {
      type: "object",
      properties: { max_acts: { type: "integer", minimum: 1, maximum: 500 } },
      additionalProperties: false,
    },
    run: (a) => one(sql`select agent_gate.acts(${int(a.max_acts) ?? 20}) as r`),
  },
  whoami: {
    description: "Which agent this connection is, and whether the gate is enforced in it.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
    run: () => one(sql`select agent_gate.whoami() as r`),
  },
};

// ------------------------------------------------------------- resources --
const RESOURCES = [
  {
    uri: "agent-gate://catalog",
    name: "catalog",
    title: "What this agent may touch",
    description: "Tables, views and functions this agent has privileges on, with columns, keys, constraints and a " +
      "fingerprint of the schema. The same answer as the discover tool.",
    mimeType: "application/json",
  },
  {
    uri: "agent-gate://whoami",
    name: "whoami",
    title: "Who this connection is",
    description: "Which agent this connection is, whether the gate is enforced in it, and how durable attempts are.",
    mimeType: "application/json",
  },
  {
    uri: "agent-gate://acts",
    name: "acts",
    title: "What this agent did",
    description: "The last 50 proposals of this agent, with every execution and why anything was refused.",
    mimeType: "application/json",
  },
];
const TEMPLATES = [
  {
    uriTemplate: "agent-gate://relation/{schema}/{name}",
    name: "relation",
    title: "One relation this agent may touch",
    description: "Columns, types, keys, constraints and comments of one table or view. A relation this agent was " +
      "not granted does not exist here.",
    mimeType: "application/json",
  },
];

class NotFound extends Error {}

const quoteIdent = (s: string) => (/^[a-z_][a-z0-9_$]*$/.test(s) ? s : `"${s.replace(/"/g, '""')}"`);

// Every branch calls a VERB. Adding a query here would give resources a power
// the tools do not have, and test/resources.mjs would catch it.
async function readResource(uri: string): Promise<{ value: unknown; ttlMs: number }> {
  if (uri === "agent-gate://catalog") return { value: await VERBS.discover.run({ max_objects: 500 }), ttlMs: CONTENT_TTL_MS };
  if (uri === "agent-gate://whoami") return { value: await VERBS.whoami.run({}), ttlMs: CONTENT_TTL_MS };
  // The history changes with every act: a client must not serve it from a cache.
  if (uri === "agent-gate://acts") return { value: await VERBS.acts.run({ max_acts: 50 }), ttlMs: 0 };
  const m = /^agent-gate:\/\/relation\/([^/]+)\/([^/]+)$/.exec(uri);
  if (m) {
    const schema = decodeURIComponent(m[1]);
    const name = decodeURIComponent(m[2]);
    const found = (await VERBS.discover.run({ filter: name, max_objects: 500 })) as
      | { relations?: Array<Record<string, unknown>> }
      | null;
    const wanted = new Set([`${schema}.${name}`, `${quoteIdent(schema)}.${quoteIdent(name)}`]);
    const relation = (found?.relations ?? []).find((r) => wanted.has(String(r.relation)));
    if (relation) return { value: relation, ttlMs: CONTENT_TTL_MS };
  }
  throw new NotFound(`resource not found: ${uri}`);
}

// --------------------------------------------------------------- prompts --
type PromptDef = {
  title: string;
  description: string;
  arguments: Array<{ name: string; description: string; required: boolean }>;
  render: (a: Record<string, string>) => string;
};

const PROMPTS: Record<string, PromptDef> = {
  change_data: {
    title: "Change data through the gate",
    description: "Make a change the way the gate expects: find what you may touch, propose one statement, see its " +
      "exact effect, then commit.",
    arguments: [{ name: "goal", description: "What should change, in plain words", required: true }],
    render: (a) =>
      [
        `Goal: ${a.goal}`,
        "",
        "You do not run SQL here: you propose it and PostgreSQL decides.",
        "1. discover -- see what you may touch: tables, columns, keys and constraints.",
        "2. propose -- ONE statement and its intent. Read every check it returns; if ok is false, fix the statement " +
          "and propose again.",
        "3. dry_run -- see exactly which rows change, before and after. If that is not the goal, go back to 2.",
        "4. commit -- only when the dry run shows the goal and nothing else. A refused commit says why.",
        "Parameters travel as text: cast them in the SQL ($1::int).",
      ].join("\n"),
  },
  investigate: {
    title: "Answer a question from the data",
    description: "Read only: find the relations that matter, propose SELECTs and commit them to read the rows. " +
      "Nothing changes.",
    arguments: [{ name: "question", description: "What you want to know", required: true }],
    render: (a) =>
      [
        `Question: ${a.question}`,
        "",
        "Answer it by reading, never by changing anything.",
        "1. discover -- find the relations and columns that can answer it.",
        "2. propose -- a SELECT and its intent. Read every check it returns.",
        "3. commit -- a read returns its rows and keeps nothing.",
        "Do not propose INSERT, UPDATE or DELETE for this question.",
      ].join("\n"),
  },
};
const promptList = Object.entries(PROMPTS).map(([name, p]) => ({
  name,
  title: p.title,
  description: p.description,
  arguments: p.arguments,
}));

type Id = string | number | null | undefined;
type Rpc = { jsonrpc: "2.0"; id?: Id; method: string; params?: Record<string, unknown> };
type Reply = { status: number; body: unknown | null };

const serverInfo = { name: "pg_agent_gate", version: VERSION };
const capabilities = { tools: { listChanged: false }, resources: {}, prompts: {} };
const instructions =
  "You do not run SQL here: you propose it and PostgreSQL decides. discover -> propose -> dry_run -> commit.";
const toolList = Object.entries(VERBS).map(([name, v]) => ({ name, description: v.description, inputSchema: v.inputSchema }));

const rpcError = (id: Id, code: number, message: string, data?: unknown) => ({
  jsonrpc: "2.0",
  id: id ?? null,
  error: data === undefined ? { code, message } : { code, message, data },
});
const result = (id: Id, body: Record<string, unknown>): Reply => ({
  status: 200,
  body: {
    jsonrpc: "2.0",
    id,
    result: { resultType: "complete", ...body, _meta: { "io.modelcontextprotocol/serverInfo": serverInfo } },
  },
});
const refuse = (status: number, id: Id, code: number, message: string, data?: unknown): Reply => ({
  status,
  body: rpcError(id, code, message, data),
});
const mismatch = (id: Id, message: string) => refuse(400, id, -32020, `Header mismatch: ${message}`);

// RFC 9110: optional whitespace around a field value is not part of it. Mcp-Name
// may carry the base64 sentinel, which is decoded before any comparison;
// `null` means the sentinel was there and its content was not valid base64.
function headerValue(raw: string | undefined, decode = false): string | null | undefined {
  if (raw === undefined) return undefined;
  const v = raw.trim();
  if (!decode) return v;
  const m = /^=\?base64\?(.*)\?=$/.exec(v);
  if (!m) return v;
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(m[1]) || m[1].length % 4 !== 0) return null;
  return Buffer.from(m[1], "base64").toString("utf8");
}

function hostAllowed(host: string | undefined): boolean {
  if (!host) return !boundToLoopback;
  const h = host.trim().toLowerCase();
  const name = h.startsWith("[") ? h.slice(0, h.indexOf("]") + 1) : h.split(":")[0];
  if (allowedHosts.length > 0) return allowedHosts.includes(h) || allowedHosts.includes(name);
  return boundToLoopback ? LOOPBACK.has(name) : true;
}

function originAllowed(origin: string | undefined): boolean {
  if (origin === undefined) return true; // not a browser: nothing to rebind
  const o = origin.trim().toLowerCase();
  if (allowedOrigins.includes(o)) return true;
  try {
    const u = new URL(o);
    return boundToLoopback && (u.protocol === "http:" || u.protocol === "https:") && LOOPBACK.has(u.hostname);
  } catch {
    return false; // includes the literal "null" origin of sandboxed pages
  }
}

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

async function callTool(msg: Rpc): Promise<Reply> {
  const name = String(msg.params?.name ?? "");
  const verb = VERBS[name];
  if (!verb) {
    return refuse(200, msg.id, -32602, `unknown tool ${name}: the tools are the gate's verbs (${Object.keys(VERBS).join(", ")})`);
  }
  const args = (isObject(msg.params?.arguments) ? msg.params?.arguments : {}) as Args;
  const required = (verb.inputSchema.required as string[] | undefined) ?? [];
  const absent = required.filter((k) => args[k] === undefined || args[k] === null);
  if (absent.length) {
    return result(msg.id, { content: [{ type: "text", text: `missing required argument(s): ${absent.join(", ")}` }], isError: true });
  }
  try {
    const r = await verb.run(args);
    // structuredContent is an OBJECT up to 2025-11-25 and a client validates it:
    // acts() returns an array, which the v1 SDK rejected as a whole response.
    return result(msg.id, {
      content: [{ type: "text", text: JSON.stringify(r, null, 2) }],
      structuredContent: isObject(r) ? r : { result: r },
      isError: false,
    });
  } catch (e) {
    const err = e as { message?: string; hint?: string; detail?: string };
    const text = [err.message, err.detail && `detail: ${err.detail}`, err.hint && `hint: ${err.hint}`]
      .filter(Boolean)
      .join("\n");
    return result(msg.id, { content: [{ type: "text", text }], isError: true });
  }
}

async function resourcesRead(msg: Rpc): Promise<Reply> {
  const uri = String(msg.params?.uri ?? "");
  try {
    const { value, ttlMs } = await readResource(uri);
    return result(msg.id, {
      contents: [{ uri, mimeType: "application/json", text: JSON.stringify(value, null, 2) }],
      ttlMs,
      // What a resource contains depends on this agent's grants: never shared across callers.
      cacheScope: "private",
    });
  } catch (e) {
    // Not found is -32602 (Invalid Params) in this revision, and never an empty contents array.
    if (e instanceof NotFound) return refuse(200, msg.id, -32602, e.message, { uri });
    return refuse(200, msg.id, -32603, `internal error reading ${uri}: ${(e as Error).message}`);
  }
}

function promptsGet(msg: Rpc): Reply {
  const name = String(msg.params?.name ?? "");
  const prompt = PROMPTS[name];
  if (!prompt) return refuse(200, msg.id, -32602, `unknown prompt ${name}: the prompts are ${Object.keys(PROMPTS).join(", ")}`);
  const given = isObject(msg.params?.arguments) ? (msg.params?.arguments as Record<string, unknown>) : {};
  const args: Record<string, string> = {};
  for (const [k, v] of Object.entries(given)) if (typeof v === "string") args[k] = v;
  const absent = prompt.arguments.filter((a) => a.required && !(args[a.name] ?? "").trim()).map((a) => a.name);
  if (absent.length) return refuse(200, msg.id, -32602, `missing required argument(s): ${absent.join(", ")}`);
  return result(msg.id, {
    description: prompt.description,
    messages: [{ role: "user", content: { type: "text", text: prompt.render(args) } }],
  });
}

const discover = (id: Id) =>
  result(id, {
    supportedVersions: SUPPORTED,
    capabilities,
    instructions,
    ttlMs: STATIC_TTL_MS,
    cacheScope: "public",
  });

// The methods both eras share, after each era has done its own checks.
async function common(msg: Rpc): Promise<Reply | null> {
  switch (msg.method) {
    case "server/discover":
      return discover(msg.id);
    case "tools/list":
      return result(msg.id, { tools: toolList, ttlMs: STATIC_TTL_MS, cacheScope: "public" });
    case "tools/call":
      return callTool(msg);
    case "resources/list":
      return result(msg.id, { resources: RESOURCES, ttlMs: STATIC_TTL_MS, cacheScope: "public" });
    case "resources/templates/list":
      return result(msg.id, { resourceTemplates: TEMPLATES, ttlMs: STATIC_TTL_MS, cacheScope: "public" });
    case "resources/read":
      return resourcesRead(msg);
    case "prompts/list":
      return result(msg.id, { prompts: promptList, ttlMs: STATIC_TTL_MS, cacheScope: "public" });
    case "prompts/get":
      return promptsGet(msg);
    default:
      return null;
  }
}

async function modern(msg: Rpc, header: (n: string) => string | undefined, metaVersion: unknown): Promise<Reply> {
  const id = msg.id;
  // A 2026-07-28 request carries its own protocol state, and one without it is
  // malformed: -32602 with 400 (basic/index.mdx, per-request protocol fields).
  // Judged before the headers on purpose: a header cannot stand in for the body.
  const meta = isObject(msg.params?._meta) ? (msg.params?._meta as Record<string, unknown>) : undefined;
  const absent = meta
    ? [
        ...(typeof meta["io.modelcontextprotocol/protocolVersion"] === "string" ? [] : ["io.modelcontextprotocol/protocolVersion"]),
        ...(isObject(meta["io.modelcontextprotocol/clientCapabilities"]) ? [] : ["io.modelcontextprotocol/clientCapabilities"]),
      ]
    : ["_meta"];
  if (absent.length) {
    return refuse(400, id, -32602, `Invalid params: missing required ${absent.join(", ")}`, { missing: absent });
  }
  const headerVersion = headerValue(header("mcp-protocol-version"));
  if (headerVersion === undefined) return mismatch(id, "the MCP-Protocol-Version header is required");
  if (typeof metaVersion === "string" && metaVersion !== headerVersion) {
    return mismatch(id, `MCP-Protocol-Version header '${headerVersion}' does not match _meta protocolVersion '${metaVersion}'`);
  }
  const requested = typeof metaVersion === "string" ? metaVersion : (headerVersion as string);
  if (!MODERN.includes(requested)) {
    return refuse(400, id, -32022, `Unsupported protocol version: ${requested}`, { requested, supported: SUPPORTED });
  }
  const method = headerValue(header("mcp-method"));
  if (method === undefined) return mismatch(id, "the Mcp-Method header is required");
  if (method !== msg.method) return mismatch(id, `Mcp-Method header '${method}' does not match body method '${msg.method}'`);
  if (NAMED.has(msg.method)) {
    const bodyName = String(msg.params?.name ?? msg.params?.uri ?? "");
    const name = headerValue(header("mcp-name"), true);
    if (name === undefined) return mismatch(id, `the Mcp-Name header is required for ${msg.method}`);
    if (name === null) return mismatch(id, "the Mcp-Name header carries an invalid base64 value");
    if (name !== bodyName) return mismatch(id, `Mcp-Name header '${name}' does not match body value '${bodyName}'`);
  }
  if (id === undefined) return { status: 202, body: null };
  // Includes what this revision removed (initialize, ping, logging/setLevel,
  // resources/subscribe): a 404 with -32601, not a quiet success.
  return (await common(msg)) ?? refuse(404, id, -32601, `method not found: ${msg.method}`);
}

async function legacy(msg: Rpc): Promise<Reply> {
  if (msg.id === undefined) return { status: 202, body: null };
  if (msg.method === "initialize") {
    const asked = String(msg.params?.protocolVersion ?? "");
    return result(msg.id, {
      protocolVersion: LEGACY.includes(asked) ? asked : LEGACY[0],
      capabilities,
      serverInfo,
      instructions,
    });
  }
  if (msg.method === "ping") return result(msg.id, {});
  return (await common(msg)) ?? refuse(200, msg.id, -32601, `method not found: ${msg.method}`);
}

function handle(msg: Rpc, header: (n: string) => string | undefined): Promise<Reply> {
  const meta = isObject(msg.params?._meta) ? (msg.params?._meta as Record<string, unknown>) : undefined;
  const metaVersion = meta?.["io.modelcontextprotocol/protocolVersion"];
  const headerVersion = headerValue(header("mcp-protocol-version"));
  // The era is what the request SAYS it speaks. A legacy version in the header
  // with no per-request _meta is the 2025 handshake; anything else is judged by
  // the 2026-07-28 rules, including a version nobody supports (-32022).
  const isModern = metaVersion !== undefined || (headerVersion !== undefined && !LEGACY.includes(headerVersion as string));
  return isModern ? modern(msg, header, metaVersion) : legacy(msg);
}

const app = new Hono();

app.use("/mcp", async (c, next) => {
  if (!hostAllowed(c.req.header("host"))) {
    return c.json(rpcError(null, -32600, "Forbidden: Host not allowed (DNS rebinding protection)"), 403);
  }
  if (!originAllowed(c.req.header("origin"))) {
    return c.json(rpcError(null, -32600, "Forbidden: Origin not allowed (DNS rebinding protection)"), 403);
  }
  if (token && c.req.header("authorization") !== `Bearer ${token}`) return c.json({ error: "unauthorized" }, 401);
  await next();
});

// No GET stream and no sessions in this server: 405 is the answer both eras expect.
app.on(["GET", "DELETE"], "/mcp", (c) => {
  c.header("Allow", "POST");
  return c.json(rpcError(null, -32600, "Method Not Allowed: this server has no GET stream and no sessions"), 405);
});

app.post("/mcp", async (c) => {
  let body: unknown;
  try {
    body = await c.req.json();
  } catch {
    return c.json(rpcError(null, -32700, "parse error"), 400);
  }
  if (Array.isArray(body)) {
    return c.json(rpcError(null, -32600, "batches are not supported: one JSON-RPC message per POST"), 400);
  }
  if (!isObject(body) || body.jsonrpc !== "2.0" || typeof body.method !== "string") {
    return c.json(rpcError(isObject(body) ? (body.id as Id) : null, -32600, "invalid JSON-RPC request"), 400);
  }
  const reply = await handle(body as Rpc, (n) => c.req.header(n));
  if (reply.body === null) return c.body(null, reply.status as 202);
  return c.json(reply.body as Record<string, unknown>, reply.status as 200);
});

app.get("/health", async (c) => c.json(await one(sql`select agent_gate.whoami() as r`)));

export default { port, hostname, fetch: app.fetch };
