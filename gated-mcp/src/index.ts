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
 * TWO ERAS ON ONE ENDPOINT, chosen per request by the MCP-Protocol-Version header
 * or the per-request _meta -- never guessed from the method:
 *   * 2026-07-28, stateless. Every request says its version, Mcp-Method and (for
 *     tools/call) Mcp-Name; they must match the body or the request is refused
 *     with 400 and -32020 before anything reaches the database. That check is a
 *     security property, not tidiness: a proxy routing on the header and a
 *     server executing the body must be looking at the same request.
 *   * 2025-11-25 and earlier, the initialize handshake -- what most clients run.
 *
 * DNS REBINDING. Bound to loopback, any web page can make a browser post here.
 * Host and Origin are checked on every request and a foreign one gets 403 before
 * the token and before the database. Bound elsewhere, set
 * AGENT_GATE_ALLOWED_HOSTS and AGENT_GATE_ALLOWED_ORIGINS.
 *
 * Measured, not assumed: test/clients.mjs (the official v2 client pinned to
 * 2026-07-28, and the v1 SDK), test/transport.mjs (the MUSTs with plain fetch),
 * and the official conformance suite.
 */
import { Hono } from "hono";
import postgres from "postgres";

const VERSION = "0.1.0";
const MODERN = ["2026-07-28"];
const LEGACY = ["2025-11-25", "2025-06-18", "2025-03-26"];
const SUPPORTED = [...MODERN, ...LEGACY];
// The tool list is the same for every caller and changes only with a deploy.
const TOOLS_TTL_MS = 3_600_000;
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

type Id = string | number | null | undefined;
type Rpc = { jsonrpc: "2.0"; id?: Id; method: string; params?: Record<string, unknown> };
type Reply = { status: number; body: unknown | null };

const serverInfo = { name: "pg_agent_gate", version: VERSION };
const capabilities = { tools: { listChanged: false } };
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

const discover = (id: Id) =>
  result(id, {
    supportedVersions: SUPPORTED,
    capabilities,
    instructions,
    ttlMs: TOOLS_TTL_MS,
    cacheScope: "public",
  });

async function modern(msg: Rpc, header: (n: string) => string | undefined, metaVersion: unknown): Promise<Reply> {
  const id = msg.id;
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
  switch (msg.method) {
    case "server/discover":
      return discover(id);
    case "tools/list":
      return result(id, { tools: toolList, ttlMs: TOOLS_TTL_MS, cacheScope: "public" });
    case "tools/call":
      return callTool(msg);
    default:
      // Includes what this revision removed (initialize, ping, logging/setLevel,
      // resources/subscribe): a 404 with -32601, not a quiet success.
      return refuse(404, id, -32601, `method not found: ${msg.method}`);
  }
}

async function legacy(msg: Rpc): Promise<Reply> {
  if (msg.id === undefined) return { status: 202, body: null };
  switch (msg.method) {
    case "initialize": {
      const asked = String(msg.params?.protocolVersion ?? "");
      return result(msg.id, {
        protocolVersion: LEGACY.includes(asked) ? asked : LEGACY[0],
        capabilities,
        serverInfo,
        instructions,
      });
    }
    case "server/discover":
      return discover(msg.id);
    case "ping":
      return result(msg.id, {});
    case "tools/list":
      return result(msg.id, { tools: toolList, ttlMs: TOOLS_TTL_MS, cacheScope: "public" });
    case "tools/call":
      return callTool(msg);
    default:
      return refuse(200, msg.id, -32601, `method not found: ${msg.method}`);
  }
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
