/**
 * pg_agent_gate edge -- the six verbs, reachable by any MCP client.
 *
 * This is NOT where the gate lives. The gate is inside PostgreSQL: this process
 * connects AS THE AGENT ROLE, so even if this file were replaced by something
 * hostile it could only call the verbs -- the database refuses anything else.
 * That is the difference with an ordinary MCP server, which holds a connection
 * and runs what it is asked.
 *
 * SIX TOOLS AND NEVER MORE. They are the verbs, not a catalog of the schema:
 * what the agent may touch comes from `discover`, derived from the live catalog.
 * If this list ever grows toward one tool per table, the edge became a catalog
 * and lost the point.
 *
 * Protocol: JSON-RPC 2.0 over HTTP POST (Streamable HTTP, JSON responses).
 * `initialize` for clients on the 2025 revisions; `server/discover` following
 * the 2026-07-28 changelog, not yet validated against a client of that revision.
 */
import { Hono } from "hono";
import postgres from "postgres";

const VERSION = "0.1.0";
const SUPPORTED = ["2026-07-28", "2025-11-25", "2025-06-18"];

const url = process.env.AGENT_GATE_DATABASE_URL;
if (!url) {
  console.error("AGENT_GATE_DATABASE_URL is required, and it must connect as the agent role");
  process.exit(1);
}
const token = process.env.AGENT_GATE_TOKEN ?? "";
const port = Number(process.env.PORT ?? 7878);
const hostname = process.env.HOST ?? "127.0.0.1";

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

type Rpc = { jsonrpc: "2.0"; id?: string | number | null; method: string; params?: Record<string, unknown> };

const serverInfo = { name: "pg_agent_gate", version: VERSION };
const capabilities = { tools: { listChanged: false } };
const ok = (id: Rpc["id"], result: Record<string, unknown>) => ({
  jsonrpc: "2.0",
  id,
  result: { resultType: "complete", ...result, _meta: { "io.modelcontextprotocol/serverInfo": serverInfo } },
});
const fail = (id: Rpc["id"], code: number, message: string) => ({ jsonrpc: "2.0", id, error: { code, message } });

function missing(verb: Verb, a: Args): string | null {
  const required = (verb.inputSchema.required as string[] | undefined) ?? [];
  const absent = required.filter((k) => a[k] === undefined || a[k] === null);
  return absent.length ? `missing required argument(s): ${absent.join(", ")}` : null;
}

async function handle(msg: Rpc): Promise<unknown | null> {
  const isNotification = msg.id === undefined;
  switch (msg.method) {
    case "initialize": {
      const asked = String(msg.params?.protocolVersion ?? "");
      return ok(msg.id, {
        protocolVersion: SUPPORTED.includes(asked) ? asked : SUPPORTED[1],
        capabilities,
        serverInfo,
        instructions:
          "You do not run SQL here: you propose it and PostgreSQL decides. discover -> propose -> dry_run -> commit.",
      });
    }
    case "server/discover":
      return ok(msg.id, { supportedVersions: SUPPORTED, capabilities, serverInfo });
    case "ping":
      return ok(msg.id, {});
    case "tools/list":
      return ok(msg.id, {
        tools: Object.entries(VERBS).map(([name, v]) => ({ name, description: v.description, inputSchema: v.inputSchema })),
      });
    case "tools/call": {
      const name = String(msg.params?.name ?? "");
      const verb = VERBS[name];
      if (!verb) return fail(msg.id, -32602, `unknown tool ${name}: the tools are the gate's verbs (${Object.keys(VERBS).join(", ")})`);
      const args = (msg.params?.arguments ?? {}) as Args;
      const why = missing(verb, args);
      if (why) return ok(msg.id, { content: [{ type: "text", text: why }], isError: true });
      try {
        const r = await verb.run(args);
        return ok(msg.id, {
          content: [{ type: "text", text: JSON.stringify(r, null, 2) }],
          structuredContent: r as Record<string, unknown>,
          isError: false,
        });
      } catch (e) {
        const err = e as { message?: string; hint?: string; detail?: string };
        const text = [err.message, err.detail && `detail: ${err.detail}`, err.hint && `hint: ${err.hint}`]
          .filter(Boolean)
          .join("\n");
        return ok(msg.id, { content: [{ type: "text", text }], isError: true });
      }
    }
    default:
      return isNotification ? null : fail(msg.id, -32601, `method not found: ${msg.method}`);
  }
}

const app = new Hono();

app.use("/mcp", async (c, next) => {
  if (token && c.req.header("authorization") !== `Bearer ${token}`) return c.json({ error: "unauthorized" }, 401);
  await next();
});

app.post("/mcp", async (c) => {
  let body: Rpc | Rpc[];
  try {
    body = await c.req.json();
  } catch {
    return c.json(fail(null, -32700, "parse error"), 400);
  }
  const batch = Array.isArray(body) ? body : [body];
  const replies = (await Promise.all(batch.map(handle))).filter((r) => r !== null);
  if (replies.length === 0) return c.body(null, 202);
  return c.json(Array.isArray(body) ? replies : replies[0]);
});

app.get("/health", async (c) => c.json(await one(sql`select agent_gate.whoami() as r`)));

export default { port, hostname, fetch: app.fetch };
