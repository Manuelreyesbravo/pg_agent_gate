/**
 * The MUSTs of the 2026-07-28 Streamable HTTP transport that need no client SDK.
 *
 * Checked with plain fetch on purpose: an SDK smooths over exactly the things a
 * server gets wrong (a 404 where a 405 is required, a missing field it defaults).
 * Each MUST is paired with the control that keeps it honest -- a server that
 * rejects EVERY Origin passes "rejects a bad Origin" and is useless.
 *
 *   GATED_MCP_URL=http://127.0.0.1:7878/mcp node test/transport.mjs
 *
 * One `ok` / `FAIL` line per case.
 */
const url = process.env.GATED_MCP_URL ?? "http://127.0.0.1:7878/mcp";
const V = "2026-07-28";
const meta = (version = V) => ({
  "io.modelcontextprotocol/protocolVersion": version,
  "io.modelcontextprotocol/clientCapabilities": {},
  "io.modelcontextprotocol/clientInfo": { name: "gated-mcp-transport-test", version: "0.1.0" },
});

let failures = 0;
let id = 0;
function check(what, ok, detail) {
  console.log(`  ${ok ? "ok  " : "FAIL"} ${what}`);
  if (!ok) {
    failures++;
    if (detail !== undefined) console.log(`       ${JSON.stringify(detail)}`.slice(0, 600));
  }
}

async function post(method, params, { version = V, headers = {} } = {}) {
  const msg = { jsonrpc: "2.0", id: ++id, method, params: { ...params, _meta: meta(version) } };
  const h = {
    "content-type": "application/json",
    accept: "application/json, text/event-stream",
    "mcp-protocol-version": version,
    "mcp-method": method,
    ...(params?.name ? { "mcp-name": params.name } : {}),
    ...headers,
  };
  const r = await fetch(url, { method: "POST", headers: h, body: JSON.stringify(msg) });
  const text = await r.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {}
  return { status: r.status, json, text: text.slice(0, 300) };
}

const isTtl = (v) => Number.isInteger(v) && v >= 0;
const isScope = (v) => v === "public" || v === "private";
const serverInfo = (res) => res?.json?.result?._meta?.["io.modelcontextprotocol/serverInfo"]?.name;

// ------------------------------------------------------------------ Origin --
const evil = await post("tools/list", {}, { headers: { origin: "https://attacker.example" } });
check("a request with a foreign Origin is rejected with 403", evil.status === 403, evil);
const local = await post("tools/list", {}, { headers: { origin: new URL(url).origin } });
check("CONTROL: a request with the server's own Origin is accepted", local.status === 200 && Array.isArray(local.json?.result?.tools), local);

// --------------------------------------------------------- server/discover --
const d = await post("server/discover", {});
const dr = d.json?.result;
check(
  "server/discover carries resultType, supportedVersions, ttlMs and cacheScope",
  d.status === 200 && dr?.resultType === "complete" && dr?.supportedVersions?.includes(V) && isTtl(dr?.ttlMs) && isScope(dr?.cacheScope),
  d,
);

// -------------------------------------------------------------- tools/list --
const t = await post("tools/list", {});
const tr = t.json?.result;
check(
  "tools/list carries resultType, ttlMs and cacheScope, and exactly six tools",
  t.status === 200 && tr?.resultType === "complete" && isTtl(tr?.ttlMs) && isScope(tr?.cacheScope) && tr?.tools?.length === 6,
  t,
);

// ------------------------------------------------------ version negotiation --
const old = await post("tools/list", {}, { version: "1999-01-01" });
check(
  "an unsupported protocol version gets 400 and -32022 listing the supported ones",
  old.status === 400 && old.json?.error?.code === -32022 && (old.json?.error?.data?.supported ?? []).includes(V),
  old,
);

// ------------------------------------------------- per-request protocol state --
// basic/index.mdx: protocolVersion and clientCapabilities are required in every
// request's _meta; a request missing either is malformed -- 400 and -32602.
const bare = await fetch(url, {
  method: "POST",
  headers: { "content-type": "application/json", accept: "application/json, text/event-stream",
    "mcp-protocol-version": V, "mcp-method": "tools/list" },
  body: JSON.stringify({ jsonrpc: "2.0", id: ++id, method: "tools/list",
    params: { _meta: { "io.modelcontextprotocol/protocolVersion": V } } }),
});
const bareJson = await bare.json().catch(() => null);
check("a request whose _meta lacks clientCapabilities gets 400 and -32602",
  bare.status === 400 && bareJson?.error?.code === -32602, { status: bare.status, body: bareJson });

// ------------------------------------------------------- header validation --
const mismatch = await post("tools/list", {}, { headers: { "mcp-method": "tools/call" } });
check("an Mcp-Method header that does not match the body gets 400 and -32020", mismatch.status === 400 && mismatch.json?.error?.code === -32020, mismatch);

// --------------------------------------------------------------------- GET --
const g = await fetch(url, { method: "GET", headers: { accept: "text/event-stream" } });
check("GET on the endpoint gets 405: this revision has no GET stream", g.status === 405, { status: g.status });

// ----------------------------------------------------------- identification --
const w = await post("tools/call", { name: "whoami", arguments: {} });
check("a tools/call result is complete and the server names itself in _meta", w.status === 200 && w.json?.result?.resultType === "complete" && !!serverInfo(w), w);

process.exit(failures ? 1 : 0);
