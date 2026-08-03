import assert from "node:assert/strict";
import { createServer } from "node:http";
import { once } from "node:events";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { createEphemeralR6Fixtures, ownerProof, signedHeaders, workerR6Vars } from "../helpers/r6.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, "..", "..");

const noConfig = await startWorker([]);
try {
  const baseline = await discover(noConfig.target);
  assert.equal(baseline.status, 200, "S-DISC-01: discovery answers without an upstream or signing keys");
  assert.equal(baseline.body.error, undefined, "S-DISC-01: discovery is not an upstream error");
  assert.deepEqual(baseline.body.result.supportedVersions, ["2026-07-28"], "S-DISC-01: supported versions are the gateway's modern surface");
  assert.deepEqual(baseline.body.result.capabilities, { tools: {} }, "S-DISC-02: unbound caller receives empty capabilities");
  assert.equal(baseline.body.result._meta["io.modelcontextprotocol/serverInfo"].name, "contextboundary-gw", "S-DISC-05: server identity is in the spec metadata location");
  assert.equal(baseline.body.result.serverInfo, undefined, "S-DISC-05: discovery has no deprecated top-level serverInfo");
  assert.equal(baseline.body.result.resultType, "complete", "S-DISC-05: response has a complete result");
} finally {
  await noConfig.stop();
}

const fixtures = await createEphemeralR6Fixtures();
const ownerBootstrapKey = "server-discover-owner-bootstrap-ephemeral";
const upstreamCalls = [];
const upstream = createServer(async (request, response) => {
  const body = await readBody(request);
  upstreamCalls.push(JSON.parse(body));
  response.writeHead(200, { "content-type": "application/json" });
  response.end(JSON.stringify({
    jsonrpc: "2.0",
    id: JSON.parse(body).id,
    result: { tools: [{ name: "triage-alert" }, { name: "apply-change" }, { name: "read-secrets" }] }
  }));
});
await listen(upstream);
const upstreamUrl = `http://127.0.0.1:${upstream.address().port}/mcp`;
const configured = await startWorker([
  `UPSTREAM_MCP_URL:${upstreamUrl}`,
  `INTENT_ENVELOPE_BOOTSTRAP_KEY:${ownerBootstrapKey}`,
  ...workerR6Vars(fixtures)
]);
try {
  const unauthenticated = await discover(configured.target, { "boundary-agent-id": "agent:run-l1" });
  assert.deepEqual(unauthenticated.body.result.capabilities, { tools: {} }, "S-DISC-02: unauthenticated identity receives empty capabilities");

  const l1Session = `discover-l1-${crypto.randomUUID()}`;
  await startSession(configured.target, fixtures, ownerBootstrapKey, "agent:run-l1", l1Session, {
    capabilities: ["triage-alert"],
    sources: ["mcp:self"],
    autonomy_tier_ceiling: "T1"
  });
  const l1 = await discoverAuthorized(configured.target, fixtures, "agent:run-l1", l1Session, 1);
  assert.deepEqual(Object.keys(l1.body.result.capabilities.tools), ["triage-alert"], "S-DISC-03: authorized identity sees policy-filtered tools/list scope");
  const l1Tools = await toolsList(configured.target, fixtures, "agent:run-l1", l1Session, 2);
  assert.deepEqual(l1Tools.body.result.tools.map((tool) => tool.name), Object.keys(l1.body.result.capabilities.tools), "S-DISC-03: discovery scope matches tools/list filtering");
  assert.equal(upstreamCalls.length, 1, "S-DISC-01: discovery itself does not call the upstream");

  const l3Session = `discover-l3-${crypto.randomUUID()}`;
  await startSession(configured.target, fixtures, ownerBootstrapKey, "agent:run-l3", l3Session, {
    capabilities: ["triage-alert", "apply-change", "read-secrets"],
    sources: ["mcp:self", "mcp:vendor"],
    autonomy_tier_ceiling: "T3"
  });
  const l3 = await discoverAuthorized(configured.target, fixtures, "agent:run-l3", l3Session, 1);
  assert.deepEqual(Object.keys(l3.body.result.capabilities.tools), ["triage-alert", "apply-change"], "S-DISC-04: identity-specific filtering does not leak vendor capability");
  assert.notDeepEqual(l1.body.result.capabilities, l3.body.result.capabilities, "S-DISC-04: two identities do not receive each other's capabilities");

  console.log(JSON.stringify({ status: "green", assertions: 15, upstream_calls: upstreamCalls.length }, null, 2));
} finally {
  await configured.stop();
  await new Promise((resolveClose) => upstream.close(resolveClose));
}

async function discover(target, headers = {}) {
  const response = await fetch(target, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "mcp-method": "server/discover",
      ...headers
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: "discover", method: "server/discover", params: {} })
  });
  return { status: response.status, body: await response.json() };
}

async function discoverAuthorized(target, fixtures, identity, sessionId, seq) {
  return discover(target, {
    "boundary-agent-id": identity,
    "mcp-session-id": sessionId,
    ...(await signedHeaders(fixtures, { sessionId, seq, action: { type: "discover" } }))
  });
}

async function toolsList(target, fixtures, identity, sessionId, seq) {
  const response = await fetch(target, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "mcp-method": "tools/list",
      "boundary-agent-id": identity,
      "mcp-session-id": sessionId,
      ...(await signedHeaders(fixtures, { sessionId, seq, action: { type: "discover" } }))
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: "tools-list", method: "tools/list", params: {} })
  });
  return { status: response.status, body: await response.json() };
}

async function startSession(target, fixtures, ownerBootstrapKey, identityId, sessionId, overrides) {
  const identity = {
    "agent:run-l1": { accountable_owner: "role:run-lead-apac", autonomy_tier: "T1" },
    "agent:run-l3": { accountable_owner: "role:run-lead-apac", autonomy_tier: "T3" }
  }[identityId];
  const envelope = {
    envelope_id: `env-${sessionId}`,
    session_id: sessionId,
    declared_by: identity.accountable_owner,
    declared_at: "2026-08-03T00:00:00.000Z",
    task_ref: "SERVER-DISCOVER",
    authorized: {
      capabilities: overrides.capabilities,
      sources: overrides.sources,
      endpoints: ["primary"],
      egress_tier_ceiling: "III",
      autonomy_tier_ceiling: overrides.autonomy_tier_ceiling
    },
    limits: { max_actions: 10, expires_at: "2030-01-01T00:00:00.000Z" }
  };
  const response = await fetch(target, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "mcp-method": "boundary/session.start",
      "boundary-agent-id": identityId,
      "mcp-session-id": sessionId,
      ...(await signedHeaders(fixtures, { sessionId, seq: 0, action: { type: "session.start" } })),
      "boundary-owner-proof": await ownerProof(ownerBootstrapKey, envelope)
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: `start-${sessionId}`, method: "boundary/session.start", params: { intent_envelope: envelope } })
  });
  const body = await response.json();
  assert.equal(response.status, 200, `${identityId}: session start HTTP status`);
  assert.equal(body.result?.decision, "allow", `${identityId}: session start`);
}

async function startWorker(vars) {
  const port = await availablePort();
  const worker = spawn(process.execPath, [
    findWrangler(), "dev", "--local", "--port", String(port), "--compatibility-date", "2026-07-02",
    ...vars.flatMap((value) => ["--var", value])
  ], { cwd: repoRoot, stdio: ["ignore", "pipe", "pipe"] });
  let output = "";
  worker.stdout.on("data", (chunk) => { output += chunk; });
  worker.stderr.on("data", (chunk) => { output += chunk; });
  const target = `http://127.0.0.1:${port}/mcp`;
  await waitForGateway(target, worker, () => output);
  return {
    target,
    async stop() {
      worker.kill();
      worker.stdout.destroy();
      worker.stderr.destroy();
      worker.unref();
    }
  };
}

async function waitForGateway(target, worker, output) {
  for (let attempt = 0; attempt < 120; attempt += 1) {
    if (worker.exitCode !== null) throw new Error(`Wrangler exited before starting:\n${output()}`);
    try {
      const response = await fetch(target.replace(/\/mcp$/, "/health"), { signal: AbortSignal.timeout(1_000) });
      if (response.ok) return;
    } catch {
      // The local Worker is still starting.
    }
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 250));
  }
  throw new Error(`Timed out starting the local Worker:\n${output()}`);
}

async function availablePort() {
  const probe = createServer();
  probe.listen(0, "127.0.0.1");
  await once(probe, "listening");
  const { port } = probe.address();
  await new Promise((resolveClose) => probe.close(resolveClose));
  return port;
}

async function listen(server) {
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
}

async function readBody(request) {
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf8");
}

function findWrangler() {
  const local = resolve(repoRoot, "node_modules", "wrangler", "bin", "wrangler.js");
  if (existsSync(local)) return local;
  const global = process.env.APPDATA
    ? resolve(process.env.APPDATA, "npm", "node_modules", "wrangler", "bin", "wrangler.js")
    : null;
  if (global && existsSync(global)) return global;
  throw new Error("Wrangler is required for server/discover tests. Run npm ci first.");
}
