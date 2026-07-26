import assert from "node:assert/strict";
import { createServer } from "node:http";
import { once } from "node:events";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { createEphemeralR6Fixtures, ownerProof, signedHeaders, workerR6Vars } from "../helpers/r6.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, "..", "..");
const calls = [];
const testSealKey = process.env.TEST_AUDIT_SEAL_KEY;
if (!testSealKey) throw new Error("TEST_AUDIT_SEAL_KEY is required for the local interception test");
const ownerBootstrapKey = "interception-owner-bootstrap-ephemeral";
const r6 = await createEphemeralR6Fixtures();
const upstream = createServer(async (request, response) => {
  const body = await readBody(request);
  const message = JSON.parse(body);
  calls.push(message);
  const result = message.method === "tools/list"
    ? { tools: [{ name: "triage-alert" }, { name: "apply-change" }, { name: "read-secrets" }] }
    : { reached_upstream: true, tool: message.params?.name };
  response.writeHead(200, { "content-type": "application/json" });
  response.end(JSON.stringify({ jsonrpc: "2.0", id: message.id, result }));
});

await listen(upstream);
const upstreamPort = upstream.address().port;
const gatewayPort = await availablePort();
const wrangler = findWrangler();
const workerArgs = [wrangler, "dev", "--local", "--port", String(gatewayPort), "--compatibility-date", "2026-07-02", "--var", `UPSTREAM_MCP_URL:http://127.0.0.1:${upstreamPort}/mcp`, "--var", `INTENT_ENVELOPE_BOOTSTRAP_KEY:${ownerBootstrapKey}`];
for (const value of workerR6Vars(r6)) workerArgs.push("--var", value);
const worker = spawn(process.execPath, workerArgs, {
  cwd: repoRoot,
  stdio: ["ignore", "pipe", "pipe"]
});
let workerOutput = "";
worker.stdout.on("data", (chunk) => { workerOutput += chunk; });
worker.stderr.on("data", (chunk) => { workerOutput += chunk; });

try {
  const gateway = `http://127.0.0.1:${gatewayPort}/mcp`;
  await waitForGateway(gateway, worker);

  const allowedSession = `intercept-${crypto.randomUUID()}`;
  await startSession(gateway, allowedSession);
  const allowed = await call(gateway, "agent:run-l1", "tools/call", { name: "triage-alert", arguments: { ticket: "INC-42137" } }, allowedSession, await signedHeaders(r6, { sessionId: allowedSession, seq: 1, action: { type: "invoke", capability: "triage-alert", payload: { ticket: "INC-42137" } } }));
  assert.equal(allowed.result.reached_upstream, true, "ALLOW must reach upstream");
  assert.equal(calls.length, 1, "only the ALLOW call may reach the spy");

  const stepUpSession = `intercept-${crypto.randomUUID()}`;
  await startSession(gateway, stepUpSession);
  const stepUp = await call(gateway, "agent:run-l1", "tools/call", { name: "apply-change", arguments: {} }, stepUpSession, await signedHeaders(r6, { sessionId: stepUpSession, seq: 1, action: { type: "invoke", capability: "apply-change", payload: {} } }));
  assert.equal(stepUp.result.decision, "approve", "STEP_UP must be returned to the caller");
  assert.equal(calls.length, 1, "STEP_UP must not reach the spy");

  const deniedSession = `intercept-${crypto.randomUUID()}`;
  await startSession(gateway, deniedSession);
  const denied = await call(gateway, "agent:run-l1", "tools/call", { name: "read-secrets", arguments: {} }, deniedSession, await signedHeaders(r6, { sessionId: deniedSession, seq: 1, action: { type: "invoke", capability: "read-secrets", payload: {} } }));
  assert.equal(denied.result.decision, "deny", "DENY must be returned to the caller");
  assert.equal(calls.length, 1, "DENY must not reach the spy");

  const unbound = await call(gateway, null, "tools/call", { name: "triage-alert", arguments: {} });
  assert.equal(unbound.result.decision, "deny", "missing identity must fail closed");
  assert.equal(calls.length, 1, "an unbound direct tools/call must not bypass policy");

  const discoverySession = `intercept-${crypto.randomUUID()}`;
  await startSession(gateway, discoverySession);
  const discovery = await call(gateway, "agent:run-l1", "tools/list", {}, discoverySession, await signedHeaders(r6, { sessionId: discoverySession, seq: 1, action: { type: "discover" } }));
  assert.deepEqual(discovery.result.tools.map((tool) => tool.name), ["triage-alert"], "tools/list must expose only policy-authorized tools");
  assert.equal(calls.length, 2, "tools/list may query upstream only after policy filtering is established");

  console.log(JSON.stringify({ status: "green", assertions: 9, upstream_calls: calls.length }, null, 2));
} finally {
  worker.kill();
  worker.stdout.destroy();
  worker.stderr.destroy();
  worker.unref();
  await Promise.race([
    once(worker, "exit"),
    new Promise((resolveDelay) => setTimeout(resolveDelay, 2_000))
  ]);
  await new Promise((resolveClose) => upstream.close(resolveClose));
}

async function call(gateway, identity, method, params, sessionId, authHeaders = {}) {
  const response = await fetch(gateway, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "mcp-method": method,
      ...(identity ? { "boundary-agent-id": identity } : {}),
      ...(sessionId ? { "mcp-session-id": sessionId } : {}),
      ...authHeaders
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: `${method}-${identity ?? "unbound"}`, method, params })
  });
  assert.equal(response.status, 200, `${method} must return HTTP 200`);
  return response.json();
}

async function startSession(gateway, sessionId) {
  const envelope = { envelope_id: `env-${sessionId}`, session_id: sessionId, declared_by: "role:run-lead-apac", declared_at: new Date().toISOString(), task_ref: "INTERCEPTION", authorized: { capabilities: ["triage-alert", "apply-change", "read-secrets"], sources: ["mcp:self", "mcp:vendor"], endpoints: ["primary"], egress_tier_ceiling: "III", autonomy_tier_ceiling: "T1" }, limits: { max_actions: 10, expires_at: new Date(Date.now() + 300_000).toISOString() } };
  const response = await call(gateway, "agent:run-l1", "boundary/session.start", { intent_envelope: envelope }, sessionId, { ...await signedHeaders(r6, { sessionId, seq: 0, action: { type: "session.start" } }), "boundary-owner-proof": await ownerProof(ownerBootstrapKey, envelope) });
  assert.equal(response.result.decision, "allow", "session start must be allowed");
}

async function waitForGateway(url, worker) {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    if (worker.exitCode !== null) throw new Error(`Wrangler exited before starting:\n${workerOutput}`);
    try {
      const response = await fetch(url.replace(/\/mcp$/, "/health"), { signal: AbortSignal.timeout(1_000) });
      if (response.ok) return;
    } catch {
      // The local Worker is still starting.
    }
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 250));
  }
  throw new Error(`Timed out starting the local Worker:\n${workerOutput}`);
}

async function listen(server) {
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
}

async function availablePort() {
  const probe = createServer();
  await listen(probe);
  const { port } = probe.address();
  await new Promise((resolveClose) => probe.close(resolveClose));
  return port;
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
  throw new Error("Wrangler is required for the local interception test. Run npm ci first.");
}
