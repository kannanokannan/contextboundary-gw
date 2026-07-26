import assert from "node:assert/strict";
import { once } from "node:events";
import { existsSync } from "node:fs";
import { createServer } from "node:http";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { createEphemeralR6Fixtures, ownerProof, signedHeaders, workerR6Vars } from "../helpers/r6.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const signer = await createEphemeralR6Fixtures();
const ownerBootstrapKey = "r4-owner-bootstrap-ephemeral";
const upstreamCalls = [];
const upstream = createServer(async (request, response) => {
  const chunks = []; for await (const chunk of request) chunks.push(chunk);
  upstreamCalls.push(JSON.parse(Buffer.concat(chunks).toString("utf8")));
  response.writeHead(200, { "content-type": "application/json" });
  response.end(JSON.stringify({ jsonrpc: "2.0", id: "spy", result: { reached_upstream: true } }));
});
await listen(upstream);
const port = await availablePort();
const workerArgs = [findWrangler(), "dev", "--local", "--port", String(port), "--compatibility-date", "2026-07-02", "--var", `UPSTREAM_MCP_URL:http://127.0.0.1:${upstream.address().port}/mcp`, "--var", `INTENT_ENVELOPE_BOOTSTRAP_KEY:${ownerBootstrapKey}`];
for (const value of workerR6Vars(signer)) workerArgs.push("--var", value);
const worker = spawn(process.execPath, workerArgs, { cwd: repoRoot, stdio: ["ignore", "pipe", "pipe"] });
let output = ""; worker.stdout.on("data", (chunk) => { output += chunk; }); worker.stderr.on("data", (chunk) => { output += chunk; });

try {
  const gateway = `http://127.0.0.1:${port}/mcp`;
  await waitForGateway(gateway);

  const mod = await session(gateway, "mod");
  const modAction = egress({ legacy_credential: 'password="old-relay-credential-9f3k2m"' });
  const modified = await evaluate(gateway, mod, modAction, 1);
  assert.equal(modified.decision, "modify", "S-R4-MOD-01 declared strip_field produces MODIFY");
  assert.ok(modified.original_action_hash && modified.transform_id && modified.resulting_action_hash, "MODIFY returns three hash-linked fields");
  assert.equal(modified.receipt.events[1].transform_id, "strip_field", "receipt records declared transform id");

  const noTransform = await session(gateway, "mod-none");
  const denied = await evaluate(gateway, noTransform, egress({ unknown_secret: 'password="old-relay-credential-9f3k2m"' }), 1);
  assert.equal(denied.decision, "deny", "S-R4-MOD-02 no declared transform that works remains DENY");

  const stillBlocked = await session(gateway, "mod-envelope", { endpoints: ["primary"] });
  const blocked = await evaluate(gateway, stillBlocked, { ...modAction, endpoint: "secondary" }, 1);
  assert.equal(blocked.decision, "deny", "S-R4-MOD-03 transform cannot bypass a second envelope rule");

  const deferredSession = await session(gateway, "defer");
  const deferredAction = { type: "invoke", capability: "triage-alert", payload: { source_ready: false } };
  const deferred = await toolCall(gateway, deferredSession, deferredAction, 1);
  assert.equal(deferred.decision, "defer", "S-R4-DEF-01 declared condition yields DEFER");
  assert.ok(deferred.resume_token && deferred.defer_reason, "DEFER records resume token and reason");
  assert.equal(upstreamCalls.length, 0, "DEFER never reaches upstream");

  const resumeAction = { type: "deferred.resume", resume_token: deferred.resume_token, condition_id: "source-ready" };
  const resumed = await raw(gateway, deferredSession, "boundary/deferred.resume", { resume_token: deferred.resume_token, condition: { id: "source-ready", satisfied: true } }, await signedHeaders(signer, { sessionId: deferredSession, seq: 2, action: resumeAction }));
  assert.equal(resumed.decision, "allow", "S-R4-DEF-02 resume reevaluates the stored action after its condition");
  assert.equal(resumed.resume_token, deferred.resume_token, "resume receipt/result references the held token");

  const stepUpSession = await session(gateway, "stepup");
  const stepUp = await evaluate(gateway, stepUpSession, { type: "invoke", capability: "apply-change", payload: {} }, 1);
  assert.equal(stepUp.decision, "approve", "S-R4-DEF-03 STEP_UP remains distinct from DEFER");
  assert.equal(stepUp.resume_token, undefined, "STEP_UP has no defer token");

  console.log(JSON.stringify({ status: "green", assertions: 14, profile: "R4-five-decision-outcomes" }, null, 2));
} finally {
  worker.kill(); worker.stdout.destroy(); worker.stderr.destroy(); worker.unref();
  await Promise.race([once(worker, "exit"), new Promise((resolveDelay) => setTimeout(resolveDelay, 2_000))]);
  await new Promise((resolveClose) => upstream.close(resolveClose));
}

async function session(gateway, suffix, overrides = {}) {
  const sessionId = `r4-${suffix}-${crypto.randomUUID()}`;
  const envelope = { envelope_id: `env-${sessionId}`, session_id: sessionId, declared_by: "role:run-lead-apac", declared_at: new Date().toISOString(), task_ref: "R4", authorized: { capabilities: ["triage-alert", "apply-change"], sources: ["mcp:self"], endpoints: overrides.endpoints ?? ["primary"], egress_tier_ceiling: "II", autonomy_tier_ceiling: "T1" }, limits: { max_actions: 20, expires_at: new Date(Date.now() + 300_000).toISOString() } };
  const result = await raw(gateway, sessionId, "boundary/session.start", { intent_envelope: envelope }, { ...await signedHeaders(signer, { sessionId, seq: 0, action: { type: "session.start" } }), "boundary-owner-proof": await ownerProof(ownerBootstrapKey, envelope) });
  assert.equal(result.decision, "allow", "R4 test session opens");
  return sessionId;
}

function egress(payload) {
  return { type: "egress", capability: "triage-alert", endpoint: "primary", crossing_egress_tier: "II", payload_egress_tier: "II", payload };
}

async function evaluate(gateway, sessionId, action, seq) {
  return raw(gateway, sessionId, "boundary/evaluate", { action }, await signedHeaders(signer, { sessionId, seq, action }));
}

async function toolCall(gateway, sessionId, action, seq) {
  return raw(gateway, sessionId, "tools/call", { name: action.capability, arguments: action.payload }, await signedHeaders(signer, { sessionId, seq, action }));
}

async function raw(gateway, sessionId, method, params, authHeaders) {
  const response = await fetch(gateway, { method: "POST", headers: { "content-type": "application/json", "mcp-method": method, "boundary-agent-id": "agent:run-l1", "mcp-session-id": sessionId, ...authHeaders }, body: JSON.stringify({ jsonrpc: "2.0", id: `${method}:${sessionId}`, method, params }) });
  const body = await response.json();
  assert.equal(response.status, 200, `${method} HTTP status`); assert.equal(body.error, undefined, `${method} JSON-RPC result`);
  return body.result;
}

async function waitForGateway(gateway) {
  for (let attempt = 0; attempt < 120; attempt += 1) {
    if (worker.exitCode !== null) throw new Error(`Wrangler exited:\n${output}`);
    try { if ((await fetch(gateway.replace(/\/mcp$/, "/health"))).ok) return; } catch {}
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 250));
  }
  throw new Error(`Worker timed out:\n${output}`);
}

async function listen(server) { server.listen(0, "127.0.0.1"); await once(server, "listening"); }
async function availablePort() { const server = createServer(); await listen(server); const { port } = server.address(); await new Promise((resolveClose) => server.close(resolveClose)); return port; }
function findWrangler() { const local = resolve(repoRoot, "node_modules", "wrangler", "bin", "wrangler.js"); if (existsSync(local)) return local; const global = process.env.APPDATA && resolve(process.env.APPDATA, "npm", "node_modules", "wrangler", "bin", "wrangler.js"); if (global && existsSync(global)) return global; throw new Error("Wrangler is required for R4 verification."); }
