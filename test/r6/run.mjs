import assert from "node:assert/strict";
import { once } from "node:events";
import { existsSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { dirname, resolve, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createServer } from "node:http";
import { spawn, execFile } from "node:child_process";
import { promisify } from "node:util";
import { tmpdir } from "node:os";
import { verifyReceipt } from "../../src/audit/receipts.js";
import { createEphemeralR6Fixtures, ownerProof, signedHeaders, thirdPartyPublicKeys, workerR6Vars } from "../helpers/r6.mjs";

const execFileAsync = promisify(execFile);
const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, "..", "..");
const ownerBootstrapKey = "r6-owner-bootstrap-ephemeral";
const oldAgent = await createEphemeralR6Fixtures({ keyId: "agent-key-old" });
const rotatedAgent = await createEphemeralR6Fixtures({ keyId: "agent-key-rotated" });
const fixtures = {
  ...oldAgent,
  agentRegistry: Object.fromEntries(Object.keys(oldAgent.agentRegistry).map((identityId) => [identityId, [oldAgent.agentRegistry[identityId][0], rotatedAgent.agentRegistry[identityId][0]]]))
};
const publicKeys = thirdPartyPublicKeys(fixtures);
const port = await availablePort();
const workerArgs = [findWrangler(), "dev", "--local", "--port", String(port), "--compatibility-date", "2026-07-02", "--var", `INTENT_ENVELOPE_BOOTSTRAP_KEY:${ownerBootstrapKey}`];
for (const value of workerR6Vars(fixtures)) workerArgs.push("--var", value);
const worker = spawn(process.execPath, workerArgs, { cwd: repoRoot, stdio: ["ignore", "pipe", "pipe"] });
let workerOutput = "";
worker.stdout.on("data", (chunk) => { workerOutput += chunk; });
worker.stderr.on("data", (chunk) => { workerOutput += chunk; });

try {
  const target = `http://127.0.0.1:${port}/mcp`;
  await waitForGateway(target, worker);
  const keyEndpoint = await fetch(`http://127.0.0.1:${port}/.well-known/contextboundary-gateway-key`);
  const publishedGatewayKey = await keyEndpoint.json();
  assert.equal(publishedGatewayKey.key_id, fixtures.gatewayKeyId, "gateway publishes the configured key id");
  assert.equal(publishedGatewayKey.public_jwk.x, fixtures.gateway.public_jwk.x, "gateway derives the public x-coordinate without exposing private material");
  assert.equal(Object.hasOwn(publishedGatewayKey.public_jwk, "d"), false, "gateway endpoint never exposes a private key");

  const session = `r6-${crypto.randomUUID()}`;
  await startSession(target, session, oldAgent, 0);
  const action = { type: "invoke", capability: "triage-alert", payload: { ticket: "INC-42137" } };
  const validHeaders = await signedHeaders(oldAgent, { sessionId: session, seq: 1, action });
  const valid = await call(target, session, action, validHeaders);
  assert.equal(valid.decision, "allow", "S-R6-01 valid signature proceeds");
  assert.equal(valid.receipt.events[1].agent_key_id, "agent-key-old", "S-R6 receipt records agent key id");
  assert.equal((await verifyReceipt(valid.receipt, publicKeys)).valid, true, "S-R6-08 third-party public-only verifier passes");

  const missing = await call(target, session, action);
  assert.equal(missing.reason, "identity_unverified", "S-R6-02 missing signature fails closed");
  const forged = await call(target, session, action, { ...await signedHeaders(oldAgent, { sessionId: session, seq: 2, action }), "boundary-agent-signature": "A".repeat(86) });
  assert.equal(forged.reason, "identity_unverified", "S-R6-03 forged signature fails closed");
  const unknown = await call(target, session, action, { ...await signedHeaders(oldAgent, { sessionId: session, seq: 3, action }), "boundary-agent-key-id": "unknown-key" });
  assert.equal(unknown.reason, "identity_unverified", "S-R6-04 unknown key fails closed");
  const replay = await call(target, session, action, validHeaders);
  assert.equal(replay.reason, "replay_detected", "S-R6-05 duplicate nonce fails closed");

  const rotatedSession = `r6-rotated-${crypto.randomUUID()}`;
  await startSession(target, rotatedSession, rotatedAgent, 0);
  const rotatedAction = await call(target, rotatedSession, action, await signedHeaders(rotatedAgent, { sessionId: rotatedSession, seq: 1, action }));
  assert.equal(rotatedAction.decision, "allow", "S-R6-06 rotated key proceeds");
  assert.equal((await verifyReceipt(valid.receipt, publicKeys)).valid, true, "S-R6-06 old receipt remains verifiable after rotation");

  const tamperedAgentSignature = structuredClone(valid.receipt);
  tamperedAgentSignature.events[1].agent_sig = "A".repeat(86);
  assert.equal((await verifyReceipt(tamperedAgentSignature, publicKeys)).code, "agent_sig_invalid", "S-R6-07 tampered agent signature is named");
  const unknownReceiptKey = structuredClone(valid.receipt);
  unknownReceiptKey.events[1].agent_key_id = "missing";
  assert.equal((await verifyReceipt(unknownReceiptKey, publicKeys)).code, "unknown_key_id", "verifier names unknown historical key id");
  const tamperedSeal = structuredClone(valid.receipt);
  tamperedSeal.events.at(-1).seal_sig = "A".repeat(86);
  assert.equal((await verifyReceipt(tamperedSeal, publicKeys)).code, "seal_sig_invalid", "S-R6-09 tampered Ed25519 seal is named");

  const publicDir = await mkdtemp(join(tmpdir(), "contextboundary-r6-public-"));
  try {
    const receiptPath = join(publicDir, "receipt.json");
    const keysPath = join(publicDir, "public-keys.json");
    await writeFile(receiptPath, JSON.stringify(valid.receipt));
    await writeFile(keysPath, JSON.stringify(publicKeys));
    const { stdout } = await execFileAsync(process.execPath, [resolve(repoRoot, "audit", "verify-receipt.mjs"), receiptPath, "--public-keys", keysPath]);
    assert.equal(JSON.parse(stdout).code, "intact", "S-R6-08 CLI verifies with only public keys");
  } finally {
    await rm(publicDir, { recursive: true, force: true });
  }
  console.log(JSON.stringify({ status: "green", assertions: 17, profile: "R6-ed25519-public-verification" }, null, 2));
} finally {
  worker.kill(); worker.stdout.destroy(); worker.stderr.destroy(); worker.unref();
}

async function startSession(target, sessionId, signer, seq) {
  const intentEnvelope = envelope(sessionId);
  const headers = {
    ...await signedHeaders(signer, { sessionId, seq, action: { type: "session.start" } }),
    "boundary-owner-proof": await ownerProof(ownerBootstrapKey, intentEnvelope)
  };
  const result = await callRaw(target, sessionId, "boundary/session.start", { intent_envelope: intentEnvelope }, headers);
  assert.equal(result.decision, "allow", "session starts with a valid owner envelope and agent signature");
}

async function call(target, sessionId, action, headers = {}) {
  return callRaw(target, sessionId, "boundary/evaluate", { action }, headers);
}

async function callRaw(target, sessionId, method, params, headers) {
  const response = await fetch(target, { method: "POST", headers: { "content-type": "application/json", "mcp-method": method, "boundary-agent-id": "agent:run-l1", "mcp-session-id": sessionId, ...headers }, body: JSON.stringify({ jsonrpc: "2.0", id: `${method}:${sessionId}`, method, params }) });
  const text = await response.text();
  let body;
  try { body = JSON.parse(text); } catch { throw new Error(`${method} returned non-JSON HTTP ${response.status}: ${text.slice(0, 500)}\n${workerOutput}`); }
  assert.equal(response.status, 200, `${method} returns HTTP 200`);
  assert.equal(body.error, undefined, `${method} has no JSON-RPC error`);
  return body.result;
}

function envelope(sessionId) {
  return { envelope_id: `env-${sessionId}`, session_id: sessionId, declared_by: "role:run-lead-apac", declared_at: new Date().toISOString(), task_ref: "INC-42137", authorized: { capabilities: ["triage-alert"], sources: ["mcp:self"], endpoints: ["primary"], egress_tier_ceiling: "II", autonomy_tier_ceiling: "T1" }, limits: { max_actions: 10, expires_at: new Date(Date.now() + 300_000).toISOString() } };
}

async function waitForGateway(target, child) {
  for (let attempt = 0; attempt < 120; attempt += 1) {
    if (child.exitCode !== null) throw new Error(`Wrangler exited before starting:\n${workerOutput}`);
    try { const response = await fetch(target.replace(/\/mcp$/, "/health")); if (response.ok) return; } catch {}
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 250));
  }
  throw new Error(`Timed out starting Worker:\n${workerOutput}`);
}

async function availablePort() {
  const probe = createServer(); probe.listen(0, "127.0.0.1"); await once(probe, "listening"); const { port } = probe.address(); await new Promise((resolveClose) => probe.close(resolveClose)); return port;
}

function findWrangler() {
  const local = resolve(repoRoot, "node_modules", "wrangler", "bin", "wrangler.js");
  if (existsSync(local)) return local;
  const global = process.env.APPDATA ? resolve(process.env.APPDATA, "npm", "node_modules", "wrangler", "bin", "wrangler.js") : null;
  if (global && existsSync(global)) return global;
  throw new Error("Wrangler is required for R6 verification.");
}
