import assert from "node:assert/strict";
import { once } from "node:events";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { verifyReceipt } from "../../src/audit/receipts.js";
import { hashIntentEnvelope, hmacSha256Hex } from "../../src/intent/canonical.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, "..", "..");
const sealKey = process.env.TEST_AUDIT_SEAL_KEY;
if (!sealKey) throw new Error("TEST_AUDIT_SEAL_KEY is required for intent-envelope verification");
const ownerBootstrapKey = process.env.TEST_INTENT_ENVELOPE_BOOTSTRAP_KEY;
if (!ownerBootstrapKey) throw new Error("TEST_INTENT_ENVELOPE_BOOTSTRAP_KEY is required for intent-envelope verification");
const testRunId = crypto.randomUUID();

const port = await availablePort();
const worker = spawn(process.execPath, [findWrangler(), "dev", "--local", "--port", String(port), "--compatibility-date", "2026-07-02", "--var", `AUDIT_SEAL_KEY:${sealKey}`, "--var", `INTENT_ENVELOPE_BOOTSTRAP_KEY:${ownerBootstrapKey}`], {
  cwd: repoRoot,
  stdio: ["ignore", "pipe", "pipe"]
});
let workerOutput = "";
worker.stdout.on("data", (chunk) => { workerOutput += chunk; });
worker.stderr.on("data", (chunk) => { workerOutput += chunk; });

try {
  const target = `http://127.0.0.1:${port}/mcp`;
  await waitForGateway(target, worker);

  const base = envelope("env-freeze", "env-freeze", { max_actions: 5 });
  const started = await sessionStart(target, "env-freeze", base);
  assert.equal(started.decision, "allow", `S-R2-ENV-01: session.start freezes a valid envelope (${started.reason ?? "no reason"})`);
  assert.equal(typeof started.envelope_hash, "string", "S-R2-ENV-01: frozen envelope has a hash");
  assert.deepEqual(started.prior_action_trace, [], "S-R2-ENV-01: trace begins empty");
  assert.equal(started.receipt.events[0].envelope_hash, started.envelope_hash, "S-R2-ENV-01: session receipt records the envelope hash");
  assert.equal(started.receipt.events[0].declared_by, "role:run-lead-apac", "S-R2-ENV-01: session receipt records the declarer");

  const agentDeclared = envelope("env-agent-declared", "env-agent-declared");
  agentDeclared.declared_by = "agent:run-l1";
  const rejectedAgentDeclaration = await sessionStart(target, "env-agent-declared", agentDeclared);
  assert.equal(rejectedAgentDeclaration.reason, "invalid_envelope:declared_by_agent", "S-R2-ENV-01: an agent cannot declare its own envelope");

  const inEnvelope = await evaluate(target, "env-freeze", { type: "invoke", capability: "triage-alert", payload: {} });
  assert.equal(inEnvelope.decision, "allow", "S-R2-ENV-01: in-envelope action remains allowed");
  assert.equal(inEnvelope.in_envelope, true, "S-R2-ENV-01: decision records envelope membership");
  assert.equal(inEnvelope.session_trace.length, 1, "S-R2-ENV-01: trace accumulates after a decision");
  assert.equal(inEnvelope.session_trace[0].capability, undefined, "S-R2-ENV-01: trace is privacy-safe action metadata");
  assert.equal(inEnvelope.session_trace[0].action.capability, "triage-alert", "S-R2-ENV-01: trace retains the capability");
  assert.equal(inEnvelope.receipt.events[1].in_envelope, true, "S-R2-ENV-01: decision receipt records envelope membership");

  const replacement = envelope("env-replacement", "env-freeze", { capabilities: ["apply-change"] });
  const widened = await sessionStart(target, "env-freeze", replacement);
  assert.equal(widened.decision, "deny", "S-R3-ENV-widen: an existing envelope cannot be replaced mid-session");
  assert.equal(widened.reason, "invalid_envelope:session_already_frozen", "S-R3-ENV-widen: frozen session rejects replacement");

  await assertViolation(target, "capability", envelope("env-capability", "env-capability", { capabilities: ["apply-change"] }), {
    type: "invoke", capability: "triage-alert", payload: {}
  });
  await assertViolation(target, "source", envelope("env-source", "env-source", { sources: ["mcp:vendor"] }), {
    type: "invoke", capability: "triage-alert", payload: {}
  });
  await assertViolation(target, "endpoint", envelope("env-endpoint", "env-endpoint", { endpoints: ["primary"] }), {
    type: "egress", capability: "triage-alert", endpoint: "secondary", crossing_egress_tier: "II", payload_egress_tier: "II", payload: {}
  });
  await assertViolation(target, "egress", envelope("env-egress", "env-egress", { egress_tier_ceiling: "I" }), {
    type: "egress", capability: "triage-alert", endpoint: "primary", crossing_egress_tier: "II", payload_egress_tier: "II", payload: {}
  });

  const budgetEnvelope = envelope("env-budget", "env-budget", { max_actions: 1 });
  await sessionStart(target, "env-budget", budgetEnvelope);
  assert.equal((await evaluate(target, "env-budget", { type: "invoke", capability: "triage-alert", payload: {} })).decision, "allow", "S-R3-ENV budget first action is within limit");
  assert.equal((await evaluate(target, "env-budget", { type: "invoke", capability: "triage-alert", payload: {} })).reason, "envelope_violation:budget", "S-R3-ENV budget blocks the next action");

  const expiredEnvelope = envelope("env-expiry", "env-expiry", { expires_at: "2020-01-01T00:00:00.000Z" });
  await sessionStart(target, "env-expiry", expiredEnvelope);
  assert.equal((await evaluate(target, "env-expiry", { type: "invoke", capability: "triage-alert", payload: {} })).reason, "envelope_violation:expiry", "S-R3-ENV expiry is fail-closed");

  const noSession = await evaluate(target, "missing-envelope", { type: "invoke", capability: "triage-alert", payload: {} });
  assert.equal(noSession.decision, "deny", "S-R2-ENV session without envelope is denied");
  assert.equal(noSession.reason, "no_envelope", "S-R2-ENV no envelope reason is explicit");

  const baseDenyEnvelope = envelope("env-base-deny", "env-base-deny");
  await sessionStart(target, "env-base-deny", baseDenyEnvelope);
  const baseDeny = await evaluate(target, "env-base-deny", {
    type: "egress", capability: "triage-alert", endpoint: "primary", crossing_egress_tier: "II", payload_egress_tier: "II", payload: { message: 'password = "old-relay-credential-9f3k2m"' }
  });
  assert.equal(baseDeny.decision, "deny", "S-R3-ENV-narrower-than-base: envelope never upgrades base deny");
  assert.equal(baseDeny.rule_id, "R4", "S-R3-ENV-narrower-than-base: base R4 denial remains authoritative");

  const stepUpEnvelope = envelope("env-step-up", "env-step-up", { capabilities: [], sources: [], amendment_policy: "approval_required" });
  await sessionStart(target, "env-step-up", stepUpEnvelope);
  const stepUp = await evaluate(target, "env-step-up", { type: "invoke", capability: "triage-alert", payload: {} });
  assert.equal(stepUp.decision, "approve", "S-R3-ENV amendment policy returns deterministic step-up");
  assert.equal(stepUp.receipt.events.some((event) => event.event_type === "envelope.amend"), true, "S-R3-ENV amendment request is receipted");

  const alteredEnvelope = structuredClone(inEnvelope.receipt);
  alteredEnvelope.intent_envelope.authorized.capabilities = ["apply-change"];
  assert.equal((await verifyReceipt(alteredEnvelope, sealKey)).code, "envelope_tampered", "S-R3-ENV-tamper: verifier detects envelope hash mismatch");

  console.log(JSON.stringify({ status: "green", assertions: 28, invariant: "base-policy-first-envelope-narrows-only" }, null, 2));
} finally {
  worker.kill();
  worker.stdout.destroy();
  worker.stderr.destroy();
  worker.unref();
}

async function assertViolation(target, dimension, intentEnvelope, action) {
  await sessionStart(target, intentEnvelope.session_id, intentEnvelope);
  const result = await evaluate(target, intentEnvelope.session_id, action);
  assert.equal(result.decision, "deny", `S-R3-ENV ${dimension}: default is deny`);
  assert.equal(result.reason, `envelope_violation:${dimension}`, `S-R3-ENV ${dimension}: reason identifies the failing dimension`);
  assert.equal(result.in_envelope, false, `S-R3-ENV ${dimension}: receipt marks the action out of envelope`);
}

function envelope(envelopeId, sessionId, overrides = {}) {
  const authorized = {
    capabilities: ["triage-alert"],
    sources: ["mcp:self"],
    endpoints: ["primary"],
    egress_tier_ceiling: "II",
    autonomy_tier_ceiling: "T1",
    ...(overrides.authorized ?? {})
  };
  for (const key of ["capabilities", "sources", "endpoints", "egress_tier_ceiling", "autonomy_tier_ceiling"]) {
    if (key in overrides) authorized[key] = overrides[key];
  }
  return {
    envelope_id: envelopeId,
    session_id: sessionId,
    declared_by: "role:run-lead-apac",
    declared_at: "2026-07-22T00:00:00.000Z",
    task_ref: "INC-42137",
    authorized,
    limits: {
      max_actions: overrides.max_actions ?? 5,
      expires_at: overrides.expires_at ?? "2030-01-01T00:00:00.000Z",
      ...(overrides.limits ?? {})
    },
    amendment_policy: overrides.amendment_policy
  };
}

async function sessionStart(target, sessionId, intentEnvelope) {
  const frozenEnvelope = { ...intentEnvelope, session_id: scopedSessionId(sessionId) };
  return call(target, sessionId, "boundary/session.start", { intent_envelope: frozenEnvelope }, {
    "boundary-owner-proof": await hmacSha256Hex(ownerBootstrapKey, await hashIntentEnvelope(frozenEnvelope))
  });
}

async function evaluate(target, sessionId, action) {
  return call(target, sessionId, "boundary/evaluate", { action });
}

async function call(target, sessionId, method, params, extraHeaders = {}) {
  const response = await fetch(target, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "mcp-method": method,
      "boundary-agent-id": "agent:run-l1",
      "mcp-session-id": scopedSessionId(sessionId),
      ...extraHeaders
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: `${method}:${sessionId}`, method, params })
  });
  const body = await response.json();
  assert.equal(response.status, 200, `${method}: HTTP status`);
  assert.equal(body.error, undefined, `${method}: JSON-RPC error ${JSON.stringify(body.error)}`);
  return body.result;
}

function scopedSessionId(sessionId) {
  return `r2r3-${testRunId}-${sessionId}`;
}

async function waitForGateway(target, child) {
  for (let attempt = 0; attempt < 120; attempt += 1) {
    if (child.exitCode !== null) throw new Error(`Wrangler exited before starting:\n${workerOutput}`);
    try {
      const response = await fetch(target.replace(/\/mcp$/, "/health"), { signal: AbortSignal.timeout(1_000) });
      const body = await response.json();
      if (response.ok && body?.status === "ok") return;
    } catch {
      // The local Worker is still starting.
    }
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 250));
  }
  throw new Error(`Timed out starting the local Worker:\n${workerOutput}`);
}

async function availablePort() {
  const probe = createServer();
  probe.listen(0, "127.0.0.1");
  await once(probe, "listening");
  const { port } = probe.address();
  await new Promise((resolveClose) => probe.close(resolveClose));
  return port;
}

function findWrangler() {
  const local = resolve(repoRoot, "node_modules", "wrangler", "bin", "wrangler.js");
  if (existsSync(local)) return local;
  const global = process.env.APPDATA
    ? resolve(process.env.APPDATA, "npm", "node_modules", "wrangler", "bin", "wrangler.js")
    : null;
  if (global && existsSync(global)) return global;
  throw new Error("Wrangler is required for intent-envelope verification. Run npm ci first.");
}
