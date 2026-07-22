#!/usr/bin/env node
// Governed AMS Ticket Change Agent - end-to-end demo.
// The accountable-owner bootstrap freezes an intent envelope before the agent acts.

import { readFile, writeFile, mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash, createHmac, randomUUID } from "node:crypto";

const here = dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const target = argValue("--target") ?? "https://contextboundary-gw-staging.kannanokannan.workers.dev/mcp";
const simulateStale = args.includes("--stale");
const saveReceipts = args.includes("--save-receipts");
const ownerBootstrapKey = process.env.BOUNDARY_OWNER_BOOTSTRAP_KEY;
let rpcId = 0;

function argValue(flag) {
  const index = args.indexOf(flag);
  return index >= 0 ? args[index + 1] : undefined;
}

async function contextOpsGate(manifest) {
  const failures = [];
  if (!manifest.context?.context_owner) failures.push("ownership: no accountable context owner");
  const lastValidated = simulateStale ? new Date(Date.now() - 30 * 24 * 3600 * 1000) : new Date(manifest.context.last_validated);
  const ageHours = (Date.now() - lastValidated.getTime()) / 3600000;
  if (ageHours > manifest.context.max_age_hours) failures.push(`freshness: ${ageHours.toFixed(0)}h old, max ${manifest.context.max_age_hours}h`);
  if (manifest.operational_context?.change_window?.state !== "open") failures.push("operational context: change window is not open");
  if (!manifest.operational_context?.cab_reference) failures.push("operational context: no CAB reference");
  const untrusted = (manifest.context.sources ?? []).filter((source) => source.trust !== "trusted");
  if (untrusted.length) failures.push(`source trust: ${untrusted.map((source) => source.id).join(", ")}`);
  return failures;
}

async function boundaryRequest(agentId, method, params, sessionId, extraHeaders = {}) {
  const response = await fetch(target, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "mcp-method": method,
      "boundary-agent-id": agentId,
      "mcp-session-id": sessionId,
      ...extraHeaders
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: ++rpcId, method, params })
  });
  if (!response.ok) throw new Error(`gateway HTTP ${response.status}`);
  const body = await response.json();
  if (!body.result) throw new Error(`no result in response: ${JSON.stringify(body)}`);
  return body.result;
}

async function boundarySessionStart(agentId, intentEnvelope, sessionId) {
  if (!ownerBootstrapKey) {
    throw new Error("BOUNDARY_OWNER_BOOTSTRAP_KEY is required: only the accountable-owner bootstrap may declare a session envelope");
  }
  return boundaryRequest(agentId, "boundary/session.start", { intent_envelope: intentEnvelope }, sessionId, {
    "boundary-owner-proof": ownerProof(intentEnvelope)
  });
}

function buildIntentEnvelope(manifest, sessionId) {
  const template = manifest.intent_envelope_template;
  return {
    envelope_id: `env-${manifest.ticket.id}-${randomUUID()}`,
    session_id: sessionId,
    declared_by: template.declared_by,
    declared_at: new Date().toISOString(),
    task_ref: template.task_ref,
    authorized: template.authorized,
    limits: {
      max_actions: template.limits.max_actions,
      expires_at: new Date(Date.now() + template.limits.expires_after_minutes * 60_000).toISOString(),
      ...(template.limits.drift_review_threshold ? { drift_review_threshold: template.limits.drift_review_threshold } : {})
    },
    amendment_policy: template.amendment_policy
  };
}

function ownerProof(intentEnvelope) {
  const envelopeHash = createHash("sha256").update(canonicalize({
    authorized: intentEnvelope.authorized,
    limits: intentEnvelope.limits
  })).digest("hex");
  return createHmac("sha256", ownerBootstrapKey).update(envelopeHash).digest("hex");
}

function canonicalize(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(",")}}`;
}

function printDecision(label, result) {
  const badge = result.decision === "allow" ? "[ALLOW]" : result.decision === "deny" ? "[DENY]" : "[APPROVE]";
  console.log(`\n${badge} ${label}`);
  console.log(`          rule: ${result.rule_id} - reason: ${result.reason ?? "-"}`);
  if (result.obligation) console.log(`          obligation: ${JSON.stringify(result.obligation)}`);
  if (result.audit) console.log(`          receipt: agent=${result.audit.agent_id} owner=${result.audit.accountable_owner} tier=${result.audit.tier_in_force} ts=${result.audit.timestamp}`);
}

async function main() {
  const manifest = JSON.parse(await readFile(join(here, "context-manifest.json"), "utf8"));
  const agent = manifest.agent_binding.agent_id;
  console.log(`Governed AMS Ticket Change Agent - ${manifest.ticket.id}: ${manifest.ticket.summary}`);
  console.log(`Gateway: ${target}`);

  const failures = await contextOpsGate(manifest);
  if (failures.length) {
    for (const failure of failures) console.log(`[BLOCK] ${failure}`);
    process.exit(2);
  }
  console.log(`[PASS] owner=${manifest.context.context_owner}; context fresh; change window open; CAB=${manifest.operational_context.cab_reference}`);

  const sessionId = `ams-${manifest.ticket.id}-${randomUUID()}`;
  const intentEnvelope = buildIntentEnvelope(manifest, sessionId);
  const receipts = [];
  const session = await boundarySessionStart(agent, intentEnvelope, sessionId);
  printDecision("Session start - accountable-owner declared intent envelope", session);
  receipts.push({ flow: "session-start", ...session.audit });

  const flowA = await boundaryRequest(agent, "boundary/evaluate", {
    action: { type: "invoke", capability: "triage-alert", payload: { ticket: manifest.ticket.id } }
  }, sessionId);
  printDecision(`Flow A - triage ${manifest.ticket.id}`, flowA);
  receipts.push({ flow: "A-allow", ...flowA.audit });

  const flowB = await boundaryRequest(agent, "boundary/evaluate", {
    action: { type: "invoke", capability: "apply-change", payload: { ticket: manifest.ticket.id, change: "rotate smtp relay config" } }
  }, sessionId);
  printDecision("Flow B - apply high-risk change", flowB);
  receipts.push({ flow: "B-approve", ...flowB.audit });

  const flowC = await boundaryRequest(agent, "boundary/evaluate", {
    action: {
      type: "egress", capability: "triage-alert", endpoint: "primary", crossing_egress_tier: "II", payload_egress_tier: "II",
      payload: { label: "II", message: 'password = "old-relay-credential-9f3k2m"' }
    }
  }, sessionId);
  printDecision("Flow C - credential-bearing egress", flowC);
  receipts.push({ flow: "C-deny", ...flowC.audit });

  if (saveReceipts) {
    const dir = join(here, "receipts");
    await mkdir(dir, { recursive: true });
    const file = join(dir, `run-${new Date().toISOString().replace(/[:.]/g, "-")}.json`);
    await writeFile(file, JSON.stringify(receipts, null, 2));
    console.log(`\nReceipts written: ${file}`);
  }
}

main().catch((error) => {
  console.error(`demo failed: ${error.message}`);
  process.exit(1);
});
