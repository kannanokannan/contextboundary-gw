#!/usr/bin/env node
// Governed AMS Ticket Change Agent — end-to-end demo.
//
// ContextOps checks the context (ownership, freshness, operational window).
// ContextBoundary (via contextboundary-gw) governs the actions:
//   Flow A — ALLOW   : triage the ticket (within tier, within egress boundary)
//   Flow B — APPROVE : apply the high-risk change (T1 agent, T3 capability -> deterministic approval)
//   Flow C — DENY    : egress carrying credential-shaped payload (Tier I content on a Tier II crossing)
//
// Usage:
//   node examples/ams-ticket-change/demo.mjs --target https://<gateway>/mcp [--stale] [--save-receipts]
//
// Zero dependencies. Node 18+.

import { readFile, writeFile, mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const target = argValue("--target") ?? "https://contextboundary-gw-staging.kannanokannan.workers.dev/mcp";
const simulateStale = args.includes("--stale");
const saveReceipts = args.includes("--save-receipts");

function argValue(flag) {
  const i = args.indexOf(flag);
  return i >= 0 ? args[i + 1] : undefined;
}

// ---------------------------------------------------------------------------
// Stage 1 — ContextOps: deterministic context checks BEFORE the agent acts.
// Signals never mutate agent state; a failed check stops the run, full stop.
// ---------------------------------------------------------------------------
async function contextOpsGate(manifest) {
  const failures = [];

  if (!manifest.context?.context_owner) {
    failures.push("ownership: no accountable context owner (ungoverned context)");
  }

  const lastValidated = simulateStale
    ? new Date(Date.now() - 30 * 24 * 3600 * 1000)
    : new Date(manifest.context.last_validated);
  const ageHours = (Date.now() - lastValidated.getTime()) / 3600000;
  if (ageHours > manifest.context.max_age_hours) {
    failures.push(`freshness: context last validated ${ageHours.toFixed(0)}h ago, max ${manifest.context.max_age_hours}h`);
  }

  if (manifest.operational_context?.change_window?.state !== "open") {
    failures.push("operational context: change window is not open");
  }
  if (!manifest.operational_context?.cab_reference) {
    failures.push("operational context: no CAB reference for a high-risk change");
  }

  const untrusted = (manifest.context.sources ?? []).filter((s) => s.trust !== "trusted");
  if (untrusted.length > 0) {
    failures.push(`source trust: untrusted sources in context: ${untrusted.map((s) => s.id).join(", ")}`);
  }

  return failures;
}

// ---------------------------------------------------------------------------
// Stage 2 — ContextBoundary: every action crosses the gateway. The gateway
// decides; the agent obeys. Each decision returns an audit receipt.
// ---------------------------------------------------------------------------
let rpcId = 0;
async function boundaryEvaluate(agentId, action) {
  const res = await fetch(target, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "mcp-method": "boundary/evaluate",
      ...(agentId ? { "boundary-agent-id": agentId } : {})
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: ++rpcId,
      method: "boundary/evaluate",
      params: { action }
    })
  });
  if (!res.ok) throw new Error(`gateway HTTP ${res.status}`);
  const body = await res.json();
  if (!body.result) throw new Error(`no result in response: ${JSON.stringify(body)}`);
  return body.result;
}

function printDecision(label, result) {
  const d = result.decision?.toUpperCase();
  const badge = d === "ALLOW" ? "[ALLOW]  " : d === "DENY" ? "[DENY]   " : "[APPROVE]";
  console.log(`\n${badge} ${label}`);
  console.log(`          rule: ${result.rule_id} · reason: ${result.reason ?? "-"}`);
  if (result.obligation) console.log(`          obligation: ${JSON.stringify(result.obligation)}`);
  if (result.audit) {
    console.log(`          receipt: agent=${result.audit.agent_id} owner=${result.audit.accountable_owner} tier=${result.audit.tier_in_force} ts=${result.audit.timestamp}`);
  }
}

async function main() {
  const manifest = JSON.parse(await readFile(join(here, "context-manifest.json"), "utf8"));
  const agent = manifest.agent_binding.agent_id;

  console.log(`Governed AMS Ticket Change Agent — ${manifest.ticket.id}: ${manifest.ticket.summary}`);
  console.log(`Gateway: ${target}`);

  // Stage 1: ContextOps
  console.log("\n── Stage 1 · ContextOps context gate ──");
  const failures = await contextOpsGate(manifest);
  if (failures.length > 0) {
    for (const f of failures) console.log(`[BLOCK]   ${f}`);
    console.log("\nContext gate failed. The agent never reaches the boundary. Fix the context, not the agent.");
    process.exit(2);
  }
  console.log(`[PASS]    owner=${manifest.context.context_owner} · fresh (< ${manifest.context.max_age_hours}h) · change window open · CAB=${manifest.operational_context.cab_reference}`);

  // Stage 2: ContextBoundary flows
  console.log("\n── Stage 2 · ContextBoundary action governance ──");
  const receipts = [];

  // Flow A — ALLOW: triage the alert/ticket (T1 capability, egress within tier)
  const a = await boundaryEvaluate(agent, {
    type: "invoke",
    capability: "triage-alert",
    payload: { ticket: manifest.ticket.id }
  });
  printDecision(`Flow A · triage ${manifest.ticket.id} (read + classify)`, a);
  receipts.push({ flow: "A-allow", ...a.audit });

  // Flow B — APPROVE: apply the high-risk change. Capability requires T3;
  // the agent holds T1. Deterministic approval — the change cannot execute.
  const b = await boundaryEvaluate(agent, {
    type: "invoke",
    capability: "apply-change",
    payload: { ticket: manifest.ticket.id, change: "rotate smtp relay config" }
  });
  printDecision("Flow B · apply high-risk change to prod-mail-gateway", b);
  receipts.push({ flow: "B-approve", ...b.audit });

  // Flow C — DENY: the change involves credentials; an egress attempt carrying
  // credential-shaped content is Tier I on a Tier II crossing. Detector fires.
  const c = await boundaryEvaluate(agent, {
    type: "egress",
    capability: "triage-alert",
    crossing_egress_tier: "II",
    payload_egress_tier: "II",
    payload: { label: "II", message: 'password = "old-relay-credential-9f3k2m"' }
  });
  printDecision("Flow C · egress ticket note containing the old credential", c);
  receipts.push({ flow: "C-deny", ...c.audit });

  if (saveReceipts) {
    const dir = join(here, "receipts");
    await mkdir(dir, { recursive: true });
    const file = join(dir, `run-${new Date().toISOString().replace(/[:.]/g, "-")}.json`);
    await writeFile(file, JSON.stringify(receipts, null, 2));
    console.log(`\nReceipts written: ${file}`);
  }

  console.log("\nDone. Allowed action executed; high-risk change is parked on deterministic approval; credential egress was blocked at the boundary. Every decision above has a receipt.");
}

main().catch((err) => {
  console.error(`demo failed: ${err.message}`);
  process.exit(1);
});
