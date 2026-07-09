import { loadPolicy } from "@open-policy-agent/opa-wasm";
import policyWasm from "./generated/policy.wasm";
import policyData from "./generated/data.json";

let policyPromise;

export async function evaluateBoundary(identityId, action) {
  const policy = await getPolicy();
  const started = performance.now();
  const evaluated = policy.evaluate({
    identity_id: identityId ?? "",
    action
  });
  const engineEvalMs = performance.now() - started;
  const rego = evaluated?.[0]?.result ?? {
    decision: "deny",
    rule_id: "R3",
    reason: "closed_by_default",
    obligations: []
  };

  const approvalRequired = rego.obligations?.includes("approval_required");
  const payloadTierIgnored = approvalRequired &&
    Object.hasOwn(action?.payload ?? {}, "autonomy_tier");

  return {
    decision: approvalRequired ? "approve" : rego.decision,
    rule_id: rego.rule_id,
    reason: payloadTierIgnored ? "payload_tier_ignored" : rego.reason,
    obligations: rego.obligations ?? [],
    engine_eval_ms: engineEvalMs
  };
}

export function identityRecord(identityId) {
  return policyData.identities[identityId] ?? null;
}

export function capabilityRecord(capabilityId) {
  return policyData.capabilities[capabilityId] ?? null;
}

export async function benchmarkBoundary(iterations) {
  const count = Math.max(1, Math.min(Number(iterations) || 100, 10000));
  const policy = await getPolicy();
  const input = {
    identity_id: "agent:run-l1",
    action: { type: "invoke", capability: "triage-alert", payload: {} }
  };
  policy.evaluate(input);
  const started = performance.now();
  for (let index = 0; index < count; index += 1) policy.evaluate(input);
  const elapsedMs = performance.now() - started;
  return {
    engine: "rego-wasm",
    iterations: count,
    elapsed_ms: elapsedMs,
    per_eval_ms: elapsedMs / count
  };
}

async function getPolicy() {
  if (!policyPromise) {
    policyPromise = loadPolicy(policyWasm).then((policy) => {
      policy.setData(policyData);
      return policy;
    });
  }
  return policyPromise;
}
