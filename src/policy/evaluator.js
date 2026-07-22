import { loadPolicy } from "@open-policy-agent/opa-wasm";
import policyWasm from "./generated/policy.wasm";
import policyData from "./generated/data.json";

let policyPromise;
const detectorPatterns = policyData.egress_detectors.map((detector) => ({
  ...detector,
  patterns: detector.pattern_set.patterns.map((pattern) => new RegExp(pattern, "i"))
}));

export async function evaluateBoundary(identityId, action, sessionContext = {}) {
  const identity = identityRecord(identityId);
  if (action.type === "discover" && identity) return evaluateDiscovery(identity);
  if (action.type === "session" && identity) return evaluateSession(identityId, action);

  const egress = classifyEgress(action);
  const policy = await getPolicy();
  const started = performance.now();
  const evaluated = policy.evaluate({
    identity_id: identityId ?? "",
    action,
    data: {
      envelope: sessionContext.envelope ?? null,
      session_trace: sessionContext.prior_action_trace ?? []
    },
    effective_egress_protection: egress.protection,
    crossing_ceiling_protection: protectionFor(action.crossing_egress_tier)
  });
  const engineEvalMs = performance.now() - started;
  const rego = evaluated?.[0]?.result ?? {
    decision: "deny",
    rule_id: "R3",
    reason: "closed_by_default",
    obligations: []
  };
  const approvalRequired = rego.obligations?.some((obligation) => obligation.approval_required);

  return {
    decision: approvalRequired ? "approve" : rego.decision,
    rule_id: rego.rule_id,
    reason: rego.reason,
    obligations: rego.obligations ?? [],
    obligation: rego.obligations?.[0] ?? null,
    effective_tier: identity?.autonomy_tier ?? null,
    egress_tier_seen: egress.tier,
    detector_id: egress.detectorId,
    target: rego.target ?? null,
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
    action: { type: "invoke", capability: "triage-alert", payload: {} },
    effective_egress_protection: 2,
    crossing_ceiling_protection: 2
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

function evaluateDiscovery(identity) {
  const capabilities = Object.values(policyData.capabilities)
    .filter((capability) =>
      identity.tier_ordinal >= capability.discover_min_tier_ordinal &&
      identity.trusted_sources.includes(capability.source))
    .map((capability) => capability.id);

  return {
    decision: "allow",
    rule_id: "R2",
    reason: "discovery_filtered",
    obligations: [],
    obligation: null,
    effective_tier: identity.autonomy_tier,
    egress_tier_seen: null,
    detector_id: null,
    capabilities,
    engine_eval_ms: 0
  };
}

async function evaluateSession(identityId, action) {
  const steps = [];
  for (const step of action.steps ?? []) {
    steps.push({ action: step, result: await evaluateBoundary(identityId, step) });
  }
  const terminal = steps.at(-1)?.result ?? {
    decision: "deny",
    rule_id: "R3",
    reason: "closed_by_default"
  };
  return {
    ...terminal,
    reason: "session_reconstructable",
    audit_steps: steps
  };
}

function classifyEgress(action) {
  if (action.type !== "egress") return { protection: 0, tier: null, detectorId: null };

  const capability = capabilityRecord(action.capability);
  const declaredProtection = Math.max(
    capability?.egress_protection ?? 0,
    protectionFor(action.payload_egress_tier)
  );
  const detectorText = extractDetectorText(action.payload);
  let effectiveProtection = declaredProtection;
  let detectorId = null;

  for (const detector of detectorPatterns) {
    const uncertain = detectorText === null || detectorText.length > detector.pattern_set.max_payload_chars;
    const matched = uncertain || detector.patterns.some((pattern) => pattern.test(detectorText));
    if (matched && detector.min_protection > effectiveProtection) {
      effectiveProtection = detector.min_protection;
      detectorId = detector.id;
    }
  }

  return {
    protection: effectiveProtection,
    tier: tierForProtection(effectiveProtection),
    detectorId
  };
}

function extractDetectorText(payload) {
  try {
    const values = [];
    const visit = (value, key = "") => {
      if (value === null || value === undefined) return;
      if (typeof value === "object") {
        for (const [childKey, childValue] of Object.entries(value)) visit(childValue, childKey);
        return;
      }
      values.push(key ? `${key}=${String(value)}` : String(value));
    };
    visit(payload);
    return values.join("\n");
  } catch {
    return null;
  }
}

function protectionFor(tier) {
  return policyData.egress_protection[tier] ?? 0;
}

function tierForProtection(protection) {
  return Object.entries(policyData.egress_protection)
    .find(([, value]) => value === protection)?.[0] ?? null;
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
