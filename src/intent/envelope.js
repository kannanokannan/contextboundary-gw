import { hashIntentEnvelope, safeIntentEnvelope } from "./canonical.js";

const TIER_ORDINAL = { T0: 0, T1: 1, T2: 2, T3: 3 };
const EGRESS_PROTECTION = { I: 3, II: 2, III: 1 };
const DEFAULT_DRIFT_REVIEW_THRESHOLD = 3;

export async function validateIntentEnvelope(envelope, identity, sessionId) {
  if (!identity) return invalid("identity_unbound");
  if (!envelope || typeof envelope !== "object") return invalid("invalid_envelope");
  if (envelope.session_id !== sessionId || !nonEmptyString(envelope.session_id)) return invalid("session_id_mismatch");
  if (!nonEmptyString(envelope.envelope_id) || !nonEmptyString(envelope.task_ref)) return invalid("invalid_envelope");
  if (!isTimestamp(envelope.declared_at)) return invalid("invalid_declared_at");
  if (envelope.declared_by === identity.id) return invalid("declared_by_agent");
  if (envelope.declared_by !== identity.accountable_owner) return invalid("declared_by_not_accountable_owner");

  const authorized = envelope.authorized;
  const limits = envelope.limits;
  if (!authorized || !limits || typeof authorized !== "object" || typeof limits !== "object") return invalid("invalid_envelope");
  if (!stringArray(authorized.capabilities) || !stringArray(authorized.sources) || !stringArray(authorized.endpoints)) return invalid("invalid_authorized_set");
  if (!(authorized.autonomy_tier_ceiling in TIER_ORDINAL) || !(identity.autonomy_tier in TIER_ORDINAL)) return invalid("invalid_autonomy_tier");
  if (TIER_ORDINAL[authorized.autonomy_tier_ceiling] > TIER_ORDINAL[identity.autonomy_tier]) return invalid("autonomy_tier_ceiling_exceeds_agent");
  if (!(authorized.egress_tier_ceiling in EGRESS_PROTECTION)) return invalid("invalid_egress_tier_ceiling");
  if (!Number.isInteger(limits.max_actions) || limits.max_actions < 1 || !isTimestamp(limits.expires_at)) return invalid("invalid_limits");
  if (limits.drift_review_threshold !== undefined && (!Number.isInteger(limits.drift_review_threshold) || limits.drift_review_threshold < 1)) {
    return invalid("invalid_drift_review_threshold");
  }
  if (envelope.amendment_policy !== undefined && envelope.amendment_policy !== "approval_required") return invalid("invalid_amendment_policy");

  const frozen = structuredClone(envelope);
  const envelopeHash = await hashIntentEnvelope(frozen);
  if (frozen.envelope_hash !== undefined && frozen.envelope_hash !== envelopeHash) return invalid("envelope_hash_mismatch");
  frozen.envelope_hash = envelopeHash;
  return { valid: true, envelope: frozen, envelope_hash: envelopeHash };
}

export function evaluateIntentEnvelope({ envelope, priorActionTrace = [], action, baseResult, capability }) {
  if (baseResult.decision === "deny") {
    return { result: withEnvelopeFields(baseResult, false, "base_policy"), traceEventType: eventTypeFor(action), drift: false };
  }

  const violation = envelopeViolation({ envelope, priorActionTrace, action, baseResult, capability });
  if (!violation) {
    const nearEdge = isNearEdge(envelope, priorActionTrace, baseResult);
    return { result: withEnvelopeFields(baseResult, true, null), traceEventType: eventTypeFor(action), drift: nearEdge };
  }

  const requiresApproval = envelope.amendment_policy === "approval_required";
  const result = {
    ...baseResult,
    decision: requiresApproval ? "approve" : "deny",
    rule_id: "R3",
    reason: `envelope_violation:${violation}`,
    obligation: requiresApproval
      ? { approval_required: true, reason: "envelope_amendment_required", failing_dimension: violation, rule_id: "R3" }
      : null,
    obligations: requiresApproval
      ? [...(baseResult.obligations ?? []), { approval_required: true, reason: "envelope_amendment_required", failing_dimension: violation, rule_id: "R3" }]
      : [],
    in_envelope: false,
    envelope_failing_dimension: violation,
    envelope_amendment_required: requiresApproval
  };
  return { result, traceEventType: requiresApproval ? "envelope.amend" : eventTypeFor(action), drift: true };
}

export function safeTraceAction(action) {
  return {
    type: action?.type ?? "unknown",
    ...(action?.capability ? { capability: action.capability } : {}),
    ...(action?.endpoint ? { endpoint: action.endpoint } : {})
  };
}

export function driftReviewThreshold(envelope) {
  return envelope?.limits?.drift_review_threshold ?? DEFAULT_DRIFT_REVIEW_THRESHOLD;
}

function envelopeViolation({ envelope, priorActionTrace, action, baseResult, capability }) {
  const authorized = envelope.authorized;
  if (action?.type !== "discover" && !authorized.capabilities.includes(action?.capability)) return "capability";
  if (action?.type !== "discover" && !authorized.sources.includes(capability?.source)) return "source";
  if (action?.type === "egress" && !authorized.endpoints.includes(action?.endpoint)) return "endpoint";
  if (action?.type === "egress" && protectionFor(baseResult.egress_tier_seen) < protectionFor(authorized.egress_tier_ceiling)) return "egress";
  if (tierFor(baseResult.effective_tier) > tierFor(authorized.autonomy_tier_ceiling)) return "autonomy";
  if (priorActionTrace.length >= envelope.limits.max_actions) return "budget";
  if (Date.now() >= Date.parse(envelope.limits.expires_at)) return "expiry";
  return null;
}

function isNearEdge(envelope, priorActionTrace, baseResult) {
  const budgetNearEdge = priorActionTrace.length + 1 >= envelope.limits.max_actions;
  const egressNearEdge = baseResult.egress_tier_seen !== null
    && protectionFor(baseResult.egress_tier_seen) === protectionFor(envelope.authorized.egress_tier_ceiling);
  return budgetNearEdge || egressNearEdge;
}

function withEnvelopeFields(result, inEnvelope, failingDimension) {
  return { ...result, in_envelope: inEnvelope, envelope_failing_dimension: failingDimension };
}

function eventTypeFor(action) {
  return ["discover", "invoke", "egress"].includes(action?.type) ? action.type : "invoke";
}

function protectionFor(tier) {
  return EGRESS_PROTECTION[tier] ?? -1;
}

function tierFor(tier) {
  return TIER_ORDINAL[tier] ?? Number.POSITIVE_INFINITY;
}

function nonEmptyString(value) {
  return typeof value === "string" && value.trim().length > 0;
}

function stringArray(value) {
  return Array.isArray(value) && value.every(nonEmptyString);
}

function isTimestamp(value) {
  return typeof value === "string" && Number.isFinite(Date.parse(value));
}

function invalid(reason) {
  return { valid: false, reason };
}

export { hashIntentEnvelope, safeIntentEnvelope };
