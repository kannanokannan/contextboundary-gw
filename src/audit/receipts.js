import { canonicalize, hashIntentEnvelope, safeIntentEnvelope, sha256Hex } from "../intent/canonical.js";
import { actionCommitment, verifyAgentReceiptEvent } from "../identity/signatures.js";
import { signGatewaySeal, verifyGatewaySeal } from "../identity/gateway-key.js";

const GENESIS_PREFIX = "cb-audit-genesis";

export async function createSealedReceipt({ sessionId = crypto.randomUUID(), identity, action, result, policyHash, retention, gatewayKey, envelopeContext = null, agentAuth = null, r4Context = null }) {
  if (!gatewayKey) throw new Error("GATEWAY_ED25519_PRIVATE_JWK is required to issue an R6 receipt");
  const timestamp = new Date().toISOString();
  const sessionSpanId = crypto.randomUUID();
  const base = {
    session_id: sessionId,
    hash_alg: "sha-256",
    agent_id: identity?.id ?? null,
    accountable_owner: identity?.accountable_owner ?? null,
    tier_in_force: identity?.autonomy_tier ?? null,
    policy_hash: policyHash,
    timestamp
  };
  const envelope = envelopeContext?.envelope ? safeIntentEnvelope(envelopeContext.envelope) : null;
  const start = await hashEvent({
    ...base, span_id: sessionSpanId, parent_span_id: null, seq: 0, event_type: "session.start",
    prev_hash: await genesisHash(sessionId, policyHash), action: { type: "session.start" }, decision: "allow", rule_id: "R1", reason: "session_opened",
    egress_tier_seen: null, detector_id: null, obligation: null, replay_inputs: {},
    ...(envelope ? { envelope_hash: envelopeContext.envelope_hash, declared_by: envelope.declared_by, expires_at: envelope.limits?.expires_at ?? null } : {})
  });
  const decision = await hashEvent({
    ...base, span_id: crypto.randomUUID(), seq: 1, event_type: eventTypeFor(action), prev_hash: start.event_hash, parent_span_id: sessionSpanId,
    action: await actionCommitment(action), decision: result.decision, rule_id: result.rule_id, reason: result.reason,
    egress_tier_seen: result.egress_tier_seen ?? null, detector_id: result.detector_id ?? null, obligation: result.obligation ?? null,
    replay_inputs: replayInputs(action, result), in_envelope: result.in_envelope === true, envelope_failing_dimension: result.envelope_failing_dimension ?? null,
    agent_sig: agentAuth?.agent_sig ?? null, agent_key_id: agentAuth?.agent_key_id ?? null, nonce: agentAuth?.nonce ?? null,
    agent_timestamp: agentAuth?.timestamp ?? null, agent_seq: agentAuth?.seq ?? null,
    ...(r4Context?.original_action_hash ? { original_action_hash: r4Context.original_action_hash } : {}),
    ...(r4Context?.transform_id ? { transform_id: r4Context.transform_id } : {}),
    ...(r4Context?.resulting_action_hash ? { resulting_action_hash: r4Context.resulting_action_hash } : {}),
    ...(r4Context?.resume_token ? { resume_token: r4Context.resume_token } : {}),
    ...(r4Context?.defer_reason ? { defer_reason: r4Context.defer_reason } : {})
  });
  const intermediate = [start, decision];
  if (result.envelope_amendment_required) {
    intermediate.push(await hashEvent({
      ...base, span_id: crypto.randomUUID(), seq: intermediate.length, event_type: "envelope.amend", prev_hash: intermediate.at(-1).event_hash, parent_span_id: sessionSpanId,
      action: { type: "envelope.amend" }, decision: "approve", rule_id: "R3", reason: "envelope_amendment_required",
      egress_tier_seen: null, detector_id: null, obligation: result.obligation ?? null, replay_inputs: {},
      old_envelope_hash: envelopeContext?.envelope_hash ?? null, new_envelope_hash: null, amendment_status: "approval_required"
    }));
  }
  const sealDraft = await hashEvent({
    ...base, span_id: crypto.randomUUID(), seq: intermediate.length, event_type: "session.seal", prev_hash: intermediate.at(-1).event_hash,
    parent_span_id: sessionSpanId, action: { type: "session.seal" }, decision: "allow", rule_id: "R1", reason: "session_sealed",
    egress_tier_seen: null, detector_id: null, obligation: null, replay_inputs: {}, event_count: intermediate.length,
    sealed_final_hash: intermediate.at(-1).event_hash, retention, seal_alg: "ed25519", gateway_key_id: gatewayKey.key_id
  });
  const seal = { ...sealDraft, seal_sig: await signGatewaySeal(gatewayKey, withoutHashAndSignature(sealDraft)) };
  return { version: "contextboundary-audit/v1", ...(envelope ? { intent_envelope: envelope } : {}), events: [...intermediate, seal] };
}

export async function policyArtifactHash(policyData) {
  return sha256Hex(canonicalize(policyData));
}

export async function verifyReceipt(receipt, publicKeys) {
  const events = receipt?.events;
  if (!Array.isArray(events) || events.length < 2) return invalid("gap_detected", "receipt has no complete event sequence");
  const sessionId = events[0]?.session_id;
  const policyHash = events[0]?.policy_hash;
  if (!sessionId || !policyHash) return invalid("event_altered", "session_id and policy_hash are required");
  if (receipt.intent_envelope) {
    const envelopeHash = await hashIntentEnvelope(receipt.intent_envelope);
    if (events[0]?.envelope_hash !== envelopeHash) return invalid("envelope_tampered", "frozen envelope hash does not match");
    if (events[0]?.declared_by !== receipt.intent_envelope.declared_by || events[0]?.expires_at !== receipt.intent_envelope.limits?.expires_at) return invalid("envelope_tampered", "receipt envelope metadata does not match");
  }

  const seenNonces = new Set();
  for (let index = 0; index < events.length; index += 1) {
    const event = events[index];
    if (event.seq !== index) return invalid("gap_detected", `expected seq ${index}, found ${event.seq}`);
    if (event.session_id !== sessionId) return invalid("event_altered", "events belong to different sessions");
    if (event.policy_hash !== policyHash) return invalid("policy_substituted", "events use different policy hashes");
    if (requiresAgentSignature(event)) {
      if (!event.agent_sig || !event.agent_key_id || !event.nonce || !Number.isInteger(event.agent_seq) || !event.agent_timestamp) return invalid("agent_sig_invalid", "decision event is missing agent signature evidence");
      if (seenNonces.has(event.nonce)) return invalid("replay_detected", "receipt reuses an agent nonce");
      seenNonces.add(event.nonce);
      const agentVerified = await verifyAgentReceiptEvent(event, publicKeys?.agent_keys);
      if (!agentVerified.ok) return invalid(agentVerified.code, "agent signature does not verify against the registered public key");
    }
    const expectedHash = await sha256Hex(canonicalize(withoutHashAndSignature(event)));
    if (event.event_hash !== expectedHash) return invalid("event_altered", `event ${index} hash does not match`);
    const expectedPrev = index === 0 ? await genesisHash(sessionId, policyHash) : events[index - 1].event_hash;
    if (event.prev_hash !== expectedPrev) return invalid("chain_broken", `event ${index} does not link to its predecessor`);
  }

  const seal = events.at(-1);
  if (seal.event_type !== "session.seal" || !seal.retention?.expires_at || seal.seal_alg !== "ed25519" || !seal.gateway_key_id || !seal.seal_sig) return invalid("seal_sig_invalid", "terminal Ed25519 seal is incomplete");
  if (seal.event_count !== events.length - 1 || seal.sealed_final_hash !== events.at(-2).event_hash) return invalid("seal_sig_invalid", "seal count or final hash does not match");
  const gatewayPublicKey = publicKeys?.gateway_keys?.[seal.gateway_key_id];
  if (!gatewayPublicKey || !(await verifyGatewaySeal(gatewayPublicKey, withoutHashAndSignature(seal), seal.seal_sig))) return invalid("seal_sig_invalid", "gateway Ed25519 seal does not verify");
  return { valid: true, code: "intact", event_count: events.length };
}

export { canonicalize };

async function hashEvent(event) {
  return { ...event, event_hash: await sha256Hex(canonicalize(withoutHashAndSignature(event))) };
}

function withoutHashAndSignature(event) {
  const { event_hash, seal_sig, ...unsigned } = event;
  return unsigned;
}

function replayInputs(action, result) {
  return { crossing_egress_tier: action?.crossing_egress_tier ?? null, payload_egress_tier: action?.payload_egress_tier ?? null, detector_firings: result?.detector_id ? [result.detector_id] : [] };
}

function eventTypeFor(action) {
  return ["discover", "invoke", "egress", "reroute"].includes(action?.type) ? action.type : "invoke";
}

function requiresAgentSignature(event) {
  return !["session.start", "session.seal", "envelope.amend"].includes(event?.event_type);
}

async function genesisHash(sessionId, policyHash) {
  return sha256Hex(`${GENESIS_PREFIX}${sessionId}${policyHash}`);
}

function invalid(code, message) {
  return { valid: false, code, message };
}
