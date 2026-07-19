const encoder = new TextEncoder();
const GENESIS_PREFIX = "cb-audit-genesis";

export async function createSealedReceipt({ sessionId = crypto.randomUUID(), identity, action, result, policyHash, retention, sealKey }) {
  if (!sealKey) throw new Error("AUDIT_SEAL_KEY is required to issue a D4 receipt");
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
  const start = await hashEvent({
    ...base,
    span_id: sessionSpanId,
    parent_span_id: null,
    seq: 0,
    event_type: "session.start",
    prev_hash: await genesisHash(sessionId, policyHash),
    action: { type: "session.start" },
    decision: "allow",
    rule_id: "R1",
    reason: "session_opened",
    egress_tier_seen: null,
    detector_id: null,
    obligation: null,
    replay_inputs: {}
  });
  const decision = await hashEvent({
    ...base,
    span_id: crypto.randomUUID(),
    seq: 1,
    event_type: eventTypeFor(action),
    prev_hash: start.event_hash,
    parent_span_id: sessionSpanId,
    action: safeAction(action),
    decision: result.decision,
    rule_id: result.rule_id,
    reason: result.reason,
    egress_tier_seen: result.egress_tier_seen ?? null,
    detector_id: result.detector_id ?? null,
    obligation: result.obligation ?? null,
    replay_inputs: replayInputs(action, result)
  });
  const sealDraft = await hashEvent({
    ...base,
    span_id: crypto.randomUUID(),
    seq: 2,
    event_type: "session.seal",
    prev_hash: decision.event_hash,
    parent_span_id: sessionSpanId,
    action: { type: "session.seal" },
    decision: "allow",
    rule_id: "R1",
    reason: "session_sealed",
    egress_tier_seen: null,
    detector_id: null,
    obligation: null,
    replay_inputs: {},
    event_count: 2,
    sealed_final_hash: decision.event_hash,
    retention,
    seal_method: "hmac-sha256"
  });
  const seal_sig = await hmacHex(sealKey, canonicalize(withoutHashAndSignature(sealDraft)));
  const seal = { ...sealDraft, seal_sig };
  return { version: "contextboundary-audit/v0", events: [start, decision, seal] };
}

export async function policyArtifactHash(policyData) {
  return sha256Hex(canonicalize(policyData));
}

export async function verifyReceipt(receipt, sealKey) {
  const events = receipt?.events;
  if (!Array.isArray(events) || events.length < 2) return invalid("gap_detected", "receipt has no complete event sequence");
  const sessionId = events[0]?.session_id;
  const policyHash = events[0]?.policy_hash;
  if (!sessionId || !policyHash) return invalid("event_altered", "session_id and policy_hash are required");

  for (let index = 0; index < events.length; index += 1) {
    const event = events[index];
    if (event.seq !== index) return invalid("gap_detected", `expected seq ${index}, found ${event.seq}`);
    if (event.session_id !== sessionId) return invalid("event_altered", "events belong to different sessions");
    if (event.policy_hash !== policyHash) return invalid("policy_substituted", "events use different policy hashes");
    const expectedHash = await sha256Hex(canonicalize(withoutHashAndSignature(event)));
    if (event.event_hash !== expectedHash) return invalid("event_altered", `event ${index} hash does not match`);
    const expectedPrev = index === 0
      ? await genesisHash(sessionId, policyHash)
      : events[index - 1].event_hash;
    if (event.prev_hash !== expectedPrev) return invalid("chain_broken", `event ${index} does not link to its predecessor`);
  }

  const seal = events.at(-1);
  if (seal.event_type !== "session.seal" || !seal.retention?.expires_at || !seal.seal_method || !seal.seal_sig) {
    return invalid("seal_invalid", "terminal seal or mandatory retention is missing");
  }
  if (seal.event_count !== events.length - 1 || seal.sealed_final_hash !== events.at(-2).event_hash) {
    return invalid("seal_invalid", "seal count or final hash does not match");
  }
  if (seal.seal_method !== "hmac-sha256" || !sealKey) return invalid("seal_invalid", "unsupported seal method or missing verification key");
  const expectedSignature = await hmacHex(sealKey, canonicalize(withoutHashAndSignature(seal)));
  if (!timingSafeEqual(seal.seal_sig, expectedSignature)) return invalid("seal_invalid", "seal signature does not verify");
  return { valid: true, code: "intact", event_count: events.length };
}

export function canonicalize(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(",")}}`;
}

async function hashEvent(event) {
  return { ...event, event_hash: await sha256Hex(canonicalize(withoutHashAndSignature(event))) };
}

function withoutHashAndSignature(event) {
  const { event_hash, seal_sig, ...unsigned } = event;
  return unsigned;
}

function safeAction(action) {
  return {
    type: action?.type ?? "unknown",
    ...(action?.capability ? { capability: action.capability } : {}),
    ...(action?.endpoint ? { endpoint: action.endpoint } : {})
  };
}

function replayInputs(action, result) {
  return {
    crossing_egress_tier: action?.crossing_egress_tier ?? null,
    payload_egress_tier: action?.payload_egress_tier ?? null,
    detector_firings: result?.detector_id ? [result.detector_id] : []
  };
}

function eventTypeFor(action) {
  return ["discover", "invoke", "egress", "reroute"].includes(action?.type) ? action.type : "invoke";
}

async function genesisHash(sessionId, policyHash) {
  return sha256Hex(`${GENESIS_PREFIX}${sessionId}${policyHash}`);
}

async function sha256Hex(value) {
  const bytes = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return toHex(new Uint8Array(bytes));
}

async function hmacHex(key, value) {
  const cryptoKey = await crypto.subtle.importKey("raw", encoder.encode(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signature = await crypto.subtle.sign("HMAC", cryptoKey, encoder.encode(value));
  return toHex(new Uint8Array(signature));
}

function toHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function timingSafeEqual(left, right) {
  if (typeof left !== "string" || left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  return difference === 0;
}

function invalid(code, message) {
  return { valid: false, code, message };
}
