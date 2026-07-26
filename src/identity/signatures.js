import { canonicalize, sha256Hex } from "../intent/canonical.js";

const encoder = new TextEncoder();
const MAX_SIGNATURE_AGE_MS = 5 * 60_000;
const MAX_FUTURE_SKEW_MS = 30_000;

export async function actionCommitment(action) {
  return {
    type: action?.type ?? "unknown",
    ...(action?.capability ? { capability: action.capability } : {}),
    ...(action?.endpoint ? { endpoint: action.endpoint } : {}),
    action_hash: await sha256Hex(canonicalize(action ?? {}))
  };
}

export async function signingPayload({ sessionId, seq, action, nonce, timestamp }) {
  return canonicalize({ session_id: sessionId, seq, action: await actionCommitment(action), nonce, timestamp });
}

export async function verifyAgentSignature({ identity, action, sessionId, keyId, signature, nonce, timestamp, seq, env }) {
  if (!identity || !sessionId || !validNonce(nonce) || !validSequence(seq) || !freshTimestamp(timestamp) || typeof keyId !== "string" || typeof signature !== "string") return invalid();
  const key = findAgentKey(identity, keyId, env);
  if (!key) return invalid();
  try {
    const publicKey = await crypto.subtle.importKey("jwk", publicJwk(key.public_jwk), { name: "Ed25519" }, false, ["verify"]);
    const verified = await crypto.subtle.verify("Ed25519", publicKey, fromBase64Url(signature), encoder.encode(await signingPayload({ sessionId, seq, action, nonce, timestamp })));
    return verified ? { ok: true, agent_key_id: keyId, agent_sig: signature, nonce, timestamp, seq, action: await actionCommitment(action) } : invalid();
  } catch {
    return invalid();
  }
}

export function findAgentKey(identity, keyId, env) {
  const configured = configuredKeys(env)?.[identity.id];
  const keys = Array.isArray(configured) ? configured : identity.agent_keys;
  return Array.isArray(keys) ? keys.find((key) => key?.key_id === keyId && isEd25519PublicJwk(key.public_jwk)) ?? null : null;
}

export async function verifyAgentReceiptEvent(event, agentKeys) {
  const keys = agentKeys?.[event?.agent_id];
  const key = Array.isArray(keys) ? keys.find((candidate) => candidate?.key_id === event.agent_key_id && isEd25519PublicJwk(candidate.public_jwk)) : null;
  if (!key) return { ok: false, code: "unknown_key_id" };
  try {
    const publicKey = await crypto.subtle.importKey("jwk", publicJwk(key.public_jwk), { name: "Ed25519" }, false, ["verify"]);
    const valid = await crypto.subtle.verify("Ed25519", publicKey, fromBase64Url(event.agent_sig), encoder.encode(canonicalize({
      session_id: event.session_id, seq: event.agent_seq, action: event.action, nonce: event.nonce, timestamp: event.agent_timestamp
    })));
    return valid ? { ok: true } : { ok: false, code: "agent_sig_invalid" };
  } catch {
    return { ok: false, code: "agent_sig_invalid" };
  }
}

export function toBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

export function fromBase64Url(value) {
  const padded = value.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - value.length % 4) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function configuredKeys(env) {
  if (!env?.AGENT_KEY_REGISTRY) return null;
  try {
    const parsed = typeof env.AGENT_KEY_REGISTRY === "string" ? JSON.parse(env.AGENT_KEY_REGISTRY) : env.AGENT_KEY_REGISTRY;
    return parsed && typeof parsed === "object" ? parsed : null;
  } catch {
    return null;
  }
}

function freshTimestamp(timestamp) {
  const parsed = typeof timestamp === "string" ? Date.parse(timestamp) : NaN;
  if (!Number.isFinite(parsed)) return false;
  const delta = Date.now() - parsed;
  return delta <= MAX_SIGNATURE_AGE_MS && delta >= -MAX_FUTURE_SKEW_MS;
}

function validNonce(value) {
  return typeof value === "string" && value.length >= 16 && value.length <= 256;
}

function validSequence(value) {
  return Number.isInteger(value) && value >= 0;
}

function isEd25519PublicJwk(value) {
  return value?.kty === "OKP" && value?.crv === "Ed25519" && typeof value?.x === "string" && !Object.hasOwn(value, "d");
}

function publicJwk(value) {
  return { kty: "OKP", crv: "Ed25519", x: value.x };
}

function invalid() {
  return { ok: false, reason: "identity_unverified" };
}
