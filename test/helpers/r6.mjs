import { hmacSha256Hex } from "../../src/intent/canonical.js";
import { signingPayload, toBase64Url } from "../../src/identity/signatures.js";

export async function createEphemeralR6Fixtures({ keyId = "test-agent-ed25519-v1", gatewayKeyId = "test-gateway-ed25519-v1" } = {}) {
  const [agent, gateway] = await Promise.all([createKeyPair(), createKeyPair()]);
  const agentRegistry = {
    "agent:run-l1": [{ key_id: keyId, public_jwk: agent.public_jwk }],
    "agent:run-l3": [{ key_id: keyId, public_jwk: agent.public_jwk }],
    "agent:run-l3v": [{ key_id: keyId, public_jwk: agent.public_jwk }]
  };
  return { agent, gateway, keyId, gatewayKeyId, agentRegistry };
}

export async function signedHeaders(fixtures, { sessionId, seq, action }) {
  const nonce = crypto.randomUUID();
  const timestamp = new Date().toISOString();
  const privateKey = await crypto.subtle.importKey("jwk", fixtures.agent.private_jwk, { name: "Ed25519" }, false, ["sign"]);
  const signature = await crypto.subtle.sign("Ed25519", privateKey, new TextEncoder().encode(await signingPayload({ sessionId, seq, action, nonce, timestamp })));
  return {
    "boundary-agent-key-id": fixtures.keyId,
    "boundary-agent-signature": toBase64Url(new Uint8Array(signature)),
    "boundary-agent-nonce": nonce,
    "boundary-agent-timestamp": timestamp,
    "boundary-agent-seq": String(seq)
  };
}

export async function ownerProof(ownerBootstrapKey, envelope) {
  const { hashIntentEnvelope } = await import("../../src/intent/canonical.js");
  return hmacSha256Hex(ownerBootstrapKey, await hashIntentEnvelope(envelope));
}

export function workerR6Vars(fixtures) {
  return [
    `GATEWAY_ED25519_KEY_ID:${fixtures.gatewayKeyId}`,
    `GATEWAY_ED25519_PRIVATE_JWK:${JSON.stringify(fixtures.gateway.private_jwk)}`,
    `AGENT_KEY_REGISTRY:${JSON.stringify(fixtures.agentRegistry)}`
  ];
}

export function thirdPartyPublicKeys(fixtures) {
  return { agent_keys: fixtures.agentRegistry, gateway_keys: { [fixtures.gatewayKeyId]: fixtures.gateway.public_jwk } };
}

async function createKeyPair() {
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  return {
    private_jwk: await crypto.subtle.exportKey("jwk", pair.privateKey),
    public_jwk: await crypto.subtle.exportKey("jwk", pair.publicKey)
  };
}
