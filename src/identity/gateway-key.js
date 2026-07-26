import { canonicalize } from "../intent/canonical.js";
import { fromBase64Url, toBase64Url } from "./signatures.js";

const encoder = new TextEncoder();

export function gatewayKeyMaterial(env) {
  const keyId = env?.GATEWAY_ED25519_KEY_ID;
  const privateJwk = parsePrivateJwk(env?.GATEWAY_ED25519_PRIVATE_JWK);
  return keyId && privateJwk ? { key_id: keyId, private_jwk: { kty: "OKP", crv: "Ed25519", x: privateJwk.x, d: privateJwk.d }, public_jwk: { kty: "OKP", crv: "Ed25519", x: privateJwk.x } } : null;
}

export async function signGatewaySeal(keyMaterial, value) {
  const privateKey = await crypto.subtle.importKey("jwk", keyMaterial.private_jwk, { name: "Ed25519" }, false, ["sign"]);
  const signature = await crypto.subtle.sign("Ed25519", privateKey, encoder.encode(canonicalize(value)));
  return toBase64Url(new Uint8Array(signature));
}

export async function verifyGatewaySeal(publicJwk, value, signature) {
  try {
    const publicKey = await crypto.subtle.importKey("jwk", { kty: "OKP", crv: "Ed25519", x: publicJwk.x }, { name: "Ed25519" }, false, ["verify"]);
    return crypto.subtle.verify("Ed25519", publicKey, fromBase64Url(signature), encoder.encode(canonicalize(value)));
  } catch {
    return false;
  }
}

function parsePrivateJwk(value) {
  try {
    const parsed = typeof value === "string" ? JSON.parse(value) : value;
    return parsed?.kty === "OKP" && parsed?.crv === "Ed25519" && typeof parsed?.x === "string" && typeof parsed?.d === "string" ? parsed : null;
  } catch {
    return null;
  }
}
