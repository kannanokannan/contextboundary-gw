const encoder = new TextEncoder();

export function canonicalize(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(",")}}`;
}

export async function sha256Hex(value) {
  const bytes = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return toHex(new Uint8Array(bytes));
}

export async function hashIntentEnvelope(envelope) {
  return sha256Hex(canonicalize({
    authorized: envelope?.authorized ?? null,
    limits: envelope?.limits ?? null
  }));
}

export async function hmacSha256Hex(key, value) {
  const cryptoKey = await crypto.subtle.importKey("raw", encoder.encode(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signature = await crypto.subtle.sign("HMAC", cryptoKey, encoder.encode(value));
  return toHex(new Uint8Array(signature));
}

export function safeIntentEnvelope(envelope) {
  if (!envelope || typeof envelope !== "object") return null;
  return {
    envelope_id: envelope.envelope_id,
    session_id: envelope.session_id,
    declared_by: envelope.declared_by,
    declared_at: envelope.declared_at,
    task_ref: envelope.task_ref,
    authorized: envelope.authorized,
    limits: envelope.limits,
    amendment_policy: envelope.amendment_policy
  };
}

function toHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}
