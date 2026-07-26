import { sha256Hex } from "../intent/canonical.js";

const SAFE_ATTRIBUTES = ["decision", "rule_id", "reason", "egress_tier_seen", "detector_id", "agent_key_id", "in_envelope", "transform_id", "resume_token"];

export async function otlpTrace(receipt) {
  const events = receipt?.events ?? [];
  const sessionId = events[0]?.session_id;
  if (!sessionId) return null;
  const traceId = (await sha256Hex(sessionId)).slice(0, 32);
  return {
    resourceSpans: [{
      resource: { attributes: [attribute("service.name", "contextboundary-gw"), attribute("contextboundary.session_id", sessionId)] },
      scopeSpans: [{
        scope: { name: "contextboundary-gw.audit", version: "v1" },
        spans: events.map((event) => span(event, traceId))
      }]
    }]
  };
}

export async function exportOtlpReceipt(receipt, env) {
  if (!env?.OTLP_HTTP_ENDPOINT) return { exported: false, reason: "not_configured" };
  const body = await otlpTrace(receipt);
  if (!body) return { exported: false, reason: "empty_receipt" };
  try {
    const response = await fetch(env.OTLP_HTTP_ENDPOINT, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
    return { exported: response.ok, status: response.status };
  } catch {
    return { exported: false, reason: "unreachable" };
  }
}

function span(event, traceId) {
  const timestamp = BigInt(Date.parse(event.timestamp)) * 1_000_000n;
  return {
    traceId,
    spanId: spanId(event.span_id),
    ...(event.parent_span_id ? { parentSpanId: spanId(event.parent_span_id) } : {}),
    name: `contextboundary.${event.event_type}`,
    kind: 1,
    startTimeUnixNano: timestamp.toString(),
    endTimeUnixNano: (timestamp + 1n).toString(),
    attributes: SAFE_ATTRIBUTES.flatMap((key) => event[key] === undefined || event[key] === null ? [] : [attribute(`contextboundary.${key}`, event[key])]),
    status: { code: ["deny"].includes(event.decision) ? 2 : 1 }
  };
}

function spanId(value) {
  return String(value ?? "").replaceAll("-", "").slice(0, 16).padEnd(16, "0");
}

function attribute(key, value) {
  if (typeof value === "boolean") return { key, value: { boolValue: value } };
  return { key, value: { stringValue: String(value) } };
}
