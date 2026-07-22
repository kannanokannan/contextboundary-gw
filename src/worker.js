import {
  benchmarkBoundary,
  capabilityRecord,
  evaluateBoundary,
  identityRecord
} from "./policy/evaluator.js";
import policyData from "./policy/generated/data.json";
import { createSealedReceipt, policyArtifactHash } from "./audit/receipts.js";
import { hashIntentEnvelope, hmacSha256Hex } from "./intent/canonical.js";
export { IntentSession } from "./intent/session.js";

const DEFAULT_UPSTREAM_MCP_URL = "https://mcp.context-stack.org/mcp";

export default {
  async fetch(request, env, ctx) {
    if (request.method === "OPTIONS") {
      return withCors(new Response(null, { status: 204 }));
    }

    const url = new URL(request.url);
    if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/health")) {
      return jsonResponse({
        status: "ok",
        name: "contextboundary-gw",
        mode: "transparent-proxy",
        upstream: upstreamUrl(env).toString(),
        mcp: "/mcp"
      });
    }

    if (request.method === "GET" && url.pathname === "/mcp") {
      return jsonResponse({
        name: "contextboundary-gw",
        transport: "streamable-http-json-rpc",
        mode: "transparent-proxy",
        upstream: upstreamUrl(env).toString(),
        note: "Send MCP JSON-RPC requests to this endpoint."
      });
    }

    if (url.pathname !== "/mcp") {
      return jsonResponse({ error: "Not found" }, { status: 404 });
    }

    if (request.method === "POST") {
      const message = await readJsonRpcMessage(request);
      const method = message?.method ?? request.headers.get("mcp-method");

      if (method === "boundary/evaluate" || method === "boundary/benchmark") {
        return message
          ? handleBoundaryRequest(message, request.headers, env)
          : jsonRpcError(null, -32600, "Invalid JSON-RPC request");
      }

      if (method === "boundary/session.start") {
        return message
          ? handleSessionStart(message, request.headers, env)
          : jsonRpcError(null, -32600, "Invalid JSON-RPC request");
      }

      if (method === "tools/call") {
        return message
          ? handleToolCall(message, request.headers, env)
          : jsonRpcError(null, -32600, "Invalid JSON-RPC request");
      }

      if (method === "tools/list") {
        return message
          ? handleToolList(message, request.headers, request, env)
          : jsonRpcError(null, -32600, "Invalid JSON-RPC request");
      }
    }

    return proxyMcpRequest(request, env);
  }
};

async function handleBoundaryRequest(message, headers, env) {
  if (message.method === "boundary/benchmark") {
    return jsonRpcResult(message.id, await benchmarkBoundary(message.params?.iterations));
  }

  const identityId = headers.get("boundary-agent-id") ?? "";
  const action = message.params?.action ?? {};
  const { result, audit, auditChain, receipt } = await evaluateAndAudit(identityId, action, env, headers.get("mcp-session-id") ?? undefined);
  return jsonRpcResult(message.id, {
    ...result,
    audit,
    receipt,
    ...(auditChain ? { audit_chain: auditChain } : {})
  });
}

async function handleSessionStart(message, headers, env) {
  const identityId = headers.get("boundary-agent-id") ?? "";
  const identity = identityRecord(identityId);
  const sessionId = headers.get("mcp-session-id") ?? message.params?.intent_envelope?.session_id;
  if (!sessionId) return jsonRpcError(message.id ?? null, -32602, "boundary/session.start requires mcp-session-id");
  if (!env?.INTENT_SESSIONS) return jsonRpcError(message.id ?? null, -32603, "intent session storage is unavailable");

  const envelope = message.params?.intent_envelope;
  const ownerProof = headers.get("boundary-owner-proof");
  const expectedOwnerProof = env?.INTENT_ENVELOPE_BOOTSTRAP_KEY && envelope
    ? await hmacSha256Hex(env.INTENT_ENVELOPE_BOOTSTRAP_KEY, await hashIntentEnvelope(envelope))
    : null;
  const started = !expectedOwnerProof
    ? { ok: false, reason: "owner_proof_unavailable" }
    : !timingSafeEqual(ownerProof, expectedOwnerProof)
      ? { ok: false, reason: "owner_proof_invalid" }
      : await intentSession(env, sessionId).start({ identity, sessionId, envelope });
  const result = started.ok
    ? {
        decision: "allow",
        rule_id: "R2",
        reason: "intent_envelope_frozen",
        obligations: [],
        obligation: null,
        effective_tier: identity?.autonomy_tier ?? null,
        egress_tier_seen: null,
        detector_id: null,
        in_envelope: true,
        envelope_failing_dimension: null
      }
    : closedEnvelopeResult(identity, started.reason);
  const policyHash = await policyArtifactHash(policyData);
  const receipt = await createReceipt(identity, { type: "session.start" }, result, policyHash, env, sessionId, started.ok ? started : null);
  const audit = receipt.events[1];
  emitAudit(env, audit);
  return jsonRpcResult(message.id ?? null, {
    ...result,
    audit,
    receipt,
    ...(started.ok ? {
      envelope_hash: started.envelope_hash,
      prior_action_trace: started.prior_action_trace,
      envelope_drift_review: started.envelope_drift_review
    } : {})
  });
}

async function handleToolCall(message, headers, env) {
  const identityId = headers.get("boundary-agent-id") ?? "";
  const capability = message.params?.name;
  if (typeof capability !== "string" || !capability) {
    return jsonRpcError(message.id ?? null, -32602, "tools/call requires params.name");
  }

  const action = {
    type: "invoke",
    capability,
    payload: message.params?.arguments ?? {}
  };
  const { result, audit } = await evaluateAndAudit(identityId, action, env, headers.get("mcp-session-id") ?? undefined);
  if (result.decision !== "allow") {
    return jsonRpcResult(message.id ?? null, { ...result, audit });
  }

  return proxyMcpRequest(new Request("https://gateway.invalid/mcp", {
    method: "POST",
    headers,
    body: JSON.stringify(message)
  }), env);
}

async function handleToolList(message, headers, request, env) {
  const identityId = headers.get("boundary-agent-id") ?? "";
  const identity = identityRecord(identityId);
  if (!identity) {
    const { result, audit } = await evaluateAndAudit(identityId, { type: "discover" }, env, headers.get("mcp-session-id") ?? undefined);
    return jsonRpcResult(message.id ?? null, { ...result, audit, tools: [] });
  }

  const discoveryAudit = await evaluateAndAudit(identityId, { type: "discover" }, env, headers.get("mcp-session-id") ?? undefined);
  const discovery = discoveryAudit.result;
  if (discovery.decision !== "allow") {
    return jsonRpcResult(message.id ?? null, { ...discovery, audit: discoveryAudit.audit, tools: [] });
  }

  const upstreamResponse = await proxyMcpRequest(request, env);
  let upstreamMessage;
  try {
    upstreamMessage = await upstreamResponse.json();
  } catch {
    return jsonRpcError(message.id ?? null, -32603, "Upstream tools/list response was not JSON");
  }

  const permitted = new Set(discovery.capabilities ?? []);
  const envelopeCapabilities = discoveryAudit.envelopeContext?.envelope?.authorized?.capabilities;
  const envelopeSources = discoveryAudit.envelopeContext?.envelope?.authorized?.sources;
  const tools = Array.isArray(upstreamMessage?.result?.tools) ? upstreamMessage.result.tools : [];
  return jsonResponse({
    ...upstreamMessage,
    result: {
      ...(upstreamMessage.result ?? {}),
      tools: tools.filter((tool) => {
        if (!permitted.has(tool?.name)) return false;
        if (!envelopeCapabilities) return true;
        const capability = capabilityRecord(tool?.name);
        return envelopeCapabilities.includes(tool?.name) && envelopeSources?.includes(capability?.source);
      })
    }
  });
}

async function evaluateAndAudit(identityId, action, env, sessionId) {
  const identity = identityRecord(identityId);
  const sessionContext = sessionId ? await readIntentSession(env, sessionId) : null;
  let result;
  let envelopeContext = null;
  if (sessionId && !sessionContext?.ok) {
    result = closedEnvelopeResult(identity, sessionContext?.reason ?? "no_envelope");
  } else {
    const baseResult = await evaluateBoundary(identityId, action, sessionContext ?? {});
    if (sessionId) {
      const decided = await intentSession(env, sessionId).decide({
        action,
        baseResult,
        capability: capabilityRecord(action.capability)
      });
      if (!decided.ok) {
        result = closedEnvelopeResult(identity, decided.reason);
      } else {
        result = decided.result;
        envelopeContext = decided;
        result = {
          ...result,
          session_trace: decided.prior_action_trace,
          envelope_drift_review: decided.envelope_drift_review
        };
      }
    } else {
      result = baseResult;
    }
  }
  const policyHash = await policyArtifactHash(policyData);
  const auditChain = result.audit_steps
    ? await Promise.all(result.audit_steps.map(async (step) => (await createReceipt(identity, step.action, step.result, policyHash, env, sessionId, envelopeContext)).events[1]))
    : null;
  const receipt = await createReceipt(identity, action, result, policyHash, env, sessionId, envelopeContext);
  const audit = auditChain?.at(-1) ?? receipt.events[1];

  for (const record of auditChain ?? [audit]) emitAudit(env, record);
  return { result, audit, auditChain, receipt, envelopeContext };
}

async function createReceipt(identity, action, result, policyHash, env, sessionId, envelopeContext = null) {
  const days = Math.max(1, Number(env?.AUDIT_RETENTION_DAYS ?? 30));
  return createSealedReceipt({
    sessionId,
    identity,
    action,
    result,
    policyHash,
    retention: {
      policy: env?.AUDIT_RETENTION_POLICY ?? "retention-30d",
      expires_at: new Date(Date.now() + days * 86_400_000).toISOString()
    },
    sealKey: env?.AUDIT_SEAL_KEY,
    envelopeContext
  });
}

async function readIntentSession(env, sessionId) {
  if (!env?.INTENT_SESSIONS) return { ok: false, reason: "no_envelope" };
  return intentSession(env, sessionId).snapshot();
}

function intentSession(env, sessionId) {
  return env.INTENT_SESSIONS.getByName(sessionId);
}

function closedEnvelopeResult(identity, reason) {
  return {
    decision: "deny",
    rule_id: "R3",
    reason: reason === "no_envelope" ? "no_envelope" : `invalid_envelope:${reason}`,
    obligations: [],
    obligation: null,
    effective_tier: identity?.autonomy_tier ?? null,
    egress_tier_seen: null,
    detector_id: null,
    in_envelope: false,
    envelope_failing_dimension: reason
  };
}

function timingSafeEqual(left, right) {
  if (typeof left !== "string" || typeof right !== "string" || left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  return difference === 0;
}

function emitAudit(env, audit) {
  if (!env?.AUDIT) return;
  env.AUDIT.writeDataPoint({
    indexes: [audit.agent_id ?? "unbound"],
    blobs: [
      audit.accountable_owner ?? "",
      audit.tier_in_force ?? "",
      JSON.stringify(audit.action),
      audit.decision,
      audit.rule_id,
      audit.egress_tier_seen ?? "",
      audit.detector_id ?? "",
      JSON.stringify(audit.obligation),
      audit.timestamp
    ],
    doubles: []
  });
}

async function proxyMcpRequest(request, env) {
  const upstream = upstreamUrl(env);
  const headers = new Headers(request.headers);
  headers.delete("host");
  headers.delete("content-length");

  const upstreamRequest = new Request(upstream, {
    method: request.method,
    headers,
    body: request.body,
    redirect: "manual"
  });

  const upstreamResponse = await fetch(upstreamRequest);
  return withCors(upstreamResponse);
}

function upstreamUrl(env) {
  return new URL(env?.UPSTREAM_MCP_URL || DEFAULT_UPSTREAM_MCP_URL);
}

function jsonResponse(body, init = {}) {
  return withCors(new Response(JSON.stringify(body, null, 2), {
    status: init.status ?? 200,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...(init.headers ?? {})
    }
  }));
}

function jsonRpcResult(id, result) {
  return jsonResponse({ jsonrpc: "2.0", id, result });
}

function jsonRpcError(id, code, message) {
  return jsonResponse({ jsonrpc: "2.0", id, error: { code, message } });
}

async function readJsonRpcMessage(request) {
  try {
    const message = await request.clone().json();
    return message && typeof message === "object" ? message : null;
  } catch {
    return null;
  }
}

function withCors(response) {
  const headers = new Headers(response.headers);
  headers.set("access-control-allow-origin", "*");
  headers.set("access-control-allow-methods", "GET,POST,OPTIONS");
  headers.set("access-control-allow-headers", "authorization, boundary-agent-id, boundary-owner-proof, content-type, mcp-method, mcp-name, mcp-protocol-version, mcp-session-id");
  headers.set("access-control-expose-headers", "mcp-protocol-version");
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
}
