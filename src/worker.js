import {
  benchmarkBoundary,
  capabilityRecord,
  evaluateBoundary,
  identityRecord
} from "./policy/evaluator.js";
import policyData from "./policy/generated/data.json";
import { createSealedReceipt, policyArtifactHash } from "./audit/receipts.js";
import { canonicalize, hashIntentEnvelope, hmacSha256Hex, sha256Hex } from "./intent/canonical.js";
import { evaluateIntentEnvelope } from "./intent/envelope.js";
import { gatewayKeyMaterial } from "./identity/gateway-key.js";
import { verifyAgentSignature } from "./identity/signatures.js";
import { applyDeclaredTransform, declaredTransforms, deferredCondition, resumeAction } from "./r4/transforms.js";
import { exportOtlpReceipt } from "./r8/otel.js";
export { IntentSession } from "./intent/session.js";

const DEFAULT_UPSTREAM_MCP_URL = "https://mcp.context-stack.org/mcp";

export default {
  async fetch(request, env, ctx) {
    if (request.method === "OPTIONS") {
      return withCors(new Response(null, { status: 204 }));
    }

    const url = new URL(request.url);
    if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/health")) {
      const gatewayKey = gatewayKeyMaterial(env);
      return jsonResponse({
        status: "ok",
        name: "contextboundary-gw",
        mode: "transparent-proxy",
        upstream: upstreamUrl(env).toString(),
        mcp: "/mcp",
        gateway_key_id: gatewayKey?.key_id ?? null
      });
    }

    if (request.method === "GET" && url.pathname === "/.well-known/contextboundary-gateway-key") {
      const gatewayKey = gatewayKeyMaterial(env);
      return gatewayKey
        ? jsonResponse({ key_id: gatewayKey.key_id, public_jwk: gatewayKey.public_jwk })
        : jsonResponse({ error: "Gateway signing key is not configured" }, { status: 503 });
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
          ? handleBoundaryRequest(message, request.headers, env, ctx)
          : jsonRpcError(null, -32600, "Invalid JSON-RPC request");
      }

      if (method === "boundary/session.start") {
        return message
          ? handleSessionStart(message, request.headers, env, ctx)
          : jsonRpcError(null, -32600, "Invalid JSON-RPC request");
      }

      if (method === "boundary/deferred.resume") {
        return message
          ? handleDeferredResume(message, request.headers, env, ctx)
          : jsonRpcError(null, -32600, "Invalid JSON-RPC request");
      }

      if (method === "tools/call") {
        return message
          ? handleToolCall(message, request.headers, env, ctx)
          : jsonRpcError(null, -32600, "Invalid JSON-RPC request");
      }

      if (method === "tools/list") {
        return message
          ? handleToolList(message, request.headers, request, env, ctx)
          : jsonRpcError(null, -32600, "Invalid JSON-RPC request");
      }
    }

    return proxyMcpRequest(request, env);
  }
};

async function handleBoundaryRequest(message, headers, env, ctx) {
  if (message.method === "boundary/benchmark") {
    return jsonRpcResult(message.id, await benchmarkBoundary(message.params?.iterations));
  }

  const identityId = headers.get("boundary-agent-id") ?? "";
  const action = message.params?.action ?? {};
  const { result, audit, auditChain, receipt } = await evaluateAndAudit(identityId, action, env, headers.get("mcp-session-id") ?? undefined, headers, ctx);
  return jsonRpcResult(message.id, {
    ...result,
    audit,
    receipt,
    ...(auditChain ? { audit_chain: auditChain } : {})
  });
}

async function handleSessionStart(message, headers, env, ctx) {
  const identityId = headers.get("boundary-agent-id") ?? "";
  const identity = identityRecord(identityId);
  const sessionId = headers.get("mcp-session-id") ?? message.params?.intent_envelope?.session_id;
  if (!sessionId) return jsonRpcError(message.id ?? null, -32602, "boundary/session.start requires mcp-session-id");
  if (!env?.INTENT_SESSIONS) return jsonRpcError(message.id ?? null, -32603, "intent session storage is unavailable");

  const envelope = message.params?.intent_envelope;
  const agentAuth = await authenticateAgentAction(identity, { type: "session.start" }, headers, env, sessionId);
  const ownerProof = headers.get("boundary-owner-proof");
  const expectedOwnerProof = env?.INTENT_ENVELOPE_BOOTSTRAP_KEY && envelope
    ? await hmacSha256Hex(env.INTENT_ENVELOPE_BOOTSTRAP_KEY, await hashIntentEnvelope(envelope))
    : null;
  const started = !agentAuth.ok
    ? { ok: false, reason: agentAuth.reason }
    : !expectedOwnerProof
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
    : authOrEnvelopeFailure(identity, started.reason);
  const policyHash = await policyArtifactHash(policyData);
  const receipt = await createReceipt(identity, { type: "session.start" }, result, policyHash, env, sessionId, started.ok ? started : null, agentAuth);
  const audit = receipt.events[1];
  emitAudit(env, audit, receipt, ctx);
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

async function handleDeferredResume(message, headers, env, ctx) {
  const identityId = headers.get("boundary-agent-id") ?? "";
  const identity = identityRecord(identityId);
  const sessionId = headers.get("mcp-session-id") ?? undefined;
  const resumeToken = message.params?.resume_token;
  const condition = message.params?.condition;
  if (!sessionId || typeof resumeToken !== "string") return jsonRpcError(message.id ?? null, -32602, "boundary/deferred.resume requires mcp-session-id and resume_token");
  const signedAction = { type: "deferred.resume", resume_token: resumeToken, condition_id: condition?.id ?? null };
  const agentAuth = await authenticateAgentAction(identity, signedAction, headers, env, sessionId);
  let result;
  let envelopeContext = null;
  let r4Context = { resume_token: resumeToken };
  if (!agentAuth.ok) {
    result = authOrEnvelopeFailure(identity, agentAuth.reason);
  } else {
    const record = await intentSession(env, sessionId).deferred(resumeToken);
    const action = resumeAction(record, condition);
    if (!record || record.identity_id !== identityId || !action) {
      result = { ...closedEnvelopeResult(identity, "deferred_record_unavailable"), rule_id: "R4", reason: "deferred_record_unavailable", resume_token: resumeToken };
    } else {
      const baseResult = await evaluateBoundary(identityId, action, await readIntentSession(env, sessionId));
      const resumed = await intentSession(env, sessionId).resume({ resumeToken, identityId, action, baseResult, capability: capabilityRecord(action.capability) });
      result = resumed.ok ? resumed.result : { ...closedEnvelopeResult(identity, resumed.reason), rule_id: "R4", reason: resumed.reason, resume_token: resumeToken };
      if (resumed.ok) envelopeContext = resumed;
      r4Context = { resume_token: resumeToken, resulting_action_hash: await sha256Hex(canonicalize(action)) };
    }
  }
  const policyHash = await policyArtifactHash(policyData);
  const receipt = await createReceipt(identity, signedAction, result, policyHash, env, sessionId, envelopeContext, agentAuth, r4Context);
  const audit = receipt.events[1];
  emitAudit(env, audit, receipt, ctx);
  return jsonRpcResult(message.id ?? null, { ...result, audit, receipt });
}

async function handleToolCall(message, headers, env, ctx) {
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
  const { result, audit, executionAction } = await evaluateAndAudit(identityId, action, env, headers.get("mcp-session-id") ?? undefined, headers, ctx);
  if (result.decision !== "allow") {
    return jsonRpcResult(message.id ?? null, { ...result, audit });
  }

  const forwarded = executionAction ?? action;
  return proxyMcpRequest(new Request("https://gateway.invalid/mcp", {
    method: "POST",
    headers,
    body: JSON.stringify({ ...message, params: { ...message.params, name: forwarded.capability, arguments: forwarded.payload ?? {} } })
  }), env);
}

async function handleToolList(message, headers, request, env, ctx) {
  const identityId = headers.get("boundary-agent-id") ?? "";
  const identity = identityRecord(identityId);
  if (!identity) {
    const { result, audit } = await evaluateAndAudit(identityId, { type: "discover" }, env, headers.get("mcp-session-id") ?? undefined, headers, ctx);
    return jsonRpcResult(message.id ?? null, { ...result, audit, tools: [] });
  }

  const discoveryAudit = await evaluateAndAudit(identityId, { type: "discover" }, env, headers.get("mcp-session-id") ?? undefined, headers, ctx);
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

async function evaluateAndAudit(identityId, action, env, sessionId, headers, ctx) {
  const identity = identityRecord(identityId);
  const agentAuth = await authenticateAgentAction(identity, action, headers, env, sessionId);
  const sessionContext = agentAuth.ok && sessionId ? await readIntentSession(env, sessionId) : null;
  let result;
  let envelopeContext = null;
  let executionAction = action;
  let r4Context = null;
  if (!agentAuth.ok) {
    result = authOrEnvelopeFailure(identity, agentAuth.reason);
  } else if (sessionId && !sessionContext?.ok) {
    result = closedEnvelopeResult(identity, sessionContext?.reason ?? "no_envelope");
  } else {
    const baseResult = await evaluateBoundary(identityId, action, sessionContext ?? {});
    if (sessionId) {
      const capability = capabilityRecord(action.capability);
      const preview = evaluateIntentEnvelope({ envelope: sessionContext.envelope, priorActionTrace: sessionContext.prior_action_trace, action, baseResult, capability }).result;
      let decided = null;
      if (preview.decision === "deny") {
        for (const transform of declaredTransforms(preview)) {
          const transformed = await applyDeclaredTransform(action, transform);
          if (!transformed) continue;
          const transformedBase = await evaluateBoundary(identityId, transformed.action, sessionContext);
          const candidate = await intentSession(env, sessionId).decide({ action: transformed.action, baseResult: transformedBase, capability: capabilityRecord(transformed.action.capability) });
          if (candidate.ok && candidate.result.decision === "allow") {
            decided = candidate;
            executionAction = transformed.action;
            r4Context = transformed;
            result = { ...candidate.result, decision: "modify", rule_id: "R4", reason: "transform_applied", transform_id: transformed.transform_id, original_action_hash: transformed.original_action_hash, resulting_action_hash: transformed.resulting_action_hash };
            break;
          }
        }
      }
      if (!decided && preview.decision === "allow" && deferredCondition(action)) {
        decided = await intentSession(env, sessionId).defer({ action, baseResult, capability, identityId, deferRule: deferredCondition(action) });
        if (decided.ok) {
          result = decided.result;
          r4Context = { resume_token: result.resume_token, defer_reason: result.defer_reason };
        }
      }
      if (!decided) decided = await intentSession(env, sessionId).decide({ action, baseResult, capability });
      if (!decided.ok) result = closedEnvelopeResult(identity, decided.reason);
      else if (!result) result = decided.result;
      if (decided.ok) {
        envelopeContext = decided;
        result = { ...result, session_trace: decided.prior_action_trace, envelope_drift_review: decided.envelope_drift_review };
      }
    } else {
      result = baseResult;
    }
  }
  const policyHash = await policyArtifactHash(policyData);
  const auditChain = result.audit_steps
    ? await Promise.all(result.audit_steps.map(async (step) => (await createReceipt(identity, step.action, step.result, policyHash, env, sessionId, envelopeContext, agentAuth)).events[1]))
    : null;
  const receipt = await createReceipt(identity, action, result, policyHash, env, sessionId, envelopeContext, agentAuth, r4Context);
  const audit = auditChain?.at(-1) ?? receipt.events[1];

  for (const record of auditChain ?? [audit]) emitAudit(env, record, receipt, ctx);
  return { result, audit, auditChain, receipt, envelopeContext, executionAction };
}

async function createReceipt(identity, action, result, policyHash, env, sessionId, envelopeContext = null, agentAuth = null, r4Context = null) {
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
    gatewayKey: gatewayKeyMaterial(env),
    envelopeContext,
    agentAuth,
    r4Context
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

function authOrEnvelopeFailure(identity, reason) {
  if (reason === "identity_unverified" || reason === "replay_detected") {
    return {
      decision: "deny", rule_id: "E1", reason, obligations: [], obligation: null,
      effective_tier: identity?.autonomy_tier ?? null, egress_tier_seen: null, detector_id: null,
      in_envelope: false, envelope_failing_dimension: null
    };
  }
  return closedEnvelopeResult(identity, reason);
}

async function authenticateAgentAction(identity, action, headers, env, sessionId) {
  const agentAuth = await verifyAgentSignature({
    identity,
    action,
    sessionId,
    keyId: headers.get("boundary-agent-key-id"),
    signature: headers.get("boundary-agent-signature"),
    nonce: headers.get("boundary-agent-nonce"),
    timestamp: headers.get("boundary-agent-timestamp"),
    seq: Number(headers.get("boundary-agent-seq")),
    env
  });
  if (!agentAuth.ok) return agentAuth;
  const nonce = await intentSession(env, sessionId).consumeNonce({ nonce: agentAuth.nonce, timestamp: agentAuth.timestamp });
  return nonce.ok ? agentAuth : { ok: false, reason: nonce.reason };
}

function timingSafeEqual(left, right) {
  if (typeof left !== "string" || typeof right !== "string" || left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  return difference === 0;
}

function emitAudit(env, audit, receipt = null, ctx = null) {
  if (env?.AUDIT) {
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
  if (receipt && ctx?.waitUntil) ctx.waitUntil(exportOtlpReceipt(receipt, env));
}

async function proxyMcpRequest(request, env) {
  const upstream = upstreamUrl(env);
  const headers = new Headers(request.headers);
  headers.delete("host");
  headers.delete("content-length");
  for (const header of ["boundary-agent-id", "boundary-agent-key-id", "boundary-agent-signature", "boundary-agent-nonce", "boundary-agent-timestamp", "boundary-agent-seq", "boundary-owner-proof"]) headers.delete(header);

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
  headers.set("access-control-allow-headers", "authorization, boundary-agent-id, boundary-agent-key-id, boundary-agent-signature, boundary-agent-nonce, boundary-agent-timestamp, boundary-agent-seq, boundary-owner-proof, content-type, mcp-method, mcp-name, mcp-protocol-version, mcp-session-id");
  headers.set("access-control-expose-headers", "mcp-protocol-version");
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
}
