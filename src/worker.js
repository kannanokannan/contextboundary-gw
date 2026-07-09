import {
  benchmarkBoundary,
  capabilityRecord,
  evaluateBoundary,
  identityRecord
} from "./policy/evaluator.js";

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
      const method = request.headers.get("mcp-method");
      if (method === "boundary/evaluate" || method === "boundary/benchmark") {
        return handleBoundaryRequest(request, env);
      }
    }

    return proxyMcpRequest(request, env);
  }
};

async function handleBoundaryRequest(request, env) {
  const message = await request.json();
  if (message.method === "boundary/benchmark") {
    return jsonRpcResult(message.id, await benchmarkBoundary(message.params?.iterations));
  }

  const identityId = request.headers.get("boundary-agent-id") ?? "";
  const action = message.params?.action ?? {};
  const result = await evaluateBoundary(identityId, action);
  const identity = identityRecord(identityId);
  const capability = capabilityRecord(action.capability);
  const audit = buildAuditRecord(identity, action, result, capability);

  emitAudit(env, audit);
  return jsonRpcResult(message.id, { ...result, audit });
}

function buildAuditRecord(identity, action, result, capability) {
  return {
    agent_id: identity?.id ?? null,
    accountable_owner: identity?.accountable_owner ?? null,
    tier_in_force: identity?.autonomy_tier ?? null,
    action,
    decision: result.decision,
    rule_id: result.rule_id,
    egress_tier_seen: action.payload_egress_tier ?? capability?.egress_tier ?? null,
    timestamp: new Date().toISOString()
  };
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

function withCors(response) {
  const headers = new Headers(response.headers);
  headers.set("access-control-allow-origin", "*");
  headers.set("access-control-allow-methods", "GET,POST,OPTIONS");
  headers.set("access-control-allow-headers", "authorization, boundary-agent-id, content-type, mcp-method, mcp-name, mcp-protocol-version, mcp-session-id");
  headers.set("access-control-expose-headers", "mcp-protocol-version");
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
}
