const DEFAULT_UPSTREAM_MCP_URL = "https://mcp.context-stack.org/mcp";

export default {
  async fetch(request, env) {
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

    return proxyMcpRequest(request, env);
  }
};

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

function withCors(response) {
  const headers = new Headers(response.headers);
  headers.set("access-control-allow-origin", "*");
  headers.set("access-control-allow-methods", "GET,POST,OPTIONS");
  headers.set("access-control-allow-headers", "authorization, content-type, mcp-method, mcp-name, mcp-protocol-version, mcp-session-id");
  headers.set("access-control-expose-headers", "mcp-protocol-version");
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
}
