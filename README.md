# contextboundary-gw

Transparent ContextBoundary MCP gateway scaffold for future policy enforcement.

This phase is intentionally pass-through only. The Worker sits in front of an MCP server, forwards MCP requests unchanged to `UPSTREAM_MCP_URL`, and returns upstream responses unchanged. No policy filtering, approval logic, identity enforcement, egress filtering, or audit persistence is implemented in this phase.

## Layout

- `src/` - Worker entry and transparent upstream proxy
- `policy/` - empty placeholder for a later ratified policy schema
- `audit/` - empty placeholder for a later audit sink implementation
- `test/conformance/` - shell harness for scenario-based conformance tests

## Local Test

```bash
npm test -- --target https://contextboundary-gw-staging.kannanokannan.workers.dev/mcp
```

The current conformance scenarios are smoke-only and expect transparent proxy behavior.
