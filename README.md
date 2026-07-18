# contextboundary-gw

ContextBoundary MCP gateway with a deploy-time policy compiler and an initial Rego WASM enforcement path.

The Worker still forwards ordinary MCP traffic unchanged to `UPSTREAM_MCP_URL`. The `boundary/evaluate` method evaluates the compiled P-STRICT policy across identity binding, discovery and source trust, autonomy tier gates, Egress Tier protection, and continuity fallback. Approval obligations are converted to the gateway-level `approve` outcome outside Rego.

The normative policy and conformance specifications live in the ContextBoundary framework repo:

- [Boundary Policy Schema](https://github.com/kannanokannan/ContextBoundary/blob/main/boundary-policy-spec.md)
- [Boundary Conformance Scenarios](https://github.com/kannanokannan/ContextBoundary/blob/main/boundary-conformance-scenarios.md)

## Layout

- `src/` - Worker entry and transparent upstream proxy
- `policy/` - deploy-time YAML policy input
- `policy/egress-detectors.json` - bounded, versioned detector patterns
- `src/policy/compile/` - engine-neutral policy compiler inputs
- `src/policy/generated/` - generated Rego, data document, and WASM module
- `test/conformance/` - red/green/xfail conformance harness
- `examples/ams-ticket-change/` - runnable end-to-end demo: Governed AMS Ticket Change Agent (ContextOps gate → allow / approve / deny flows → audit receipts)

## Local Test

```bash
npm test -- --target https://contextboundary-gw-staging.kannanokannan.workers.dev/mcp
```

The harness contains executable forms of all 21 normative scenarios.
