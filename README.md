# contextboundary-gw

ContextBoundary MCP gateway with a deploy-time policy compiler and an initial Rego WASM enforcement path.

The Worker still forwards ordinary MCP traffic unchanged to `UPSTREAM_MCP_URL`. The `boundary/evaluate` method now evaluates R1 identity binding and R3 tier gates against the compiled P-STRICT policy. Approval obligations are converted to the gateway-level `approve` outcome outside Rego. Discovery filtering, egress enforcement, and continuity enforcement remain intentionally unimplemented.

## Layout

- `src/` - Worker entry and transparent upstream proxy
- `docs/` - draft policy schema and conformance scenarios
- `policy/` - deploy-time YAML policy input
- `src/policy/compile/` - engine-neutral policy compiler inputs
- `src/policy/generated/` - generated Rego, data document, and WASM module
- `test/conformance/` - red/green/xfail conformance harness

## Local Test

```bash
npm test -- --target https://contextboundary-gw-staging.kannanokannan.workers.dev/mcp
```

The harness currently contains every named draft scenario. Red results are the remaining Phase B implementation work, and S-R4-03 remains an expected failure until the payload-classification gap is resolved.
