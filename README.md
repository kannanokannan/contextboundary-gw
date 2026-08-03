# contextboundary-gw

[![PR gate](https://github.com/kannanokannan/contextboundary-gw/actions/workflows/pr-gate.yml/badge.svg?branch=main)](https://github.com/kannanokannan/contextboundary-gw/actions/workflows/pr-gate.yml)

`contextboundary-gw` is a self-hosted MCP gateway that applies deterministic, compiled policy to tool discovery, invocation, and outbound data flow. No model is in the enforcement path.

**AARM-aligned strict-determinism profile. All Core requirements (R1–R6) are implemented and CI-verified. Independent conformance review has not been undertaken.**

R7 is a designed deterministic divergence: envelope-drift counting replaces semantic-distance tracking to keep a model out of the enforcement path. R8 OpenTelemetry export is implemented as a non-authoritative mirror; JSONL remains the system of record.

## Quickstart

The test suite runs locally. It does not require a deployed Worker or any network access after `git clone` and `npm ci`.

```bash
git clone https://github.com/kannanokannan/contextboundary-gw.git
cd contextboundary-gw
npm ci

export TEST_AUDIT_SEAL_KEY='local-test-value'
export TEST_INTENT_ENVELOPE_BOOTSTRAP_KEY='local-owner-bootstrap-value'

npm run test:conformance
npm run test:interception
npm run test:receipts
npm run test:intent-envelope
npm run test:r4
npm run test:r6
npm run test:r8
npm run test:server-discover
```

```powershell
git clone https://github.com/kannanokannan/contextboundary-gw.git
Set-Location contextboundary-gw
npm ci

$env:TEST_AUDIT_SEAL_KEY = 'local-test-value'
$env:TEST_INTENT_ENVELOPE_BOOTSTRAP_KEY = 'local-owner-bootstrap-value'

npm run test:conformance
npm run test:interception
npm run test:receipts
npm run test:intent-envelope
npm run test:r4
npm run test:r6
npm run test:r8
npm run test:server-discover
```

`TEST_AUDIT_SEAL_KEY` and `TEST_INTENT_ENVELOPE_BOOTSTRAP_KEY` are arbitrary, non-empty values used only by local tests; they are not production secrets. `test:conformance` and `test:intent-envelope` require both values. `test:interception` requires `TEST_AUDIT_SEAL_KEY`. The other four existing suites create their own ephemeral test material; `test:server-discover` needs no test values.

| Suite | Coverage | Local execution |
| --- | --- | --- |
| `test:conformance` | 21 normative policy scenarios | Local Worker |
| `test:interception` | 9 assertions for discovery and invocation interception | Local Worker and local spy upstream |
| `test:receipts` | 10 assertions for chained receipts and public-key verification | Node-only |
| `test:intent-envelope` | 28 assertions for frozen declared-intent envelopes | Local Worker |
| `test:r4` | 14 assertions for MODIFY and DEFER outcomes | Local Worker and local spy upstream |
| `test:r6` | 17 assertions for agent signatures, rotation, replay, and public-key verification | Local Worker |
| `test:r8` | 10 assertions for OpenTelemetry export | Node-only with a local collector |
| `test:server-discover` | 15 assertions for locally-answered, policy-filtered discovery | Local Worker and local spy upstream |

## Mediation boundary

- `tools/call` is evaluated before forwarding; only an `allow` decision is proxied upstream.
- `tools/list` is evaluated; a non-ALLOW result returns an empty list, and an allowed upstream list is filtered to permitted capabilities and envelope scope.
- All other MCP methods are proxied to `UPSTREAM_MCP_URL`, with `boundary-*` identity and signature headers stripped before forwarding.

The gateway also handles `boundary/evaluate`, `boundary/session.start`, and `boundary/deferred.resume` locally.

## Receipts and verification

Decision receipts are hash-chained and sealed with Ed25519. Verification uses public keys only, so a third party can verify a receipt without a private key. HMAC-SHA256 is used only for the intent-envelope bootstrap proof, not for the gateway receipt seal.

Run the verifier with a receipt and public-key bundle:

```bash
node audit/verify-receipt.mjs receipt.json --public-keys public-keys.json
```

See [`audit/verify-receipt.mjs`](audit/verify-receipt.mjs) and the runnable [AMS ticket-change example](examples/ams-ticket-change/).

## Current limitations

- This is a self-hosted reference implementation, not a hosted service; it is not deployed.
- Independent conformance review has not been undertaken.
- R6 proves that the key registered to agent X signed an action. It does not identify the human behind that agent.
- R7 deliberately differs from AARM's semantic-distance approach by using deterministic envelope-drift counting.
- Production operation requires deployment-specific Worker bindings, an agent public-key registry, and gateway signing material configured outside this repository.

## Specifications and related projects

- [ContextBoundary](https://github.com/kannanokannan/ContextBoundary)
- [Boundary Policy Schema](https://github.com/kannanokannan/ContextBoundary/blob/main/boundary-policy-spec.md)
- [Boundary Conformance Scenarios](https://github.com/kannanokannan/ContextBoundary/blob/main/boundary-conformance-scenarios.md)
- [Runtime maturity ladder](https://github.com/kannanokannan/ContextBoundary/blob/main/maturity-ladder.md)
