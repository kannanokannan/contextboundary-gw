# Governed AMS Ticket Change Agent

A runnable demonstration of an AMS agent's actions on ticket **INC-42137** ("rotate SMTP relay credentials on the prod mail gateway"). The gateway transparently intercepts every action, applies the base policy and a frozen accountable-owner intent envelope, verifies the acting agent's Ed25519 signature, and issues a third-party-verifiable receipt.

**"I can run this, inspect the decision, and understand why the action was allowed or denied."** That is the point of this example.

> **Honest state (v1.1, done-undeployed).** The repository implements the R1-R6 governance path, including deterministic MODIFY and DEFER outcomes, R6 signatures, Ed25519 receipt seals, and an R8 OpenTelemetry mirror. A live deployment still requires Kannan to configure the production Worker secrets and trusted public-key registry; no production private key is in this repository.

## What it demonstrates

| Stage | Layer | What happens |
|---|---|---|
| 1 | **ContextOps** (operating model) | Deterministic context gate before the agent acts: context ownership, freshness (<=72h), open change window, CAB reference, and source trust from [`context-manifest.json`](./context-manifest.json). Failed checks stop the run; the agent never reaches the boundary. |
| 2 | **ContextBoundary** (gateway) | Every ordinary MCP `tools/call` is evaluated before forwarding, `tools/list` discovery is policy-filtered, and unbound or unsigned identities fail closed. |
|  | Flow A — **ALLOW** | Triage the ticket within Autonomy Tier T1 and the egress boundary. |
|  | Flow B — **APPROVE** | Apply the high-risk change. The capability requires T3 while the agent holds T1, so deterministic approval is required. |
|  | Flow C — **DENY** | Egress a ticket note containing the old credential. `det:credential-pattern` classifies it as Tier I on a Tier II crossing: `R4 / egress_violation`. |
|  | **R2/R3** | An accountable owner, never the agent, declares and freezes the envelope. Base P-STRICT runs first; the envelope can only narrow authority. |
|  | **R6** | Each request is signed by an agent-held Ed25519 private key. The gateway verifies the registered public key before policy evaluation and rejects missing, forged, unknown, or replayed signatures. |
|  | **Receipt** | Every decision emits a privacy-safe hash chain with the agent signature evidence and an Ed25519 gateway seal. The sample below verifies with public keys only. |
|  | **Sthala** (placement) | Credential rotation belongs in the Customer Sovereign Zone. Only the Tier II narration (never the secret) could cross outward; Flow C shows the boundary enforcing that rule. |

## Run it

From a clean clone, install the local runtime and run the example:

```bash
npm ci
node examples/ams-ticket-change/run-local.mjs
```

`run-local.mjs` starts `npx wrangler dev --local --port 8787`, then runs `demo.mjs` with no `--target` argument. It generates an agent keypair, a gateway signing keypair, and the owner-bootstrap value only in memory for this local run. They are obvious local test values, never production secrets, and are not written or committed. The three demonstrated `boundary/evaluate` paths are handled by the gateway itself, so this run needs no upstream MCP server.

The output shows the three outcomes and `[VERIFY]` lines for the session and each flow. With `--save-receipts`, the launcher writes complete receipt documents plus a public-key bundle to a temporary directory and prints the exact `node audit/verify-receipt.mjs ... --public-keys ...` commands for independent verification.

The agent signer and the gateway have distinct key responsibilities:

- The agent runtime holds its private Ed25519 key and signs every request.
- The gateway is configured with that agent's public key in its trusted `AGENT_KEY_REGISTRY`.
- The gateway's `GATEWAY_ED25519_PRIVATE_JWK` remains a Worker secret. Its derived public key is published at `/.well-known/contextboundary-gateway-key`.

To point the demo at an operator-configured gateway, provide a matching registered agent key, `BOUNDARY_OWNER_BOOTSTRAP_KEY`, and the gateway target:

```bash
BOUNDARY_OWNER_BOOTSTRAP_KEY=<operator-supplied-value> node examples/ams-ticket-change/demo.mjs --target https://<your-gateway>/mcp --save-receipts
```

The configured public agent key must match the demo agent key. Production setup remains intentionally pending the Worker-secret and trusted-registry configuration.

Flags: `--stale` simulates expired context (the ContextOps gate blocks and the boundary is never consulted); `--save-receipts` writes the receipt chains to `receipts/`.

Expected governed decisions:

```text
[ALLOW]   Flow A — triage INC-42137
[APPROVE] Flow B — apply high-risk change to prod-mail-gateway
[DENY]    Flow C — credential-bearing egress (R4 / egress_violation / det:credential-pattern)
[VERIFY]  each receipt — third-party Ed25519 verification with public keys only
```

## Third-party receipt verification

The committed sample receipt was created with runtime-only test keys. Its companion public-key file contains no secret material:

```bash
node audit/verify-receipt.mjs examples/ams-ticket-change/receipts/sample-receipt.json --public-keys examples/ams-ticket-change/receipts/sample-public-keys.json
```

## AARM alignment (what this example claims — and what it does not)

This gateway is an **AARM-aligned, Core-partial, strict-determinism profile**:

- **R1 pre-execution interception** — every ordinary MCP `tools/call` is evaluated before forwarding; DENY and APPROVE never reach upstream, and `tools/list` is policy-filtered.
- **R2 session context / R3 stated intent** — an accountable-owner-declared, hash-frozen envelope and privacy-safe prior-action trace are present for each governed session. Base P-STRICT runs first; the envelope can only narrow the result. Missing or invalid envelopes fail closed.
- **R4 decisions** — ALLOW, DENY, STEP_UP, MODIFY, and DEFER are implemented. The three AMS flows above focus on allow/approval/deny; the runnable R4 suite exercises declared transforms and durable condition-gated resumes.
- **R5 tamper-evident receipts** — privacy-safe hash-chain receipts detect altered, dropped, reordered, and invalidly sealed events.
- **R6 per-agent cryptographic identity** — a receipt proves that the key registered to agent X signed the action, and the Ed25519 gateway seal is independently verifiable with public keys. It does **not** prove which human is behind agent X; federation is outside v1.1.

**No AARM conformance or approval claim is made.** The live ceiling is AARM-aligned, Core-partial, strict-determinism profile.

## Current limitations

- **Deployment remains pending.** Kannan must configure the production `GATEWAY_ED25519_PRIVATE_JWK` Worker secret and the trusted public agent-key registry. Missing key material fails closed; no private key is stored in this repository.
- **Intent scope is deterministic, not semantic.** The gateway blocks capabilities, sources, endpoints, egress, autonomy, budget, and expiry outside the frozen envelope. It deliberately does not infer semantic drift within an authorized set.
- **R6 scope is agent-key identity, not human identity.** Human or organization federation is a later concern.
- **R8 is a non-authoritative mirror.** The OTLP/HTTP binding exports receipt metadata only; the JSONL/receipt record remains the system of record, and export failure never blocks a decision.
- **Conformance ceiling holds:** AARM-aligned, Core-partial, strict-determinism profile. R1-R6 implementation is complete, but no conformance/approval claim is made without production operation and external evidence review.

## Files

- [`demo.mjs`](./demo.mjs) — runnable ContextOps gate and three signed governed flows
- [`context-manifest.json`](./context-manifest.json) — ContextOps context artifact
- [`receipts/sample-receipt.json`](./receipts/sample-receipt.json) — complete signed audit receipt
- [`receipts/sample-public-keys.json`](./receipts/sample-public-keys.json) — public keys for independent verification
- Policy: compiled P-STRICT fixture [`test/conformance/fixtures/p-strict.json`](../../test/conformance/fixtures/p-strict.json)
- Conformance: [`test/conformance/scenarios.json`](../../test/conformance/scenarios.json) and R6 tests in [`test/r6`](../../test/r6)

## Fresh-clone proof

From a fresh checkout, this single command installs the test runtime and demonstrates ALLOW, APPROVE, DENY, MODIFY, DEFER/resume, and public-key receipt verification with runtime-only test keys:

```bash
npm ci && npm run test:r4 && npm run test:r6
```
