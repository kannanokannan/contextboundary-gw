# Governed AMS Ticket Change Agent

A runnable demonstration of the stack: an AMS agent's actions on ticket **INC-42137** ("rotate SMTP relay credentials on the prod mail gateway") are each evaluated by the boundary, and every decision is deterministic and receipted.

**"I can run this, inspect the decision, and understand why the action was allowed or denied."** That is the whole point of this example.

> **Honest state (v0).** This demonstrates governance *decisions* — ALLOW / APPROVE / DENY, each with an audit record. Two things it does NOT yet do, tracked and in progress: (1) it calls `boundary/evaluate` explicitly per action rather than transparently intercepting every MCP `tools/call`; (2) the receipt is a flat audit record, not yet the signed hash-chain defined in `boundary-audit-spec.md`. See **Current limitations** below.

## What it demonstrates

| Stage | Layer | What happens |
|---|---|---|
| 1 | **ContextOps** (operating model) | Deterministic context gate before the agent acts: context ownership, freshness (≤72h), open change window, CAB reference, source trust — from [`context-manifest.json`](./context-manifest.json). Failed checks stop the run; the agent never reaches the boundary. |
| 2 | **ContextBoundary** (gateway) | The demo submits each action to `boundary/evaluate` (explicit call; transparent interception of all MCP `tools/call` is in progress). Three flows: |
| | Flow A — **ALLOW** | Triage the ticket. Within Autonomy Tier (T1), within egress boundary. |
| | Flow B — **APPROVE** | Apply the high-risk change. Capability requires T3; agent holds T1. **A high-risk change cannot execute without deterministic approval** — the decision is made by compiled policy, not by the model. |
| | Flow C — **DENY** | Egress a ticket note that carries the old credential. The `det:credential-pattern` detector classifies the payload Tier I on a Tier II crossing → `R4 / egress_violation`. |
| — | **Receipt** | Every decision emits an audit record: agent, accountable owner, tier in force, action, decision, rule, egress tier seen, detector, obligation, timestamp. See [`receipts/sample-receipt.json`](./receipts/sample-receipt.json) — captured from a live run. *This is a flat record; the signed hash-chain seal in `boundary-audit-spec.md` §5–§6 is specified but not yet implemented here.* |
| — | **Sthala** (placement) | Where the sensitive part runs: the credential rotation itself belongs in the Customer Sovereign Zone (Tier I never leaves). A Sthala-profiled runtime executes the Compute step locally; only the Tier II narration (ticket update, no secrets) may cross outward — which is exactly what Flow C enforces. |

## Run it

```bash
node examples/ams-ticket-change/demo.mjs --target https://<your-gateway>/mcp --save-receipts
```

No dependencies, Node 18+. Flags: `--stale` simulates expired context (the ContextOps gate blocks and the boundary is never consulted); `--save-receipts` writes the receipt chain to `receipts/`.

Expected output:

```
── Stage 1 · ContextOps context gate ──
[PASS]    owner=role:run-lead-apac · fresh (< 72h) · change window open · CAB=CAB-2026-0711-08

── Stage 2 · ContextBoundary action governance ──
[ALLOW]   Flow A · triage INC-42137 (read + classify)          rule: R3 · tier_satisfied
[APPROVE] Flow B · apply high-risk change to prod-mail-gateway  rule: R3 · tier_escalation
[DENY]    Flow C · egress ticket note with the old credential   rule: R4 · egress_violation · det:credential-pattern
```

## AARM alignment (what this example claims — and what it doesn't)

This gateway is an **AARM-aligned strict-determinism profile** (AARM v1.0, CSA — §6.1 Protocol Gateway architecture):

- **R1 pre-execution interception** — actions submitted to the boundary are evaluated before execution. **Partial:** the demo calls `boundary/evaluate` explicitly; transparent interception of all MCP `tools/call` is in progress.
- **R5 tamper-evident receipts** — every decision emits an audit record with policy context. **Partial:** records are not yet sealed / hash-chained per `boundary-audit-spec.md` §5–§6.
- **R4 decisions** — ALLOW / DENY / STEP_UP (our `approve`) shown here; MODIFY and DEFER are v1.1 scope.
- **R2 / R3 / R6** — session context, intent envelopes, and per-agent cryptographic identity are open gaps for the Core-partial profile.

**No AARM approval claim is made.** The claim is: AARM-aligned profile, Core-partial, gaps explicit, full Core targeted at v1.1. Egress-sovereignty tiers, the credential detector, and vendor-continuity are profile *extensions* in the space AARM leaves open.

## Current limitations (v0 — honest state, closing next)

- **Interception is explicit, not transparent.** The demo submits actions to `boundary/evaluate` directly. The gateway does not yet auto-mediate every ordinary MCP `tools/call`, so this demo does not by itself prove a denied action cannot reach the tool by another path. In progress.
- **Receipts are not yet sealed.** The audit record is real but flat — no session/sequence/prev-hash/policy-hash/signature, and no verifier. The tamper-evident chain in `boundary-audit-spec.md` §5–§6 is specified, not yet implemented here. In progress.
- **Conformance ceiling holds:** AARM Core-partial + strict-determinism profile. No conformance/approval claim until external evidence review.

When these two close, this section shrinks and the R1/R5 marks above move from *Partial* to met.

## Files

- [`demo.mjs`](./demo.mjs) — the runnable demo (ContextOps gate + three governed flows)
- [`context-manifest.json`](./context-manifest.json) — the ContextOps context artifact
- [`receipts/sample-receipt.json`](./receipts/sample-receipt.json) — one complete audit receipt from a live run
- Policy: the compiled P-STRICT fixture ([`test/conformance/fixtures/p-strict.json`](../../test/conformance/fixtures/p-strict.json)) — identities, capabilities, egress detectors, continuity endpoints
- Conformance: the same primitives are covered by the 21 normative scenarios in [`test/conformance/scenarios.json`](../../test/conformance/scenarios.json)
