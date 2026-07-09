# Boundary Policy Schema (D1)

**ContextBoundary — machine-checkable policy vocabulary.**
Version: 0.1 DRAFT (2026-07-08) · Status: WP1, pending Kannan review + GLOSSARY canonicalization · License: Apache 2.0

This is the compilable form of the framework: it expresses agent-authority (A1–A4), enforcement (E1–E3), vendor-continuity (V1–V3), and egress tiers as one declarative document a gateway can evaluate. It defines meaning and shape only — not the engine (see the engine spike).

---

## 1. Design constraints

- Deterministic: same policy + same request → same decision, always. No model in the path.
- Deploy-time compilable: policy compiles to lookup structures at deploy, not interpreted per request (Worker CPU-ms limit).
- Closed by default: anything not permitted is denied (Least Agency, A3).
- Explainable: every decision names the rule that produced it (feeds audit, D4).

## 2. Top-level shape

```yaml
apiVersion: contextboundary/v0
kind: BoundaryPolicy
metadata:
  name: <string>
  description: <string>
  default_decision: deny        # deny | approve  (never "allow"; A3 least agency)

tiers:            # autonomy tiers, ordered least->most (A2)
egress_tiers:     # data sensitivity zones (existing 3-axis: I/II/III)
identities:       # agents + their grants (A1, A2, A4)
capabilities:     # tools/MCP surfaces + their requirements (E2, E3, egress)
endpoints:        # upstream model/compute endpoints for continuity (V1-V3)
audit:            # what each crossing must emit (D4)
```

## 3. Blocks

### 3.1 tiers (A2, A3)
Ordered list; index = authority level. Discovery/invocation compare against these.
```yaml
tiers:
  - id: T0            # narrate-only: no tool action
  - id: T1            # bounded read/act on trusted, low-egress tools
  - id: T2            # act on tier-II data, still within approved set
  - id: T3            # bounded autonomous within an approved envelope
```
Rule of meaning: a grant of Tn implies Tn and below. Escalation is explicit (a grant), never implicit.

### 3.2 egress_tiers (existing axis)
```yaml
egress_tiers:
  - id: I             # freely crossable
  - id: II            # crossable within jurisdiction/vendor zone
  - id: III           # must not leave boundary
```

### 3.3 identities (A1 accountable owner, A2 tier, A4 supply)
```yaml
identities:
  - id: agent:example-runbot
    accountable_owner: role:run-lead        # A1 — REQUIRED; policy invalid without it
    autonomy_tier: T1                        # A2
    trusted_sources: [mcp:self, mcp:vendor-x]# A4 — sources this agent may consume
```
Validation: an identity with no `accountable_owner` fails schema validation (E1 has nothing to bind).

### 3.4 capabilities (E2 tier gate, E3 source filter, egress)
```yaml
capabilities:
  - id: tool:close-ticket
    source: mcp:self                         # A4 — which supply it comes from
    required_tier: T1                        # E2 — min tier to invoke
    discover_min_tier: T1                    # E3 — min tier to even see it
    egress_tier: II                          # data class this tool can surface
    requires_approval: false
```
Discovery (E3): a capability is returned to an agent at `server/discover`/`tools/list` only if agent.tier ≥ discover_min_tier AND capability.source ∈ agent.trusted_sources. Otherwise it is invisible — not denied-on-use, invisible.

### 3.5 endpoints (V1 class, V2 fallback, V3 suspension)
```yaml
endpoints:
  - id: endpoint:primary
    continuity_class: export-exposed         # V1 — withdrawable by 3rd party
    zone: II
    fallbacks: [endpoint:secondary]          # V2 — must be pre-classified
  - id: endpoint:secondary
    continuity_class: domestic
    zone: II
    fallbacks: []
```
Reroute rule (V3): on suspension of primary, route only to a fallback whose `zone` is equal-or-stricter. No equal-or-stricter fallback → deny + audit. Never silent.

### 3.6 audit (D4)
```yaml
audit:
  emit:
    - agent_id
    - accountable_owner
    - tier_in_force
    - action
    - decision            # allow | deny | approve
    - rule_id             # which rule decided
    - egress_tier_seen
    - timestamp
  sink: <deploy-time binding>
```

## 4. The five canonical rules (decision order)

Evaluated top-down; first match that denies wins; closed by default.

1. **R1 Identity (E1/A1):** action lacks a bound `accountable_owner` → **deny**(unbound_identity).
2. **R2 Discovery (E3/A4):** discovery request → return only capabilities where tier ≥ discover_min_tier AND source ∈ trusted_sources.
3. **R3 Tier (E2/A2):** invoke where agent.tier < capability.required_tier → **approve**(tier_escalation) if approvable, else **deny**.
4. **R4 Egress:** response payload class > crossing egress_tier → **deny**(egress_violation).
5. **R5 Continuity (V3):** target endpoint suspended → reroute to equal-or-stricter fallback; none → **deny**(no_fallback).

These five are also the conformance backbone (D3) — each expands into permissive, boundary, and adversarial scenarios.

## 5. Worked example A — permissive dev policy
```yaml
apiVersion: contextboundary/v0
kind: BoundaryPolicy
metadata: {name: dev, description: loose local, default_decision: approve}
tiers: [{id: T0},{id: T1},{id: T2}]
egress_tiers: [{id: I},{id: II},{id: III}]
identities:
  - id: agent:dev
    accountable_owner: role:developer
    autonomy_tier: T2
    trusted_sources: [mcp:self]
capabilities:
  - {id: tool:read-doc, source: mcp:self, required_tier: T0, discover_min_tier: T0, egress_tier: I, requires_approval: false}
  - {id: tool:write-file, source: mcp:self, required_tier: T1, discover_min_tier: T1, egress_tier: II, requires_approval: false}
endpoints: []
audit: {emit: [agent_id, accountable_owner, tier_in_force, action, decision, rule_id], sink: console}
```

## 6. Worked example B — strict prod policy
```yaml
apiVersion: contextboundary/v0
kind: BoundaryPolicy
metadata: {name: prod, description: strict run estate, default_decision: deny}
tiers: [{id: T0},{id: T1},{id: T2},{id: T3}]
egress_tiers: [{id: I},{id: II},{id: III}]
identities:
  - id: agent:run-l1
    accountable_owner: role:run-lead-apac
    autonomy_tier: T1
    trusted_sources: [mcp:self]
capabilities:
  - {id: tool:triage-alert, source: mcp:self, required_tier: T1, discover_min_tier: T1, egress_tier: II, requires_approval: false}
  - {id: tool:apply-change, source: mcp:self, required_tier: T3, discover_min_tier: T2, egress_tier: II, requires_approval: true}
  - {id: tool:read-secrets, source: mcp:vendor, required_tier: T3, discover_min_tier: T3, egress_tier: III, requires_approval: true}
endpoints:
  - {id: endpoint:primary, continuity_class: export-exposed, zone: II, fallbacks: [endpoint:secondary]}
  - {id: endpoint:secondary, continuity_class: domestic, zone: II, fallbacks: []}
audit: {emit: [agent_id, accountable_owner, tier_in_force, action, decision, rule_id, egress_tier_seen, timestamp], sink: analytics-engine}
```
In B, agent:run-l1 (T1): cannot even see `read-secrets` (discover_min_tier T3, and source not trusted); can see but not invoke `apply-change` without approval (needs T3); can use `triage-alert`. That is the whole thesis in one policy.

## 7. JSON Schema (validation, abridged)
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["apiVersion","kind","metadata","tiers","identities","capabilities"],
  "properties": {
    "apiVersion": {"const": "contextboundary/v0"},
    "kind": {"const": "BoundaryPolicy"},
    "metadata": {"type":"object","required":["name","default_decision"],
      "properties":{"default_decision":{"enum":["deny","approve"]}}},
    "tiers": {"type":"array","minItems":1,"items":{"type":"object","required":["id"]}},
    "identities": {"type":"array","items":{"type":"object",
      "required":["id","accountable_owner","autonomy_tier"],
      "properties":{"trusted_sources":{"type":"array"}}}},
    "capabilities": {"type":"array","items":{"type":"object",
      "required":["id","source","required_tier","discover_min_tier","egress_tier"]}},
    "endpoints": {"type":"array","items":{"type":"object",
      "required":["id","continuity_class","zone"]}}
  }
}
```
Note: `default_decision` deliberately excludes `allow` — closed-by-default is structural, not configurable.

## 8. Open questions for review (WP1 → Kannan)
- Tiers as global ordinals vs per-domain sets? (v0 = global ordinal; simpler, may be too coarse.)
- Should `trusted_sources` support wildcards/patterns, or exact IDs only? (v0 = exact; safer.)
- Approval path: is `approve` a terminal decision the gateway records, or does the gateway broker the approval? (v0 = records the requirement; brokering is Phase B.)
- Egress classification of a *response*: declared per-capability (v0) vs inspected per-payload? Per-payload is stronger but needs content classification — scope risk.

## Changelog
- 2026-07-08 — v0.1 draft. Full policy shape, 5 canonical rules, 2 worked examples, abridged JSON Schema. Vendor-neutral (no company names). Pending Kannan review (§8) and engine decision (D-03 spike). Authored by Chanakya.
