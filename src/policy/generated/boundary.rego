package boundary

default decision := {
  "decision": "deny",
  "rule_id": "R3",
  "reason": "closed_by_default",
  "obligations": [],
}

decision := {
  "decision": "deny",
  "rule_id": "R1",
  "reason": "unbound_identity",
  "obligations": [],
} if {
  object.get(data.identities, input.identity_id, null) == null
} else := {
  "decision": "deny",
  "rule_id": "R2",
  "reason": "untrusted_source",
  "obligations": [],
} if {
  input.action.type == "invoke"
  identity := data.identities[input.identity_id]
  capability := data.capabilities[input.action.capability]
  not capability.source in identity.trusted_sources
} else := {
  "decision": "allow",
  "rule_id": "R3",
  "reason": "tier_satisfied",
  "obligations": [],
} if {
  input.action.type == "invoke"
  identity := data.identities[input.identity_id]
  capability := data.capabilities[input.action.capability]
  identity.tier_ordinal >= capability.required_tier_ordinal
} else := {
  "decision": "deny",
  "rule_id": "R3",
  "reason": "tier_escalation",
  "obligations": [{
    "approval_required": true,
    "approver_role": identity.accountable_owner,
    "reason": "tier_escalation",
    "rule_id": "R3",
  }],
} if {
  input.action.type == "invoke"
  identity := data.identities[input.identity_id]
  capability := data.capabilities[input.action.capability]
  identity.tier_ordinal < capability.required_tier_ordinal
  capability.requires_approval
} else := {
  "decision": "deny",
  "rule_id": "R3",
  "reason": "insufficient_tier",
  "obligations": [],
} if {
  input.action.type == "invoke"
  identity := data.identities[input.identity_id]
  capability := data.capabilities[input.action.capability]
  identity.tier_ordinal < capability.required_tier_ordinal
  not capability.requires_approval
} else := {
  "decision": "deny",
  "rule_id": "R4",
  "reason": "egress_violation",
  "obligations": [],
} if {
  input.action.type == "egress"
  input.effective_egress_protection > input.crossing_ceiling_protection
} else := {
  "decision": "allow",
  "rule_id": "R4",
  "reason": "egress_within_boundary",
  "obligations": [],
} if {
  input.action.type == "egress"
  input.effective_egress_protection <= input.crossing_ceiling_protection
} else := {
  "decision": "deny",
  "rule_id": "R5",
  "reason": "undeclared_fallback",
  "obligations": [],
} if {
  input.action.type == "continuity"
  input.action.suspended == true
  endpoint := data.endpoints[input.action.endpoint]
  requested := object.get(input.action, "requested_target", "")
  requested != ""
  not requested in endpoint.fallbacks
} else := {
  "decision": "deny",
  "rule_id": "R5",
  "reason": "no_fallback",
  "obligations": [],
} if {
  input.action.type == "continuity"
  input.action.suspended == true
  endpoint := data.endpoints[input.action.endpoint]
  count(endpoint.fallbacks) == 0
} else := {
  "decision": "deny",
  "rule_id": "R5",
  "reason": "no_valid_fallback",
  "obligations": [],
} if {
  input.action.type == "continuity"
  input.action.suspended == true
  endpoint := data.endpoints[input.action.endpoint]
  count(endpoint.fallbacks) > 0
  count(valid_fallbacks(endpoint)) == 0
} else := {
  "decision": "allow",
  "rule_id": "R5",
  "reason": "suspension_reroute",
  "obligations": [],
  "target": target,
} if {
  input.action.type == "continuity"
  input.action.suspended == true
  endpoint := data.endpoints[input.action.endpoint]
  valid := valid_fallbacks(endpoint)
  count(valid) > 0
  requested := object.get(input.action, "requested_target", "")
  target := choose_target(requested, valid)
}

valid_fallbacks(endpoint) := [
  fallback_id |
  fallback_id := endpoint.fallbacks[_]
  fallback := data.endpoints[fallback_id]
  fallback.zone_protection >= endpoint.zone_protection
]

choose_target(requested, valid) := requested if {
  requested != ""
  requested in valid
} else := valid[0]
