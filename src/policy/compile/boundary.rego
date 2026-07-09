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
}

decision := {
  "decision": "allow",
  "rule_id": "R3",
  "reason": "tier_satisfied",
  "obligations": [],
} if {
  input.action.type == "invoke"
  identity := data.identities[input.identity_id]
  capability := data.capabilities[input.action.capability]
  identity.tier_ordinal >= capability.required_tier_ordinal
}

decision := {
  "decision": "deny",
  "rule_id": "R3",
  "reason": "tier_escalation",
  "obligations": ["approval_required"],
} if {
  input.action.type == "invoke"
  identity := data.identities[input.identity_id]
  capability := data.capabilities[input.action.capability]
  identity.tier_ordinal < capability.required_tier_ordinal
  capability.requires_approval
}

decision := {
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
}
