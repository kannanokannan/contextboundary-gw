import policyData from "../policy/generated/data.json";
import { canonicalize, sha256Hex } from "../intent/canonical.js";

const EGRESS_PROTECTION = { I: 3, II: 2, III: 1 };

export function declaredTransforms(result) {
  return (policyData.remediation?.rules ?? [])
    .filter((rule) => rule.rule_id === result?.rule_id && rule.reason === result?.reason && (!rule.detector_id || rule.detector_id === result?.detector_id))
    .flatMap((rule) => rule.transforms ?? [])
    .map((id) => (policyData.remediation?.transforms ?? []).find((transform) => transform.id === id))
    .filter(Boolean);
}

export function deferredCondition(action) {
  return (policyData.remediation?.defer_rules ?? []).find((rule) =>
    rule.action_type === action?.type && rule.capability === action?.capability && valueAt(action, rule.when?.path) === rule.when?.equals
  ) ?? null;
}

export async function applyDeclaredTransform(action, transform) {
  const original = structuredClone(action);
  const transformed = structuredClone(action);
  if (transform.id === "strip_field") deleteAt(transformed, transform.path);
  else if (transform.id === "redact_match") redactAt(transformed, transform.path, new RegExp(transform.pattern, "gi"));
  else if (transform.id === "clamp_tier") clampTier(transformed, transform.path, transform.ceiling);
  else return null;

  if (canonicalize(original) === canonicalize(transformed)) return null;
  if (!narrows(original, transformed, transform)) return null;
  return {
    action: transformed,
    transform_id: transform.id,
    original_action_hash: await sha256Hex(canonicalize(original)),
    resulting_action_hash: await sha256Hex(canonicalize(transformed))
  };
}

export function resumeAction(record, condition) {
  if (!record?.defer_rule || !condition?.satisfied || condition.id !== record.defer_rule.resume_condition) return null;
  const action = structuredClone(record.action);
  setAt(action, record.defer_rule.resume_path, condition.value ?? true);
  return action;
}

function narrows(original, transformed, transform) {
  if (transform.id === "strip_field" || transform.id === "redact_match") return true;
  if (transform.id !== "clamp_tier") return false;
  const before = EGRESS_PROTECTION[valueAt(original, transform.path)] ?? 0;
  const after = EGRESS_PROTECTION[valueAt(transformed, transform.path)] ?? 0;
  return after >= before;
}

function clampTier(action, path, ceiling) {
  const current = valueAt(action, path);
  if (!(current in EGRESS_PROTECTION) || !(ceiling in EGRESS_PROTECTION)) return;
  if (EGRESS_PROTECTION[ceiling] >= EGRESS_PROTECTION[current]) setAt(action, path, ceiling);
}

function redactAt(object, path, pattern) {
  const current = valueAt(object, path);
  if (typeof current === "string") setAt(object, path, current.replace(pattern, "[REDACTED]"));
}

function deleteAt(object, path) {
  const [parent, key] = parentAt(object, path);
  if (parent && key in parent) delete parent[key];
}

function setAt(object, path, value) {
  const [parent, key] = parentAt(object, path);
  if (parent) parent[key] = value;
}

function valueAt(object, path) {
  return (path ?? []).reduce((value, key) => value && typeof value === "object" ? value[key] : undefined, object);
}

function parentAt(object, path) {
  if (!Array.isArray(path) || path.length === 0) return [null, null];
  const key = path.at(-1);
  const parent = path.slice(0, -1).reduce((value, part) => value && typeof value === "object" ? value[part] : undefined, object);
  return [parent, key];
}
