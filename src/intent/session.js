import { DurableObject } from "cloudflare:workers";
import {
  driftReviewThreshold,
  evaluateIntentEnvelope,
  safeTraceAction,
  validateIntentEnvelope
} from "./envelope.js";

export class IntentSession extends DurableObject {
  async consumeNonce({ nonce, timestamp }) {
    const nonceState = (await this.ctx.storage.get("nonce_state")) ?? { nonces: [] };
    const now = Date.now();
    const retained = nonceState.nonces.filter((entry) => entry.expires_at > now);
    if (retained.some((entry) => entry.nonce === nonce)) return { ok: false, reason: "replay_detected" };
    retained.push({ nonce, expires_at: Math.max(now, Date.parse(timestamp)) + 10 * 60_000 });
    await this.ctx.storage.put("nonce_state", { nonces: retained });
    return { ok: true };
  }

  async start({ identity, sessionId, envelope }) {
    const existing = await this.ctx.storage.get("state");
    if (existing) return { ok: false, reason: "session_already_frozen" };

    const validation = await validateIntentEnvelope(envelope, identity, sessionId);
    if (!validation.valid) return { ok: false, reason: validation.reason };

    const state = {
      envelope: validation.envelope,
      envelope_hash: validation.envelope_hash,
      prior_action_trace: [],
      envelope_drift_count: 0,
      envelope_drift_review: false
    };
    await this.ctx.storage.put("state", state);
    return { ok: true, ...snapshot(state) };
  }

  async decide({ action, baseResult, capability }) {
    const state = await this.ctx.storage.get("state");
    if (!state?.envelope) return { ok: false, reason: "no_envelope" };

    const evaluated = evaluateIntentEnvelope({
      envelope: state.envelope,
      priorActionTrace: state.prior_action_trace,
      action,
      baseResult,
      capability
    });
    const driftCount = state.envelope_drift_count + (evaluated.drift ? 1 : 0);
    const next = {
      ...state,
      prior_action_trace: [...state.prior_action_trace, {
        seq: state.prior_action_trace.length,
        event_type: evaluated.traceEventType,
        action: safeTraceAction(action),
        decision: evaluated.result.decision,
        rule_id: evaluated.result.rule_id,
        reason: evaluated.result.reason
      }],
      envelope_drift_count: driftCount,
      envelope_drift_review: state.envelope_drift_review || driftCount >= driftReviewThreshold(state.envelope)
    };
    await this.ctx.storage.put("state", next);
    return { ok: true, result: evaluated.result, ...snapshot(next) };
  }

  async defer({ action, baseResult, capability, identityId, deferRule }) {
    const state = await this.ctx.storage.get("state");
    if (!state?.envelope) return { ok: false, reason: "no_envelope" };
    const evaluated = evaluateIntentEnvelope({ envelope: state.envelope, priorActionTrace: state.prior_action_trace, action, baseResult, capability });
    if (evaluated.result.decision !== "allow") return { ok: true, result: evaluated.result, ...snapshot(state) };
    const resumeToken = crypto.randomUUID();
    const deferred = (await this.ctx.storage.get("deferred")) ?? {};
    const result = {
      ...evaluated.result,
      decision: "defer",
      rule_id: "R4",
      reason: deferRule.id,
      resume_token: resumeToken,
      defer_reason: deferRule.id
    };
    const next = withTrace(state, action, result, { resume_token: resumeToken, trace_event_type: "defer" });
    deferred[resumeToken] = {
      resume_token: resumeToken,
      status: "pending",
      identity_id: identityId,
      action: structuredClone(action),
      envelope: state.envelope,
      prior_action_trace: state.prior_action_trace,
      defer_rule: deferRule,
      created_at: new Date().toISOString()
    };
    await this.ctx.storage.put("state", next);
    await this.ctx.storage.put("deferred", deferred);
    return { ok: true, result, deferred_record: deferred[resumeToken], ...snapshot(next) };
  }

  async resume({ resumeToken, identityId, action, baseResult, capability }) {
    const state = await this.ctx.storage.get("state");
    const deferred = (await this.ctx.storage.get("deferred")) ?? {};
    const record = deferred[resumeToken];
    if (!state?.envelope || !record || record.status !== "pending" || record.identity_id !== identityId) return { ok: false, reason: "deferred_record_unavailable" };
    const evaluated = evaluateIntentEnvelope({ envelope: state.envelope, priorActionTrace: state.prior_action_trace, action, baseResult, capability });
    const result = { ...evaluated.result, resume_token: resumeToken, resumed_from: resumeToken };
    const next = withTrace(state, action, result, { resume_token: resumeToken, trace_event_type: "deferred.resume" });
    deferred[resumeToken] = { ...record, status: "resumed", resumed_at: new Date().toISOString(), resumed_decision: result.decision };
    await this.ctx.storage.put("state", next);
    await this.ctx.storage.put("deferred", deferred);
    return { ok: true, result, deferred_record: deferred[resumeToken], ...snapshot(next) };
  }

  async deferred(resumeToken) {
    const deferred = (await this.ctx.storage.get("deferred")) ?? {};
    return deferred[resumeToken] ?? null;
  }

  async snapshot() {
    const state = await this.ctx.storage.get("state");
    return state ? { ok: true, ...snapshot(state) } : { ok: false, reason: "no_envelope" };
  }
}

function withTrace(state, action, result, extras = {}) {
  return {
    ...state,
    prior_action_trace: [...state.prior_action_trace, {
      seq: state.prior_action_trace.length,
      event_type: extras.trace_event_type ?? eventTypeFor(action),
      action: safeTraceAction(action),
      decision: result.decision,
      rule_id: result.rule_id,
      reason: result.reason,
      ...(extras.resume_token ? { resume_token: extras.resume_token } : {})
    }],
    envelope_drift_count: state.envelope_drift_count + 0
  };
}

function eventTypeFor(action) {
  return ["discover", "invoke", "egress"].includes(action?.type) ? action.type : "invoke";
}

function snapshot(state) {
  return {
    envelope: state.envelope,
    envelope_hash: state.envelope_hash,
    prior_action_trace: state.prior_action_trace,
    envelope_drift_count: state.envelope_drift_count,
    envelope_drift_review: state.envelope_drift_review
  };
}
