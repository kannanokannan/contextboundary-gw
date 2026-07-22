import { DurableObject } from "cloudflare:workers";
import {
  driftReviewThreshold,
  evaluateIntentEnvelope,
  safeTraceAction,
  validateIntentEnvelope
} from "./envelope.js";

export class IntentSession extends DurableObject {
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

  async snapshot() {
    const state = await this.ctx.storage.get("state");
    return state ? { ok: true, ...snapshot(state) } : { ok: false, reason: "no_envelope" };
  }
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
