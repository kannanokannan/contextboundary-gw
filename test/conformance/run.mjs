import assert from "node:assert/strict";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { hmacSha256Hex, hashIntentEnvelope } from "../../src/intent/canonical.js";
import { policyArtifactHash } from "../../src/audit/receipts.js";
import policyData from "../../src/policy/generated/data.json" with { type: "json" };
import { signingPayload, toBase64Url } from "../../src/identity/signatures.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const args = parseArgs(process.argv.slice(2));
const target = args.target ?? process.env.GATEWAY_URL ?? "http://127.0.0.1:8787/mcp";
const scenariosPath = args.scenarios ?? resolve(__dirname, "scenarios.json");
const fixturesPath = args.fixtures ?? resolve(__dirname, "fixtures", "p-strict.json");

const scenarios = JSON.parse(await readFile(scenariosPath, "utf8"));
const fixtures = JSON.parse(await readFile(fixturesPath, "utf8"));
const expectedPolicyHash = args["expect-policy-hash"] ?? await policyArtifactHash(policyData);
const results = [];
let policyHashVerified = 0;

for (const scenario of scenarios) {
  try {
    const response = await callGateway(target, scenario, fixtures);
    assert.equal(response.status, 200, `${scenario.id}: gateway returned HTTP ${response.status}`);
    assert.equal(response.body?.error, undefined, `${scenario.id}: gateway returned JSON-RPC error`);

    const result = response.body?.result ?? {};
    assert.equal(result.audit?.policy_hash, expectedPolicyHash, `${scenario.id}: policy_hash binding`);
    policyHashVerified += 1;
    assert.equal(result.decision, scenario.expect.decision, `${scenario.id}: decision`);
    assert.equal(result.rule_id, scenario.expect.rule_id, `${scenario.id}: rule_id`);

    if (scenario.expect.reason !== undefined) {
      assert.equal(result.reason, scenario.expect.reason, `${scenario.id}: reason`);
    }
    if (scenario.expect.accountable_owner !== undefined) {
      assert.equal(result.audit?.accountable_owner, scenario.expect.accountable_owner, `${scenario.id}: accountable_owner`);
    }
    if (scenario.expect.egress_tier_seen !== undefined) {
      assert.equal(result.audit?.egress_tier_seen, scenario.expect.egress_tier_seen, `${scenario.id}: egress_tier_seen`);
    }
    if (scenario.expect.detector_id !== undefined) {
      assert.equal(result.audit?.detector_id, scenario.expect.detector_id, `${scenario.id}: detector_id`);
    }
    if (scenario.expect.effective_tier !== undefined) {
      assert.equal(result.effective_tier, scenario.expect.effective_tier, `${scenario.id}: effective_tier`);
    }
    if (scenario.expect.capabilities !== undefined) {
      assert.deepEqual(result.capabilities, scenario.expect.capabilities, `${scenario.id}: discovery set`);
    }
    if (scenario.expect.target !== undefined) {
      assert.equal(result.target, scenario.expect.target, `${scenario.id}: reroute target`);
    }
    if (scenario.expect.audit_chain_length !== undefined) {
      assert.equal(result.audit_chain?.length, scenario.expect.audit_chain_length, `${scenario.id}: audit chain length`);
    }

    assertAudit(result.audit, scenario);
    results.push({ id: scenario.id, status: scenario.xfail ? "xpass" : "green" });
  } catch (error) {
    results.push({
      id: scenario.id,
      status: scenario.xfail ? "xfail" : "red",
      error: error instanceof Error ? error.message : String(error)
    });
  }
}

const summary = {
  green: results.filter((result) => result.status === "green").length,
  red: results.filter((result) => result.status === "red").length,
  xfail: results.filter((result) => result.status === "xfail").length,
  xpass: results.filter((result) => result.status === "xpass").length
};
const families = Object.fromEntries(
  ["R1", "R2", "R3", "R4", "R5", "AUD"].map((family) => {
    const familyResults = results.filter((result) => result.id.startsWith(`S-${family}-`));
    return [family, {
      green: familyResults.filter((result) => result.status === "green").length,
      red: familyResults.filter((result) => result.status === "red").length,
      xfail: familyResults.filter((result) => result.status === "xfail").length
    }];
  })
);

console.log(JSON.stringify({ target, total: results.length, summary, families, results }, null, 2));
if (args.report) {
  await writeReport(args.report, { expectedPolicyHash, policyHashVerified, results, summary, families });
}
process.exitCode = summary.red > 0 || summary.xpass > 0 ? 1 : 0;

async function callGateway(url, scenario, fixtures) {
  const identity = scenario.identity ? fixtures.identities[scenario.identity] : null;
  const sessionId = identity ? `conformance-${scenario.id}-${crypto.randomUUID()}` : null;
  if (identity) await startSession(url, identity, sessionId);
  const body = {
    jsonrpc: "2.0",
    id: scenario.id,
    method: "boundary/evaluate",
    params: {
      identity_id: identity?.id ?? null,
      action: scenario.action
    }
  };

  const response = await fetch(url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "mcp-protocol-version": "2026-07-28",
      "mcp-method": "boundary/evaluate",
      ...(identity ? { "boundary-agent-id": identity.id, "mcp-session-id": sessionId, ...await signatureHeaders(sessionId, 1, scenario.action) } : {})
    },
    body: JSON.stringify(body)
  });

  const text = await response.text();
  try {
    return { status: response.status, body: JSON.parse(text) };
  } catch {
    throw new Error(`gateway returned non-JSON HTTP ${response.status}: ${text.slice(0, 500)}`);
  }
}

async function startSession(url, identity, sessionId) {
  const envelope = {
    envelope_id: `env-${sessionId}`,
    session_id: sessionId,
    declared_by: identity.accountable_owner,
    declared_at: new Date().toISOString(),
    task_ref: "CONFORMANCE",
    authorized: {
      capabilities: ["triage-alert", "apply-change", "read-secrets"],
      sources: ["mcp:self", "mcp:vendor"],
      endpoints: ["primary", "secondary", "loose", "primary-loose-only"],
      egress_tier_ceiling: "III",
      autonomy_tier_ceiling: identity.autonomy_tier
    },
    limits: { max_actions: 100, expires_at: new Date(Date.now() + 300_000).toISOString() }
  };
  const ownerKey = process.env.TEST_R6_OWNER_BOOTSTRAP_KEY;
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "content-type": "application/json", "mcp-method": "boundary/session.start", "boundary-agent-id": identity.id, "mcp-session-id": sessionId,
      ...await signatureHeaders(sessionId, 0, { type: "session.start" }),
      "boundary-owner-proof": await hmacSha256Hex(ownerKey, await hashIntentEnvelope(envelope))
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: `start-${sessionId}`, method: "boundary/session.start", params: { intent_envelope: envelope } })
  });
  const body = await response.json();
  assert.equal(body.result?.decision, "allow", `session start for ${identity.id}`);
}

async function signatureHeaders(sessionId, seq, action) {
  const nonce = crypto.randomUUID();
  const timestamp = new Date().toISOString();
  const privateJwk = JSON.parse(process.env.TEST_R6_AGENT_PRIVATE_JWK);
  const privateKey = await crypto.subtle.importKey("jwk", { kty: "OKP", crv: "Ed25519", x: privateJwk.x, d: privateJwk.d }, { name: "Ed25519" }, false, ["sign"]);
  const signature = await crypto.subtle.sign("Ed25519", privateKey, new TextEncoder().encode(await signingPayload({ sessionId, seq, action, nonce, timestamp })));
  return { "boundary-agent-key-id": process.env.TEST_R6_AGENT_KEY_ID, "boundary-agent-signature": toBase64Url(new Uint8Array(signature)), "boundary-agent-nonce": nonce, "boundary-agent-timestamp": timestamp, "boundary-agent-seq": String(seq) };
}

function assertAudit(audit, scenario) {
  assert.equal(typeof audit, "object", `${scenario.id}: audit record missing`);
  for (const field of [
    "agent_id",
    "accountable_owner",
    "tier_in_force",
    "action",
    "decision",
    "rule_id",
    "egress_tier_seen",
    "detector_id",
    "obligation",
    "timestamp"
  ]) {
    assert.ok(Object.hasOwn(audit, field), `${scenario.id}: audit.${field} missing`);
  }
}

async function writeReport(reportPath, { expectedPolicyHash, policyHashVerified, results, summary, families }) {
  const resolvedReportPath = resolve(reportPath);
  await mkdir(dirname(resolvedReportPath), { recursive: true });
  const verdict = summary.red === 0 && summary.xpass === 0 ? "PASS" : "FAIL";
  const familyRows = Object.entries(families)
    .map(([family, counts]) => `| ${family} | ${counts.green} | ${counts.red} | ${counts.xfail} | ${counts.xpass ?? 0} |`)
    .join("\n");
  const scenarioRows = results
    .map((result) => `| ${result.id} | ${result.status} | ${result.status === "red" ? formatCell(result.error) : "-"} |`)
    .join("\n");
  const report = [
    `# Conformance report`,
    ``,
    `## Verdict: ${verdict}`,
    ``,
    `Counts: ${results.length} total; ${summary.green} green; ${summary.red} red; ${summary.xfail} xfail; ${summary.xpass} xpass.`,
    ``,
    `Policy artifact hash: \`${expectedPolicyHash}\``,
    `Policy hash verified on ${policyHashVerified} responses.`,
    ``,
    `Scenario inputs are synthetic. Decisions are produced by the reference gateway and are reproducible from a clean clone.`,
    ``,
    `Coverage: these scenarios exercise families R1-R5 and audit. R6 agent identity is proved by \`npm run test:r6\` and the intent-envelope suite, not by the scenarios below. Adversarial scenarios are authored in this repository; no external red team has reviewed them.`,
    ``,
    `## By family`,
    ``,
    `| Family | Green | Red | Xfail | Xpass |`,
    `| --- | ---: | ---: | ---: | ---: |`,
    familyRows,
    ``,
    `## By scenario`,
    ``,
    `| Scenario | Status | Failure detail |`,
    `| --- | --- | --- |`,
    scenarioRows,
    ``
  ].join("\n");
  await writeFile(resolvedReportPath, report, "utf8");
}

function formatCell(value) {
  return String(value ?? "").replace(/\|/g, "\\|").replace(/\s+/g, " ").trim();
}

function parseArgs(argv) {
  const parsed = {};
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (!arg.startsWith("--")) continue;
    const key = arg.slice(2);
    const value = argv[index + 1] && !argv[index + 1].startsWith("--") ? argv[++index] : "true";
    parsed[key] = value;
  }
  return parsed;
}
