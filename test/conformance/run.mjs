import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const args = parseArgs(process.argv.slice(2));
const target = args.target ?? process.env.GATEWAY_URL ?? "http://127.0.0.1:8787/mcp";
const scenariosPath = args.scenarios ?? resolve(__dirname, "scenarios.json");
const fixturesPath = args.fixtures ?? resolve(__dirname, "fixtures", "p-strict.json");

const scenarios = JSON.parse(await readFile(scenariosPath, "utf8"));
const fixtures = JSON.parse(await readFile(fixturesPath, "utf8"));
const results = [];

for (const scenario of scenarios) {
  try {
    const response = await callGateway(target, scenario, fixtures);
    assert.equal(response.status, 200, `${scenario.id}: gateway returned HTTP ${response.status}`);
    assert.equal(response.body?.error, undefined, `${scenario.id}: gateway returned JSON-RPC error`);

    const result = response.body?.result ?? {};
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
process.exitCode = summary.red > 0 || summary.xpass > 0 ? 1 : 0;

async function callGateway(url, scenario, policy) {
  const identity = scenario.identity ? policy.identities[scenario.identity] : null;
  const body = {
    jsonrpc: "2.0",
    id: scenario.id,
    method: "boundary/evaluate",
    params: {
      policy,
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
      ...(identity ? { "boundary-agent-id": identity.id } : {})
    },
    body: JSON.stringify(body)
  });

  return {
    status: response.status,
    body: await response.json()
  };
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
