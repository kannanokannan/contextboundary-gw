import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const args = parseArgs(process.argv.slice(2));
const target = args.target ?? process.env.GATEWAY_URL ?? "http://127.0.0.1:8787/mcp";
const upstream = args.upstream ?? process.env.UPSTREAM_MCP_URL ?? "https://mcp.context-stack.org/mcp";
const scenariosPath = args.scenarios ?? resolve(__dirname, "scenarios.json");

const scenarios = JSON.parse(await readFile(scenariosPath, "utf8"));
const results = [];

for (const scenario of scenarios) {
  const gatewayResult = await callMcp(target, scenario.action);
  assert.equal(gatewayResult.status, 200, `${scenario.id}: gateway returned non-200`);

  const upstreamResult = await callMcp(upstream, scenario.action);
  assert.deepEqual(gatewayResult.body, upstreamResult.body, `${scenario.id}: gateway response differs from upstream`);

  const outcome = gatewayResult.body?.error ? "deny" : "allow";
  assert.equal(outcome, scenario.expect.outcome, `${scenario.id}: unexpected outcome`);

  const auditRecord = buildAuditRecord(scenario, outcome, gatewayResult);
  assertAuditShape(auditRecord, scenario.expect.auditRecord);

  results.push({
    id: scenario.id,
    outcome,
    method: scenario.action.body.method,
    auditRecord
  });
}

console.log(JSON.stringify({
  target,
  upstream,
  passed: results.length,
  results
}, null, 2));

async function callMcp(url, action) {
  const response = await fetch(url, {
    method: action.method ?? "POST",
    headers: action.headers ?? { "content-type": "application/json" },
    body: JSON.stringify(action.body)
  });

  return {
    status: response.status,
    headers: Object.fromEntries(response.headers),
    body: await response.json()
  };
}

function buildAuditRecord(scenario, outcome, gatewayResult) {
  return {
    schemaVersion: "conformance.audit.v0",
    scenarioId: scenario.id,
    identity: scenario.identity,
    action: {
      method: scenario.action.body.method,
      name: scenario.action.body.params?.name ?? scenario.action.body.params?.uri ?? null
    },
    decision: {
      outcome
    },
    observed: {
      httpStatus: gatewayResult.status,
      jsonrpc: gatewayResult.body?.jsonrpc ?? null,
      hasError: Boolean(gatewayResult.body?.error)
    }
  };
}

function assertAuditShape(auditRecord, expectedShape = {}) {
  assert.equal(typeof auditRecord.schemaVersion, "string");
  assert.equal(typeof auditRecord.scenarioId, "string");
  assert.equal(typeof auditRecord.identity, "object");
  assert.equal(typeof auditRecord.action, "object");
  assert.equal(typeof auditRecord.decision, "object");
  assert.equal(typeof auditRecord.observed, "object");

  for (const key of expectedShape.required ?? []) {
    assert.ok(hasPath(auditRecord, key), `audit record missing ${key}`);
  }
}

function hasPath(value, path) {
  return path.split(".").every((part) => {
    if (!value || typeof value !== "object" || !(part in value)) return false;
    value = value[part];
    return true;
  });
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
