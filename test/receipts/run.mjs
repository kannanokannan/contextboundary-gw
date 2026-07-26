import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { promisify } from "node:util";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createSealedReceipt, policyArtifactHash, verifyReceipt } from "../../src/audit/receipts.js";
import { verifyAgentSignature } from "../../src/identity/signatures.js";
import { createEphemeralR6Fixtures, signedHeaders, thirdPartyPublicKeys } from "../helpers/r6.mjs";

const execFileAsync = promisify(execFile);
const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, "..", "..");
const fixtures = await createEphemeralR6Fixtures();
const publicKeys = thirdPartyPublicKeys(fixtures);
const sentinel = 'password = "old-relay-credential-9f3k2m"';
const identity = { id: "agent:run-l1", accountable_owner: "role:run-lead-apac", autonomy_tier: "T1" };
const action = { type: "egress", capability: "triage-alert", crossing_egress_tier: "II", payload_egress_tier: "II", payload: { message: sentinel } };
const sessionId = "session-receipt-test";
const headers = await signedHeaders(fixtures, { sessionId, seq: 1, action });
const agentAuth = await verifyAgentSignature({ identity, action, sessionId, keyId: headers["boundary-agent-key-id"], signature: headers["boundary-agent-signature"], nonce: headers["boundary-agent-nonce"], timestamp: headers["boundary-agent-timestamp"], seq: 1, env: { AGENT_KEY_REGISTRY: JSON.stringify(fixtures.agentRegistry) } });
assert.equal(agentAuth.ok, true, "test action signature must be valid");
const receipt = await createSealedReceipt({
  sessionId, identity, action,
  result: { decision: "deny", rule_id: "R4", reason: "egress_violation", egress_tier_seen: "I", detector_id: "det:credential-pattern", obligation: null },
  policyHash: await policyArtifactHash({ fixture: "P-STRICT" }), retention: { policy: "retention-30d", expires_at: "2026-08-18T00:00:00.000Z" },
  gatewayKey: { key_id: fixtures.gatewayKeyId, private_jwk: fixtures.gateway.private_jwk, public_jwk: fixtures.gateway.public_jwk }, agentAuth
});

assert.equal((await verifyReceipt(receipt, publicKeys)).valid, true, "fresh R6 receipt verifies with public keys only");
const altered = structuredClone(receipt); altered.events[1].agent_sig = "A".repeat(86);
assert.equal((await verifyReceipt(altered, publicKeys)).code, "agent_sig_invalid", "tampered agent evidence must be named");
const dropped = structuredClone(receipt); dropped.events.splice(1, 1);
assert.equal((await verifyReceipt(dropped, publicKeys)).code, "gap_detected", "dropped event must be named");
const reordered = structuredClone(receipt); [reordered.events[1], reordered.events[2]] = [reordered.events[2], reordered.events[1]];
assert.equal((await verifyReceipt(reordered, publicKeys)).code, "gap_detected", "reordered event must be named");
const brokenSeal = structuredClone(receipt); brokenSeal.events.at(-1).seal_sig = "A".repeat(86);
assert.equal((await verifyReceipt(brokenSeal, publicKeys)).code, "seal_sig_invalid", "broken Ed25519 seal must be named");
assert.equal(JSON.stringify(receipt).includes(sentinel), false, "raw secret material must not enter receipt fields");
assert.equal(JSON.stringify(receipt).includes('"payload":'), false, "raw payloads must not enter receipt fields");

const tempDir = await mkdtemp(join(tmpdir(), "contextboundary-receipt-"));
try {
  const receiptPath = join(tempDir, "fresh-receipt.json");
  const keysPath = join(tempDir, "public-keys.json");
  await writeFile(receiptPath, JSON.stringify(receipt));
  await writeFile(keysPath, JSON.stringify(publicKeys));
  const { stdout } = await execFileAsync(process.execPath, [resolve(repoRoot, "audit", "verify-receipt.mjs"), receiptPath, "--public-keys", keysPath]);
  assert.equal(JSON.parse(stdout).code, "intact", "verifier CLI must accept a fresh public-key receipt");
} finally {
  await rm(tempDir, { recursive: true, force: true });
}

console.log(JSON.stringify({ status: "green", assertions: 10, receipt_fields: Object.keys(receipt.events[1]).sort() }, null, 2));
