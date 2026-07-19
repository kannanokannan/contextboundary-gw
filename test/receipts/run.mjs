import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { promisify } from "node:util";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createSealedReceipt, policyArtifactHash, verifyReceipt } from "../../src/audit/receipts.js";

const execFileAsync = promisify(execFile);
const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, "..", "..");
const sealKey = process.env.TEST_AUDIT_SEAL_KEY;
if (!sealKey) throw new Error("TEST_AUDIT_SEAL_KEY is required for receipt verification");
const sentinel = 'password = "old-relay-credential-9f3k2m"';
const receipt = await createSealedReceipt({
  sessionId: "session-receipt-test",
  identity: { id: "agent:run-l1", accountable_owner: "role:run-lead-apac", autonomy_tier: "T1" },
  action: { type: "egress", capability: "triage-alert", crossing_egress_tier: "II", payload_egress_tier: "II", payload: { message: sentinel } },
  result: { decision: "deny", rule_id: "R4", reason: "egress_violation", egress_tier_seen: "I", detector_id: "det:credential-pattern", obligation: null },
  policyHash: await policyArtifactHash({ fixture: "P-STRICT" }),
  retention: { policy: "retention-30d", expires_at: "2026-08-18T00:00:00.000Z" },
  sealKey
});

assert.equal((await verifyReceipt(receipt, sealKey)).valid, true, "fresh receipt must verify");
const altered = structuredClone(receipt);
altered.events[1].decision = "allow";
assert.equal((await verifyReceipt(altered, sealKey)).code, "event_altered", "altered event must be named");
const dropped = structuredClone(receipt);
dropped.events.splice(1, 1);
assert.equal((await verifyReceipt(dropped, sealKey)).code, "gap_detected", "dropped event must be named");
const reordered = structuredClone(receipt);
[reordered.events[1], reordered.events[2]] = [reordered.events[2], reordered.events[1]];
assert.equal((await verifyReceipt(reordered, sealKey)).code, "gap_detected", "reordered event must be named");
const brokenSeal = structuredClone(receipt);
brokenSeal.events.at(-1).seal_sig = "0".repeat(64);
assert.equal((await verifyReceipt(brokenSeal, sealKey)).code, "seal_invalid", "broken seal must be named");
assert.equal(JSON.stringify(receipt).includes(sentinel), false, "raw secret material must not enter receipt fields");
assert.equal(JSON.stringify(receipt).includes('"payload":'), false, "raw payloads must not enter receipt fields");

const tempDir = await mkdtemp(join(tmpdir(), "contextboundary-receipt-"));
try {
  const receiptPath = join(tempDir, "fresh-receipt.json");
  await writeFile(receiptPath, JSON.stringify(receipt));
  const { stdout } = await execFileAsync(process.execPath, [resolve(repoRoot, "audit", "verify-receipt.mjs"), receiptPath, "--key", sealKey]);
  assert.equal(JSON.parse(stdout).code, "intact", "verifier CLI must accept a fresh receipt");
} finally {
  await rm(tempDir, { recursive: true, force: true });
}

console.log(JSON.stringify({ status: "green", assertions: 9, receipt_fields: Object.keys(receipt.events[1]).sort() }, null, 2));
