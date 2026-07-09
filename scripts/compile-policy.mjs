import { execFileSync } from "node:child_process";
import { copyFile, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parse } from "yaml";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const inputPath = resolve(root, process.argv[2] ?? "policy/boundary-policy.yaml");
const generatedDir = resolve(root, "src/policy/generated");
const buildDir = resolve(root, ".policy-build");
const regoPath = resolve(root, "src/policy/compile/boundary.rego");
const detectorSetsPath = resolve(root, "policy/egress-detectors.json");
const opaBin = process.env.OPA_BIN ?? "opa";

const policy = parse(await readFile(inputPath, "utf8"));
const detectorSets = JSON.parse(await readFile(detectorSetsPath, "utf8"));
validatePolicy(policy);

const tierOrdinals = Object.fromEntries(policy.tiers.map((tier, index) => [tier.id, index]));
const egressProtection = { I: 3, II: 2, III: 1 };
const data = {
  metadata: policy.metadata,
  tiers: tierOrdinals,
  egress_protection: egressProtection,
  egress_detectors: policy.egress_detectors.map((detector) => ({
    ...detector,
    min_protection: requiredOrdinal(egressProtection, detector.min_tier, `detector ${detector.id}`),
    pattern_set: detectorSets[detector.match] ?? fail(`Detector ${detector.id} references unknown pattern set ${detector.match}`)
  })),
  identities: Object.fromEntries(policy.identities.map((identity) => [
    identity.id,
    {
      ...identity,
      tier_ordinal: requiredOrdinal(tierOrdinals, identity.autonomy_tier, `identity ${identity.id}`)
    }
  ])),
  capabilities: Object.fromEntries(policy.capabilities.map((capability) => [
    capability.id,
    {
      ...capability,
      required_tier_ordinal: requiredOrdinal(tierOrdinals, capability.required_tier, `capability ${capability.id}`),
      discover_min_tier_ordinal: requiredOrdinal(tierOrdinals, capability.discover_min_tier, `capability ${capability.id}`),
      egress_protection: requiredOrdinal(egressProtection, capability.egress_tier, `capability ${capability.id}`)
    }
  ])),
  endpoints: Object.fromEntries(policy.endpoints.map((endpoint) => [
    endpoint.id,
    {
      ...endpoint,
      zone_protection: requiredOrdinal(egressProtection, endpoint.zone, `endpoint ${endpoint.id}`)
    }
  ])),
  audit: policy.audit
};

await rm(buildDir, { recursive: true, force: true });
await mkdir(generatedDir, { recursive: true });
await mkdir(buildDir, { recursive: true });
await writeFile(resolve(generatedDir, "data.json"), `${JSON.stringify(data, null, 2)}\n`);
await copyFile(regoPath, resolve(generatedDir, "boundary.rego"));

execFileSync(opaBin, [
  "build",
  "-t", "wasm",
  "-e", "boundary/decision",
  regoPath,
  "-o", resolve(buildDir, "bundle.tar.gz")
], { stdio: "inherit" });

execFileSync("tar", [
  "-xzf", resolve(buildDir, "bundle.tar.gz"),
  "-C", buildDir,
  "/policy.wasm"
], { stdio: "inherit" });

await copyFile(resolve(buildDir, "policy.wasm"), resolve(generatedDir, "policy.wasm"));
await rm(buildDir, { recursive: true, force: true });
console.log(`Compiled ${inputPath} to ${generatedDir}`);

function validatePolicy(value) {
  for (const key of ["tiers", "egress_tiers", "egress_detectors", "identities", "capabilities", "endpoints", "audit"]) {
    if (value?.[key] === undefined) throw new Error(`Policy is missing ${key}`);
  }
  for (const identity of value.identities) {
    if (!identity.accountable_owner) throw new Error(`Identity ${identity.id} has no accountable_owner`);
  }
}

function fail(message) {
  throw new Error(message);
}

function requiredOrdinal(ordinals, id, context) {
  const ordinal = ordinals[id];
  if (ordinal === undefined) throw new Error(`${context} references unknown tier ${id}`);
  return ordinal;
}
