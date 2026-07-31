#!/usr/bin/env node
// Starts the AMS example with runtime-only local test material. No key is read
// from disk or committed, and the three boundary/evaluate flows need no upstream.

import { spawn } from "node:child_process";
import { once } from "node:events";
import { existsSync } from "node:fs";
import { mkdtemp } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "..", "..");
const port = 8787;
const ownerBootstrapKey = "local-demo-owner-bootstrap-value";
const agentId = "agent:run-l1";
const agentKeyId = "local-demo-agent-ed25519-ephemeral";
const gatewayKeyId = "local-demo-gateway-ed25519-ephemeral";

if (await portInUse(port)) {
  throw new Error(`Local port ${port} is already in use. Stop the existing process and run this example again.`);
}

const [agent, gateway] = await Promise.all([createKeyPair(), createKeyPair()]);
const registry = { [agentId]: [{ key_id: agentKeyId, public_jwk: agent.public_jwk }] };
const receiptsDir = await mkdtemp(join(tmpdir(), "contextboundary-ams-receipts-"));
const worker = spawn(process.execPath, [
  findWrangler(), "dev", "--local", "--port", String(port),
  "--var", "UPSTREAM_MCP_URL:http://127.0.0.1:9/mcp",
  "--var", `INTENT_ENVELOPE_BOOTSTRAP_KEY:${ownerBootstrapKey}`,
  "--var", `GATEWAY_ED25519_KEY_ID:${gatewayKeyId}`,
  "--var", `GATEWAY_ED25519_PRIVATE_JWK:${JSON.stringify(gateway.private_jwk)}`,
  "--var", `AGENT_KEY_REGISTRY:${JSON.stringify(registry)}`
], { cwd: repoRoot, stdio: ["ignore", "pipe", "pipe"] });

let workerOutput = "";
worker.stdout.on("data", (chunk) => { workerOutput += chunk; });
worker.stderr.on("data", (chunk) => { workerOutput += chunk; });

try {
  await waitForGateway(worker);
  console.log(`Local gateway: http://127.0.0.1:${port}/mcp`);
  console.log("All bootstrap and signing values are runtime-only local test values.");
  const demo = spawn(process.execPath, [join(here, "demo.mjs"), "--save-receipts"], {
    cwd: repoRoot,
    stdio: "inherit",
    env: {
      ...process.env,
      BOUNDARY_OWNER_BOOTSTRAP_KEY: ownerBootstrapKey,
      DEMO_AGENT_PRIVATE_JWK: JSON.stringify(agent.private_jwk),
      DEMO_AGENT_KEY_ID: agentKeyId,
      DEMO_RECEIPTS_DIR: receiptsDir
    }
  });
  const [exitCode] = await once(demo, "exit");
  process.exitCode = exitCode ?? 1;
} finally {
  worker.kill();
  worker.stdout.destroy();
  worker.stderr.destroy();
  worker.unref();
}

async function createKeyPair() {
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const private_jwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
  const public_jwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
  return { private_jwk, public_jwk: { kty: "OKP", crv: "Ed25519", x: public_jwk.x } };
}

async function waitForGateway(child) {
  for (let attempt = 0; attempt < 120; attempt += 1) {
    if (child.exitCode !== null) throw new Error(`Wrangler exited before starting:\n${workerOutput}`);
    try {
      const response = await fetch(`http://127.0.0.1:${port}/health`, { signal: AbortSignal.timeout(1_000) });
      if (response.ok) return;
    } catch {
      // The local Worker is still starting.
    }
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 250));
  }
  throw new Error(`Timed out starting the local Worker:\n${workerOutput}`);
}

async function portInUse(value) {
  const probe = createServer();
  try {
    probe.listen(value, "127.0.0.1");
    await once(probe, "listening");
    return false;
  } catch (error) {
    if (error?.code === "EADDRINUSE") return true;
    throw error;
  } finally {
    if (probe.listening) await new Promise((resolveClose) => probe.close(resolveClose));
  }
}

function findWrangler() {
  const local = resolve(repoRoot, "node_modules", "wrangler", "bin", "wrangler.js");
  if (existsSync(local)) return local;
  throw new Error("Wrangler is required for the local AMS example. Run npm ci first.");
}
