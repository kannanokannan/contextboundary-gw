import { once } from "node:events";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createServer } from "node:http";
import { spawn } from "node:child_process";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, "..", "..");
const port = await availablePort();
const wrangler = findWrangler();
const worker = spawn(process.execPath, [wrangler, "dev", "--local", "--port", String(port), "--compatibility-date", "2026-07-02", "--var", "AUDIT_SEAL_KEY:test-seal-key"], {
  cwd: repoRoot,
  stdio: ["ignore", "pipe", "pipe"]
});
let workerOutput = "";
worker.stdout.on("data", (chunk) => { workerOutput += chunk; });
worker.stderr.on("data", (chunk) => { workerOutput += chunk; });

try {
  const target = `http://127.0.0.1:${port}/mcp`;
  await waitForGateway(target, worker);
  const suite = spawn(process.execPath, [resolve(__dirname, "run.mjs"), "--target", target], {
    cwd: repoRoot,
    stdio: "inherit"
  });
  const [code] = await once(suite, "exit");
  process.exitCode = code ?? 1;
} finally {
  worker.kill();
  worker.stdout.destroy();
  worker.stderr.destroy();
  worker.unref();
}

async function waitForGateway(target, child) {
  for (let attempt = 0; attempt < 120; attempt += 1) {
    if (child.exitCode !== null) throw new Error(`Wrangler exited before starting:\n${workerOutput}`);
    try {
      const response = await fetch(target.replace(/\/mcp$/, "/health"), { signal: AbortSignal.timeout(1_000) });
      if (response.ok) return;
    } catch {
      // The local Worker is still starting.
    }
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 250));
  }
  throw new Error(`Timed out starting the local Worker:\n${workerOutput}`);
}

async function availablePort() {
  const probe = createServer();
  probe.listen(0, "127.0.0.1");
  await once(probe, "listening");
  const { port } = probe.address();
  await new Promise((resolveClose) => probe.close(resolveClose));
  return port;
}

function findWrangler() {
  const local = resolve(repoRoot, "node_modules", "wrangler", "bin", "wrangler.js");
  if (existsSync(local)) return local;
  const global = process.env.APPDATA
    ? resolve(process.env.APPDATA, "npm", "node_modules", "wrangler", "bin", "wrangler.js")
    : null;
  if (global && existsSync(global)) return global;
  throw new Error("Wrangler is required for the local conformance test. Run npm ci first.");
}
