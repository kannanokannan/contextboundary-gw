import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createServer } from "node:http";
import { once } from "node:events";
import { exportOtlpReceipt, otlpTrace } from "../../src/r8/otel.js";

const receipt = JSON.parse(await readFile(new URL("../../examples/ams-ticket-change/receipts/sample-receipt.json", import.meta.url), "utf8"));
const trace = await otlpTrace(receipt);
const spans = trace.resourceSpans[0].scopeSpans[0].spans;
assert.equal(spans.length, receipt.events.length, "S-R8-01 exports one span per receipt event");
assert.ok(spans.every((span) => span.traceId === spans[0].traceId && /^[0-9a-f]{32}$/.test(span.traceId)), "S-R8-01 produces one valid deterministic trace id per session");
assert.equal(spans[1].parentSpanId, spans[0].spanId, "S-R8-01 preserves receipt parentage");
const serialized = JSON.stringify(trace);
assert.equal(serialized.includes("old-relay-credential"), false, "S-R8-02 never exports raw payload content");
assert.equal(serialized.includes('"d"'), false, "S-R8-02 never exports private-key material");
assert.ok(serialized.includes("contextboundary.agent_key_id"), "S-R8-01 exports required decision metadata");

let received;
const collector = createServer(async (request, response) => {
  const chunks = []; for await (const chunk of request) chunks.push(chunk);
  received = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  response.writeHead(202).end();
});
collector.listen(0, "127.0.0.1"); await once(collector, "listening");
const endpoint = `http://127.0.0.1:${collector.address().port}/v1/traces`;
assert.equal((await exportOtlpReceipt(receipt, { OTLP_HTTP_ENDPOINT: endpoint })).exported, true, "S-R8-01 exports OTLP/HTTP JSON");
assert.equal(received.resourceSpans[0].scopeSpans[0].spans.length, receipt.events.length, "collector receives the complete trace");
await new Promise((resolveClose) => collector.close(resolveClose));

const unavailable = await exportOtlpReceipt(receipt, { OTLP_HTTP_ENDPOINT: endpoint });
assert.equal(unavailable.exported, false, "S-R8-03 unreachable OTLP endpoint is non-authoritative");
assert.equal(receipt.events.length, 3, "S-R8-03 receipt system of record remains complete after export failure");

console.log(JSON.stringify({ status: "green", assertions: 10, profile: "R8-otlp-non-authoritative-mirror" }, null, 2));
