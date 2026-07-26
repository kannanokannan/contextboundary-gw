#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { verifyReceipt } from "../src/audit/receipts.js";

const args = process.argv.slice(2);
const receiptPath = args.find((arg) => !arg.startsWith("--"));
const keysIndex = args.indexOf("--public-keys");
const publicKeysPath = keysIndex >= 0 ? args[keysIndex + 1] : undefined;

if (!receiptPath || !publicKeysPath) {
  console.error("Usage: node audit/verify-receipt.mjs <receipt.json> --public-keys <public-keys.json>");
  process.exit(2);
}

const [receipt, publicKeys] = await Promise.all([
  readFile(receiptPath, "utf8").then(JSON.parse),
  readFile(publicKeysPath, "utf8").then(JSON.parse)
]);
const result = await verifyReceipt(receipt, publicKeys);
console.log(JSON.stringify(result, null, 2));
process.exitCode = result.valid ? 0 : 1;
