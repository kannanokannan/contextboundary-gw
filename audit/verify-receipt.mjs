#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { verifyReceipt } from "../src/audit/receipts.js";

const [receiptPath] = process.argv.slice(2).filter((arg) => !arg.startsWith("--"));
const keyIndex = process.argv.indexOf("--key");
const sealKey = keyIndex >= 0 ? process.argv[keyIndex + 1] : process.env.AUDIT_SEAL_KEY;

if (!receiptPath || !sealKey) {
  console.error("Usage: node audit/verify-receipt.mjs <receipt.json> --key <seal-key>");
  process.exit(2);
}

const receipt = JSON.parse(await readFile(receiptPath, "utf8"));
const result = await verifyReceipt(receipt, sealKey);
console.log(JSON.stringify(result, null, 2));
process.exitCode = result.valid ? 0 : 1;
