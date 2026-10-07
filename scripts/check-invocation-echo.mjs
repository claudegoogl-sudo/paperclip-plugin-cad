#!/usr/bin/env node
/**
 * Fails if dist/worker.js declares `echoesInvocationId` but never echoes
 * `paperclipInvocationId`.
 *
 * When a worker declares `echoesInvocationId` at initialize, the host turns
 * off its single-in-flight fallback and rejects every worker->host call that
 * does not carry the active invocation id (-32005, "missing, expired, or
 * unknown invocation scope"). A bundled SDK that declares the flag but never
 * stamps the id breaks every in-dispatch host call (config.get,
 * secrets.resolve). Grepping the shipped bundle is the gate: dependency pins
 * alone do not prove which SDK bytes were bundled.
 *
 * Usage: node scripts/check-invocation-echo.mjs [path/to/worker.js]
 */
import { readFileSync } from "node:fs";

const file = process.argv[2] ?? "dist/worker.js";
const src = readFileSync(file, "utf8");
const count = (needle) => src.split(needle).length - 1;

const declares = count("echoesInvocationId");
const echoes = count("paperclipInvocationId");
console.log(`[invocation-echo] ${file}: echoesInvocationId=${declares} paperclipInvocationId=${echoes}`);

if (declares > 0 && echoes === 0) {
  console.error(
    "[invocation-echo] FAIL: the worker declares echoesInvocationId but never sends paperclipInvocationId.\n" +
      "The host will reject every in-dispatch worker->host call. Bundle an SDK that echoes the id.",
  );
  process.exit(1);
}
console.log("[invocation-echo] OK");
