#!/usr/bin/env node
/**
 * Fails if dist/worker.js has any bare import of a non-builtin package.
 *
 * The host registers the extracted package directory as-is and does not run
 * `npm install`, so the installed plugin has no node_modules. Any bare
 * specifier other than a Node builtin (for example
 * `from "@paperclipai/plugin-sdk"`) dies on activation with
 * ERR_MODULE_NOT_FOUND. The worker must bundle every third-party dependency.
 *
 * Usage: node scripts/check-worker-self-contained.mjs [path/to/worker.js]
 */
import { readFileSync } from "node:fs";
import { builtinModules } from "node:module";

const file = process.argv[2] ?? "dist/worker.js";
const src = readFileSync(file, "utf8");

const builtins = new Set(builtinModules);
const isBuiltin = (spec) =>
  spec.startsWith("node:") || builtins.has(spec) || builtins.has(spec.split("/")[0]);
const isRelative = (spec) =>
  spec.startsWith("./") || spec.startsWith("../") || spec.startsWith("/") ||
  spec.startsWith("file:") || spec.startsWith("data:");

// Static `import ... from "x"`, `export ... from "x"`, side-effect
// `import "x"`, dynamic `import("x")` and `require("x")`.
const patterns = [
  /\b(?:import|export)\b[^;"'`]*?\bfrom\s*["']([^"']+)["']/g,
  /\bimport\s*["']([^"']+)["']/g,
  /\bimport\s*\(\s*["']([^"']+)["']\s*\)/g,
  /\brequire\s*\(\s*["']([^"']+)["']\s*\)/g,
];

const specs = new Set();
for (const re of patterns) for (const m of src.matchAll(re)) specs.add(m[1]);

const bad = [...specs].filter((s) => !isBuiltin(s) && !isRelative(s)).sort();
const builtinsUsed = [...specs].filter(isBuiltin).sort();

console.log(`[worker-self-contained] ${file}: ${specs.size} import specifier(s); builtins: ${builtinsUsed.join(", ") || "(none)"}`);
if (bad.length) {
  console.error(`[worker-self-contained] FAIL: bare non-builtin import(s) in ${file}:`);
  for (const b of bad) console.error(`  - ${b}`);
  console.error("Bundle these into the worker (see esbuild.config.mjs workerOptions).");
  process.exit(1);
}
console.log("[worker-self-contained] OK: no bare non-builtin imports");
