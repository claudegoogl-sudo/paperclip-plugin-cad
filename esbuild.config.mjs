/**
 * esbuild configuration for the CAD plugin.
 *
 * Produces two bundles:
 *   dist/manifest.js — plugin manifest (re-exported as default)
 *   dist/worker.js   — plugin worker entry point
 */

import * as esbuild from "esbuild";
import { existsSync, mkdirSync } from "node:fs";

const watch = process.argv.includes("--watch");

if (!existsSync("dist")) mkdirSync("dist");

const sharedOptions = {
  bundle: true,
  platform: "node",
  target: "node20",
  format: "esm",
  packages: "external",
  sourcemap: true,
};

async function build() {
  const ctx = await esbuild.context({
    ...sharedOptions,
    entryPoints: {
      manifest: "src/manifest.ts",
      worker: "src/worker.ts",
    },
    outdir: "dist",
  });

  if (watch) {
    await ctx.watch();
    console.log("Watching for changes...");
  } else {
    await ctx.rebuild();
    await ctx.dispose();
    console.log("Build complete.");
  }
}

build().catch((err) => {
  console.error(err);
  process.exit(1);
});
