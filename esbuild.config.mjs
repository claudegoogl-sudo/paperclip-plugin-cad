/**
 * esbuild configuration for the CAD plugin.
 *
 * Produces:
 *   dist/manifest.js   — plugin manifest (re-exported as default)
 *   dist/worker.js     — plugin worker entry point
 *
 * PLA-114: at build time, this script substitutes the sha256 of
 * `worker/seccomp_filter.bpf` into the manifest in place of the
 * `__PLA114_SECCOMP_FILTER_SHA256__` placeholder. If the bpf blob is
 * missing the substitution is skipped with a warning — the placeholder
 * survives to runtime and the spawn helper fails closed.
 */

import * as esbuild from "esbuild";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";

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

/**
 * Compute the seccomp filter blob digest, with a fallback for builds that
 * pre-date the C compile (e.g. running `npm run build` on a developer machine
 * without libseccomp-dev). The placeholder remains in that case and the
 * runtime spawn-helper detects + refuses to start with a clear error.
 */
function computeSeccompFilterSha256() {
  const path = "worker/seccomp_filter.bpf";
  if (!existsSync(path)) {
    console.warn(
      `[build] worker/seccomp_filter.bpf not found — manifest will retain ` +
        `the placeholder digest. Run \`make -C worker\` on a host with ` +
        `libseccomp-dev to produce it before publishing the plugin tarball.`,
    );
    return null;
  }
  const buf = readFileSync(path);
  return createHash("sha256").update(buf).digest("hex");
}

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

    // PLA-114: substitute the seccomp filter digest into the bundled manifest
    // (and into a sidecar dist/manifest.json) so the host's capability
    // negotiation can pin to a content-addressed blob.
    const sha = computeSeccompFilterSha256();
    if (sha) {
      const manifestJsPath = "dist/manifest.js";
      const src = readFileSync(manifestJsPath, "utf8");
      const replaced = src.replace(/__PLA114_SECCOMP_FILTER_SHA256__/g, sha);
      writeFileSync(manifestJsPath, replaced);
      writeFileSync("dist/seccomp_filter.bpf.sha256", `${sha}\n`);
      console.log(`[build] manifest pinned to seccomp_filter.bpf sha256=${sha}`);
    }

    console.log("Build complete.");
  }
}

build().catch((err) => {
  console.error(err);
  process.exit(1);
});
