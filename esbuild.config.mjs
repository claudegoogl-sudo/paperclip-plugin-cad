/**
 * esbuild configuration for the CAD plugin.
 *
 * Produces:
 *   dist/manifest.js   — plugin manifest (re-exported as default)
 *   dist/worker.js     — plugin worker entry point
 *
 * PLA-114: at build time, this script substitutes the sha256 of
 * `worker/seccomp_filter.bpf` AND `worker/seccomp_load.py` into the
 * manifest in place of the `__PLA114_SECCOMP_FILTER_SHA256__` and
 * `__PLA114_SECCOMP_LOADER_SHA256__` placeholders (rev-4 §5.2 dual pin).
 * If either source is missing the substitution is skipped with a
 * warning — the placeholder survives to runtime and the spawn helper
 * fails closed on the sha256 length check.
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

/**
 * Compute the seccomp loader shim digest (rev-4 §5.2 dual pin). The shim
 * is a checked-in python source file, so this should always succeed; the
 * existsSync check is symmetry with the blob path and a defense against
 * accidental deletion.
 */
function computeSeccompLoaderSha256() {
  const path = "worker/seccomp_load.py";
  if (!existsSync(path)) {
    console.warn(
      `[build] worker/seccomp_load.py not found — manifest will retain ` +
        `the placeholder digest. The loader shim is checked in; this ` +
        `indicates a corrupted source tree.`,
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

    // PLA-114: substitute the seccomp filter digest AND the loader-shim
    // digest into the bundled manifest (and into sidecars) so the host's
    // capability negotiation can pin to content-addressed blobs. Both
    // pins are required by rev-4 §5.2 — the loader pin closes the
    // substitution-attack window where the prctl-issuing python shim is
    // swapped for a no-op while the filter blob digest stays unchanged.
    //
    // PLA-215: the same placeholders also appear in the bundled
    // `dist/worker.js` (cad-worker-client.ts imports them from manifest.ts
    // for runtime verification — esbuild inlines manifest.ts into both
    // bundle outputs because they're separate entrypoints). We substitute
    // BOTH files so the runtime verifier in worker.js sees real digests
    // instead of placeholders. An unsubstituted placeholder failing the
    // sha256 length check at startup is the intended fail-closed signal.
    const targets = ["dist/manifest.js", "dist/worker.js"];
    const filterSha = computeSeccompFilterSha256();
    const loaderSha = computeSeccompLoaderSha256();

    if (filterSha) {
      writeFileSync("dist/seccomp_filter.bpf.sha256", `${filterSha}\n`);
      console.log(
        `[build] manifest pinned to seccomp_filter.bpf sha256=${filterSha}`,
      );
    }
    if (loaderSha) {
      writeFileSync("dist/seccomp_load.py.sha256", `${loaderSha}\n`);
      console.log(
        `[build] manifest pinned to seccomp_load.py sha256=${loaderSha}`,
      );
    }

    if (filterSha || loaderSha) {
      for (const target of targets) {
        if (!existsSync(target)) continue;
        let src = readFileSync(target, "utf8");
        if (filterSha) {
          src = src.replace(/__PLA114_SECCOMP_FILTER_SHA256__/g, filterSha);
        }
        if (loaderSha) {
          src = src.replace(/__PLA114_SECCOMP_LOADER_SHA256__/g, loaderSha);
        }
        writeFileSync(target, src);
      }
    }

    console.log("Build complete.");
  }
}

build().catch((err) => {
  console.error(err);
  process.exit(1);
});
