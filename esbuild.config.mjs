/**
 * esbuild configuration for the CAD plugin.
 *
 * Produces:
 *   dist/manifest.js     — plugin manifest (re-exported as default)
 *   dist/worker.js       — plugin worker entry point
 *   dist/cad_worker.py   — copied from src/ so the bundled worker
 *                          (running from dist/) can resolve it via
 *                          `join(__dirname, "cad_worker.py")` after
 *                          npm extracts the tarball (PLA-447).
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
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { createHash } from "node:crypto";

const watch = process.argv.includes("--watch");

if (!existsSync("dist")) mkdirSync("dist");

// PLA-526 — single source of truth for the plugin version.
//
// `src/manifest.ts` previously hardcoded its `version` field, which had
// drifted from `package.json.version` before (v0.1.3 / PLA-443 — manifest
// said "0.1.2" while the tarball said "0.1.3", so `paperclipai plugin
// inspect` reported the wrong version after a clean install). PLA-443
// added a post-hoc parity vitest; PLA-526 makes drift impossible by
// substituting `__PLUGIN_VERSION__` at build time via esbuild's `define`.
// `src/globals.d.ts` declares the ambient for `tsc --noEmit`; the
// constant is a string literal at runtime, byte-identical to
// `package.json.version`. The post-build
// `scripts/check-manifest-version.mjs` gate re-parses `dist/manifest.js`
// and fails the build on any future mismatch (e.g. if the `define` line
// is removed or a literal is reintroduced).
const pkg = JSON.parse(readFileSync("package.json", "utf8"));
const versionDefine = {
  __PLUGIN_VERSION__: JSON.stringify(pkg.version),
};

const sharedOptions = {
  bundle: true,
  platform: "node",
  target: "node20",
  format: "esm",
  sourcemap: true,
  define: versionDefine,
};

// Manifest entry — src/manifest.ts imports the SDK type-only
// (`import type { PaperclipPluginManifestV1 }`), which esbuild erases, so the
// emitted dist/manifest.js carries no runtime SDK import. We keep the blanket
// `packages: "external"` here to preserve prior manifest output byte-for-byte.
const manifestOptions = {
  ...sharedOptions,
  packages: "external",
  entryPoints: { manifest: "src/manifest.ts" },
  outdir: "dist",
};

// Worker entry (PLA-748) — bundle @paperclipai/plugin-sdk, the worker's only
// third-party runtime dependency, INTO dist/worker.js. The host's
// `plugin install -l <dir>` registers a package directory as-is and does NOT
// run `npm install`, so a bare-extracted release tarball has no
// node_modules/@paperclipai/plugin-sdk and a bare external import dies on
// activation with ERR_MODULE_NOT_FOUND (the v525 CAD outage, PLA-639; live
// 0.1.6 only survives via a manual `npm install --omit=dev` hotfix). We
// therefore omit `packages: "external"` for the worker: Node builtins stay
// external automatically because platform:"node", while the SDK (and its
// transitive deps) is inlined. Mirrors klipper's worker preset, whose only
// externals are react/react-dom — neither of which CAD imports. The
// `check:release-tarball` self-contained gate regresses CI if this is undone.
const workerOptions = {
  ...sharedOptions,
  entryPoints: { worker: "src/worker.ts" },
  outdir: "dist",
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
  const manifestCtx = await esbuild.context(manifestOptions);
  const workerCtx = await esbuild.context(workerOptions);

  if (watch) {
    await Promise.all([manifestCtx.watch(), workerCtx.watch()]);
    console.log("Watching for changes...");
  } else {
    await Promise.all([manifestCtx.rebuild(), workerCtx.rebuild()]);
    await Promise.all([manifestCtx.dispose(), workerCtx.dispose()]);

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

    // PLA-447: copy the python worker source into dist/ so the bundled
    // node worker (running from dist/worker.js) can resolve it via
    // `join(__dirname, "cad_worker.py")` after npm extracts the tarball.
    // The runtime contract (src/cad-worker-client.ts:107) expects this
    // file adjacent to worker.js; without the copy step the published
    // tarball ships src/cad_worker.py only and the host's bwrap spawn
    // fails with `Can't find source path .../package/dist/cad_worker.py`.
    const WORKER_PY_SRC = "src/cad_worker.py";
    const WORKER_PY_DST = "dist/cad_worker.py";
    if (!existsSync(WORKER_PY_SRC)) {
      throw new Error(
        `[build] ${WORKER_PY_SRC} missing — refusing to produce a tarball ` +
          `that would 500 at first dispatch. See PLA-447.`,
      );
    }
    copyFileSync(WORKER_PY_SRC, WORKER_PY_DST);
    console.log(`[build] copied ${WORKER_PY_SRC} → ${WORKER_PY_DST}`);

    console.log("Build complete.");
  }
}

build().catch((err) => {
  console.error(err);
  process.exit(1);
});
