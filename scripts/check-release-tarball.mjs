#!/usr/bin/env node
/**
 * PLA-447 — release-time tarball smoke-check.
 *
 * Runs `npm pack --json` against the current working tree and asserts
 * that every entry in `REQUIRED_RUNTIME_ASSETS` is present inside the
 * produced tarball. Exits non-zero (and deletes the half-baked tarball)
 * on any missing path so the release pipeline halts before publish.
 *
 * Catches the whole class of "release-asset blob missing from npm
 * package" defects that produced the v0.1.4→v0.1.5 (seccomp_filter.bpf,
 * PLA-444) and v0.1.5→v0.1.6 (dist/cad_worker.py, PLA-447) regressions.
 * Both went undetected through `npm publish` because the host install
 * succeeded — the failure mode is at runtime, when the worker's bwrap
 * spawn can't find a `--ro-bind` source path inside the extracted
 * package.
 *
 * Add new required runtime assets to `REQUIRED_RUNTIME_ASSETS` whenever
 * a runtime spawn path materializes a new package-relative file.
 *
 * Wired into:
 *   - `npm run check:release-tarball` (developer ergonomic; runs npm pack)
 *   - `.github/workflows/release.yml` (CI gate; not yet enabled)
 *
 * Self-test: pass `--self-test` to skip `npm pack` and run the gate
 * against a synthetic file-listing fixture, proving the gate refuses
 * a tarball that omits a required asset.
 */
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, unlinkSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(SCRIPT_DIR, "..");

/**
 * Runtime asset files that MUST exist inside the published tarball.
 *
 * Each path is package-relative (i.e. inside the `package/` prefix
 * that npm adds to every tarball entry — `tar tf` emits these as
 * `package/<path>`).
 *
 * Source for each entry:
 *   - dist/manifest.js        — host plugin registry entrypoint
 *                               (package.json paperclipPlugin.manifest)
 *   - dist/worker.js          — bundled node worker entrypoint
 *                               (package.json paperclipPlugin.worker)
 *   - dist/cad_worker.py      — python worker bwrap'd from
 *                               cad-worker-client.ts:107 via
 *                               `join(__dirname, "cad_worker.py")`.
 *                               PLA-447 added the build-step copy.
 *   - worker/seccomp_filter.bpf
 *                             — kernel-sandbox BPF blob, bwrap'd from
 *                               cad-worker-client.ts:117 (PLA-444 added
 *                               to files allowlist in v0.1.5).
 *   - worker/seccomp_load.py  — python loader shim that installs the
 *                               BPF filter via prctl, bwrap'd from
 *                               cad-worker-client.ts:127.
 *   - worker/cad_preexec      — preexec wrapper binary, exec'd from
 *                               cad-worker-client.ts:139 (PLA-444).
 */
const REQUIRED_RUNTIME_ASSETS = [
  "dist/manifest.js",
  "dist/worker.js",
  "dist/cad_worker.py",
  "worker/seccomp_filter.bpf",
  "worker/seccomp_load.py",
  "worker/cad_preexec",
];

/**
 * Compute the tarball filename npm pack will produce for the current
 * package.json: `<scope>-<name>-<version>.tgz` with `@scope/` flattened
 * to `<scope>-`. Matches the npm 8+ filename convention used by
 * `npm pack` when no `--pack-destination` is set.
 */
function computeTarballFilename() {
  const pkg = JSON.parse(readFileSync(resolve(REPO_ROOT, "package.json"), "utf8"));
  const flatName = pkg.name.replace(/^@/, "").replace("/", "-");
  return `${flatName}-${pkg.version}.tgz`;
}

/**
 * Run `npm pack` in the repo root (prepack hook builds + validates) and
 * return `{ tarball, entries }`. We compute the tarball filename
 * ourselves rather than parsing `npm pack --json` because the prepack
 * lifecycle leaks `make` and esbuild output onto npm's stdout even with
 * `--silent`, so JSON parsing is unreliable across npm versions.
 *
 * Throws if `npm pack` fails or the predicted tarball isn't on disk.
 */
function packAndList() {
  const result = spawnSync("npm", ["pack"], {
    cwd: REPO_ROOT,
    stdio: "inherit",
  });
  if (result.status !== 0) {
    throw new Error(`[release-check] npm pack failed (exit ${result.status})`);
  }
  const tarball = resolve(REPO_ROOT, computeTarballFilename());
  if (!existsSync(tarball)) {
    throw new Error(`[release-check] expected tarball missing on disk: ${tarball}`);
  }
  const entries = listTarballEntries(tarball);
  return { tarball, entries };
}

/**
 * Run `tar tzf <tarball>` and return the set of entries with the
 * leading `package/` prefix stripped (so callers can match against the
 * package-relative paths in `REQUIRED_RUNTIME_ASSETS`).
 */
function listTarballEntries(tarball) {
  const result = spawnSync("tar", ["tzf", tarball], { encoding: "utf8" });
  if (result.status !== 0) {
    throw new Error(
      `[release-check] tar tzf failed (exit ${result.status}): ${result.stderr}`,
    );
  }
  const entries = new Set();
  for (const line of result.stdout.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    // npm always prefixes entries with `package/`. Strip it so callers
    // can match against package-relative paths.
    entries.add(trimmed.startsWith("package/") ? trimmed.slice("package/".length) : trimmed);
  }
  return entries;
}

/**
 * Assert every entry in `required` is present in `entries`. Returns the
 * missing list (empty array on success).
 */
function checkRequired(entries, required) {
  return required.filter((path) => !entries.has(path));
}

/**
 * PLA-748 — self-contained-bundle gate.
 *
 * The host's `plugin install -l <dir>` registers an extracted tarball as-is
 * and does NOT run `npm install`, so a bare-extracted package has no
 * `node_modules/`. CAD's worker therefore MUST bundle its only third-party
 * runtime dependency (`@paperclipai/plugin-sdk`, plus its transitive
 * `@paperclipai/shared`) into `dist/worker.js` — an un-bundled (`packages:
 * "external"`) build emits a top-level `import … from "@paperclipai/…"` that
 * dies on activation with ERR_MODULE_NOT_FOUND (the v525 CAD outage, PLA-639).
 *
 * `esbuild` inlines bundled modules under `// node_modules/@paperclipai/…`
 * banner comments (not import statements), so we scan only for the
 * *unresolved external import/require forms*. Any hit means the SDK leaked
 * back out as external and the tarball is NOT self-contained — fail the gate
 * so a future un-bundling regresses CI.
 */
function findBareSdkImports(workerSource) {
  const patterns = [
    /\bfrom\s*["'](@paperclipai\/[^"']+)["']/g, // import/export … from "@paperclipai/…"
    /\bimport\s*["'](@paperclipai\/[^"']+)["']/g, // bare `import "@paperclipai/…"`
    /\brequire\(\s*["'](@paperclipai\/[^"']+)["']\s*\)/g, // CJS interop
  ];
  const found = new Set();
  for (const re of patterns) {
    let m;
    while ((m = re.exec(workerSource)) !== null) found.add(m[1]);
  }
  return [...found];
}

/**
 * Extract a single package-relative file's contents from the tarball without
 * unpacking the whole archive (`tar -xzO package/<rel>` streams to stdout).
 */
function readTarballEntry(tarball, packageRelPath) {
  const result = spawnSync("tar", ["-xzOf", tarball, `package/${packageRelPath}`], {
    encoding: "utf8",
  });
  if (result.status !== 0) {
    throw new Error(
      `[release-check] tar -xzO ${packageRelPath} failed (exit ${result.status}): ${result.stderr}`,
    );
  }
  return result.stdout;
}

/**
 * Self-test: drive `checkRequired` with a synthetic file list to prove
 * the gate fires when a required asset is missing. This is the
 * "intentionally break the file list locally to prove the gate fires"
 * acceptance criterion from PLA-447 — captured as code so it can't drift.
 */
function runSelfTest() {
  const complete = new Set(REQUIRED_RUNTIME_ASSETS);
  const passing = checkRequired(complete, REQUIRED_RUNTIME_ASSETS);
  if (passing.length !== 0) {
    console.error(
      `[release-check][self-test] FAIL — complete fixture rejected: ${passing.join(", ")}`,
    );
    process.exit(1);
  }

  const broken = new Set(REQUIRED_RUNTIME_ASSETS);
  broken.delete("dist/cad_worker.py");
  const failing = checkRequired(broken, REQUIRED_RUNTIME_ASSETS);
  if (failing.length !== 1 || failing[0] !== "dist/cad_worker.py") {
    console.error(
      `[release-check][self-test] FAIL — broken fixture not rejected as expected; got: ${failing.join(", ") || "<empty>"}`,
    );
    process.exit(1);
  }

  // PLA-748: prove the self-contained gate accepts a bundled worker (banner
  // comments only) and rejects an un-bundled one (external import statement).
  const bundledWorker = [
    "// node_modules/@paperclipai/plugin-sdk/dist/define-plugin.js",
    'var x = "uses @paperclipai/plugin-sdk at runtime";',
    "function defineWorkerPlugin() {}",
  ].join("\n");
  const bundledHits = findBareSdkImports(bundledWorker);
  if (bundledHits.length !== 0) {
    console.error(
      `[release-check][self-test] FAIL — bundled worker fixture flagged as external: ${bundledHits.join(", ")}`,
    );
    process.exit(1);
  }

  const externalWorker = 'import { defineWorkerPlugin } from "@paperclipai/plugin-sdk";\n';
  const externalHits = findBareSdkImports(externalWorker);
  if (externalHits.length !== 1 || externalHits[0] !== "@paperclipai/plugin-sdk") {
    console.error(
      `[release-check][self-test] FAIL — external worker fixture not flagged; got: ${externalHits.join(", ") || "<empty>"}`,
    );
    process.exit(1);
  }

  console.log(
    "[release-check][self-test] OK — gate accepts complete set, rejects missing dist/cad_worker.py, " +
      "and the self-contained check accepts a bundled worker while rejecting an external SDK import.",
  );
}

function main() {
  const args = process.argv.slice(2);
  if (args.includes("--self-test")) {
    runSelfTest();
    return;
  }

  const keepTarball = args.includes("--keep");
  const { tarball, entries } = packAndList();
  const missing = checkRequired(entries, REQUIRED_RUNTIME_ASSETS);

  // PLA-748: self-contained-bundle gate. Read the packed worker bundle and
  // assert the SDK is inlined (no external `@paperclipai/…` import survives),
  // so the bare-extracted tarball activates with no node_modules/ present.
  const bareImports = findBareSdkImports(readTarballEntry(tarball, "dist/worker.js"));
  if (bareImports.length > 0) {
    console.error(
      `[release-check] FAIL — tarball ${tarball} is NOT self-contained: ` +
        `dist/worker.js carries unbundled external import(s):`,
    );
    for (const spec of bareImports) console.error(`  - ${spec}`);
    console.error(
      `\nThe host's \`plugin install -l\` does not run \`npm install\`, so these ` +
        `imports die with ERR_MODULE_NOT_FOUND on activation (PLA-639/PLA-748). ` +
        `Bundle them into dist/worker.js (do NOT mark @paperclipai/* external for ` +
        `the worker entry in esbuild.config.mjs), then re-run \`npm run check:release-tarball\`.`,
    );
    if (!keepTarball && existsSync(tarball)) {
      try {
        unlinkSync(tarball);
      } catch (err) {
        console.error(`[release-check] (failed to delete tarball: ${err.message})`);
      }
    }
    process.exit(1);
  }

  if (missing.length > 0) {
    console.error(
      `[release-check] FAIL — tarball ${tarball} is missing required runtime assets:`,
    );
    for (const path of missing) console.error(`  - package/${path}`);
    console.error(
      `\nFix the package.json "files" allowlist or the build step that produces these paths, ` +
        `then re-run \`npm run check:release-tarball\`. See PLA-447 for context.`,
    );
    if (!keepTarball && existsSync(tarball)) {
      try {
        unlinkSync(tarball);
      } catch (err) {
        console.error(`[release-check] (failed to delete tarball: ${err.message})`);
      }
    }
    process.exit(1);
  }

  console.log(`[release-check] OK — tarball ${tarball} contains all required runtime assets:`);
  for (const path of REQUIRED_RUNTIME_ASSETS) console.log(`  package/${path}`);
  console.log(
    "[release-check] OK — dist/worker.js is self-contained (no external @paperclipai/* import; " +
      "activates with no node_modules/ present).",
  );
  if (!keepTarball && existsSync(tarball)) {
    try {
      unlinkSync(tarball);
      console.log(`[release-check] cleaned up ${tarball} (pass --keep to retain).`);
    } catch (err) {
      console.error(`[release-check] (failed to delete tarball: ${err.message})`);
    }
  }
}

main();
