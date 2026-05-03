/**
 * Runtime sha256 integrity verification — PLA-215 / PLA-114 §5.2 (rev 4).
 *
 * Spec invariant under test: the plugin runtime MUST verify that the bytes
 * of `worker/seccomp_filter.bpf` and `worker/seccomp_load.py` match the
 * sha256 pins recorded in the build manifest before launching a worker.
 * Either mismatch is a hard error, not a warning. This closes the
 * substitution-attack window where an attacker with write access to the
 * deployed plugin's worker assets swaps the loader (the python shim that
 * issues `prctl(PR_SET_SECCOMP)`) for a no-op while leaving the filter
 * blob unchanged — bwrap+netns+cap-drop would still hold but the kernel
 * seccomp denylist would be silently inert.
 *
 * The three tests below are the regression gate the issue requires:
 *   1. Tampered loader  (mismatched sha256 on seccompLoaderPath)
 *   2. Tampered filter  (mismatched sha256 on seccompFilterPath)
 *   3. Unsubstituted placeholder (pin still equal to the literal
 *      __PLA114_SECCOMP_*_SHA256__ token — length check fires first)
 *
 * Each test must FAIL against commit 01475ac (no runtime verifier exists
 * there) and PASS after the fix lands. The tests do NOT require bwrap on
 * the host: they exercise the verifier in isolation by injecting a
 * fabricated `SpawnModeDecision` via the `decisionOverride` test seam on
 * `createCadWorker`. `verifySeccompPins` itself is also exported for
 * direct unit assertions on error-message shape.
 */

import { describe, it, expect, beforeAll } from "vitest";
import { mkdtempSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";

import {
  createCadWorker,
  verifySeccompPins,
  type SpawnModeDecision,
  type SeccompPins,
} from "./cad-worker-client.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
// `worker/` lives at the repo root, sibling of `src/` and `dist/`.
const REPO_ROOT = resolve(__dirname, "..");
const REAL_FILTER_PATH = join(REPO_ROOT, "worker", "seccomp_filter.bpf");
const REAL_LOADER_PATH = join(REPO_ROOT, "worker", "seccomp_load.py");

function sha256OfFile(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

/** Silent logger so the per-test `WARN sandbox.dev_fallback` lines stay out of CI output. */
const SILENT_LOGGER = { info: () => {}, warn: () => {} };

let REAL_FILTER_SHA: string;
let REAL_LOADER_SHA: string;

beforeAll(() => {
  // Skip the suite cleanly if the seccomp blob has not been built — this
  // file is checked-in only after `make -C worker seccomp_filter.bpf`. The
  // test vector relies on a concrete blob being present on disk so the
  // runtime verifier has bytes to hash.
  if (!existsSync(REAL_FILTER_PATH)) {
    return;
  }
  REAL_FILTER_SHA = sha256OfFile(REAL_FILTER_PATH);
  REAL_LOADER_SHA = sha256OfFile(REAL_LOADER_PATH);
});

const HAS_BLOB = existsSync(REAL_FILTER_PATH) && existsSync(REAL_LOADER_PATH);

/**
 * Build a fabricated bwrap+seccomp `SpawnModeDecision`. Tests don't actually
 * spawn anything; the verifier only reads files and hashes them.
 */
function fakeDecision(opts: {
  filterPath?: string;
  loaderPath?: string;
}): SpawnModeDecision {
  return {
    mode: "bwrap+seccomp",
    bwrapPath: "/usr/bin/bwrap",
    bwrapHasNativeRlimits: false,
    seccompFilterPath: opts.filterPath ?? REAL_FILTER_PATH,
    seccompLoaderPath: opts.loaderPath ?? REAL_LOADER_PATH,
    preexecPath: "/nonexistent",
  };
}

describe.skipIf(!HAS_BLOB)(
  "PLA-215: runtime sha256 verification of seccomp bootstrap files",
  () => {
    it("createCadWorker throws on a tampered loader (sha256 mismatch)", () => {
      // Copy the real loader, comment out the prctl call — the canonical
      // substitution-attack payload (no-op loader) the rev-4 §5.2 dual pin
      // was added to defeat.
      const dir = mkdtempSync(join(tmpdir(), "pla215-loader-"));
      const tamperedLoader = join(dir, "seccomp_load.py");
      const original = readFileSync(REAL_LOADER_PATH, "utf8");
      const tampered = original.replace(/(\bprctl\s*\()/g, "# $1");
      // Sanity: the substitution must have actually changed bytes.
      expect(tampered).not.toBe(original);
      writeFileSync(tamperedLoader, tampered);

      const decision = fakeDecision({ loaderPath: tamperedLoader });
      // Pin overrides: when tests run directly from `src/`, the manifest
      // module still carries unsubstituted placeholder strings (esbuild's
      // build-time substitution only patches `dist/`). Inject the real
      // computed digests so the file-hash mismatch path is exercised
      // independently of the placeholder-length error path.
      const realPins: SeccompPins = {
        filterSha256: REAL_FILTER_SHA,
        loaderSha256: REAL_LOADER_SHA,
      };

      expect(() => createCadWorker(SILENT_LOGGER, decision, realPins)).toThrow(
        /seccomp_load\.py.*sha256 mismatch/,
      );
    });

    it("createCadWorker throws on a tampered filter blob (one byte flipped)", () => {
      const dir = mkdtempSync(join(tmpdir(), "pla215-filter-"));
      const tamperedFilter = join(dir, "seccomp_filter.bpf");
      const buf = Buffer.from(readFileSync(REAL_FILTER_PATH));
      // Flip the low bit of the first byte so the bytes change but the
      // overall length (and therefore the §1.2 invariant-iv length-modulo
      // check) stays valid — proving sha256 verification is a STRICTLY
      // stronger check than the existing structural sanity check.
      buf[0] = buf[0] ^ 0x01;
      writeFileSync(tamperedFilter, buf);

      const decision = fakeDecision({ filterPath: tamperedFilter });
      // See the loader test for why pin overrides are required when
      // running from `src/`.
      const realPins: SeccompPins = {
        filterSha256: REAL_FILTER_SHA,
        loaderSha256: REAL_LOADER_SHA,
      };

      expect(() => createCadWorker(SILENT_LOGGER, decision, realPins)).toThrow(
        /seccomp_filter\.bpf.*sha256 mismatch/,
      );
    });

    it("createCadWorker throws on an unsubstituted manifest placeholder", () => {
      // The placeholder `__PLA114_SECCOMP_FILTER_SHA256__` is 32 chars
      // long; sha256 hex is 64. The length check fires before the file
      // hash, surfacing a "build manifest unsubstituted" message that
      // tells operators the esbuild substitution step did not run.
      const decision = fakeDecision({});
      const placeholderPins: SeccompPins = {
        filterSha256: "__PLA114_SECCOMP_FILTER_SHA256__",
        loaderSha256: REAL_LOADER_SHA,
      };

      expect(() =>
        createCadWorker(SILENT_LOGGER, decision, placeholderPins),
      ).toThrow(/build manifest unsubstituted/);
    });

    it("verifySeccompPins is a no-op for dev_direct mode", () => {
      // Defense-in-depth: the verifier MUST NOT block CAD_WORKER_UNSAFE_DEV
      // since that path explicitly opts out of the kernel layer.
      expect(() =>
        verifySeccompPins({ mode: "dev_direct" }),
      ).not.toThrow();
    });

    it("verifySeccompPins accepts the real, untampered files against their real digests", () => {
      // Sanity gate: the verifier doesn't false-positive on the legit
      // checked-in blobs, so a passing CI build of the unit suite proves
      // the canonical bootstrap is still self-consistent.
      const decision = fakeDecision({});
      expect(() =>
        verifySeccompPins(decision, {
          filterSha256: REAL_FILTER_SHA,
          loaderSha256: REAL_LOADER_SHA,
        }),
      ).not.toThrow();
    });
  },
);
