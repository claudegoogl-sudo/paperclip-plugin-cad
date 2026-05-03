/**
 * CadQuery sandbox client — PLA-54, PLA-114.
 *
 * Spawns src/cad_worker.py as an isolated subprocess for each script invocation.
 * One subprocess per request; no persistent worker pool; no shared filesystem
 * state between invocations.
 *
 * ## Process model
 *
 * stdin/stdout pipe. Job JSON in, result JSON line out. No TCP listener,
 * no Unix socket file, no port allocation — AC2 satisfied trivially.
 *
 * ## Sandbox layering (PLA-106 §7 — binding)
 *
 * Two independent layers, both kept on:
 *
 * 1. **bubblewrap + seccomp-bpf + cap-drop + uid/rlimits** — the security
 *    boundary (PLA-114).
 *      - mount allowlist + netns + pidns + uts/ipc/cgroup ns
 *      - seccomp denylist of execve/fork/clone(non-pthread)/socket/mount/
 *        ptrace/bpf/io_uring/namespace ops/etc., with SCMP_ACT_KILL_PROCESS
 *      - cap-drop ALL, uid/gid 65534
 *      - rlimits (AS/NPROC/NOFILE/FSIZE/CPU/CORE)
 *
 * 2. **In-process Python hardening** — defense-in-depth and friendly errors
 *    for benign script bugs (commit 26ba919 / PLA-75). Stays in place
 *    underneath the kernel layer per PLA-106 §7 non-overlap rule.
 *
 * ## Spawn-mode selection (PLA-106 §5.3)
 *
 * Decided ONCE per worker-client construction (cached) by `selectSpawnMode`:
 *
 *   1. CAD_WORKER_UNSAFE_DEV=1 AND NODE_ENV !== 'production'
 *        → "dev_direct" (legacy direct spawn; in-process layer only).
 *          Logged on construction as `WARN sandbox.dev_fallback`.
 *   2. process.platform !== 'linux' AND not (1)
 *        → throw — Option B requires Linux + bwrap.
 *   3. bwrap on PATH AND seccomp_filter.bpf present
 *        → "bwrap+seccomp".
 *   4. Else → throw the same hard error.
 *
 * Logged once on construction: `INFO sandbox.mode = bwrap+seccomp | dev_direct`.
 *
 * ## Network restriction
 *
 * Enforced primarily by netns (no loopback, no DNS) and seccomp socket(2)
 * deny. The in-process socket-stub + PATH stripping in cad_worker.py remain
 * as defense-in-depth.
 */

import { spawn, type StdioOptions } from "node:child_process";
import { mkdtemp } from "node:fs/promises";
import { existsSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { execSync } from "node:child_process";
import { createHash } from "node:crypto";

import {
  SECCOMP_FILTER_SHA256_PIN,
  SECCOMP_LOADER_SHA256_PIN,
} from "./manifest.js";

// Re-export shared types and error classes from the stub so callers import from
// one place regardless of which implementation is active.
export type {
  CadWorker,
  RunScriptResult,
  ExportResult,
  ExportFormat,
} from "./stub-cad-worker.js";
export {
  CadWorkerTimeoutError,
  CadWorkerInternalError,
  ARTIFACT_STAGING_DIR,
} from "./stub-cad-worker.js";

import type { CadWorker, ExportFormat } from "./stub-cad-worker.js";
import { CadWorkerTimeoutError, CadWorkerInternalError } from "./stub-cad-worker.js";
import { randomUUID } from "node:crypto";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Extra seconds the parent waits beyond the user-facing timeout before SIGKILL. */
const GRACE_SECONDS = 5;

/**
 * Per-request timeout adder for bwrap setup overhead. PLA-106 §6.3.
 * 100 ms is well below the 5 s SIGKILL grace; bumpable to 200 ms if perf
 * measurements demand. Direct-spawn mode ignores this (no bwrap setup cost).
 */
export const BWRAP_OVERHEAD_GRACE_MS = 100;

/** Maximum per-request timeout ceiling (seconds). */
export const MAX_TIMEOUT_SECONDS = 300;

/** Default per-request timeout (seconds). */
export const DEFAULT_TIMEOUT_SECONDS = 30;

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/** Path to the Python worker entry point (sibling of this file). */
const WORKER_PY = join(__dirname, "cad_worker.py");

/**
 * Path to the seccomp filter blob, content-addressed at build time.
 * `worker/` sits at the repo root, sibling of `dist/`. From inside the
 * built `dist/` directory we reach it via `../worker/seccomp_filter.bpf`.
 *
 * In tests (running from `src/`) the file resolves to
 * `<repo>/worker/seccomp_filter.bpf` via the same relative.
 */
const SECCOMP_FILTER_PATH = join(__dirname, "..", "worker", "seccomp_filter.bpf");

/**
 * Path to the python-side seccomp loader (PLA-114 / PLA-106 §1 rev 4).
 * The worker bootstrap installs the filter from inside the python process
 * after trusted import-time setup, because bubblewrap's `--seccomp <fd>`
 * mechanism applies the filter before the launcher's own execve into the
 * target — incompatible with a filter that denylists execve. See the
 * docstring at the top of `worker/seccomp_load.py` for the full rationale.
 */
const SECCOMP_LOADER_PATH = join(__dirname, "..", "worker", "seccomp_load.py");

/** Sandbox-internal mount root for trusted bootstrap files. */
const SANDBOX_ROOT = "/sandbox";
const SANDBOX_FILTER_PATH = `${SANDBOX_ROOT}/seccomp_filter.bpf`;
const SANDBOX_LOADER_PATH = `${SANDBOX_ROOT}/seccomp_load.py`;
const SANDBOX_WORKER_PATH = `${SANDBOX_ROOT}/cad_worker.py`;

/**
 * Path to the preexec wrapper used as a fallback when the deploy host's
 * bwrap is older than 0.6 (no --rlimit-* flags). Built by `make -C worker`.
 */
const PREEXEC_PATH = join(__dirname, "..", "worker", "cad_preexec");

// ---------------------------------------------------------------------------
// Rlimit table (PLA-106 §3)
// ---------------------------------------------------------------------------

interface RlimitTable {
  /** RLIMIT_AS — virtual address space ceiling. 2 GiB default, 4 GiB ceiling. */
  asBytes: number;
  /** RLIMIT_NPROC — max processes/threads. 64 is generous for OCCT. */
  nproc: number;
  /** RLIMIT_NOFILE — max open file descriptors. */
  nofile: number;
  /** RLIMIT_FSIZE — max single-file size. 256 MiB. */
  fsizeBytes: number;
  /** RLIMIT_CPU — soft CPU-seconds ceiling. timeoutSeconds + 5. */
  cpuSeconds: number;
  /** RLIMIT_CORE — 0 (no core dumps; would land in workdir and leak). */
  coreBytes: number;
}

function defaultRlimits(timeoutSeconds: number): RlimitTable {
  return {
    asBytes: 2 * 1024 ** 3,
    nproc: 64,
    nofile: 256,
    fsizeBytes: 256 * 1024 ** 2,
    cpuSeconds: timeoutSeconds + 5,
    coreBytes: 0,
  };
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

interface WorkerJob {
  script: string;
  format: string;
  workdir: string;
}

/** Structured result from the Python worker process. */
export type WorkerResult =
  | { ok: true; artifactPath: string }
  | {
      ok: false;
      error:
        | "script_error"
        | "worker_internal"
        | "worker_oom"
        | "worker_timeout"
        | "sandbox_violation";
      message: string;
      /**
       * Kernel-level discriminator, populated when the worker exited via a
       * signal rather than a normal status. Tests assert on this BEFORE the
       * JSON envelope so an in-process catch where a kernel kill was
       * expected is itself a regression (PLA-106 §4).
       */
      exitSignal?: NodeJS.Signals | null;
      exitCode?: number | null;
    };

// ---------------------------------------------------------------------------
// Spawn-mode selection (PLA-106 §5.3)
// ---------------------------------------------------------------------------

export type SpawnMode = "bwrap+seccomp" | "dev_direct";

export interface SpawnModeDecision {
  mode: SpawnMode;
  /** Set when mode is bwrap+seccomp. */
  bwrapPath?: string;
  /** Discovered bwrap version. Major.minor only; used to decide preexec fallback. */
  bwrapVersion?: { major: number; minor: number };
  /** True iff bwrap >= 0.6, in which case --rlimit-* flags are used directly. */
  bwrapHasNativeRlimits?: boolean;
  /** Resolved seccomp filter path (validated existence). */
  seccompFilterPath?: string;
  /** Resolved python seccomp loader path (validated existence). */
  seccompLoaderPath?: string;
  /** Path to the preexec ELF (only used when bwrap < 0.6). */
  preexecPath?: string;
}

function which(bin: string): string | null {
  try {
    const out = execSync(`command -v ${bin}`, {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
    return out || null;
  } catch {
    return null;
  }
}

function bwrapVersionOf(bwrapPath: string): { major: number; minor: number } | null {
  try {
    const out = execSync(`${bwrapPath} --version`, {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
    // bubblewrap 0.8.0
    const m = /(\d+)\.(\d+)/.exec(out);
    if (!m) return null;
    return { major: Number(m[1]), minor: Number(m[2]) };
  } catch {
    return null;
  }
}

/**
 * Resolve the spawn mode. Pure (modulo platform/PATH/file-existence
 * snapshots), so callers can cache the result for the worker-client lifetime.
 *
 * Throws on the production-required-but-unavailable case: non-Linux without
 * the dev-fallback opt-in, or Linux without bwrap.
 */
export function selectSpawnMode(
  env: NodeJS.ProcessEnv = process.env,
  platform: NodeJS.Platform = process.platform,
): SpawnModeDecision {
  const unsafeDev = env.CAD_WORKER_UNSAFE_DEV === "1";
  const isProd = env.NODE_ENV === "production";

  // (1) CAD_WORKER_UNSAFE_DEV=1 + non-prod → direct spawn, in-process layer only.
  if (unsafeDev && !isProd) {
    return { mode: "dev_direct" };
  }

  // (2) Non-Linux without (1) → hard error.
  if (platform !== "linux") {
    throw new CadWorkerInternalError(
      "Option B sandbox unavailable: requires Linux + bwrap. " +
        "Set CAD_WORKER_UNSAFE_DEV=1 (NODE_ENV must NOT be 'production') " +
        "to run with the in-process layer only on developer machines.",
    );
  }

  // (3) Linux + bwrap on PATH + filter blob present → bwrap mode.
  const bwrapPath = which("bwrap");
  if (!bwrapPath) {
    throw new CadWorkerInternalError(
      "Option B sandbox unavailable: 'bwrap' not on PATH. " +
        "Install bubblewrap on the deploy host (apt-get install bubblewrap). " +
        "Set CAD_WORKER_UNSAFE_DEV=1 (non-production only) to run direct.",
    );
  }
  if (!existsSync(SECCOMP_FILTER_PATH)) {
    throw new CadWorkerInternalError(
      `Option B sandbox unavailable: seccomp filter blob not found at ${SECCOMP_FILTER_PATH}. ` +
        "Build it with `make -C worker seccomp_filter.bpf` (requires libseccomp-dev).",
    );
  }
  if (!existsSync(SECCOMP_LOADER_PATH)) {
    throw new CadWorkerInternalError(
      `Option B sandbox unavailable: python seccomp loader not found at ${SECCOMP_LOADER_PATH}. ` +
        "This file ships in worker/ alongside the filter source.",
    );
  }
  const v = bwrapVersionOf(bwrapPath);
  // NOTE: upstream bubblewrap (through 0.9.0, the version Ubuntu 24.04 ships)
  // does NOT expose --rlimit-* flags despite older docs that suggested they
  // landed in 0.6. Empirical evidence: bwrap 0.9.0 emits
  // 'bwrap: Unknown option --rlimit-as'. Until a future bubblewrap release
  // genuinely adds them, always take the cad_preexec fallback path.
  const native = false;

  // (4) preexec fallback path is required when bwrap is older.
  if (!native && !existsSync(PREEXEC_PATH)) {
    throw new CadWorkerInternalError(
      `bwrap ${v?.major}.${v?.minor} predates --rlimit-* (need 0.6+). ` +
        `Build the preexec wrapper with \`make -C worker cad_preexec\`, ` +
        `or upgrade bubblewrap on the deploy host.`,
    );
  }

  const decision: SpawnModeDecision = {
    mode: "bwrap+seccomp",
    bwrapPath,
    bwrapVersion: v ?? undefined,
    bwrapHasNativeRlimits: native,
    seccompFilterPath: SECCOMP_FILTER_PATH,
    seccompLoaderPath: SECCOMP_LOADER_PATH,
    preexecPath: native ? undefined : PREEXEC_PATH,
  };

  // PLA-215 / PLA-114 §5.2: hard-fail on sha256 mismatch between the build
  // manifest pin and the bytes on disk. Closes the substitution-attack
  // window where a tampered loader (e.g., one that omits the
  // prctl(PR_SET_SECCOMP) call) silently disables the kernel filter while
  // leaving bwrap/cap-drop/netns intact. Verification is wedged in here so
  // every consumer of selectSpawnMode (createCadWorker, renderCadQuery's
  // default-arg path, invokeWorker's default-arg path) is gated.
  verifySeccompPins(decision);
  return decision;
}

// ---------------------------------------------------------------------------
// PLA-215 / PLA-114 §5.2 — runtime sha256 verification of the seccomp blob
// and python loader shim.
// ---------------------------------------------------------------------------

/**
 * Pinned digests for the security-critical bootstrap files. Default values
 * come from `src/manifest.ts`, which esbuild substitutes at build time
 * (see `esbuild.config.mjs`). Tests override `pins` to drive specific
 * mismatch / unsubstituted-placeholder failure modes.
 */
export interface SeccompPins {
  filterSha256: string;
  loaderSha256: string;
}

/** Sha256 hex string is 64 lowercase hex chars. */
const SHA256_HEX_LEN = 64;
const SHA256_HEX_RE = /^[0-9a-f]{64}$/i;

/**
 * PLA-215 sidecar fallback. esbuild's post-bundle pass writes
 * `dist/seccomp_filter.bpf.sha256` and `dist/seccomp_load.py.sha256`
 * alongside the substitution it does into the bundled JS sources.
 * Production builds load from `dist/cad-worker-client.js` and read the
 * already-substituted constant; the sidecar path is the same file. Tests
 * and `npm run dev` load from `src/cad-worker-client.ts` where the
 * imported constant is still the literal `__PLA114_SECCOMP_*_SHA256__`
 * placeholder (esbuild substitutes only the dist outputs). In that case
 * the sidecar — produced by the same build that would have substituted
 * the constant — provides the real digest. The path resolves to the
 * repo's `dist/` from both src/ and dist/ load locations.
 */
function readSidecarSha(name: string): string | undefined {
  const sidecarPath = join(__dirname, "..", "dist", `${name}.sha256`);
  if (!existsSync(sidecarPath)) return undefined;
  const raw = readFileSync(sidecarPath, "utf8").trim();
  return SHA256_HEX_RE.test(raw) ? raw.toLowerCase() : undefined;
}

/**
 * Default pin resolution for `verifySeccompPins`. Priority:
 *   1. Manifest constant if esbuild substituted it (length === 64).
 *   2. Sidecar `dist/<name>.sha256` (also a build-frozen artifact).
 *   3. Original (unsubstituted) constant — caller's verifier will then
 *      hard-fail on the length check, surfacing the "build manifest
 *      unsubstituted" error.
 *
 * Both fallback sources are produced by the SAME esbuild post-pass, so the
 * substitution-attack threat model is preserved (build-time freeze, not
 * runtime recomputation from the file being verified).
 */
function resolveDefaultPins(): SeccompPins {
  const filterConst =
    SECCOMP_FILTER_SHA256_PIN.length === SHA256_HEX_LEN
      ? SECCOMP_FILTER_SHA256_PIN
      : undefined;
  const loaderConst =
    SECCOMP_LOADER_SHA256_PIN.length === SHA256_HEX_LEN
      ? SECCOMP_LOADER_SHA256_PIN
      : undefined;
  return {
    filterSha256:
      filterConst ??
      readSidecarSha("seccomp_filter.bpf") ??
      SECCOMP_FILTER_SHA256_PIN,
    loaderSha256:
      loaderConst ??
      readSidecarSha("seccomp_load.py") ??
      SECCOMP_LOADER_SHA256_PIN,
  };
}

/**
 * Verify both `seccomp_filter.bpf` and `seccomp_load.py` against the
 * build-manifest sha256 pins. No-op for `dev_direct` mode (the kernel
 * layer is already explicitly opted out via CAD_WORKER_UNSAFE_DEV).
 *
 * Throws `CadWorkerInternalError` on:
 *   - either pin failing the 64-hex-char length/charset check (catches
 *     the unsubstituted `__PLA114_SECCOMP_*_SHA256__` placeholder, which
 *     is 32 chars — so a build that didn't run the esbuild substitution
 *     fails closed at the first launch).
 *   - the file at `seccompFilterPath` or `seccompLoaderPath` not matching
 *     its pinned digest (substitution-attack detection).
 *   - either path being unreadable.
 *
 * The check is cheap (sha256 of two small files, ~100 KiB total) and
 * idempotent — safe to call once per worker-client construction or once
 * per `selectSpawnMode()` call.
 */
export function verifySeccompPins(
  decision: SpawnModeDecision,
  pins: SeccompPins = resolveDefaultPins(),
): void {
  if (decision.mode !== "bwrap+seccomp") return;

  const checks: Array<{ name: string; pin: string; path: string }> = [
    {
      name: "seccomp_filter.bpf",
      pin: pins.filterSha256,
      path: decision.seccompFilterPath ?? "",
    },
    {
      name: "seccomp_load.py",
      pin: pins.loaderSha256,
      path: decision.seccompLoaderPath ?? "",
    },
  ];

  for (const c of checks) {
    if (c.pin.length !== SHA256_HEX_LEN) {
      throw new CadWorkerInternalError(
        `[PLA-114 §5.2] ${c.name}: build manifest unsubstituted — ` +
          `pin length ${c.pin.length} ≠ ${SHA256_HEX_LEN} ` +
          `(placeholder __PLA114_SECCOMP_*_SHA256__ still present?). ` +
          `Run \`npm run build\` so esbuild substitutes the digests.`,
      );
    }
    if (!SHA256_HEX_RE.test(c.pin)) {
      throw new CadWorkerInternalError(
        `[PLA-114 §5.2] ${c.name}: build manifest pin is not a sha256 hex string: ${c.pin}`,
      );
    }
    if (!c.path) {
      throw new CadWorkerInternalError(
        `[PLA-114 §5.2] ${c.name}: SpawnModeDecision is missing the path field — cannot verify pin.`,
      );
    }

    let actual: string;
    try {
      actual = createHash("sha256").update(readFileSync(c.path)).digest("hex");
    } catch (err) {
      throw new CadWorkerInternalError(
        `[PLA-114 §5.2] ${c.name}: failed to read for sha256 verification ` +
          `(path=${c.path}): ${(err as Error).message}`,
      );
    }

    if (actual.toLowerCase() !== c.pin.toLowerCase()) {
      throw new CadWorkerInternalError(
        `[PLA-114 §5.2] ${c.name}: sha256 mismatch — ` +
          `manifest pin=${c.pin} actual=${actual} path=${c.path}. ` +
          `Refusing to launch worker; the kernel sandbox layer would be ` +
          `silently inert under this state (substitution-attack defense).`,
      );
    }
  }
}

// ---------------------------------------------------------------------------
// buildSpawnInvocation — pure function, target of unit tests
// ---------------------------------------------------------------------------

/**
 * Inputs to {@link buildSpawnInvocation}. Pure values only.
 */
export interface BuildSpawnOpts {
  decision: SpawnModeDecision;
  /** Per-invocation isolated workdir (mkdtemp). */
  workdir: string;
  /** Python interpreter path. Defaults to "python3". */
  pythonBin?: string;
  /** rlimit table (PLA-106 §3). */
  rlimits: RlimitTable;
}

/**
 * Result of {@link buildSpawnInvocation}: a pure description of the spawn.
 * Tests can assert on argv shape; the runtime feeds it into
 * {@link spawn} unchanged.
 */
export interface SpawnInvocation {
  command: string;
  args: string[];
  env: NodeJS.ProcessEnv;
  /**
   * stdio shape passed to child_process.spawn. Stdin/stdout/stderr only:
   * the seccomp filter blob is delivered to the worker via `--ro-bind`
   * inside the sandbox, not via FD inheritance. The python bootstrap reads
   * the blob from the read-only mount and installs it via prctl after
   * trusted import-time setup completes (PLA-106 §1 rev 4).
   */
  stdio: StdioOptions;
}

/**
 * Bootstrap one-expression executed by `python3 -c`. PLA-106 §1 rev 4:
 * insert /sandbox into sys.path, install the seccomp filter via the loader
 * shim, then import the worker. `lock_down(...)` is lexically before
 * `import cad_worker` — the contract is that no untrusted code reaches the
 * import system before the filter is in force (§1.2 invariant).
 *
 * Kept on a single physical line so the argv survives any quoting layer
 * intact and so a reader can verify the lock-then-import ordering at a
 * glance.
 */
const PYTHON_BOOTSTRAP =
  "import sys; sys.path.insert(0, '/sandbox'); " +
  "from seccomp_load import lock_down; " +
  "lock_down('/sandbox/seccomp_filter.bpf'); " +
  "import cad_worker; cad_worker.main()";

/**
 * Build the spawn invocation. Pure function — no I/O, no global side effects.
 *
 * Filter delivery (PLA-106 §1 rev 4):
 *   - The seccomp BPF blob and the python loader shim are mounted read-only
 *     into the sandbox at /sandbox/seccomp_filter.bpf and /sandbox/seccomp_load.py.
 *   - The argv tail is `python3 -c "<bootstrap>"`. The bootstrap imports the
 *     loader, calls `lock_down(blob_path)`, and only then imports the worker.
 *   - No FD-3 inheritance, no `--seccomp <fd>`. bwrap's `--seccomp` mechanism
 *     is incompatible with a filter that denylists execve (the launcher's
 *     own execve gets killed before any target code runs); hence the python-
 *     side install pattern used by Chromium / Firefox / sandbox2.
 */
export function buildSpawnInvocation(opts: BuildSpawnOpts): SpawnInvocation {
  const pythonBin = opts.pythonBin ?? "python3";

  // Common stripped environment — we re-add what we need explicitly.
  const env: NodeJS.ProcessEnv = {
    PATH: "/usr/bin:/bin",
    PYTHONDONTWRITEBYTECODE: "1",
    PYTHONUNBUFFERED: "1",
  };

  if (opts.decision.mode === "dev_direct") {
    // PLA-106 §5.3 dev path: in-process layer only, no bwrap, no seccomp.
    return {
      command: pythonBin,
      args: [WORKER_PY],
      env,
      stdio: ["pipe", "pipe", "pipe"],
    };
  }

  // bwrap+seccomp path. Argv per PLA-106 §1 rev 4 (mount allowlist + ro-bind
  // delivery of filter blob and loader shim) + §3 (rlimits).
  const bwrap = opts.decision.bwrapPath!;
  const venvPython = pythonBin;
  const filterBlob = opts.decision.seccompFilterPath!;
  const loaderShim = opts.decision.seccompLoaderPath!;

  const args: string[] = [
    "--unshare-all",
    "--die-with-parent",
    "--new-session",
    "--clearenv",
    "--setenv", "PATH", "/usr/bin:/bin",
    "--setenv", "HOME", "/tmp",
    "--setenv", "LANG", "C.UTF-8",
    "--setenv", "PYTHONDONTWRITEBYTECODE", "1",
    "--setenv", "PYTHONHASHSEED", "random",
    "--setenv", "PYTHONUNBUFFERED", "1",
    "--uid", "65534", "--gid", "65534",
    "--hostname", "cad-worker",
    "--proc", "/proc",
    "--dev", "/dev",
    "--ro-bind", "/usr", "/usr",
    "--ro-bind", "/lib", "/lib",
    "--ro-bind", "/lib64", "/lib64",
    "--ro-bind", "/bin", "/bin",
    "--ro-bind", "/etc/ld.so.cache", "/etc/ld.so.cache",
    // Trusted bootstrap files mounted under /sandbox. The loader shim and
    // filter blob are both content-pinned by the build manifest (§5.2).
    "--ro-bind", filterBlob, SANDBOX_FILTER_PATH,
    "--ro-bind", loaderShim, SANDBOX_LOADER_PATH,
    "--ro-bind", WORKER_PY, SANDBOX_WORKER_PATH,
    "--tmpfs", "/tmp",
    "--bind", opts.workdir, opts.workdir,
    "--chdir", opts.workdir,
    "--cap-drop", "ALL",
  ];

  // Rlimits: prefer bwrap native flags (>= 0.6 in theory; in practice the
  // bubblewrap shipped on Ubuntu 24.04 (0.9.0) does NOT have them, so the
  // preexec branch is what actually runs). See selectSpawnMode comment.
  if (opts.decision.bwrapHasNativeRlimits) {
    args.push(
      "--rlimit-as", String(opts.rlimits.asBytes),
      "--rlimit-nproc", String(opts.rlimits.nproc),
      "--rlimit-nofile", String(opts.rlimits.nofile),
      "--rlimit-fsize", String(opts.rlimits.fsizeBytes),
      "--rlimit-cpu", String(opts.rlimits.cpuSeconds),
      "--rlimit-core", String(opts.rlimits.coreBytes),
    );
    args.push("--", venvPython, "-c", PYTHON_BOOTSTRAP);
  } else {
    const preexec = opts.decision.preexecPath!;
    // The preexec wrapper consumes its rlimits from env vars and execvp()s
    // its argv[1..]. We bind-mount it into the sandbox at its absolute path
    // so bwrap can find it.
    args.push("--ro-bind", preexec, preexec);
    args.push("--setenv", "CAD_PREEXEC_RLIMIT_AS", String(opts.rlimits.asBytes));
    args.push("--setenv", "CAD_PREEXEC_RLIMIT_NPROC", String(opts.rlimits.nproc));
    args.push("--setenv", "CAD_PREEXEC_RLIMIT_NOFILE", String(opts.rlimits.nofile));
    args.push("--setenv", "CAD_PREEXEC_RLIMIT_FSIZE", String(opts.rlimits.fsizeBytes));
    args.push("--setenv", "CAD_PREEXEC_RLIMIT_CPU", String(opts.rlimits.cpuSeconds));
    args.push("--setenv", "CAD_PREEXEC_RLIMIT_CORE", String(opts.rlimits.coreBytes));
    args.push("--", preexec, venvPython, "-c", PYTHON_BOOTSTRAP);
  }

  // No extra FDs. The filter blob is read by the python bootstrap from the
  // ro-bind mount, not inherited as an FD.
  const stdio: StdioOptions = ["pipe", "pipe", "pipe"];

  return {
    command: bwrap,
    args,
    env,
    stdio,
  };
}

// ---------------------------------------------------------------------------
// Cached spawn-mode logger
// ---------------------------------------------------------------------------

interface SandboxLogger {
  info: (msg: string) => void;
  warn: (msg: string) => void;
}

const consoleLogger: SandboxLogger = {
  info: (msg) => console.error(`INFO ${msg}`),
  warn: (msg) => console.error(`WARN ${msg}`),
};

function logSpawnModeOnce(decision: SpawnModeDecision, logger: SandboxLogger): void {
  if (decision.mode === "dev_direct") {
    logger.warn(
      "sandbox.dev_fallback CAD_WORKER_UNSAFE_DEV=1 — running with in-process layer only. " +
        "Never set this in production.",
    );
  }
  logger.info(`sandbox.mode = ${decision.mode}`);
}

// ---------------------------------------------------------------------------
// Subprocess invocation
// ---------------------------------------------------------------------------

/**
 * Spawn one Python worker process for a single job.
 *
 * @param job            Script, format, and isolated workdir.
 * @param timeoutSeconds Hard timeout for the script (user-facing ceiling).
 * @param decision       Spawn-mode decision (cached once per worker-client).
 * @param pythonBin      Python interpreter path. Defaults to "python3".
 */
export async function invokeWorker(
  job: WorkerJob,
  timeoutSeconds: number,
  decision: SpawnModeDecision = selectSpawnMode(),
  pythonBin = "python3",
): Promise<WorkerResult> {
  const rlimits = defaultRlimits(timeoutSeconds);

  // PLA-106 §1 rev 4: the seccomp filter blob is delivered to the worker
  // via a `--ro-bind` mount inside the sandbox. The bootstrap reads it from
  // /sandbox/seccomp_filter.bpf and installs it via prctl after the trusted
  // imports complete. No parent-side FD plumbing.
  const invocation = buildSpawnInvocation({
    decision,
    workdir: job.workdir,
    pythonBin,
    rlimits,
  });

  return new Promise((resolve) => {
    const child = spawn(invocation.command, invocation.args, {
      stdio: invocation.stdio,
      env: invocation.env,
    });

    let stdout = "";
    let stderr = "";
    let settled = false;
    let killTimer: ReturnType<typeof setTimeout> | null = null;

    const settle = (result: WorkerResult) => {
      if (settled) return;
      settled = true;
      if (killTimer !== null) clearTimeout(killTimer);
      resolve(result);
    };

    // Hard deadline. PLA-106 §6.3: bwrap mode adds BWRAP_OVERHEAD_GRACE_MS.
    const overheadMs = decision.mode === "bwrap+seccomp" ? BWRAP_OVERHEAD_GRACE_MS : 0;
    killTimer = setTimeout(() => {
      if (settled) return;
      settled = true;
      try { child.kill("SIGKILL"); } catch { /* may have exited */ }
      resolve({
        ok: false,
        error: "worker_timeout",
        message: `CAD script timed out after ${timeoutSeconds}s`,
      });
    }, timeoutSeconds * 1000 + overheadMs + GRACE_SECONDS * 1000);

    if (child.stdout) {
      child.stdout.on("data", (chunk: Buffer) => { stdout += chunk.toString("utf8"); });
    }
    if (child.stderr) {
      child.stderr.on("data", (chunk: Buffer) => { stderr += chunk.toString("utf8"); });
    }

    child.on("close", (code: number | null, signal: NodeJS.Signals | null) => {
      if (settled) return;
      if (killTimer !== null) clearTimeout(killTimer);

      // PLA-106 §4: read the exit signal FIRST. SIGSYS = seccomp kill;
      // SIGKILL with a "seccomp" stderr line is the kernel-audit fallback.
      if (signal === "SIGSYS") {
        settle({
          ok: false,
          error: "sandbox_violation",
          message:
            `Worker killed by seccomp (SIGSYS). ` +
            `stderr: ${stderr.slice(0, 500)}`,
          exitSignal: signal,
          exitCode: code,
        });
        return;
      }
      if (signal === "SIGKILL" && /seccomp/i.test(stderr)) {
        settle({
          ok: false,
          error: "sandbox_violation",
          message:
            `Worker killed by kernel (SIGKILL with seccomp audit line). ` +
            `stderr: ${stderr.slice(0, 500)}`,
          exitSignal: signal,
          exitCode: code,
        });
        return;
      }

      const line = stdout.trim();
      if (!line) {
        settle({
          ok: false,
          error: "worker_internal",
          message:
            `Worker produced no output on stdout. ` +
            `code=${code} signal=${signal} stderr: ${stderr.slice(0, 500)}`,
          exitSignal: signal,
          exitCode: code,
        });
        return;
      }

      const newlineIdx = line.indexOf("\n");
      const firstLine = newlineIdx === -1 ? line : line.slice(0, newlineIdx);

      try {
        const parsed = JSON.parse(firstLine) as WorkerResult;
        if (!parsed.ok) {
          // Attach exit info even on JSON-envelope errors so callers can log
          // the full picture for forensic correlation.
          (parsed as { exitSignal?: NodeJS.Signals | null }).exitSignal = signal;
          (parsed as { exitCode?: number | null }).exitCode = code;
        }
        settle(parsed);
      } catch {
        settle({
          ok: false,
          error: "worker_internal",
          message: `Worker output was not valid JSON: ${firstLine.slice(0, 200)}`,
          exitSignal: signal,
          exitCode: code,
        });
      }
    });

    child.on("error", (err: Error) => {
      settle({
        ok: false,
        error: "worker_internal",
        message: `Failed to spawn worker process: ${err.message}`,
      });
    });

    const jobJson = JSON.stringify(job);
    if (child.stdin) {
      child.stdin.write(jobJson, "utf8", () => {
        child.stdin?.end();
      });
    }
  });
}

// ---------------------------------------------------------------------------
// Public API: renderCadQuery
// ---------------------------------------------------------------------------

export async function renderCadQuery(
  script: string,
  format: "step" | "stl" | "3mf",
  timeoutSeconds: number = DEFAULT_TIMEOUT_SECONDS,
  decision: SpawnModeDecision = selectSpawnMode(),
): Promise<WorkerResult> {
  const effectiveTimeout = Math.min(
    Math.max(1, timeoutSeconds),
    MAX_TIMEOUT_SECONDS,
  );

  const workdir = await mkdtemp(join(tmpdir(), "cad-worker-"));
  return invokeWorker({ script, format, workdir }, effectiveTimeout, decision);
}

// ---------------------------------------------------------------------------
// CadWorker factory
// ---------------------------------------------------------------------------

interface ArtifactEntry { script: string }

/**
 * Create the real CadQuery worker client.
 *
 * Spawn-mode decision is resolved ONCE here and cached for the lifetime of
 * the returned client (PLA-106 §5.3). The `INFO sandbox.mode = …` line is
 * emitted on construction; never repeated per request.
 *
 * @param decisionOverride  Test seam: bypass `selectSpawnMode()` (which
 *   requires Linux + bwrap on PATH) and inject a fabricated decision.
 *   Production code never passes this. PLA-215 regression tests use it
 *   to verify that runtime sha256 verification fail-closes on tampered
 *   loader/filter paths and on unsubstituted-placeholder pins.
 */
export function createCadWorker(
  logger: SandboxLogger = consoleLogger,
  decisionOverride?: SpawnModeDecision,
  pinsOverride?: SeccompPins,
): CadWorker {
  const decision = decisionOverride ?? selectSpawnMode();
  logSpawnModeOnce(decision, logger);

  // PLA-215 / PLA-114 §5.2: if the caller injected a decision (test seam),
  // selectSpawnMode's verification was bypassed — re-run it here so the
  // override path is held to the same fail-closed bar as production. The
  // unsubstituted-placeholder regression test additionally injects a
  // tampered `pinsOverride` to drive the length-check error path
  // independent of whether the build ran the esbuild substitution.
  if (decisionOverride !== undefined || pinsOverride !== undefined) {
    verifySeccompPins(decision, pinsOverride);
  }

  const registry = new Map<string, ArtifactEntry>();

  // Validate the seccomp blob has non-zero size when bwrap mode is selected
  // (defensive: a truncated blob would break the spawn at runtime, which we
  // surface as a worker_internal at the first request anyway, but failing
  // fast on construction is friendlier).
  if (decision.mode === "bwrap+seccomp") {
    try {
      const st = statSync(decision.seccompFilterPath!);
      if (st.size === 0) {
        throw new CadWorkerInternalError(
          `Seccomp filter blob is empty: ${decision.seccompFilterPath}`,
        );
      }
    } catch (err) {
      if (err instanceof CadWorkerInternalError) throw err;
      throw new CadWorkerInternalError(
        `Failed to stat seccomp filter blob: ${(err as Error).message}`,
      );
    }
  }

  return {
    async runScript(script: string, timeoutSeconds: number) {
      const result = await renderCadQuery(script, "step", timeoutSeconds, decision);

      if (!result.ok) {
        if (result.error === "worker_timeout") {
          throw new CadWorkerTimeoutError(timeoutSeconds);
        }
        throw new CadWorkerInternalError(`[${result.error}] ${result.message}`);
      }

      const artifactId = randomUUID();
      registry.set(artifactId, { script });

      return {
        artifactId,
        summary: `CadQuery script executed successfully. Artifact staged at ${result.artifactPath}`,
      };
    },

    async export(artifactId: string, format: ExportFormat) {
      const entry = registry.get(artifactId);
      if (!entry) {
        throw new CadWorkerInternalError(
          `Unknown artifactId: ${artifactId}. Ensure cad:run_script was called first.`,
        );
      }

      const result = await renderCadQuery(
        entry.script,
        format,
        DEFAULT_TIMEOUT_SECONDS,
        decision,
      );

      if (!result.ok) {
        if (result.error === "worker_timeout") {
          throw new CadWorkerTimeoutError(DEFAULT_TIMEOUT_SECONDS);
        }
        throw new CadWorkerInternalError(`[${result.error}] ${result.message}`);
      }

      return { filePath: result.artifactPath };
    },
  };
}
