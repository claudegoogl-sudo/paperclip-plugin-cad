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
import { existsSync, openSync, closeSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { execSync } from "node:child_process";

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
  const v = bwrapVersionOf(bwrapPath);
  const native = v != null && (v.major > 0 || (v.major === 0 && v.minor >= 6));

  // (4) preexec fallback path is required when bwrap is older.
  if (!native && !existsSync(PREEXEC_PATH)) {
    throw new CadWorkerInternalError(
      `bwrap ${v?.major}.${v?.minor} predates --rlimit-* (need 0.6+). ` +
        `Build the preexec wrapper with \`make -C worker cad_preexec\`, ` +
        `or upgrade bubblewrap on the deploy host.`,
    );
  }

  return {
    mode: "bwrap+seccomp",
    bwrapPath,
    bwrapVersion: v ?? undefined,
    bwrapHasNativeRlimits: native,
    seccompFilterPath: SECCOMP_FILTER_PATH,
    preexecPath: native ? undefined : PREEXEC_PATH,
  };
}

// ---------------------------------------------------------------------------
// buildSpawnInvocation — pure function, target of unit tests
// ---------------------------------------------------------------------------

/**
 * Inputs to {@link buildSpawnInvocation}. Pure values only; the caller is
 * responsible for opening any file descriptors that need to be inherited.
 */
export interface BuildSpawnOpts {
  decision: SpawnModeDecision;
  /** Per-invocation isolated workdir (mkdtemp). */
  workdir: string;
  /** Python interpreter path. Defaults to "python3". */
  pythonBin?: string;
  /**
   * File descriptor of the seccomp filter blob, opened read-only by the
   * caller. Only consulted when `decision.mode === "bwrap+seccomp"`. Caller
   * passes it via the `stdio` array and closes its parent-side handle after
   * spawn returns.
   */
  seccompFd?: number;
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
   * stdio shape passed to child_process.spawn. Indices 0/1/2 are stdin/stdout/
   * stderr pipes; index 3+ may be { type: "fd", fd } entries for FD inheritance.
   * The `--seccomp 10` argv depends on the filter FD landing in the bwrap
   * process at FD 10; we achieve that by passing the parent-side FD on the
   * Node `stdio` array slot 3, which becomes child FD 3. bwrap relays FDs
   * via the `--seccomp <N>` argument, where N is the FD number AS SEEN BY
   * bwrap. We chose `10` to match the spec; we land it at FD 10 inside bwrap
   * by chaining `--file 10 <fd>` is **not** what bwrap supports for seccomp
   * — bwrap reads `--seccomp <N>` directly, so we instead pass the FD via
   * `stdio` and use that FD number directly in argv.
   *
   * Concrete chosen form (Node 20 child_process.spawn):
   *   stdio: [
   *     "pipe",                                 // 0 = stdin to worker
   *     "pipe",                                 // 1 = stdout from worker
   *     "pipe",                                 // 2 = stderr (bwrap + python)
   *     { type: "fd", fd: seccompFd } as any,   // 3 = filter blob, NOT closed-on-exec
   *   ]
   *
   * argv then references `--seccomp 3`. (We use 3 instead of 10 because Node
   * 20 deterministically lands the first `{type:"fd"}` entry at FD 3 in the
   * child; using FD 10 would require a manual dup2 dance that bwrap also
   * already does internally. The spec named "10" as a convention; the
   * security-relevant property — filter FD reaches bwrap with no leak —
   * is preserved.)
   */
  stdio: StdioOptions;
}

/**
 * Build the spawn invocation. Pure function — no I/O, no global side effects.
 *
 * The seccomp FD plumbing chosen (PLA-114 spec §1 + §5.3):
 *   - The caller opens `seccomp_filter.bpf` read-only with `openSync(..., 'r')`
 *     before calling this function.
 *   - We declare the `stdio` slot at index 3 to inherit that FD into the
 *     child as FD 3 (Node 20 `child_process.spawn` inherits the listed
 *     parent FDs into sequential child FDs starting at 0).
 *   - The bwrap argv uses `--seccomp 3` to consume the filter from that FD.
 *   - The caller closes the parent-side FD immediately after spawn returns;
 *     no other child can inherit it (we don't keep it open across spawns).
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

  // bwrap+seccomp path. Argv per PLA-106 §1 (mount allowlist) + §3 (rlimits).
  if (opts.seccompFd === undefined) {
    throw new CadWorkerInternalError(
      "buildSpawnInvocation(bwrap+seccomp): seccompFd is required",
    );
  }
  const bwrap = opts.decision.bwrapPath!;
  const venvPython = pythonBin;

  const args: string[] = [
    "--unshare-all",
    "--share-net=false",
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
    "--ro-bind", WORKER_PY, WORKER_PY,
    "--tmpfs", "/tmp",
    "--bind", opts.workdir, opts.workdir,
    "--chdir", opts.workdir,
    "--cap-drop", "ALL",
    // Filter FD: the parent-side FD lives at child FD 3 (first `stdio` extra).
    "--seccomp", "3",
  ];

  // Rlimits: prefer bwrap native flags (>= 0.6); else pass through preexec
  // wrapper invoked between bwrap and python.
  if (opts.decision.bwrapHasNativeRlimits) {
    args.push(
      "--rlimit-as", String(opts.rlimits.asBytes),
      "--rlimit-nproc", String(opts.rlimits.nproc),
      "--rlimit-nofile", String(opts.rlimits.nofile),
      "--rlimit-fsize", String(opts.rlimits.fsizeBytes),
      "--rlimit-cpu", String(opts.rlimits.cpuSeconds),
      "--rlimit-core", String(opts.rlimits.coreBytes),
    );
    args.push("--", venvPython, WORKER_PY);
  } else {
    const preexec = opts.decision.preexecPath!;
    // The preexec wrapper consumes its rlimits from env vars and execvp()s
    // its argv[1..]. We bind-mount it into the sandbox at its absolute path
    // so the worker can find it.
    args.push("--ro-bind", preexec, preexec);
    args.push("--setenv", "CAD_PREEXEC_RLIMIT_AS", String(opts.rlimits.asBytes));
    args.push("--setenv", "CAD_PREEXEC_RLIMIT_NPROC", String(opts.rlimits.nproc));
    args.push("--setenv", "CAD_PREEXEC_RLIMIT_NOFILE", String(opts.rlimits.nofile));
    args.push("--setenv", "CAD_PREEXEC_RLIMIT_FSIZE", String(opts.rlimits.fsizeBytes));
    args.push("--setenv", "CAD_PREEXEC_RLIMIT_CPU", String(opts.rlimits.cpuSeconds));
    args.push("--setenv", "CAD_PREEXEC_RLIMIT_CORE", String(opts.rlimits.coreBytes));
    args.push("--", preexec, venvPython, WORKER_PY);
  }

  // The seccomp filter FD is passed via the stdio slot at index 3.
  // Node 20 docs: each entry in `stdio` after [0..2] becomes a child FD at
  // the same index (so slot 3 → child FD 3). The `{ type: "fd", fd }` form
  // inherits the parent FD without closing it; the caller closes it after
  // spawn() returns.
  const stdio: StdioOptions = [
    "pipe",
    "pipe",
    "pipe",
    { type: "fd", fd: opts.seccompFd } as unknown as "pipe",
  ];

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

  // Open the seccomp filter blob ONCE per spawn. The FD is inherited into
  // the bwrap child at FD 3 and consumed by `--seccomp 3`. We close the
  // parent-side handle immediately after spawn() returns to avoid FD leaks
  // to any sibling children — though there are none in this codepath.
  let seccompFd: number | undefined;
  if (decision.mode === "bwrap+seccomp") {
    seccompFd = openSync(decision.seccompFilterPath!, "r");
  }

  let invocation: SpawnInvocation;
  try {
    invocation = buildSpawnInvocation({
      decision,
      workdir: job.workdir,
      pythonBin,
      seccompFd,
      rlimits,
    });
  } catch (err) {
    if (seccompFd !== undefined) closeSync(seccompFd);
    throw err;
  }

  return new Promise((resolve) => {
    const child = spawn(invocation.command, invocation.args, {
      stdio: invocation.stdio,
      env: invocation.env,
    });

    // Close the parent-side filter FD now that the child has inherited it.
    if (seccompFd !== undefined) {
      try { closeSync(seccompFd); } catch { /* already closed */ }
    }

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
 */
export function createCadWorker(logger: SandboxLogger = consoleLogger): CadWorker {
  const decision = selectSpawnMode();
  logSpawnModeOnce(decision, logger);

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
