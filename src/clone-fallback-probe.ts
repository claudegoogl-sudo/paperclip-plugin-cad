/**
 * Deploy-time clone3-fallback self-test — PLA-137 / PLA-106 §6.4
 *
 * Runs at worker startup, ONCE per process, against the loaded production
 * seccomp filter, before any tool is registered. The probe exercises the
 * two enforcement rules that the §6.4 evidence experiment exists to prove
 * are in effect on this exact host's glibc + Python:
 *
 *   1. `clone3` syscall returns errno=ENOSYS (filter rule:
 *      `SCMP_ACT_ERRNO(ENOSYS)` for clone3).
 *   2. `clone(2)` with a non-PTHREAD_CLONE_FLAGS argument is killed with
 *      SIGSYS (filter rule: `SCMP_ACT_KILL_PROCESS` when arg0 !=
 *      PTHREAD_CLONE_FLAGS).
 *
 * Why this exists (PLA-137):
 *   The §6.4 evidence already captured on the GitHub-hosted runner
 *   (Ubuntu 24.04 / glibc 2.39 / Python 3.12) is the deploy-class proxy
 *   accepted by SecurityEngineer. But the §6.4 assumption — glibc's
 *   clone3 → ENOSYS → clone(2) fallback chain — is a glibc property; if
 *   the *first-deploy* host has a divergent glibc that breaks the
 *   chain, the seccomp filter would invert from "compatibility alias"
 *   into a denylist hole. NEW14 catches a *future* regression but cannot
 *   catch a first-deploy mismatch. This probe does, by running the same
 *   two rules at startup against the production binary every boot.
 *
 * Reading the AC literally: "invoke flag-checked clone(2) once with
 *   PTHREAD_CLONE_FLAGS, assert SIGSYS." That input does NOT produce
 *   SIGSYS — the filter explicitly allows clone(2) when arg0 ==
 *   PTHREAD_CLONE_FLAGS (see worker/seccomp_filter.c §clone). The
 *   semantic intent is: invoke the *flag-checked clone(2) rule*, i.e.
 *   call clone(2) with NON-PTHREAD flags so the != predicate fires. We
 *   use clone(SIGCHLD, 0) (the same shape as `fork`-style clone) and
 *   assert SIGSYS, matching spec NEW15 ("chained clone3(SIGCHLD) →
 *   ENOSYS, clone(SIGCHLD) → SIGSYS"). Documented here so the reviewer
 *   can audit the deviation.
 *
 * Architecture:
 *   - Two short-lived bwrap+seccomp invocations, each running a tiny
 *     inline Python ctypes probe under the SAME filter blob the
 *     production worker uses (from the cached SpawnModeDecision).
 *   - The parent reads the JSON probe output (Step 1) and the exit
 *     signal (Step 2).
 *   - On any deviation, returns a structured ProbeFail. The caller (in
 *     worker.ts setup()) is responsible for logging + process.exit(1)
 *     so no tool is registered.
 *
 * Gating:
 *   - Probe only runs when `decision.mode === "bwrap+seccomp"`. In
 *     `dev_direct` mode (CAD_WORKER_UNSAFE_DEV=1, non-production) it
 *     returns a config error and the caller skips with a WARN.
 *
 * This probe is unit-testable: the spawn dependency is injected so a
 * vitest can simulate ENOSYS-correct, errno-wrong, and SIGSYS-missing
 * outcomes without a real bwrap. Integration tests in
 * `clone-fallback-probe.bwrap.test.ts` exercise the real bwrap path
 * when the host has bubblewrap installed.
 */

import { spawn as defaultSpawn, type ChildProcess } from "node:child_process";
import { openSync as defaultOpenSync, closeSync as defaultCloseSync } from "node:fs";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import type { SpawnModeDecision } from "./cad-worker-client.js";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/** Successful probe result — both rules verified on this host. */
export interface ProbeOk {
  ok: true;
  /** glibc version string from `platform.libc_ver()`, e.g. "glibc-2.39". */
  glibc: string;
  /** Python version from `platform.python_version()`, e.g. "3.12.3". */
  python: string;
  /** Architecture string from `os.uname().machine`, e.g. "x86_64". */
  arch: string;
  /** errno name returned by clone3 (must be "ENOSYS" for ok). */
  clone3ErrnoName: string;
  /** errno integer returned by clone3 (38 on Linux x86_64/aarch64). */
  clone3Errno: number;
  /** Exit signal observed for clone(SIGCHLD) — "SIGSYS" or kernel-equivalent. */
  clone2ExitSignal: NodeJS.Signals;
}

/** Failed probe result — one of the rules did not behave as expected. */
export interface ProbeFail {
  ok: false;
  step: "config" | "spawn" | "clone3" | "clone2";
  message: string;
  observed?: {
    rc?: number;
    errno?: number;
    errnoName?: string;
    signal?: NodeJS.Signals | null;
    code?: number | null;
    stderrTail?: string;
  };
}

export type ProbeResult = ProbeOk | ProbeFail;

/** Dependency-injection seam for unit tests. */
export interface ProbeDeps {
  spawn?: typeof defaultSpawn;
  openSync?: typeof defaultOpenSync;
  closeSync?: typeof defaultCloseSync;
}

export interface ProbeOptions {
  /** Python interpreter; defaults to "python3". */
  python?: string;
  /**
   * Pre-created tmp directory bind-mounted into bwrap as the workdir.
   * If omitted, the probe creates and re-uses a fresh `mkdtemp` directory
   * for both sub-probes.
   */
  workdir?: string;
  /** Per-probe ceiling, default 10s. Two sub-probes ⇒ 20s worst case. */
  timeoutMs?: number;
  /** Test-only DI seam; production callers omit this. */
  deps?: ProbeDeps;
}

// ---------------------------------------------------------------------------
// Inline Python probes (kept here so there's no extra file to bind into bwrap)
// ---------------------------------------------------------------------------

/**
 * Step 1 — clone3 → ENOSYS. Emits ONE JSON line on stdout, then exits 0.
 *
 * Uses raw syscall(SYS_clone3, ...) via ctypes. SYS_clone3 = 435 on every
 * supported Linux architecture (x86_64, aarch64, riscv64), so no per-arch
 * branch is needed for clone3. The kernel ABI for the args struct is the
 * same v0 layout (64 bytes) on all of them.
 */
const PYTHON_PROBE_CLONE3 = `
import ctypes, errno as _errno, json, platform, sys
_libc = ctypes.CDLL(None, use_errno=True)
_SYS_clone3 = 435
# struct clone_args v0 = 8 u64 fields = 64 bytes; index 4 = exit_signal.
_buf = (ctypes.c_uint64 * 8)(0,0,0,0,17,0,0,0)  # 17 = SIGCHLD
ctypes.set_errno(0)
_rc = _libc.syscall(_SYS_clone3, ctypes.byref(_buf), ctypes.c_size_t(64))
_e = ctypes.get_errno()
_glibc_pair = platform.libc_ver()
_glibc = "-".join(p for p in _glibc_pair if p) or "unknown"
print(json.dumps({
    "step": "clone3",
    "rc": int(_rc),
    "errno": int(_e),
    "errno_name": _errno.errorcode.get(_e, str(_e)),
    "glibc": _glibc,
    "python": platform.python_version(),
    "arch": platform.machine(),
}), flush=True)
sys.exit(0)
`.trim();

/**
 * Step 2 — clone(SIGCHLD, 0) → SIGSYS. Expected to be killed by the kernel
 * before printing anything; if the print runs, the filter is broken.
 *
 * SYS_clone is per-architecture:
 *   x86_64  = 56
 *   aarch64 = 220
 *   riscv64 = 220
 *   Other archs (i386, mips, sparc, ppc) are not supported deploy targets
 *   for v0.1.0 and the probe returns "unsupported_arch" so the caller
 *   fails closed.
 */
const PYTHON_PROBE_CLONE2 = `
import ctypes, json, platform, sys
_arch = platform.machine()
_SYS_clone = {"x86_64": 56, "aarch64": 220, "riscv64": 220}.get(_arch)
if _SYS_clone is None:
    print(json.dumps({"step": "clone2", "error": "unsupported_arch", "arch": _arch}), flush=True)
    sys.exit(3)
_libc = ctypes.CDLL(None, use_errno=True)
# clone(SIGCHLD, 0) — fork-style, no PTHREAD flags. Filter rule
# SCMP_ACT_KILL_PROCESS when arg0 != PTHREAD_CLONE_FLAGS must fire.
_libc.syscall(_SYS_clone, 17, 0)  # 17 = SIGCHLD
print(json.dumps({"step": "clone2", "error": "UNEXPECTED_SURVIVED", "arch": _arch}), flush=True)
sys.exit(2)
`.trim();

// ---------------------------------------------------------------------------
// bwrap argv builder (probe-specific — narrower than the worker's mounts)
// ---------------------------------------------------------------------------

interface ProbeArgvArgs {
  workdir: string;
  python: string;
  pythonScript: string;
}

function buildProbeArgv({ workdir, python, pythonScript }: ProbeArgvArgs): string[] {
  // Mirrors the production spawn argv (cad-worker-client.ts buildSpawnInvocation
  // bwrap+seccomp branch) MINUS the cad_worker.py bind-mount and the rlimit
  // flags — neither matters for the syscall-rule check. The seccomp FD lands
  // at child FD 3 the same way (`stdio` slot 3 ⇒ child FD 3 ⇒ `--seccomp 3`).
  return [
    "--unshare-all",
    "--share-net=false",
    "--die-with-parent",
    "--new-session",
    "--clearenv",
    "--setenv", "PATH", "/usr/bin:/bin",
    "--setenv", "LANG", "C.UTF-8",
    "--setenv", "PYTHONUNBUFFERED", "1",
    "--setenv", "PYTHONDONTWRITEBYTECODE", "1",
    "--uid", "65534", "--gid", "65534",
    "--hostname", "cad-probe",
    "--proc", "/proc",
    "--dev", "/dev",
    "--ro-bind", "/usr", "/usr",
    "--ro-bind", "/lib", "/lib",
    "--ro-bind", "/lib64", "/lib64",
    "--ro-bind", "/bin", "/bin",
    "--ro-bind", "/etc/ld.so.cache", "/etc/ld.so.cache",
    "--tmpfs", "/tmp",
    "--bind", workdir, workdir,
    "--chdir", workdir,
    "--cap-drop", "ALL",
    "--seccomp", "3",
    "--", python, "-c", pythonScript,
  ];
}

// ---------------------------------------------------------------------------
// One-shot bwrap probe runner
// ---------------------------------------------------------------------------

interface RawProbe {
  stdout: string;
  stderr: string;
  signal: NodeJS.Signals | null;
  code: number | null;
}

async function runOneProbe(
  decision: SpawnModeDecision,
  pythonScript: string,
  options: Required<Pick<ProbeOptions, "python" | "workdir" | "timeoutMs">>,
  deps: Required<ProbeDeps>,
): Promise<RawProbe> {
  const seccompFd = deps.openSync(decision.seccompFilterPath!, "r");
  let closed = false;
  const closeFd = () => {
    if (closed) return;
    closed = true;
    try { deps.closeSync(seccompFd); } catch { /* ignore */ }
  };

  try {
    const argv = buildProbeArgv({
      workdir: options.workdir,
      python: options.python,
      pythonScript,
    });

    return await new Promise<RawProbe>((resolve, reject) => {
      let child: ChildProcess;
      try {
        child = deps.spawn(decision.bwrapPath!, argv, {
          stdio: [
            "ignore",
            "pipe",
            "pipe",
            { type: "fd", fd: seccompFd } as unknown as "pipe",
          ],
          env: { PATH: "/usr/bin:/bin" },
        });
      } catch (err) {
        reject(err);
        return;
      }

      // Close the parent-side filter FD now that bwrap has inherited it.
      closeFd();

      let stdout = "";
      let stderr = "";
      let killTimer: ReturnType<typeof setTimeout> | null = setTimeout(() => {
        try { child.kill("SIGKILL"); } catch { /* ignore */ }
      }, options.timeoutMs);

      child.stdout?.on("data", (b: Buffer) => { stdout += b.toString("utf8"); });
      child.stderr?.on("data", (b: Buffer) => { stderr += b.toString("utf8"); });
      child.on("error", (err) => {
        if (killTimer) { clearTimeout(killTimer); killTimer = null; }
        reject(err);
      });
      child.on("close", (code: number | null, signal: NodeJS.Signals | null) => {
        if (killTimer) { clearTimeout(killTimer); killTimer = null; }
        resolve({ stdout, stderr, signal, code });
      });
    });
  } finally {
    closeFd();
  }
}

// ---------------------------------------------------------------------------
// Public entry: runCloneFallbackProbe
// ---------------------------------------------------------------------------

/**
 * Run the deploy-time clone-fallback self-test against `decision`'s seccomp
 * filter blob. Returns ok with discovered host metadata on success, or a
 * structured failure on any rule deviation.
 *
 * Idempotent and side-effect-free outside the temp workdir it creates (or
 * the one passed in via `options.workdir`).
 */
export async function runCloneFallbackProbe(
  decision: SpawnModeDecision,
  options: ProbeOptions = {},
): Promise<ProbeResult> {
  if (decision.mode !== "bwrap+seccomp") {
    return {
      ok: false,
      step: "config",
      message:
        `clone-fallback probe requires bwrap+seccomp mode (got ${decision.mode}). ` +
        "Probe is gated to skip in dev_direct; this error is returned only if a " +
        "non-bwrap decision is passed in by mistake.",
    };
  }
  if (!decision.bwrapPath || !decision.seccompFilterPath) {
    return {
      ok: false,
      step: "config",
      message: "decision missing bwrapPath or seccompFilterPath",
    };
  }

  const deps: Required<ProbeDeps> = {
    spawn: options.deps?.spawn ?? defaultSpawn,
    openSync: options.deps?.openSync ?? defaultOpenSync,
    closeSync: options.deps?.closeSync ?? defaultCloseSync,
  };
  const python = options.python ?? "python3";
  const timeoutMs = options.timeoutMs ?? 10_000;
  const workdir = options.workdir ?? (await mkdtemp(join(tmpdir(), "cad-probe-")));

  const opts = { python, workdir, timeoutMs };

  // -------------------- Step 1: clone3 → ENOSYS --------------------
  let r1: RawProbe;
  try {
    r1 = await runOneProbe(decision, PYTHON_PROBE_CLONE3, opts, deps);
  } catch (err) {
    return {
      ok: false,
      step: "spawn",
      message: `clone3 probe spawn failed: ${(err as Error).message}`,
    };
  }

  if (r1.signal !== null) {
    return {
      ok: false,
      step: "clone3",
      message:
        `clone3 probe exited via signal ${r1.signal} (expected normal exit). ` +
        `If SIGSYS, the filter is killing clone3 instead of returning ENOSYS — ` +
        `the glibc fallback chain is broken on this host.`,
      observed: { signal: r1.signal, code: r1.code, stderrTail: r1.stderr.slice(-300) },
    };
  }

  // The probe emits exactly one JSON line; tolerate trailing newlines + any
  // pre-Python stderr that ended up on stdout (shouldn't, but be defensive).
  const lastLine = r1.stdout.trim().split("\n").pop() ?? "";
  let parsed: {
    rc: number; errno: number; errno_name: string;
    glibc: string; python: string; arch: string;
  };
  try {
    parsed = JSON.parse(lastLine);
  } catch {
    return {
      ok: false,
      step: "clone3",
      message: `clone3 probe stdout was not valid JSON: ${lastLine.slice(0, 300)}`,
      observed: { code: r1.code, signal: r1.signal, stderrTail: r1.stderr.slice(-300) },
    };
  }

  if (parsed.rc !== -1 || parsed.errno_name !== "ENOSYS") {
    return {
      ok: false,
      step: "clone3",
      message:
        `clone3 returned rc=${parsed.rc} errno=${parsed.errno_name} (expected rc=-1 errno=ENOSYS). ` +
        `glibc=${parsed.glibc} python=${parsed.python} arch=${parsed.arch}. ` +
        `Filter rule SCMP_ACT_ERRNO(ENOSYS) is not in effect on this host.`,
      observed: { rc: parsed.rc, errno: parsed.errno, errnoName: parsed.errno_name },
    };
  }

  // -------------------- Step 2: clone(SIGCHLD, 0) → SIGSYS --------------------
  let r2: RawProbe;
  try {
    r2 = await runOneProbe(decision, PYTHON_PROBE_CLONE2, opts, deps);
  } catch (err) {
    return {
      ok: false,
      step: "spawn",
      message: `clone(2) probe spawn failed: ${(err as Error).message}`,
    };
  }

  // Accept SIGSYS, or SIGKILL with an audit-style "seccomp" stderr line —
  // matches spec §4 kernel-level discriminator (sandbox.bwrap.test.ts).
  const isSigsys = r2.signal === "SIGSYS";
  const isKernelKillFallback =
    r2.signal === "SIGKILL" && /seccomp/i.test(r2.stderr);

  if (!isSigsys && !isKernelKillFallback) {
    return {
      ok: false,
      step: "clone2",
      message:
        `clone(SIGCHLD) did not produce SIGSYS (got signal=${r2.signal} code=${r2.code}). ` +
        `Filter rule SCMP_ACT_KILL_PROCESS for clone arg0 != PTHREAD_CLONE_FLAGS ` +
        `is not in effect on this host. stdout=${r2.stdout.slice(0, 200)}`,
      observed: {
        signal: r2.signal,
        code: r2.code,
        stderrTail: r2.stderr.slice(-300),
      },
    };
  }

  return {
    ok: true,
    glibc: parsed.glibc,
    python: parsed.python,
    arch: parsed.arch,
    clone3Errno: parsed.errno,
    clone3ErrnoName: parsed.errno_name,
    clone2ExitSignal: (r2.signal ?? "SIGKILL") as NodeJS.Signals,
  };
}

// Exported for tests so they can sanity-check the inline probe text without
// duplicating it.
export const __TEST_ONLY__ = {
  PYTHON_PROBE_CLONE3,
  PYTHON_PROBE_CLONE2,
  buildProbeArgv,
};
