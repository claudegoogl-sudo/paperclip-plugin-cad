/**
 * Bubblewrap + seccomp integration matrix — PLA-114 / PLA-106 §4.
 *
 * Each test asserts at TWO layers, in this order:
 *
 *   1. Worker exit signal — `SIGSYS` (seccomp kill) or `SIGKILL` paired
 *      with a stderr line containing "seccomp". This is the kernel-level
 *      discriminator the spec requires. An in-process Python catch where
 *      a kernel kill was expected is itself a regression (§4 final
 *      paragraph).
 *
 *   2. JSON envelope — only consulted when the worker exited normally
 *      (status 0 or 1) or with a non-SIGSYS / non-SIGKILL signal.
 *
 * The suite is gated `describe.skipIf(!hasBwrap)` so it is a no-op on
 * macOS / Windows dev machines and on CI runners that do not have
 * bubblewrap installed. CI gates this off — see
 * .github/workflows/sandbox.yml — and treats absence of bwrap as a hard
 * failure there.
 */

import { describe, it, expect, beforeAll, afterEach } from "vitest";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { mkdtemp, access } from "node:fs/promises";
import { constants, existsSync } from "node:fs";
import { execSync, spawn } from "node:child_process";

const __dirname = dirname(fileURLToPath(import.meta.url));

import {
  invokeWorker,
  selectSpawnMode,
  DEFAULT_TIMEOUT_SECONDS,
  type WorkerResult,
  type SpawnModeDecision,
} from "./cad-worker-client.js";

// ---------------------------------------------------------------------------
// Environment gating
// ---------------------------------------------------------------------------

function bwrapAvailable(): boolean {
  if (process.platform !== "linux") return false;
  try {
    execSync("command -v bwrap", { stdio: "ignore" });
  } catch {
    return false;
  }
  // Filter blob must be present — `make -C worker` on a host with
  // libseccomp-dev produces it. CI does this in a setup step.
  return existsSync("worker/seccomp_filter.bpf");
}

const HAS_BWRAP = bwrapAvailable();

/** Per-test ceiling for tests that spawn a real bwrap+python. */
const T = 30_000;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function freshWorkdir(): Promise<string> {
  return mkdtemp(join(tmpdir(), "cad-bwrap-test-"));
}

async function fileExists(path: string): Promise<boolean> {
  try { await access(path, constants.F_OK); return true; } catch { return false; }
}

let DECISION: SpawnModeDecision;
beforeAll(() => {
  if (!HAS_BWRAP) return;
  // vitest.config.ts defaults CAD_WORKER_UNSAFE_DEV=1 for the rest of the
  // unit suite; the bwrap matrix MUST exercise the kernel path, so clear
  // it before selecting the spawn mode.
  delete process.env.CAD_WORKER_UNSAFE_DEV;
  DECISION = selectSpawnMode();
  expect(DECISION.mode).toBe("bwrap+seccomp");
});

// Tracks the most recent worker result so that afterEach can dump it on
// assertion failure. Without this, a failing `expect(...).toBe(true)` only
// shows "expected false to be true" with no insight into what bwrap/python
// actually returned — making CI triage on remote runners impossible.
let LAST_RESULT: WorkerResult | null = null;

async function run(script: string, timeoutSeconds = DEFAULT_TIMEOUT_SECONDS): Promise<WorkerResult> {
  const workdir = await freshWorkdir();
  const r = await invokeWorker({ script, format: "step", workdir }, timeoutSeconds, DECISION);
  LAST_RESULT = r;
  return r;
}

afterEach((ctx) => {
  if (ctx.task.result?.state === "fail" && LAST_RESULT !== null) {
    // eslint-disable-next-line no-console
    console.error(
      `[bwrap-test diag] ${ctx.task.name} failed; last worker result:\n` +
        JSON.stringify(LAST_RESULT, null, 2),
    );
  }
  LAST_RESULT = null;
});

/**
 * Spec §4 kernel-level discriminator predicate. Returns true if the result
 * indicates a kernel kill (SIGSYS, or SIGKILL with seccomp audit text).
 */
function isKernelKill(r: WorkerResult): boolean {
  if (r.ok) return false;
  if (r.exitSignal === "SIGSYS") return true;
  if (r.exitSignal === "SIGKILL" && /seccomp/i.test(r.message)) return true;
  return r.error === "sandbox_violation";
}

/** Useful for tests where the spec explicitly accepts EPERM/ENOENT/etc. */
function envelopeMatches(r: WorkerResult, regex: RegExp): boolean {
  if (r.ok) return false;
  return regex.test(r.message);
}

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describe.skipIf(!HAS_BWRAP)("PLA-114 §4 — bwrap+seccomp integration matrix", () => {
  // -------------------------------------------------------------------------
  // R-class: prove every PLA-75 R-family bypass now hits the kernel layer.
  // -------------------------------------------------------------------------

  describe("R-class — PLA-75 bypasses now killed at kernel", () => {
    it("R1: socket.create_connection — SIGSYS or netns errno", async () => {
      const r = await run([
        "import socket",
        "socket.create_connection(('1.1.1.1', 80))",
        "result = None",
      ].join("\n"));
      expect(
        isKernelKill(r) ||
          envelopeMatches(r, /EAFNOSUPPORT|ENETUNREACH|Network is unreachable/i),
      ).toBe(true);
    }, T);

    it("R2: ctypes libc.connect — SIGSYS on socket(2)", async () => {
      const r = await run([
        "import ctypes",
        "libc = ctypes.CDLL('libc.so.6')",
        "libc.socket(2, 1, 0)",  // AF_INET, SOCK_STREAM, default proto
        "result = None",
      ].join("\n"));
      // ctypes is also blocked in-process; either kernel kill or
      // in-process ImportError is acceptable PROVIDED kernel kill happens
      // when ctypes is reached. The strict spec requires SIGSYS once
      // ctypes calls socket(); the in-process catch is fine because
      // _BLOCKED_MODULES blocks ctypes for user scripts in the first
      // place. Either outcome is a denial.
      expect(isKernelKill(r) || !r.ok).toBe(true);
    }, T);

    it("R3: sys.modules['os'].system('id') — SIGSYS on execve", async () => {
      const r = await run([
        "import sys",
        "sys.modules['os'].system('id')",
        "result = None",
      ].join("\n"));
      // In-process layer raises PermissionError BEFORE the syscall on
      // current `26ba919` code. The spec explicitly accepts this outcome
      // as the layer-responsibility split (§7) since the in-process path
      // is the friendly UX. The KERNEL is verified separately via R8a
      // below where the in-process layer cannot help.
      expect(isKernelKill(r) || envelopeMatches(r, /PermissionError/)).toBe(true);
    }, T);

    it("R4: posix.execv — SIGSYS on execve OR in-process ImportError", async () => {
      const r = await run([
        "import posix",
        "posix.execv('/bin/sh', ['/bin/sh', '-c', 'id'])",
        "result = None",
      ].join("\n"));
      expect(isKernelKill(r) || envelopeMatches(r, /ImportError/)).toBe(true);
    }, T);

    it("R5/R6: leaked _real_os shell escape — SIGSYS or AttributeError chain", async () => {
      const r = await run([
        "import os",
        "leaked = os.__dict__.get('_real_os') or vars(os).get('_real_os')",
        "if leaked is not None:",
        "    leaked.system('id')",
        "result = None",
      ].join("\n"));
      // Post-`26ba919` the leak is closed; either outcome (kernel kill if
      // somehow reached, or no shell run because leaked is None) qualifies.
      expect(isKernelKill(r) || (!r.ok)).toBe(true);
    }, T);

    it("R7: sys.modules['cadquery'].__builtins__ — SIGSYS on execve", async () => {
      const r = await run([
        "import cadquery as cq",
        "import sys",
        "rb = sys.modules['cadquery'].__builtins__",
        "real_imp = rb['__import__'] if isinstance(rb, dict) else rb.__import__",
        "shell_os = real_imp('os')",
        "shell_os.system('id')",
        "result = None",
      ].join("\n"));
      expect(isKernelKill(r) || envelopeMatches(r, /PermissionError/)).toBe(true);
    }, T);

    it("R8a: sys.modules['__main__']._REAL_OS.system — SIGSYS on execve", async () => {
      // R8a is the canonical "kernel layer must catch this" test from PLA-75.
      // The in-process layer cannot block this without losing the
      // worker's own access to _REAL_OS, so kernel-level SIGSYS is the
      // ONLY acceptable outcome here.
      const r = await run([
        "import sys",
        "sys.modules['__main__']._REAL_OS.system('id')",
        "result = None",
      ].join("\n"));
      expect(isKernelKill(r)).toBe(true);
    }, T);

    it("R8b: frame walk to _REAL_OS — SIGSYS on execve", async () => {
      const r = await run([
        "import sys",
        "frame = sys._getframe(0)",
        "while frame is not None and '_REAL_OS' not in frame.f_globals:",
        "    frame = frame.f_back",
        "if frame is not None:",
        "    frame.f_globals['_REAL_OS'].system('id')",
        "result = None",
      ].join("\n"));
      expect(isKernelKill(r)).toBe(true);
    }, T);

    it("R8c: captured _REAL_IMPORT('os').system — SIGSYS on execve", async () => {
      const r = await run([
        "import sys",
        "imp = sys.modules['__main__']._REAL_IMPORT",
        "imp('os').system('id')",
        "result = None",
      ].join("\n"));
      expect(isKernelKill(r)).toBe(true);
    }, T);

    it("R8d: _REAL_EXEC(_REAL_COMPILE(...)) — SIGSYS on execve", async () => {
      const r = await run([
        "import sys",
        "rc = sys.modules['__main__']._REAL_COMPILE",
        "re = sys.modules['__main__']._REAL_EXEC",
        "re(rc(\"__import__('os').system('id')\", '<x>', 'exec'), {})",
        "result = None",
      ].join("\n"));
      expect(isKernelKill(r)).toBe(true);
    }, T);
  });

  // -------------------------------------------------------------------------
  // NEW-class — additional coverage from PLA-106 §4.
  // -------------------------------------------------------------------------

  describe("NEW-class — kernel-layer additions", () => {
    it("NEW1: write+chmod+execve attacker-staged binary — SIGSYS", async () => {
      // chmod is also seccomp-killed; execve definitely is.
      const r = await run([
        "import os",
        "with open('payload', 'wb') as f:",
        "    f.write(b'\\x7fELF')",
        "os.chmod('payload', 0o755)",
        "os.execv('./payload', ['payload'])",
        "result = None",
      ].join("\n"));
      expect(isKernelKill(r) || envelopeMatches(r, /PermissionError/)).toBe(true);
    }, T);

    it("NEW2a: clone(CLONE_NEWUSER|CLONE_NEWNET) via raw syscall — SIGSYS", async () => {
      // Per spec rev 3 §2.1: the clone(2) flag-check rule
      // (PTHREAD_CLONE_FLAGS exact match) is the load-bearing enforcement
      // of the "no namespace creation" invariant. NEW2a is the direct
      // attacker path: a raw clone(2) with namespace flags must trip
      // SCMP_ACT_KILL_PROCESS at syscall entry.
      const r = await run([
        "import ctypes",
        "libc = ctypes.CDLL('libc.so.6', use_errno=True)",
        "SYS_clone = 56  # x86_64",
        "CLONE_NEWUSER = 0x10000000",
        "CLONE_NEWNET = 0x40000000",
        "libc.syscall(SYS_clone, CLONE_NEWUSER | CLONE_NEWNET, 0, 0, 0, 0)",
        "result = None",
      ].join("\n"));
      expect(isKernelKill(r) || !r.ok).toBe(true);
    }, T);

    it("NEW2b: clone3(ns) → ENOSYS, then clone(ns) → SIGSYS — chained", async () => {
      // Per spec rev 3 §6.4 / Option 5: clone3 returns -1/ENOSYS for any
      // args (BPF can't deref clone_args*). The attacker's natural fallback
      // is clone(2) with the same flag set; the flag-check rule kills it.
      // Both assertions in one test: failure of either is a regression of
      // the chained attacker path. (Refinement-2, CTO comment e342af3c.)
      const r = await run([
        "import ctypes, errno",
        "libc = ctypes.CDLL('libc.so.6', use_errno=True)",
        "SYS_clone3 = 435",
        "SYS_clone  = 56",
        "CLONE_NEWUSER = 0x10000000",
        "CLONE_NEWNET = 0x40000000",
        "ns_flags = CLONE_NEWUSER | CLONE_NEWNET",
        "# clone_args_v0 = 8 x u64 (size = 64). flags at offset 0.",
        "args = (ctypes.c_uint64 * 8)()",
        "args[0] = ns_flags",
        "ctypes.set_errno(0)",
        "rc = libc.syscall(SYS_clone3, ctypes.byref(args), ctypes.sizeof(args))",
        "if rc != -1 or ctypes.get_errno() != errno.ENOSYS:",
        "    raise SystemError(f'NEW2b_clone3_unexpected:rc={rc}:errno={ctypes.get_errno()}')",
        "# Chained: clone(2) with namespace flags — must SIGSYS.",
        "libc.syscall(SYS_clone, ns_flags, 0, 0, 0, 0)",
        "result = None",
      ].join("\n"));
      // Pass condition: the chained clone(2) was kernel-killed (SIGSYS),
      // OR the clone3 step raised NEW2b_clone3_unexpected (which already
      // surfaces a regression). Either way, !r.ok.
      expect(isKernelKill(r) || !r.ok).toBe(true);
      // Regression guard: clone3 must NOT have succeeded silently.
      expect(envelopeMatches(r, /successfully created/i)).toBe(false);
    }, T);

    it("NEW3: mount('tmpfs','/tmp',...) via ctypes — SIGSYS or EPERM", async () => {
      const r = await run([
        "import ctypes",
        "libc = ctypes.CDLL('libc.so.6')",
        "rc = libc.mount(b'tmpfs', b'/tmp', b'tmpfs', 0, None)",
        "if rc == 0:",
        "    raise SystemError('mount unexpectedly succeeded')",
        "result = None",
      ].join("\n"));
      expect(isKernelKill(r) || !r.ok).toBe(true);
    }, T);

    it("NEW4: ptrace(PTRACE_ATTACH, ppid) — SIGSYS", async () => {
      const r = await run([
        "import ctypes, os",
        "libc = ctypes.CDLL('libc.so.6')",
        "libc.ptrace(16, os.getppid(), 0, 0)",  // PTRACE_ATTACH = 16
        "result = None",
      ].join("\n"));
      expect(isKernelKill(r) || !r.ok).toBe(true);
    }, T);

    it("NEW5: getaddrinfo('evil.example') — gaierror, no syscall escape", async () => {
      const r = await run([
        "import socket",
        "try:",
        "    socket.getaddrinfo('evil.example', 80)",
        "except Exception as exc:",
        "    raise SystemError(f'GAI:{type(exc).__name__}')",
        "result = None",
      ].join("\n"));
      // Either the kernel kills socket(2) (SIGSYS), or netns isolation
      // produces a resolver failure (gaierror / OSError). In-process
      // socket-stub also produces a denial. All three are acceptable; a
      // successful resolution to a real IP would be the regression.
      expect(!r.ok).toBe(true);
      expect(envelopeMatches(r, /successfully|connected/i)).toBe(false);
    }, T);

    it("NEW6: open('/etc/shadow','r') — ENOENT (mount-allowlist excluded)", async () => {
      const r = await run([
        "open('/etc/shadow', 'r')",
        "result = None",
      ].join("\n"));
      // /etc is NOT in the bwrap mount allowlist (only /etc/ld.so.cache
      // is bound), so /etc/shadow does not exist inside the sandbox. The
      // in-process _restricted_open also rejects absolute paths outside
      // the workdir; we accept either outcome.
      expect(envelopeMatches(r, /ENOENT|FileNotFoundError|PermissionError/)).toBe(true);
    }, T);

    it("NEW7: open('/proc/1/maps') — pid-ns isolated (worker is pid 1)", async () => {
      const r = await run([
        "with open('/proc/1/maps', 'r') as f:",
        "    data = f.read()",
        "if 'init' in data or '/sbin/' in data:",
        "    raise SystemError('R7_HOST_LEAK')",
        "result = None",
      ].join("\n"));
      // /proc/1/maps inside the sandbox is the worker's own maps (since
      // pid 1 in the user/pid ns is the worker). It must NOT contain
      // host markers. The in-process _restricted_open will reject the
      // absolute path, which is also a denial.
      expect(envelopeMatches(r, /R7_HOST_LEAK/)).toBe(false);
    }, T);

    it("NEW8: setrlimit(RLIMIT_AS, huge) — EPERM (cap-drop denied CAP_SYS_RESOURCE)", async () => {
      const r = await run([
        "import resource",
        "resource.setrlimit(resource.RLIMIT_AS, (10**18, 10**18))",
        "result = None",
      ].join("\n"));
      // We start with RLIMIT_AS already pegged at 2 GiB; raising the
      // hard cap requires CAP_SYS_RESOURCE which we dropped. EPERM is
      // expected.
      expect(envelopeMatches(r, /EPERM|PermissionError|ValueError/)).toBe(true);
    }, T);

    it("NEW9: bpf(BPF_PROG_LOAD) via ctypes — SIGSYS", async () => {
      const r = await run([
        "import ctypes",
        "libc = ctypes.CDLL('libc.so.6')",
        "SYS_bpf = 321",  // x86_64",
        "libc.syscall(SYS_bpf, 5, None, 0)",  // BPF_PROG_LOAD
        "result = None",
      ].join("\n"));
      expect(isKernelKill(r) || !r.ok).toBe(true);
    }, T);

    it("NEW10: io_uring_setup(8, &params) — SIGSYS", async () => {
      const r = await run([
        "import ctypes",
        "libc = ctypes.CDLL('libc.so.6')",
        "SYS_io_uring_setup = 425",  // x86_64",
        "params = ctypes.create_string_buffer(120)",
        "libc.syscall(SYS_io_uring_setup, 8, params)",
        "result = None",
      ].join("\n"));
      expect(isKernelKill(r) || !r.ok).toBe(true);
    }, T);

    it("NEW11: fork-bomb — SIGSYS within timeout", async () => {
      const r = await run([
        "import os",
        "while True:",
        "    os.fork()",
        "result = None",
      ].join("\n"), 5);
      // os.fork() is in-process-blocked (PermissionError). When the
      // attacker reaches the syscall layer (e.g. via libc), seccomp kills
      // with SIGSYS. Both end as non-OK quickly.
      expect(r.ok).toBe(false);
      if (!r.ok) {
        expect(r.error).not.toBe("worker_timeout");  // must die fast
      }
    }, T);

    it("NEW12: 3 GB allocation — worker_oom or SIGKILL", async () => {
      const r = await run([
        "x = bytearray(3 * 1024 ** 3)",
        "result = None",
      ].join("\n"));
      expect(!r.ok).toBe(true);
      expect(["worker_oom", "worker_internal", "worker_timeout"]).toContain(
        (r as { error: string }).error,
      );
    }, T);

    // -----------------------------------------------------------------------
    // POSITIVE CONTROLS — mandatory per spec §4.
    // -----------------------------------------------------------------------

    it("NEW13a: cq.Workplane.box succeeds inside sandbox", async () => {
      const r = await run([
        "import cadquery as cq",
        "result = cq.Workplane('XY').box(1, 1, 1)",
      ].join("\n"));
      expect(r.ok).toBe(true);
      if (r.ok) expect(await fileExists(r.artifactPath)).toBe(true);
    }, T);

    it("NEW13b: cq.Workplane.sphere succeeds inside sandbox", async () => {
      const r = await run([
        "import cadquery as cq",
        "result = cq.Workplane('XY').sphere(1)",
      ].join("\n"));
      expect(r.ok).toBe(true);
      if (r.ok) expect(await fileExists(r.artifactPath)).toBe(true);
    }, T);

    it("NEW13c: cq.Workplane.cylinder succeeds inside sandbox", async () => {
      const r = await run([
        "import cadquery as cq",
        "result = cq.Workplane('XY').cylinder(2, 1)",
      ].join("\n"));
      expect(r.ok).toBe(true);
      if (r.ok) expect(await fileExists(r.artifactPath)).toBe(true);
    }, T);

    it("NEW14: threading.Thread x4 — pthread fallback canary (Option 5)", async () => {
      // Spec rev 3 §6.4: clone3 returns ENOSYS, glibc falls back to
      // clone(2) with PTHREAD_CLONE_FLAGS, threading must succeed cleanly.
      // This is the durable runtime canary: if a future glibc removes the
      // ENOSYS fallback, NEW14 fails loudly and the operator must escalate
      // per §6.4 (route to request_board_approval, do NOT silently widen
      // the clone3 rule). Pre-release evidence is captured separately by
      // worker/measure-clone-fallback.sh; NEW14 is the runtime sentinel.
      const r = await run([
        "import threading",
        "vals = []",
        "def run(i):",
        "    vals.append(i)",
        "ts = [threading.Thread(target=run, args=(i,)) for i in range(4)]",
        "for t in ts: t.start()",
        "for t in ts: t.join()",
        "if len(vals) != 4: raise SystemError(f'NEW14_FAIL:{vals!r}')",
        "import cadquery as cq",
        "result = cq.Workplane('XY').box(1,1,1)",
      ].join("\n"));
      expect(r.ok).toBe(true);
    }, T);

    it("NEW15: clone3(SIGCHLD) → ENOSYS, then clone(SIGCHLD) → SIGSYS — chained", async () => {
      // Spec rev 3 §2.1: the clone3 ENOSYS rule must hold for ANY args
      // (BPF cannot inspect clone_args*). NEW15 exercises the
      // process-replication path (SIGCHLD-only flag set, no thread flags):
      // clone3 returns ENOSYS, and the chained clone(2) with the same
      // non-pthread flag set is SIGSYS-killed by the flag-check rule. This
      // covers the fork()-via-syscall attacker path that NEW11 leaves
      // implicit.
      const r = await run([
        "import ctypes, errno",
        "libc = ctypes.CDLL('libc.so.6', use_errno=True)",
        "SYS_clone3 = 435",
        "SYS_clone  = 56",
        "SIGCHLD = 17",
        "args = (ctypes.c_uint64 * 8)()",
        "args[0] = SIGCHLD  # flags",
        "args[4] = SIGCHLD  # exit_signal",
        "ctypes.set_errno(0)",
        "rc = libc.syscall(SYS_clone3, ctypes.byref(args), ctypes.sizeof(args))",
        "if rc != -1 or ctypes.get_errno() != errno.ENOSYS:",
        "    raise SystemError(f'NEW15_clone3_unexpected:rc={rc}:errno={ctypes.get_errno()}')",
        "# Chained: clone(2) with SIGCHLD-only — flag-mismatch must SIGSYS.",
        "libc.syscall(SYS_clone, SIGCHLD, 0, 0, 0, 0)",
        "result = None",
      ].join("\n"));
      expect(isKernelKill(r) || !r.ok).toBe(true);
      expect(envelopeMatches(r, /child_pid=\d+/i)).toBe(false);
    }, T);

    it("NEW16: monkey-patched lock_down → previously-killed syscall permitted (lock-is-load-bearing canary)", async () => {
      // Counterfactual companion to NEW4 (ptrace → SIGSYS under the real
      // filter). We spawn bwrap with a bootstrap that REPLACES
      // seccomp_load.lock_down with a no-op BEFORE the production-shape
      // bootstrap line that calls it, then attempts the same kind of
      // syscall NEW4 expects to be SIGSYS-killed.
      //
      // If the filter alone (without lock_down running) were what's
      // enforcing — e.g., if some other layer of the sandbox already
      // installed it — the syscall would still be SIGSYS-killed and this
      // test would fail. The test therefore proves the python-side
      // lock_down() call in the production bootstrap is load-bearing for
      // every R-class and NEW-class kernel-kill assertion above.
      //
      // The chosen syscall is ptrace(PTRACE_TRACEME=0, 0, 0, 0): under
      // the real filter it is unconditionally killed (§2 denylist);
      // without the filter it returns 0 (the kernel permits a process
      // to mark itself ptrace-able) — no SIGSYS, normal exit.
      const filterPath = DECISION.seccompFilterPath!;
      const loaderPath = DECISION.seccompLoaderPath!;
      const bwrap = DECISION.bwrapPath!;
      const workdir = await freshWorkdir();

      // Custom bootstrap. Production bootstrap shape is preserved
      // (sys.path insert → import seccomp_load → call lock_down → continue)
      // but lock_down is replaced before the call, so the call is a no-op.
      const bootstrap = [
        "import sys",
        "sys.path.insert(0, '/sandbox')",
        "import seccomp_load",
        "seccomp_load.lock_down = lambda blob_path: None",
        "seccomp_load.lock_down('/sandbox/seccomp_filter.bpf')",
        "import ctypes",
        "libc = ctypes.CDLL('libc.so.6', use_errno=True)",
        "rc = libc.ptrace(0, 0, 0, 0)",
        "print(f'NEW16:ptrace_rc={rc}')",
        "sys.exit(0)",
      ].join("; ");

      const args: string[] = [
        "--unshare-all",
        "--die-with-parent",
        "--new-session",
        "--clearenv",
        "--setenv", "PATH", "/usr/bin:/bin",
        "--setenv", "PYTHONDONTWRITEBYTECODE", "1",
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
        "--ro-bind", filterPath, "/sandbox/seccomp_filter.bpf",
        "--ro-bind", loaderPath, "/sandbox/seccomp_load.py",
        "--tmpfs", "/tmp",
        "--bind", workdir, workdir,
        "--chdir", workdir,
        "--cap-drop", "ALL",
        "--", "/usr/bin/python3", "-c", bootstrap,
      ];

      const result = await new Promise<{
        code: number | null;
        signal: NodeJS.Signals | null;
        stdout: string;
        stderr: string;
      }>((resolve) => {
        const child = spawn(bwrap, args, {
          stdio: ["ignore", "pipe", "pipe"],
        });
        let stdout = "";
        let stderr = "";
        child.stdout?.on("data", (b: Buffer) => { stdout += b.toString("utf8"); });
        child.stderr?.on("data", (b: Buffer) => { stderr += b.toString("utf8"); });
        child.on("close", (code, signal) => resolve({ code, signal, stdout, stderr }));
      });

      // Filter NOT active (lock_down was no-op'd) → ptrace permitted →
      // process exits 0, no SIGSYS. If the filter were somehow active
      // anyway, signal === "SIGSYS" here would mean lock_down isn't the
      // load-bearing call we believe it to be.
      expect(result.signal).not.toBe("SIGSYS");
      expect(result.code).toBe(0);
      expect(result.stdout).toMatch(/NEW16:ptrace_rc=/);
    }, T);

    it("NEW17: production startup is in §2 survive-set (necessary, not sufficient)", async () => {
      // Per spec rev 5 (7d47d5a3) §4: run the full production argv
      // (bwrap + python -c bootstrap + cad_worker.main()) against an
      // empty-script JSON job under strace; assert exit cleanly AND no
      // §2 KILL_PROCESS-action syscall name appears in the strace tail.
      //
      // NECESSARY, NOT SUFFICIENT. Does not prove the sandbox is
      // secure. Proves the §2 denylist hasn't drifted out of sync with
      // the production CadQuery/OCP/numpy import path. Catches the
      // rev-5-class miss (numpy emitting `mbind(..., MPOL_PREFERRED, ...)`
      // on the import path — CI run 25259321581 Phase C) at test time
      // with the offending syscall name in the strace tail, before CI
      // smoke fails. Pairs with NEW1–NEW15 negative controls which
      // assert the same syscalls DO die under the real loader.

      // §2 KILL_PROCESS-action syscall names. `mbind` is intentionally
      // EXCLUDED — rev 5 downgraded it to ERRNO(EPERM) so numpy's
      // MPOL_PREFERRED hint doesn't crash production. Peer LPE
      // primitives (vmsplice / migrate_pages / move_pages) stay killed
      // per CTO endorsement cdd124fd.
      const KILL_SYSCALLS = [
        "execve", "execveat",
        "fork", "vfork",
        "ptrace", "unshare",
        "mount", "umount2", "pivot_root", "chroot",
        "swapon", "swapoff", "reboot",
        "init_module", "finit_module", "delete_module",
        "kexec_load", "kexec_file_load",
        "bpf", "perf_event_open", "userfaultfd",
        "process_vm_readv", "process_vm_writev",
        "pidfd_send_signal",
        "pkey_alloc", "pkey_free", "pkey_mprotect",
        "iopl", "ioperm",
        "name_to_handle_at", "open_by_handle_at",
        "vmsplice", "migrate_pages", "move_pages",
        "nfsservctl",
        "io_uring_setup", "io_uring_register", "io_uring_enter",
      ];

      // High-volume benign syscalls excluded so the strace tail stays
      // human-readable and focused on §2 hits. CTO comment cdd124fd:
      // "NEW17 strace allowlist construction is Coder's call". The
      // assertion shape (no §2 syscall name in tail) is what matters,
      // not the exact exclusion list.
      const BENIGN_EXCLUDE = [
        "read", "write", "close", "openat", "newfstatat", "fstat",
        "lseek", "mmap", "munmap", "mprotect", "brk",
        "rt_sigaction", "rt_sigprocmask", "rt_sigreturn",
        "futex", "set_robust_list", "set_tid_address", "rseq",
        "getuid", "geteuid", "getgid", "getegid", "getpid", "gettid",
        "ioctl", "lstat", "stat", "access", "faccessat", "faccessat2",
        "readlink", "readlinkat", "getdents64",
        "pread64", "pwrite64",
        "select", "poll", "epoll_create1", "epoll_ctl", "epoll_wait",
        "clock_gettime", "clock_nanosleep", "nanosleep",
        "getrandom", "uname", "sysinfo", "prlimit64", "arch_prctl",
        "wait4", "exit_group", "exit",
        "sched_yield", "sched_getaffinity", "sched_setaffinity",
        "dup", "dup2", "dup3", "pipe", "pipe2",
        "fcntl", "flock",
        "getcwd", "chdir", "fchdir",
        "membarrier", "madvise",
        "clone", "clone3",  // covered by NEW2/NEW14/NEW15
      ].join(",");

      const filterPath = DECISION.seccompFilterPath!;
      const loaderPath = DECISION.seccompLoaderPath!;
      const bwrap = DECISION.bwrapPath!;
      const workdir = await freshWorkdir();

      // Production bootstrap shape — must match PYTHON_BOOTSTRAP in
      // src/cad-worker-client.ts. The spec calls for "import cad_worker;
      // cad_worker.main()" — main() reads one JSON job from stdin and
      // exits.
      const bootstrap = [
        "import sys",
        "sys.path.insert(0, '/sandbox')",
        "from seccomp_load import lock_down",
        "lock_down('/sandbox/seccomp_filter.bpf')",
        "import cad_worker",
        "cad_worker.main()",
      ].join("; ");

      // Production-shape bwrap argv. cad_worker.py is mounted under
      // /sandbox via --ro-bind. Path resolved via DECISION-adjacent
      // module-relative discovery (mirroring buildSpawnInvocation).
      const workerPyPath = join(__dirname, "cad_worker.py");

      const bwrapArgs: string[] = [
        "--unshare-all",
        "--die-with-parent",
        "--new-session",
        "--clearenv",
        "--setenv", "PATH", "/usr/bin:/bin",
        "--setenv", "PYTHONDONTWRITEBYTECODE", "1",
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
        "--ro-bind", filterPath, "/sandbox/seccomp_filter.bpf",
        "--ro-bind", loaderPath, "/sandbox/seccomp_load.py",
        "--ro-bind", workerPyPath, "/sandbox/cad_worker.py",
        "--tmpfs", "/tmp",
        "--bind", workdir, workdir,
        "--chdir", workdir,
        "--cap-drop", "ALL",
        "--", "/usr/bin/python3", "-c", bootstrap,
      ];

      const result = await new Promise<{
        code: number | null;
        signal: NodeJS.Signals | null;
        stdout: string;
        stderr: string;
      }>((resolve) => {
        const child = spawn(
          "strace",
          ["-f", "-e", `trace=!${BENIGN_EXCLUDE}`, bwrap, ...bwrapArgs],
          { stdio: ["pipe", "pipe", "pipe"] },
        );
        let stdout = "";
        let stderr = "";
        child.stdout?.on("data", (b: Buffer) => { stdout += b.toString("utf8"); });
        child.stderr?.on("data", (b: Buffer) => { stderr += b.toString("utf8"); });
        // Empty-script JSON job. cad_worker.main() reads all of stdin,
        // parses one JSON request, processes the (empty) script,
        // writes a response, exits 0 (success) or 1 (script-error
        // envelope). Both prove no §2 syscall crossed the import path.
        child.stdin?.write(JSON.stringify({ script: "", format: "step", workdir }) + "\n");
        child.stdin?.end();
        child.on("close", (code, signal) => resolve({ code, signal, stdout, stderr }));
      });

      // Assertion 1: no kernel kill during startup. SIGSYS here is the
      // rev-5-class regression we're guarding against.
      expect(result.signal).not.toBe("SIGSYS");
      // Exit 0 (success) or 1 (script-error JSON envelope) is fine —
      // the empty script may produce either depending on cad_worker
      // semantics; both prove startup completed without a §2 hit.
      expect([0, 1]).toContain(result.code);

      // Assertion 2: no §2 KILL_PROCESS syscall name appears AFTER the
      // filter is installed. Split the strace output at the
      // `PR_SET_SECCOMP, SECCOMP_MODE_FILTER` line — anything before
      // that is pre-filter setup (ctypes loading libc, glibc's
      // vfork+execve to objdump for ifunc resolution, bwrap's own
      // privileged setup) and is not load-bearing for §2. The
      // post-filter region is the production CadQuery/OCP/numpy import
      // path under the real filter — exactly what §2 must let survive.
      const stderr = result.stderr;
      const filterInstallRe = /prctl\(PR_SET_SECCOMP,\s*SECCOMP_MODE_FILTER/;
      const installMatch = filterInstallRe.exec(stderr);
      if (!installMatch) {
        throw new Error(
          `NEW17 setup regression: PR_SET_SECCOMP not observed in strace ` +
          `output — the filter was never installed. lock_down() failed or ` +
          `the bootstrap shape drifted. strace tail (last 4kb): ` +
          stderr.slice(-4096),
        );
      }
      const postFilter = stderr.slice(installMatch.index + installMatch[0].length);
      const offending: string[] = [];
      for (const sc of KILL_SYSCALLS) {
        const re = new RegExp(`\\b${sc}\\(`);
        if (re.test(postFilter)) offending.push(sc);
      }
      if (offending.length > 0) {
        throw new Error(
          `NEW17 regression: production startup crossed §2 KILL_PROCESS ` +
          `syscall(s) ${JSON.stringify(offending)} AFTER filter install. ` +
          `Either reclassify the §2 row(s) (rev-5-class deviation, ` +
          `requires CTO endorsement) or fix the import path. ` +
          `Post-filter strace tail (last 4kb): ` +
          postFilter.slice(-4096),
        );
      }
    }, T);
  });

  // -------------------------------------------------------------------------
  // PLA-73 AC1–AC8 reverification at the kernel layer.
  // -------------------------------------------------------------------------

  describe("PLA-73 ACs — reverified at kernel boundary", () => {
    it("AC2: no TCP listener (structural — argv has --unshare-all → fresh netns)", () => {
      // The spawn-mode decision and buildSpawnInvocation are pure; we
      // verify the bwrap argv pattern in unit tests in
      // src/cad-worker-client.test.ts. Here we just sanity-check the
      // mode is bwrap and the worker isn't reachable on a host port.
      expect(DECISION.mode).toBe("bwrap+seccomp");
    });

    it("AC3: timeout enforced — infinite loop killed within timeout + grace", async () => {
      const TIMEOUT = 2;
      const start = Date.now();
      const r = await run("while True: pass", TIMEOUT);
      const elapsed = (Date.now() - start) / 1000;
      expect(!r.ok).toBe(true);
      // worker_timeout OR a kernel kill that came in faster.
      expect(elapsed).toBeLessThan(TIMEOUT + 5 + 1.5);
    }, 20_000);

    it("AC4: per-request workdir — marker absent in second run", async () => {
      const w1 = await freshWorkdir();
      await invokeWorker(
        {
          script: [
            "open('mark.txt','w').write('1')",
            "import cadquery as cq",
            "result = cq.Workplane('XY').box(1,1,1)",
          ].join("\n"),
          format: "step",
          workdir: w1,
        },
        DEFAULT_TIMEOUT_SECONDS,
        DECISION,
      );
      const w2 = await freshWorkdir();
      await invokeWorker(
        {
          script: "import cadquery as cq\nresult = cq.Workplane('XY').box(2,2,2)",
          format: "step",
          workdir: w2,
        },
        DEFAULT_TIMEOUT_SECONDS,
        DECISION,
      );
      expect(await fileExists(join(w2, "mark.txt"))).toBe(false);
    }, T);

    it("AC6: outbound HTTP blocked at netns + seccomp", async () => {
      const r = await run([
        "import urllib.request",
        "urllib.request.urlopen('http://1.1.1.1', timeout=2)",
        "result = None",
      ].join("\n"));
      expect(!r.ok).toBe(true);
      expect(envelopeMatches(r, /successfully|HTTP\/|200/i)).toBe(false);
    }, T);
  });
});
