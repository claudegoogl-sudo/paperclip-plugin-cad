/**
 * Unit tests for the deploy-time clone-fallback self-test — PLA-137.
 *
 * AC coverage from PLA-137 Path B:
 *   - (i) probe success path
 *   - (ii) probe-fails-with-wrong-errno → caller will process.exit non-zero
 *
 * Plus additional sub-cases that document the failure taxonomy:
 *   - clone3 dies via SIGSYS (filter is killing instead of returning ENOSYS)
 *   - clone(2) survives (filter kill rule absent)
 *   - clone(2) returns SIGKILL with audit "seccomp" stderr (kernel-equivalent)
 *
 * The unit test stubs `spawn` via the ProbeDeps DI seam so it can simulate
 * each outcome without a real bwrap. A separate integration test (gated on
 * bwrapAvailable()) lives below to exercise the real bwrap path.
 */

import { describe, it, expect, vi } from "vitest";
import { EventEmitter } from "node:events";
import { execSync } from "node:child_process";
import { existsSync } from "node:fs";
import { Readable } from "node:stream";

import { runCloneFallbackProbe, type ProbeDeps } from "./clone-fallback-probe.js";
import type { SpawnModeDecision } from "./cad-worker-client.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

interface StubExit {
  stdout?: string;
  stderr?: string;
  code?: number | null;
  signal?: NodeJS.Signals | null;
  /** Throw synchronously from spawn() to simulate a node-level spawn error. */
  spawnThrow?: Error;
}

/**
 * Build a fake `spawn` that returns a ChildProcess-shaped EventEmitter,
 * emits the configured stdout/stderr, then closes with the configured
 * exit code/signal on next-tick.
 */
function makeStubSpawn(...exits: StubExit[]): {
  spawn: ProbeDeps["spawn"];
  calls: { command: string; args: string[] }[];
} {
  const calls: { command: string; args: string[] }[] = [];
  let i = 0;
  const spawn = ((command: string, args: string[]) => {
    calls.push({ command, args });
    const exit = exits[i++] ?? { code: 0 };
    if (exit.spawnThrow) throw exit.spawnThrow;

    const ee = new EventEmitter() as EventEmitter & {
      stdout: Readable;
      stderr: Readable;
      kill: (sig?: NodeJS.Signals) => void;
    };
    ee.stdout = Readable.from(
      exit.stdout ? [Buffer.from(exit.stdout, "utf8")] : [],
    );
    ee.stderr = Readable.from(
      exit.stderr ? [Buffer.from(exit.stderr, "utf8")] : [],
    );
    ee.kill = () => undefined;
    setImmediate(() => {
      ee.emit("close", exit.code ?? null, exit.signal ?? null);
    });
    return ee as unknown as ReturnType<NonNullable<ProbeDeps["spawn"]>>;
  }) as ProbeDeps["spawn"];
  return { spawn, calls };
}

const FAKE_DECISION: SpawnModeDecision = {
  mode: "bwrap+seccomp",
  bwrapPath: "/usr/bin/bwrap",
  bwrapHasNativeRlimits: true,
  seccompFilterPath: "/tmp/fake-seccomp_filter.bpf",
};

const fakeFsDeps: Pick<ProbeDeps, "openSync" | "closeSync"> = {
  openSync: () => 99 as number,
  closeSync: () => undefined,
};

// ---------------------------------------------------------------------------
// Suite — unit (DI-stubbed)
// ---------------------------------------------------------------------------

describe("PLA-137 — runCloneFallbackProbe (DI-stubbed)", () => {
  // -----------------------------------------------------------------------
  // (i) probe success path
  // -----------------------------------------------------------------------
  it("returns ok when clone3 → ENOSYS and clone(2) → SIGSYS", async () => {
    const { spawn } = makeStubSpawn(
      {
        stdout: JSON.stringify({
          step: "clone3",
          rc: -1,
          errno: 38,
          errno_name: "ENOSYS",
          glibc: "glibc-2.39",
          python: "3.12.3",
          arch: "x86_64",
        }) + "\n",
        code: 0,
        signal: null,
      },
      {
        // Killed by the kernel via SIGSYS — no stdout from the probe.
        stdout: "",
        signal: "SIGSYS",
        code: null,
      },
    );

    const result = await runCloneFallbackProbe(FAKE_DECISION, {
      workdir: "/tmp/fake",
      deps: { spawn, ...fakeFsDeps },
    });

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.clone3ErrnoName).toBe("ENOSYS");
      expect(result.clone3Errno).toBe(38);
      expect(result.clone2ExitSignal).toBe("SIGSYS");
      expect(result.glibc).toBe("glibc-2.39");
      expect(result.python).toBe("3.12.3");
      expect(result.arch).toBe("x86_64");
    }
  });

  it("accepts SIGKILL with seccomp audit text on clone(2) as kernel-equivalent", async () => {
    const { spawn } = makeStubSpawn(
      {
        stdout: JSON.stringify({
          step: "clone3", rc: -1, errno: 38, errno_name: "ENOSYS",
          glibc: "glibc-2.39", python: "3.12.3", arch: "x86_64",
        }),
        code: 0, signal: null,
      },
      {
        stderr: "audit: type=1326 seccomp violation",
        signal: "SIGKILL",
        code: null,
      },
    );
    const result = await runCloneFallbackProbe(FAKE_DECISION, {
      workdir: "/tmp/fake",
      deps: { spawn, ...fakeFsDeps },
    });
    expect(result.ok).toBe(true);
  });

  // -----------------------------------------------------------------------
  // (ii) probe-fails-with-wrong-errno path
  // -----------------------------------------------------------------------
  it("returns clone3 fail when errno is not ENOSYS (e.g. EPERM)", async () => {
    const { spawn } = makeStubSpawn({
      stdout: JSON.stringify({
        step: "clone3", rc: -1, errno: 1, errno_name: "EPERM",
        glibc: "glibc-2.39", python: "3.12.3", arch: "x86_64",
      }),
      code: 0, signal: null,
    });
    const result = await runCloneFallbackProbe(FAKE_DECISION, {
      workdir: "/tmp/fake",
      deps: { spawn, ...fakeFsDeps },
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.step).toBe("clone3");
      expect(result.message).toMatch(/errno=EPERM/);
      expect(result.message).toMatch(/expected.*ENOSYS/);
      expect(result.observed?.errnoName).toBe("EPERM");
    }
  });

  it("returns clone3 fail when clone3 actually succeeded (rc != -1)", async () => {
    const { spawn } = makeStubSpawn({
      stdout: JSON.stringify({
        step: "clone3", rc: 12345, errno: 0, errno_name: "0",
        glibc: "glibc-2.39", python: "3.12.3", arch: "x86_64",
      }),
      code: 0, signal: null,
    });
    const result = await runCloneFallbackProbe(FAKE_DECISION, {
      workdir: "/tmp/fake",
      deps: { spawn, ...fakeFsDeps },
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.step).toBe("clone3");
      expect(result.message).toMatch(/rc=12345/);
    }
  });

  it("returns clone3 fail when the probe dies via SIGSYS (filter killing instead of ENOSYS)", async () => {
    const { spawn } = makeStubSpawn({
      stdout: "",
      signal: "SIGSYS",
      code: null,
    });
    const result = await runCloneFallbackProbe(FAKE_DECISION, {
      workdir: "/tmp/fake",
      deps: { spawn, ...fakeFsDeps },
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.step).toBe("clone3");
      expect(result.observed?.signal).toBe("SIGSYS");
    }
  });

  it("returns clone2 fail when clone(SIGCHLD) survives (filter rule missing)", async () => {
    const { spawn } = makeStubSpawn(
      {
        stdout: JSON.stringify({
          step: "clone3", rc: -1, errno: 38, errno_name: "ENOSYS",
          glibc: "glibc-2.39", python: "3.12.3", arch: "x86_64",
        }),
        code: 0, signal: null,
      },
      {
        stdout: JSON.stringify({ step: "clone2", error: "UNEXPECTED_SURVIVED", arch: "x86_64" }),
        code: 2,
        signal: null,
      },
    );
    const result = await runCloneFallbackProbe(FAKE_DECISION, {
      workdir: "/tmp/fake",
      deps: { spawn, ...fakeFsDeps },
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.step).toBe("clone2");
      expect(result.message).toMatch(/SIGSYS/);
    }
  });

  it("returns clone3 fail when stdout is unparseable", async () => {
    const { spawn } = makeStubSpawn({ stdout: "garbage not json", code: 0, signal: null });
    const result = await runCloneFallbackProbe(FAKE_DECISION, {
      workdir: "/tmp/fake",
      deps: { spawn, ...fakeFsDeps },
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.step).toBe("clone3");
      expect(result.message).toMatch(/not valid JSON/);
    }
  });

  it("returns spawn fail when spawn throws", async () => {
    const { spawn } = makeStubSpawn({ spawnThrow: new Error("ENOENT bwrap") });
    const result = await runCloneFallbackProbe(FAKE_DECISION, {
      workdir: "/tmp/fake",
      deps: { spawn, ...fakeFsDeps },
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.step).toBe("spawn");
      expect(result.message).toMatch(/ENOENT bwrap/);
    }
  });

  it("returns config fail when decision is dev_direct", async () => {
    const result = await runCloneFallbackProbe(
      { mode: "dev_direct" } as SpawnModeDecision,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.step).toBe("config");
    }
  });
});

// ---------------------------------------------------------------------------
// Integration — gated on a host with bwrap + the seccomp filter blob built
// ---------------------------------------------------------------------------

function bwrapAvailable(): boolean {
  if (process.platform !== "linux") return false;
  try {
    execSync("command -v bwrap", { stdio: "ignore" });
  } catch {
    return false;
  }
  return existsSync("worker/seccomp_filter.bpf");
}

const HAS_BWRAP = bwrapAvailable();

describe.skipIf(!HAS_BWRAP)("PLA-137 — runCloneFallbackProbe (real bwrap)", () => {
  it("succeeds against the production seccomp filter", async () => {
    // The vitest config defaults CAD_WORKER_UNSAFE_DEV=1 to force dev_direct
    // for the rest of the unit suite; clear it so the real spawn-mode is
    // resolved.
    delete process.env.CAD_WORKER_UNSAFE_DEV;
    const { selectSpawnMode } = await import("./cad-worker-client.js");
    const decision = selectSpawnMode();
    expect(decision.mode).toBe("bwrap+seccomp");

    const result = await runCloneFallbackProbe(decision);
    if (!result.ok) {
      // Surface the diagnostic so the CI log is actionable on failure.
      throw new Error(
        `Probe failed at step=${result.step}: ${result.message} ` +
        `observed=${JSON.stringify(result.observed)}`,
      );
    }
    expect(result.clone3ErrnoName).toBe("ENOSYS");
    expect(["SIGSYS", "SIGKILL"]).toContain(result.clone2ExitSignal);
    // Useful trace for §6.4-style evidence in CI logs.
    // eslint-disable-next-line no-console
    console.log(
      `[PLA-137] probe ok glibc=${result.glibc} python=${result.python} ` +
      `arch=${result.arch} clone3=${result.clone3ErrnoName} clone2=${result.clone2ExitSignal}`,
    );
  }, 30_000);
});

// Touch the import so vi tree-shake doesn't drop it; keeps lint happy when
// only the integration suite uses it.
void vi.fn;
