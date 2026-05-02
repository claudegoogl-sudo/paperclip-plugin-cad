/**
 * Worker setup() — clone-fallback-probe wiring tests (PLA-137).
 *
 * Covers the AC "(ii) probe-fails-with-wrong-errno path → process exits non-zero":
 *   - When selectSpawnMode → bwrap+seccomp and the probe returns ok,
 *     setup() completes and tools are registered. INFO log line emitted.
 *   - When the probe returns fail, setup() calls process.exit(1) and ERROR
 *     log line is emitted. Tool registration MUST NOT run after the failure.
 *
 * Notes for reviewers:
 *   - We mock `selectSpawnMode` and `runCloneFallbackProbe` directly so the
 *     test exercises the worker wiring without needing a real bwrap.
 *   - process.exit is stubbed; tests assert on the exit code argument.
 *     Because the real plugin would NOT proceed past process.exit(1), we
 *     additionally assert that no tools were registered when the probe
 *     fails.
 *   - Each test does an isolated `vi.resetModules()` import so the worker
 *     module is freshly loaded with the per-test mocks.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// SDK mock — same as worker.test.ts
vi.mock("@paperclipai/plugin-sdk", () => ({
  definePlugin: (config: unknown) => config,
  runWorker: vi.fn(),
}));

// cad-worker-client mock — surface a minimal selectSpawnMode + the
// renderCadQuery / DEFAULT_TIMEOUT_SECONDS the worker imports for tools.
vi.mock("./cad-worker-client.js", () => ({
  selectSpawnMode: vi.fn(),
  renderCadQuery: vi.fn(),
  DEFAULT_TIMEOUT_SECONDS: 30,
}));

// Probe mock — drives both success and failure paths.
vi.mock("./clone-fallback-probe.js", () => ({
  runCloneFallbackProbe: vi.fn(),
}));

import * as cadWorkerClient from "./cad-worker-client.js";
import * as probe from "./clone-fallback-probe.js";

type ToolHandler = (params: unknown, runCtx: unknown) => Promise<unknown>;

function buildMockCtx() {
  const handlers: Record<string, ToolHandler> = {};
  const logCalls: { level: string; message: string; meta?: Record<string, unknown> }[] = [];
  const ctx = {
    logger: {
      info: vi.fn((m: string, meta?: Record<string, unknown>) => { logCalls.push({ level: "info", message: m, meta }); }),
      warn: vi.fn((m: string, meta?: Record<string, unknown>) => { logCalls.push({ level: "warn", message: m, meta }); }),
      error: vi.fn((m: string, meta?: Record<string, unknown>) => { logCalls.push({ level: "error", message: m, meta }); }),
      debug: vi.fn(),
    },
    metrics: { write: vi.fn(async () => undefined) },
    tools: {
      register: vi.fn((name: string, _decl: unknown, h: ToolHandler) => {
        handlers[name] = h;
      }),
    },
  };
  return { ctx, handlers, logCalls };
}

beforeEach(() => {
  vi.resetModules();
  vi.clearAllMocks();
});

async function loadSetup() {
  const mod = (await import("./worker.js")) as unknown as {
    default: { setup: (ctx: unknown) => Promise<void> };
  };
  return mod.default.setup;
}

describe("PLA-137 — worker.setup() probe wiring", () => {
  it("(success) probe ok → tools registered + INFO ok line", async () => {
    vi.mocked(cadWorkerClient.selectSpawnMode).mockReturnValue({
      mode: "bwrap+seccomp",
      bwrapPath: "/usr/bin/bwrap",
      seccompFilterPath: "/tmp/fake.bpf",
      bwrapHasNativeRlimits: true,
    });
    vi.mocked(probe.runCloneFallbackProbe).mockResolvedValue({
      ok: true,
      glibc: "glibc-2.39",
      python: "3.12.3",
      arch: "x86_64",
      clone3Errno: 38,
      clone3ErrnoName: "ENOSYS",
      clone2ExitSignal: "SIGSYS",
    });

    const { ctx, handlers, logCalls } = buildMockCtx();
    const exitSpy = vi.spyOn(process, "exit").mockImplementation(((code?: number) => {
      throw new Error(`process.exit(${code}) was called unexpectedly`);
    }) as never);

    const setup = await loadSetup();
    await setup(ctx);

    expect(exitSpy).not.toHaveBeenCalled();
    expect(handlers["cad:run_script"]).toBeTypeOf("function");
    expect(handlers["cad:export"]).toBeTypeOf("function");

    const okLog = logCalls.find((c) => c.message === "sandbox.clone_fallback_probe ok");
    expect(okLog).toBeDefined();
    expect(okLog?.level).toBe("info");
    expect(okLog?.meta).toMatchObject({
      glibc: "glibc-2.39",
      python: "3.12.3",
      arch: "x86_64",
      clone3ErrnoName: "ENOSYS",
      clone2ExitSignal: "SIGSYS",
    });

    exitSpy.mockRestore();
  });

  it("(failure) probe fail with wrong errno → process.exit(1) + no tools registered", async () => {
    vi.mocked(cadWorkerClient.selectSpawnMode).mockReturnValue({
      mode: "bwrap+seccomp",
      bwrapPath: "/usr/bin/bwrap",
      seccompFilterPath: "/tmp/fake.bpf",
      bwrapHasNativeRlimits: true,
    });
    vi.mocked(probe.runCloneFallbackProbe).mockResolvedValue({
      ok: false,
      step: "clone3",
      message: "clone3 returned rc=-1 errno=EPERM (expected rc=-1 errno=ENOSYS)",
      observed: { rc: -1, errno: 1, errnoName: "EPERM" },
    });

    const { ctx, handlers, logCalls } = buildMockCtx();
    let exitCode: number | string | null | undefined;
    const exitSpy = vi.spyOn(process, "exit").mockImplementation(((code?: number) => {
      exitCode = code;
      // Simulate process.exit semantics: throw to abort setup() flow.
      throw new Error("__process_exit_called__");
    }) as never);

    const setup = await loadSetup();
    await expect(setup(ctx)).rejects.toThrow("__process_exit_called__");

    expect(exitSpy).toHaveBeenCalledTimes(1);
    expect(exitCode).toBe(1);

    // Fail-closed: tools must not be registered if the probe failed.
    expect(handlers["cad:run_script"]).toBeUndefined();
    expect(handlers["cad:export"]).toBeUndefined();

    const errLog = logCalls.find((c) => c.message === "sandbox.clone_fallback_probe FAILED — refusing to register tools");
    expect(errLog).toBeDefined();
    expect(errLog?.level).toBe("error");
    expect(errLog?.meta).toMatchObject({
      step: "clone3",
      message: expect.stringContaining("EPERM") as unknown,
    });

    exitSpy.mockRestore();
  });

  it("(skip) dev_direct mode → probe skipped with WARN, tools still registered", async () => {
    vi.mocked(cadWorkerClient.selectSpawnMode).mockReturnValue({
      mode: "dev_direct",
    });

    const { ctx, handlers, logCalls } = buildMockCtx();
    const exitSpy = vi.spyOn(process, "exit").mockImplementation(((code?: number) => {
      throw new Error(`process.exit(${code}) was called unexpectedly`);
    }) as never);

    const setup = await loadSetup();
    await setup(ctx);

    // Probe must NOT have been called.
    expect(probe.runCloneFallbackProbe).not.toHaveBeenCalled();
    expect(exitSpy).not.toHaveBeenCalled();

    expect(handlers["cad:run_script"]).toBeTypeOf("function");
    expect(handlers["cad:export"]).toBeTypeOf("function");

    const skipLog = logCalls.find((c) =>
      c.message === "sandbox.clone_fallback_probe skipped (kernel sandbox not active)",
    );
    expect(skipLog).toBeDefined();
    expect(skipLog?.level).toBe("warn");
    expect(skipLog?.meta).toMatchObject({ mode: "dev_direct" });

    exitSpy.mockRestore();
  });
});
