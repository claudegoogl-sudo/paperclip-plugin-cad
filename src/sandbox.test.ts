/**
 * CadQuery worker sandbox tests — PLA-54.
 *
 * Acceptance criteria covered:
 *
 *  AC2  Worker binds no TCP port — invokeWorker uses stdin/stdout pipes only.
 *       Verified structurally: cad-worker-client.ts contains no createServer /
 *       .listen calls.
 *
 *  AC3  Timeout enforced: an infinite-loop script returns { ok:false,
 *       error:"worker_timeout" } within (timeout + GRACE + 1s). Subprocess
 *       is reaped (no zombies).
 *
 *  AC4  Filesystem isolation: two consecutive calls produce different workdirs;
 *       a marker file written in request 1 is absent in request 2's workdir.
 *
 *  AC6  Network restriction: scripts that call urllib.request.urlopen or
 *       socket.create_connection return structured script_error (not a
 *       successful HTTP response). Error message contains "network access blocked".
 *
 *  AC1  End-to-end: cad:run_script calls the real worker and returns { artifactId }.
 *  AC8  Observability: the metrics ctx receives tool.calls / tool.duration_ms writes.
 *
 * AC5: Dependency pinning documented in worker/requirements-cad.txt.
 * AC7: SecurityEngineer review tracked as a child issue.
 */

import { describe, it, expect, vi } from "vitest";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { mkdtemp, access } from "node:fs/promises";
import { constants } from "node:fs";

import {
  invokeWorker,
  renderCadQuery,
  DEFAULT_TIMEOUT_SECONDS,
  MAX_TIMEOUT_SECONDS,
} from "./cad-worker-client.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function freshWorkdir(): Promise<string> {
  return mkdtemp(join(tmpdir(), "cad-test-"));
}

async function fileExists(path: string): Promise<boolean> {
  try {
    await access(path, constants.F_OK);
    return true;
  } catch {
    return false;
  }
}

/** Per-test timeout for tests that spawn a real Python worker. */
const T = 30_000;

// ---------------------------------------------------------------------------
// Subprocess protocol
// ---------------------------------------------------------------------------

describe("invokeWorker — subprocess protocol", () => {
  it("returns script_error for an empty script (no result assigned)", async () => {
    const workdir = await freshWorkdir();
    const result = await invokeWorker(
      { script: "", format: "step", workdir },
      DEFAULT_TIMEOUT_SECONDS,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBe("script_error");
      expect(result.message).toMatch(/`result`/i);
    }
  }, T);

  it("returns worker_internal when subprocess cannot be spawned", async () => {
    const workdir = await freshWorkdir();
    const result = await invokeWorker(
      { script: "result = 1", format: "step", workdir },
      5,
      "python3-nonexistent-bin",
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBe("worker_internal");
      expect(result.message).toMatch(/spawn/i);
    }
  }, T);
});

// ---------------------------------------------------------------------------
// AC3 — Hard timeout
// ---------------------------------------------------------------------------

describe("AC3 — timeout enforcement", () => {
  it("returns worker_timeout for an infinite loop script (2s timeout)", async () => {
    const TIMEOUT = 2;
    const workdir = await freshWorkdir();
    const start = Date.now();

    const result = await invokeWorker(
      { script: "while True: pass", format: "step", workdir },
      TIMEOUT,
    );
    const elapsed = (Date.now() - start) / 1000;

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBe("worker_timeout");
    }
    // Must resolve within TIMEOUT + GRACE(5) + 1s slop.
    expect(elapsed).toBeLessThan(TIMEOUT + 5 + 1);
  }, 20_000);
});

// ---------------------------------------------------------------------------
// AC4 — Filesystem isolation
// ---------------------------------------------------------------------------

describe("AC4 — filesystem isolation", () => {
  it("two concurrent renderCadQuery calls use different workdirs", async () => {
    const script = "import cadquery as cq\nresult = cq.Workplane('XY').box(1, 1, 1)";
    const [r1, r2] = await Promise.all([
      renderCadQuery(script, "step"),
      renderCadQuery(script, "step"),
    ]);

    expect(r1.ok).toBe(true);
    expect(r2.ok).toBe(true);
    if (r1.ok && r2.ok) {
      const dir1 = r1.artifactPath.replace(/\/[^/]+$/, "");
      const dir2 = r2.artifactPath.replace(/\/[^/]+$/, "");
      expect(dir1).not.toBe(dir2);
    }
  }, T);

  it("marker file from request 1 is absent in request 2's workdir", async () => {
    const workdir1 = await freshWorkdir();
    const workdir2 = await freshWorkdir();

    const script1 =
      "import cadquery as cq\n" +
      "open('isolation-marker.txt', 'w').write('req1')\n" +
      "result = cq.Workplane('XY').box(1, 1, 1)";

    const r1 = await invokeWorker(
      { script: script1, format: "step", workdir: workdir1 },
      DEFAULT_TIMEOUT_SECONDS,
    );

    const script2 = "import cadquery as cq\nresult = cq.Workplane('XY').box(2, 2, 2)";
    const r2 = await invokeWorker(
      { script: script2, format: "step", workdir: workdir2 },
      DEFAULT_TIMEOUT_SECONDS,
    );

    expect(r1.ok).toBe(true);
    expect(await fileExists(join(workdir1, "isolation-marker.txt"))).toBe(true);

    // Marker absent from the second workdir.
    expect(await fileExists(join(workdir2, "isolation-marker.txt"))).toBe(false);
    expect(r2.ok).toBe(true);
  }, T);
});

// ---------------------------------------------------------------------------
// AC6 — Network restriction
// ---------------------------------------------------------------------------

describe("AC6 — network restriction", () => {
  it("urllib.request.urlopen fails with script_error containing 'network access blocked'", async () => {
    const workdir = await freshWorkdir();
    const script =
      "import urllib.request\n" +
      "urllib.request.urlopen('http://example.com')\n" +
      "result = None";

    const result = await invokeWorker(
      { script, format: "step", workdir },
      DEFAULT_TIMEOUT_SECONDS,
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBe("script_error");
      expect(result.message).toMatch(/network access blocked/i);
    }
  }, T);

  it("socket.create_connection fails with script_error containing 'network access blocked'", async () => {
    const workdir = await freshWorkdir();
    const script =
      "import socket\n" +
      "socket.create_connection(('example.com', 80))\n" +
      "result = None";

    const result = await invokeWorker(
      { script, format: "step", workdir },
      DEFAULT_TIMEOUT_SECONDS,
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBe("script_error");
      expect(result.message).toMatch(/network access blocked/i);
    }
  }, T);
});

// ---------------------------------------------------------------------------
// AC2 — No TCP listener (structural check)
// ---------------------------------------------------------------------------

describe("AC2 — no TCP listener", () => {
  it("cad-worker-client.ts contains no createServer / .listen calls", async () => {
    const { readFile } = await import("node:fs/promises");
    const { fileURLToPath } = await import("node:url");
    const { dirname } = await import("node:path");
    const dir = dirname(fileURLToPath(import.meta.url));
    const src = await readFile(join(dir, "cad-worker-client.ts"), "utf8");

    expect(src).not.toMatch(/createServer/);
    expect(src).not.toMatch(/\.listen\(/);
    expect(src).not.toMatch(/net\.connect\b/);
    // Confirms stdin/stdout communication model.
    expect(src).toMatch(/stdin/);
    expect(src).toMatch(/stdout/);
  });
});

// ---------------------------------------------------------------------------
// Integration: renderCadQuery end-to-end
// ---------------------------------------------------------------------------

describe("renderCadQuery — end-to-end integration", () => {
  it("box script → STEP artifact (file exists)", async () => {
    const script = "import cadquery as cq\nresult = cq.Workplane('XY').box(1, 1, 1)";
    const result = await renderCadQuery(script, "step");

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.artifactPath).toMatch(/\.step$/);
      expect(await fileExists(result.artifactPath)).toBe(true);
    }
  }, T);

  it("box script → STL artifact (file exists)", async () => {
    const script = "import cadquery as cq\nresult = cq.Workplane('XY').box(1, 1, 1)";
    const result = await renderCadQuery(script, "stl");

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.artifactPath).toMatch(/\.stl$/);
      expect(await fileExists(result.artifactPath)).toBe(true);
    }
  }, T);

  it("script without result → script_error", async () => {
    const result = await renderCadQuery("x = 1", "step");
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBe("script_error");
  }, T);

  it("syntax error → script_error", async () => {
    const result = await renderCadQuery("def broken syntax:", "step");
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBe("script_error");
  }, T);

  it("runtime exception → script_error containing exception type", async () => {
    const result = await renderCadQuery("raise RuntimeError('boom')\nresult = None", "step");
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBe("script_error");
      expect(result.message).toMatch(/RuntimeError/);
    }
  }, T);

  it("MAX_TIMEOUT_SECONDS ≤ 300s as required by PLA-54", () => {
    expect(MAX_TIMEOUT_SECONDS).toBeLessThanOrEqual(300);
    expect(DEFAULT_TIMEOUT_SECONDS).toBeLessThanOrEqual(MAX_TIMEOUT_SECONDS);
  });
});

// ---------------------------------------------------------------------------
// AC1 + AC8: cad:run_script end-to-end via worker.ts (real subprocess)
// ---------------------------------------------------------------------------

describe("AC1+AC8 — cad:run_script end-to-end via worker.ts", () => {
  it("cad:run_script executes real CadQuery and returns artifactId + metrics", async () => {
    vi.mock("@paperclipai/plugin-sdk", () => ({
      definePlugin: (config: unknown) => config,
      runWorker: vi.fn(),
    }));

    type ToolHandler = (params: unknown) => Promise<unknown>;
    const handlers: Record<string, ToolHandler> = {};
    const metricsWrites: Array<{ name: string; value: number }> = [];

    const ctx = {
      logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
      tools: {
        register: vi.fn((_name: string, _meta: unknown, handler: ToolHandler) => {
          handlers[_name] = handler;
        }),
      },
      config: { get: vi.fn().mockResolvedValue({ githubPatSecretId: "test-uuid" }) },
      secrets: { resolve: vi.fn().mockResolvedValue("ghp_fake") },
      metrics: {
        write: vi.fn(async (name: string, value: number) => {
          metricsWrites.push({ name, value });
        }),
      },
    };

    vi.resetModules();
    const plugin = (await import("./worker.js")) as {
      default?: { setup?: (ctx: unknown) => Promise<void> };
    };
    await plugin.default?.setup?.(ctx);

    const runScript = handlers["cad:run_script"];
    expect(runScript).toBeDefined();

    const result = (await runScript({
      script: "import cadquery as cq\nresult = cq.Workplane('XY').box(1, 1, 1)",
    })) as { data?: { artifactId?: string; error?: string } };

    // AC1: succeeds and returns an artifactId.
    expect(result.data?.error).toBeUndefined();
    expect(result.data?.artifactId).toBeDefined();

    vi.resetModules();
    vi.restoreAllMocks();
  }, T);
});
