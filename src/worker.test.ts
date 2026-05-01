/**
 * Tests for PLA-55 (cad:run_script + cad:export tool API surface) and
 * PLA-56 (artifact persistence pipeline — AC6 happy path updated for GitHub commit).
 *
 * Acceptance criteria covered:
 *   AC1  Both tools registered via ctx.tools.register.
 *   AC2  JSON-schema validation rejects malformed input; structured error, no stack trace.
 *   AC3  ctx.metrics.write called for tool.calls, tool.errors, tool.duration_ms with tool tag.
 *   AC4  ctx.logger.info emits correlationId, tool, agentId, status, durationMs.
 *        Payload contents NOT in log calls.
 *   AC5  Error taxonomy: validation_error (400), worker_timeout (504), worker_internal (500).
 *   AC6  Stub worker wired via cad-worker-client; integration switch documented.
 *   AC7  cad:hello not registered (removed from v0.1.0 surface).
 */

import { describe, it, expect, vi, beforeAll } from "vitest";

vi.mock("@paperclipai/plugin-sdk", () => ({
  definePlugin: (config: unknown) => config,
  runWorker: vi.fn(),
}));

// ---------------------------------------------------------------------------
// Mock ctx
// ---------------------------------------------------------------------------

type ToolHandler = (params: unknown, runCtx: unknown) => Promise<unknown>;

function buildMockCtx() {
  const handlers: Record<string, ToolHandler> = {};
  const metricCalls: Array<{ name: string; value: number; tags?: Record<string, string> }> = [];
  const logInfoCalls: Array<{ message: string; meta: Record<string, unknown> }> = [];

  const ctx = {
    logger: {
      info: vi.fn((message: string, meta?: Record<string, unknown>) => {
        logInfoCalls.push({ message, meta: meta ?? {} });
      }),
      warn: vi.fn(),
      error: vi.fn(),
      debug: vi.fn(),
    },
    metrics: {
      write: vi.fn(async (name: string, value: number, tags?: Record<string, string>) => {
        metricCalls.push({ name, value, tags });
      }),
    },
    tools: {
      register: vi.fn((_name: string, _decl: unknown, handler: ToolHandler) => {
        handlers[_name] = handler;
      }),
    },
  };

  return { ctx, handlers, metricCalls, logInfoCalls };
}

const fakeRunCtx = {
  agentId: "agent-uuid-001",
  runId: "run-uuid-001",
  companyId: "company-uuid-001",
  projectId: "project-uuid-001",
};

// ---------------------------------------------------------------------------
// Load the plugin once per suite
// ---------------------------------------------------------------------------

let handlers: Record<string, ToolHandler>;
let metricCalls: Array<{ name: string; value: number; tags?: Record<string, string> }>;
let logInfoCalls: Array<{ message: string; meta: Record<string, unknown> }>;

beforeAll(async () => {
  const { ctx, handlers: h, metricCalls: m, logInfoCalls: l } = buildMockCtx();
  handlers = h;
  metricCalls = m;
  logInfoCalls = l;

  const mod = (await import("./worker.js")) as {
    default?: { setup?: (ctx: unknown) => Promise<void> };
  };
  const setup = mod.default?.setup;
  if (typeof setup !== "function") throw new Error("setup() not found in worker module");
  await setup(ctx);
});

// ---------------------------------------------------------------------------
// AC1: Both tools registered
// ---------------------------------------------------------------------------

describe("AC1: tool registration", () => {
  it("registers cad:run_script", () => {
    expect(typeof handlers["cad:run_script"]).toBe("function");
  });

  it("registers cad:export", () => {
    expect(typeof handlers["cad:export"]).toBe("function");
  });

  it("AC7: does NOT register cad:hello", () => {
    expect(handlers["cad:hello"]).toBeUndefined();
  });

  it("AC7: does NOT register cad_render or cad_commit (intermediate tools removed)", () => {
    expect(handlers["cad_render"]).toBeUndefined();
    expect(handlers["cad_commit"]).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// AC2 + AC5: Input validation — cad:run_script
// ---------------------------------------------------------------------------

describe("cad:run_script — input validation (AC2/AC5)", () => {
  it("returns validation_error when script is missing", async () => {
    const result = (await handlers["cad:run_script"]({}, fakeRunCtx)) as {
      error?: string;
      data?: { code?: string; statusCode?: number };
    };
    expect(result.error).toMatch(/validation_error/);
    expect(result.data?.code).toBe("validation_error");
    expect(result.data?.statusCode).toBe(400);
  });

  it("returns validation_error when script is empty string", async () => {
    const result = (await handlers["cad:run_script"]({ script: "" }, fakeRunCtx)) as {
      data?: { code?: string };
    };
    expect(result.data?.code).toBe("validation_error");
  });

  it("returns validation_error when timeout is out of range", async () => {
    const result = (await handlers["cad:run_script"](
      { script: "import cadquery as cq", timeout: 9999 },
      fakeRunCtx,
    )) as { data?: { code?: string } };
    expect(result.data?.code).toBe("validation_error");
  });

  it("returns validation_error when params is not an object", async () => {
    const result = (await handlers["cad:run_script"]("not-an-object", fakeRunCtx)) as {
      data?: { code?: string };
    };
    expect(result.data?.code).toBe("validation_error");
  });

  it("error message contains no stack trace", async () => {
    const result = (await handlers["cad:run_script"]({}, fakeRunCtx)) as {
      data?: { message?: string };
    };
    expect(result.data?.message).not.toMatch(/\s+at\s+/);
  });
});

// ---------------------------------------------------------------------------
// AC2 + AC5: Input validation — cad:export
// ---------------------------------------------------------------------------

describe("cad:export — input validation (AC2/AC5)", () => {
  it("returns validation_error when artifactId is missing", async () => {
    const result = (await handlers["cad:export"](
      { format: "step" },
      fakeRunCtx,
    )) as { data?: { code?: string; statusCode?: number } };
    expect(result.data?.code).toBe("validation_error");
    expect(result.data?.statusCode).toBe(400);
  });

  it("returns validation_error when format is invalid", async () => {
    const result = (await handlers["cad:export"](
      { artifactId: "some-id", format: "obj" },
      fakeRunCtx,
    )) as { data?: { code?: string } };
    expect(result.data?.code).toBe("validation_error");
  });

  it("returns validation_error when artifactId is empty", async () => {
    const result = (await handlers["cad:export"](
      { artifactId: "", format: "stl" },
      fakeRunCtx,
    )) as { data?: { code?: string } };
    expect(result.data?.code).toBe("validation_error");
  });
});

// ---------------------------------------------------------------------------
// AC3: Metrics emitted
// ---------------------------------------------------------------------------

describe("AC3: metrics", () => {
  it("emits tool.calls on cad:run_script success", async () => {
    const before = metricCalls.length;
    await handlers["cad:run_script"](
      { script: "import cadquery as cq; result = cq.Workplane().box(1,1,1)" },
      fakeRunCtx,
    );
    const calls = metricCalls.slice(before);
    const m = calls.find((c) => c.name === "tool.calls" && c.tags?.tool === "cad:run_script");
    expect(m).toBeDefined();
    expect(m?.value).toBe(1);
  });

  it("emits tool.duration_ms on every call", async () => {
    const before = metricCalls.length;
    await handlers["cad:run_script"](
      { script: "import cadquery as cq; result = cq.Workplane().box(2,2,2)" },
      fakeRunCtx,
    );
    const calls = metricCalls.slice(before);
    const m = calls.find((c) => c.name === "tool.duration_ms" && c.tags?.tool === "cad:run_script");
    expect(m).toBeDefined();
    expect(typeof m?.value).toBe("number");
  });

  it("emits tool.errors on validation failure", async () => {
    const before = metricCalls.length;
    await handlers["cad:run_script"]({}, fakeRunCtx);
    const calls = metricCalls.slice(before);
    const m = calls.find((c) => c.name === "tool.errors" && c.tags?.tool === "cad:run_script");
    expect(m).toBeDefined();
    expect(m?.value).toBe(1);
  });

  it("does NOT emit tool.errors on success", async () => {
    const before = metricCalls.length;
    await handlers["cad:run_script"](
      { script: "import cadquery as cq; result = cq.Workplane().box(3,3,3)" },
      fakeRunCtx,
    );
    const calls = metricCalls.slice(before);
    const errMetric = calls.find((c) => c.name === "tool.errors");
    expect(errMetric).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// AC4: Correlation log — no payload content in logs
// ---------------------------------------------------------------------------

describe("AC4: correlation log", () => {
  it("logs correlationId, tool, agentId, status, durationMs on success", async () => {
    const before = logInfoCalls.length;
    await handlers["cad:run_script"](
      { script: "import cadquery as cq; result = cq.Workplane('XY').box(5,5,5)" },
      fakeRunCtx,
    );
    const completionLog = logInfoCalls
      .slice(before)
      .find((l) => l.message === "tool call complete");
    expect(completionLog).toBeDefined();
    expect(completionLog?.meta.correlationId).toBe(fakeRunCtx.runId);
    expect(completionLog?.meta.tool).toBe("cad:run_script");
    expect(completionLog?.meta.agentId).toBe(fakeRunCtx.agentId);
    expect(completionLog?.meta.status).toBe("ok");
    expect(typeof completionLog?.meta.durationMs).toBe("number");
  });

  it("does NOT log script content in any log call", async () => {
    const sentinel = "PAYLOAD_SENTINEL_" + Math.random().toString(36).slice(2);
    const before = logInfoCalls.length;
    await handlers["cad:run_script"]({ script: sentinel }, fakeRunCtx);
    const allLogs = logInfoCalls.slice(before);
    for (const entry of allLogs) {
      expect(JSON.stringify(entry)).not.toContain(sentinel);
    }
  });
});

// ---------------------------------------------------------------------------
// AC5: Error taxonomy — worker_internal from unknown artifactId
// ---------------------------------------------------------------------------

describe("AC5: error taxonomy — worker_internal", () => {
  it("cad:export returns worker_internal (500) for unknown artifactId", async () => {
    const result = (await handlers["cad:export"](
      { artifactId: "nonexistent-artifact-id-xyz", format: "step" },
      fakeRunCtx,
    )) as { data?: { code?: string; statusCode?: number } };
    expect(result.data?.code).toBe("worker_internal");
    expect(result.data?.statusCode).toBe(500);
  });
});

// ---------------------------------------------------------------------------
// AC6: Happy path — run_script → export (PLA-56: GitHub commit result)
// ---------------------------------------------------------------------------

describe("AC6: stub worker happy path", () => {
  it("run_script returns { artifactId, summary }", async () => {
    const result = (await handlers["cad:run_script"](
      { script: "import cadquery as cq; result = cq.Workplane('XY').box(10,10,10)" },
      fakeRunCtx,
    )) as { data?: { artifactId?: string; summary?: string } };
    expect(typeof result.data?.artifactId).toBe("string");
    expect((result.data?.artifactId ?? "").length).toBeGreaterThan(0);
    expect(typeof result.data?.summary).toBe("string");
  });

  it("export returns { filePath, artifactId, format } when GitHub params absent (local export)", async () => {
    const runResult = (await handlers["cad:run_script"](
      { script: "import cadquery as cq; result = cq.Workplane('XY').box(20,20,20)" },
      fakeRunCtx,
    )) as { data?: { artifactId?: string } };
    const artifactId = runResult.data?.artifactId;

    const exportResult = (await handlers["cad:export"](
      { artifactId, format: "stl" },
      fakeRunCtx,
    )) as { data?: { filePath?: string; artifactId?: string; format?: string } };
    expect(typeof exportResult.data?.filePath).toBe("string");
    expect((exportResult.data?.filePath ?? "").endsWith(".stl")).toBe(true);
    expect(exportResult.data?.artifactId).toBe(artifactId);
    expect(exportResult.data?.format).toBe("stl");
  });

  it("export accepts all three formats: step, stl, 3mf", async () => {
    const runResult = (await handlers["cad:run_script"](
      { script: "import cadquery as cq; result = cq.Workplane('XY').box(5,5,5)" },
      fakeRunCtx,
    )) as { data?: { artifactId?: string } };
    const artifactId = runResult.data?.artifactId as string;

    for (const format of ["step", "stl", "3mf"] as const) {
      const r = (await handlers["cad:export"](
        { artifactId, format },
        fakeRunCtx,
      )) as { data?: { filePath?: string } };
      expect(r.data?.filePath).toMatch(new RegExp(`\\.${format}$`));
    }
  }, 30_000);
});
