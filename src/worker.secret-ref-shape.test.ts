/**
 * Integration-ish tests: a string-typed AND an object-typed secret-ref config
 * value both drive a resolve through the normalize wrapper, with the SAME
 * canonical binding reaching ctx.secrets.resolve (no double-wrap of an
 * object-shaped stored value, no legacy raw string reaching the host's
 * object-ref-only resolve path).
 *
 * Mirrors the intake-PAT separation-of-duties harness: the sandbox is never
 * touched — the mocked GitHub fetch 404s after the resolve, proving WHICH
 * argument the handler passed.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

vi.mock("@paperclipai/plugin-sdk", () => ({
  definePlugin: (config: unknown) => config,
  runWorker: vi.fn(),
}));

type ToolHandler = (params: unknown, runCtx?: unknown) => Promise<unknown>;

const DEFAULT_RUN_CTX = { companyId: "company-A", agentId: "agent-A", runId: "run-A", projectId: "project-A" };
const EXPORT_PAT_UUID = "679b5cb9-079e-45a2-9423-c1720172131a";
const INTAKE_PAT_UUID = "0f0e8d8c-7b6a-4988-8776-655443322211";
const CANONICAL_EXPORT = { type: "secret_ref", secretId: EXPORT_PAT_UUID, version: "latest" };
const CANONICAL_INTAKE = { type: "secret_ref", secretId: INTAKE_PAT_UUID, version: "latest" };

function buildMockCtx(config: Record<string, unknown>) {
  const handlers: Record<string, ToolHandler> = {};
  const resolve = vi.fn(async (_binding: unknown) => "ghp_fake");
  const ctx = {
    logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
    metrics: { write: vi.fn(async () => {}) },
    tools: {
      register: vi.fn((_name: string, _meta: unknown, handler: ToolHandler) => {
        handlers[_name] = handler;
      }),
    },
    config: { get: vi.fn().mockResolvedValue(config) },
    secrets: { resolve },
  };
  return { ctx, handlers, resolve };
}

async function bootWorker(config: Record<string, unknown>) {
  vi.resetModules();
  const { ctx, handlers, resolve } = buildMockCtx(config);
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => ({ ok: false, status: 404, headers: { get: () => null }, arrayBuffer: async () => new ArrayBuffer(0) }) as unknown as Response),
  );
  const plugin = (await import("./worker.js")) as { default?: { setup?: (ctx: unknown) => Promise<void> } };
  await plugin.default?.setup?.(ctx);
  return { handlers, resolve };
}

const BOX_SCRIPT = "import cadquery as cq\nresult = cq.Workplane('XY').box(1, 1, 1)";

/**
 * Stage an artifact, then drive cad.export up to the resolve seam: the
 * resolve happens BEFORE the GitHub prereq fetch, which the global fetch
 * mock 404s — the handler returns prerequisite_missing right after the
 * resolve argument was recorded.
 */
async function runExport(handlers: Record<string, ToolHandler>) {
  const runScript = handlers["cad.run_script"];
  expect(runScript).toBeDefined();
  const staged = (await runScript({ script: BOX_SCRIPT }, DEFAULT_RUN_CTX)) as {
    data?: { artifactId?: string };
  };
  const artifactId = staged.data?.artifactId;
  if (!artifactId) throw new Error("cad.run_script did not return artifactId");
  const exportTool = handlers["cad.export"];
  expect(exportTool).toBeDefined();
  return exportTool(
    { artifactId, paperclipTicketId: "TEST-56", toolCallId: "call-shape-1", format: "step" as const },
    DEFAULT_RUN_CTX,
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.resetModules();
});

describe("secret-ref config shape → resolve seam", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });

  it("legacy string config resolves through the canonical binding (export path)", async () => {
    const { handlers, resolve } = await bootWorker({ githubPatSecretId: EXPORT_PAT_UUID });
    await runExport(handlers);
    expect(resolve).toHaveBeenCalledTimes(1);
    expect(resolve).toHaveBeenCalledWith(CANONICAL_EXPORT);
  });

  it("object config resolves WITHOUT double-wrap (export path)", async () => {
    const { handlers, resolve } = await bootWorker({
      githubPatSecretId: { type: "secret_ref", secretId: EXPORT_PAT_UUID, version: "latest" },
    });
    await runExport(handlers);
    expect(resolve).toHaveBeenCalledTimes(1);
    expect(resolve).toHaveBeenCalledWith(CANONICAL_EXPORT);
  });

  it("legacy string config resolves through the canonical binding (intake path)", async () => {
    const { handlers, resolve } = await bootWorker({ githubPatSecretId: EXPORT_PAT_UUID });
    const runScript = handlers["cad.run_script"];
    await runScript(
      { script: "pass", inputArtifacts: [{ repoPath: "user-uploads/scan.stl" }] },
      DEFAULT_RUN_CTX,
    );
    expect(resolve).toHaveBeenCalledTimes(1);
    expect(resolve).toHaveBeenCalledWith(CANONICAL_EXPORT);
  });

  it("object config on the dedicated intake PAT resolves with its own binding (no cross-field wrap)", async () => {
    const { handlers, resolve } = await bootWorker({
      githubPatSecretId: EXPORT_PAT_UUID,
      intakePatSecretId: { type: "secret_ref", secretId: INTAKE_PAT_UUID },
    });
    const runScript = handlers["cad.run_script"];
    await runScript(
      { script: "pass", inputArtifacts: [{ repoPath: "user-uploads/scan.stl" }] },
      DEFAULT_RUN_CTX,
    );
    expect(resolve).toHaveBeenCalledTimes(1);
    // object passthrough carries exactly what was stored: no version key on
    // the input → no version key on the binding (host defaults to latest).
    expect(resolve).toHaveBeenCalledWith({ type: "secret_ref", secretId: INTAKE_PAT_UUID });
  });

  it("both fields as objects stay distinct — export uses githubPatSecretId, intake uses intakePatSecretId", async () => {
    const { handlers, resolve } = await bootWorker({
      githubPatSecretId: { type: "secret_ref", secretId: EXPORT_PAT_UUID, version: "latest" },
      intakePatSecretId: { type: "secret_ref", secretId: INTAKE_PAT_UUID, version: "latest" },
    });
    // intake resolve happens first (run_script with inputArtifacts)…
    const runScript = handlers["cad.run_script"];
    await runScript(
      { script: "pass", inputArtifacts: [{ repoPath: "user-uploads/scan.stl" }] },
      DEFAULT_RUN_CTX,
    );
    expect(resolve).toHaveBeenNthCalledWith(1, CANONICAL_INTAKE);
    // …then the export resolve on the same binding values.
    await runExport(handlers);
    expect(resolve).toHaveBeenNthCalledWith(2, CANONICAL_EXPORT);
  });

  it("a malformed string value fails opaquely at the seam (never reaches the host)", async () => {
    const { handlers, resolve } = await bootWorker({ githubPatSecretId: "not-a-valid-secret" });
    await expect(runExport(handlers)).rejects.toThrowError(/invalid secret ref/);
    expect(resolve).not.toHaveBeenCalled();
  });
});
