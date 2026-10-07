/**
 * 1094 — optional read-only intake PAT (separation of duties).
 *
 * Verifies the secret-resolution seam without touching the bwrap/seccomp
 * sandbox: the intake-fetch resolves its PAT BEFORE the GitHub fetch, so a
 * fast 404 short-circuits the render while still proving WHICH secret id the
 * handler resolved.
 *
 * Acceptance criteria 3, 4, 6:
 *   - intake resolves `intakePatSecretId` when set;
 *   - intake falls back to `githubPatSecretId` when intakePatSecretId is unset
 *     (byte-identical back-compat);
 *   - export ALWAYS resolves `githubPatSecretId`, even when intakePatSecretId
 *     is set.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

vi.mock("@paperclipai/plugin-sdk", () => ({
  definePlugin: (config: unknown) => config,
  runWorker: vi.fn(),
}));

type ToolHandler = (params: unknown, runCtx?: unknown) => Promise<unknown>;

const DEFAULT_RUN_CTX = { companyId: "company-A", agentId: "agent-A", runId: "run-A", projectId: "project-A" };
const BOX_SCRIPT = "import cadquery as cq\nresult = cq.Workplane('XY').box(1, 1, 1)";

function buildMockCtx(config: Record<string, unknown>) {
  const handlers: Record<string, ToolHandler> = {};
  const resolve = vi.fn(async (_binding: unknown) => "pat-fake");
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

/** Boot a fresh worker against a given instance config; returns the handlers + resolve spy. */
async function bootWorker(config: Record<string, unknown>) {
  vi.resetModules();
  const { ctx, handlers, resolve } = buildMockCtx(config);
  vi.stubGlobal("fetch", vi.fn());
  const plugin = (await import("./worker.js")) as { default?: { setup?: (ctx: unknown) => Promise<void> } };
  await plugin.default?.setup?.(ctx);
  return { handlers, resolve };
}

// Intake GitHub raw fetch → 404. fetchInputArtifacts throws not_found AFTER the
// PAT has already been resolved, so the sandbox render never runs.
function mockIntake404() {
  const fetchMock = vi.mocked(globalThis.fetch);
  fetchMock.mockReset();
  fetchMock.mockResolvedValueOnce({
    ok: false,
    status: 404,
    headers: { get: () => null },
    arrayBuffer: async () => new ArrayBuffer(0),
  } as unknown as Response);
  return fetchMock;
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.resetModules();
});

describe("TEST-1094 intake PAT separation of duties", () => {
  it("AC3: intake resolves intakePatSecretId when it is set", async () => {
    const { handlers, resolve } = await bootWorker({
      githubPatSecretId: "679b5cb9-079e-45a2-9423-c1720172131a",
      intakePatSecretId: "0f0e8d8c-7b6a-4988-8776-655443322211",
    });
    mockIntake404();

    await handlers["cad.run_script"](
      { script: BOX_SCRIPT, inputArtifacts: [{ repoPath: "user-uploads/scan.stl" }] },
      DEFAULT_RUN_CTX,
    );

    expect(resolve).toHaveBeenCalledTimes(1);
    expect(resolve).toHaveBeenCalledWith({ type: "secret_ref", secretId: "0f0e8d8c-7b6a-4988-8776-655443322211", version: "latest" });
    expect(resolve).not.toHaveBeenCalledWith({ type: "secret_ref", secretId: "679b5cb9-079e-45a2-9423-c1720172131a", version: "latest" });
  });

  it("AC4: intake falls back to githubPatSecretId when intakePatSecretId is unset (back-compat)", async () => {
    const { handlers, resolve } = await bootWorker({ githubPatSecretId: "679b5cb9-079e-45a2-9423-c1720172131a" });
    mockIntake404();

    await handlers["cad.run_script"](
      { script: BOX_SCRIPT, inputArtifacts: [{ repoPath: "user-uploads/scan.stl" }] },
      DEFAULT_RUN_CTX,
    );

    expect(resolve).toHaveBeenCalledTimes(1);
    expect(resolve).toHaveBeenCalledWith({ type: "secret_ref", secretId: "679b5cb9-079e-45a2-9423-c1720172131a", version: "latest" });
  });

  it("AC6: export always resolves githubPatSecretId, even when intakePatSecretId is set", async () => {
    const { handlers, resolve } = await bootWorker({
      githubPatSecretId: "679b5cb9-079e-45a2-9423-c1720172131a",
      intakePatSecretId: "0f0e8d8c-7b6a-4988-8776-655443322211",
    });

    // Stage a real artifact (no inputArtifacts → no intake resolve).
    const staged = (await handlers["cad.run_script"]({ script: BOX_SCRIPT }, DEFAULT_RUN_CTX)) as {
      data?: { artifactId?: string };
    };
    const artifactId = staged.data?.artifactId;
    expect(artifactId, JSON.stringify(staged)).toBeTruthy();
    expect(resolve).not.toHaveBeenCalled();

    // Export prereq → 404 short-circuits AFTER the export PAT is resolved.
    const fetchMock = vi.mocked(globalThis.fetch);
    fetchMock.mockReset();
    fetchMock.mockResolvedValueOnce({ ok: false, status: 404, json: async () => ({}), text: async () => "" } as Response);

    await handlers["cad.export"](
      { artifactId, format: "step" as const, paperclipTicketId: "TEST-1094", toolCallId: "call-1" },
      DEFAULT_RUN_CTX,
    );

    expect(resolve).toHaveBeenCalledTimes(1);
    expect(resolve).toHaveBeenCalledWith({ type: "secret_ref", secretId: "679b5cb9-079e-45a2-9423-c1720172131a", version: "latest" });
    expect(resolve).not.toHaveBeenCalledWith({ type: "secret_ref", secretId: "0f0e8d8c-7b6a-4988-8776-655443322211", version: "latest" });
  }, 60_000);
});
