/**
 * Tests for PLA-56: cad:export GitHub artifact persistence pipeline.
 *
 * Flow: cad:run_script → cad:export (commit to GitHub).
 *
 * Acceptance criteria covered:
 *   AC1  Prerequisite check: 404/403 on repo → prerequisite_missing.
 *   AC2  Successful render + single commit+push.
 *   AC3  PAT not present in returned data.
 *   AC4  Idempotency: existing artifact path → return existing commit info, no re-push.
 *   AC5  Commit message contains paperclipTicketId and toolCallId.
 *   AC6  Uses config.artifactRepoUrl when set.
 *   AC8  Result includes commitSha, permalink, artifactPath; no PAT.
 *
 * Error path tests:
 *   auth error (403 on PUT) → { error: "auth" }
 *   network error (503 on PUT) → { error: "network" }
 *   conflict (409) + retry success
 *   conflict (409) + retry fail → { error: "conflict" }
 */

import { describe, it, expect, vi, beforeAll, afterAll } from "vitest";

vi.mock("@paperclipai/plugin-sdk", () => ({
  definePlugin: (config: unknown) => config,
  runWorker: vi.fn(),
}));

type ToolHandler = (params: unknown, runCtx?: unknown) => Promise<unknown>;

// PLA-80 (F6): default tenant identity used by every test that doesn't
// intentionally exercise cross-tenant isolation. Real `ToolRunContext` shape
// (companyId, agentId, runId, projectId) — see plugin-sdk types.ts.
const DEFAULT_RUN_CTX = {
  companyId: "company-A",
  agentId: "agent-A",
  runId: "run-A",
  projectId: "project-A",
};

function buildMockCtx(
  pat = "ghp_fake_token_pla56",
  config: Record<string, unknown> = { githubPatSecretId: "secret-uuid-pla56" },
) {
  const handlers: Record<string, ToolHandler> = {};
  const ctx = {
    logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
    metrics: { write: vi.fn(async () => {}) },
    tools: {
      register: vi.fn((_name: string, _meta: unknown, handler: ToolHandler) => {
        handlers[_name] = handler;
      }),
    },
    config: { get: vi.fn().mockResolvedValue(config) },
    secrets: { resolve: vi.fn().mockResolvedValue(pat) },
  };
  return { ctx, handlers };
}

let cadRunScript: ToolHandler;
let cadExport: ToolHandler;

beforeAll(async () => {
  const { ctx, handlers } = buildMockCtx();
  vi.stubGlobal("fetch", vi.fn());
  vi.resetModules();

  const plugin = (await import("./worker.js")) as {
    default?: { setup?: (ctx: unknown) => Promise<void> };
  };
  await plugin.default?.setup?.(ctx);

  cadRunScript = handlers["cad:run_script"];
  cadExport = handlers["cad:export"];
  if (typeof cadRunScript !== "function") throw new Error("cad:run_script not registered");
  if (typeof cadExport !== "function") throw new Error("cad:export not registered");
});

afterAll(() => {
  vi.unstubAllGlobals();
  vi.resetModules();
});

const BOX_SCRIPT = "import cadquery as cq\nresult = cq.Workplane('XY').box(1, 1, 1)";

// Helper: stage an artifact via cad:run_script.
async function stageArtifact(
  script = BOX_SCRIPT,
  runCtx: Record<string, string> = DEFAULT_RUN_CTX,
): Promise<string> {
  const r = (await cadRunScript({ script }, runCtx)) as { data?: { artifactId?: string } };
  const id = r.data?.artifactId;
  if (!id) throw new Error("cad:run_script did not return artifactId");
  return id;
}

// Helper: invoke cad:export with a tenant-scoped runCtx.
async function exportArtifact(
  params: Record<string, unknown>,
  runCtx: Record<string, string> = DEFAULT_RUN_CTX,
): Promise<unknown> {
  return cadExport(params, runCtx);
}

// Mock helpers for the GitHub call sequence in cad:export:
//   1. GET /repos/{owner}/{repo}         — prereq check
//   2. GET /repos/{owner}/{repo}/contents/{path}  — idempotency check
//   3. GET /repos/{owner}/{repo}/contents/{path}  — push: existing sha check
//   4. PUT /repos/{owner}/{repo}/contents/{path}  — push: commit

const ok200 = (json: unknown = {}) => ({ ok: true, status: 200, json: async () => json, text: async () => "" } as Response);
const notFound = () => ({ ok: false, status: 404, json: async () => ({}), text: async () => "not found" } as Response);
const putOk = (sha = "abc123commit") => ({
  ok: true, status: 201,
  json: async () => ({ commit: { sha } }),
  text: async () => "",
} as Response);

const BASE_PARAMS = {
  paperclipTicketId: "PLA-56",
  toolCallId: "call-001",
  format: "step" as const,
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("cad:export PLA-56 pipeline", () => {
  it("AC1: prereq check — 404 → prerequisite_missing", async () => {
    const artifactId = await stageArtifact();
    const fetchMock = vi.mocked(globalThis.fetch);
    fetchMock.mockReset();
    fetchMock.mockResolvedValueOnce({ ok: false, status: 404, json: async () => ({}), text: async () => "" } as Response);

    const result = (await exportArtifact({ ...BASE_PARAMS, artifactId })) as { data?: { error?: string; message?: string } };
    expect(result.data?.error).toBe("prerequisite_missing");
    expect(result.data?.message).toMatch(/404/);
    expect(result.data?.message).toMatch(/operator/i);
  });

  it("AC1: prereq check — 403 → prerequisite_missing", async () => {
    const artifactId = await stageArtifact();
    const fetchMock = vi.mocked(globalThis.fetch);
    fetchMock.mockReset();
    fetchMock.mockResolvedValueOnce({ ok: false, status: 403, json: async () => ({}), text: async () => "" } as Response);

    const result = (await exportArtifact({ ...BASE_PARAMS, artifactId })) as { data?: { error?: string } };
    expect(result.data?.error).toBe("prerequisite_missing");
  });

  it("AC4: idempotency — artifact already exists → returns existing commitSha, no re-push", async () => {
    const artifactId = await stageArtifact();
    const fetchMock = vi.mocked(globalThis.fetch);
    fetchMock.mockReset();

    fetchMock.mockResolvedValueOnce(ok200({ name: "cad-artifacts" }));          // 1. prereq
    fetchMock.mockResolvedValueOnce(ok200({ sha: "blobsha123", html_url: "https://github.com/o/r/blob/main/path" })); // 2. idempotency → exists
    fetchMock.mockResolvedValueOnce(ok200([{ sha: "commitsha456" }]));           // 3. commits?path=...

    const result = (await exportArtifact({ ...BASE_PARAMS, artifactId })) as {
      data?: { commitSha?: string; permalink?: string; artifactPath?: string; error?: string };
    };
    expect(result.data?.error).toBeUndefined();
    expect(result.data?.commitSha).toBe("commitsha456");
    expect(result.data?.permalink).toContain("commitsha456");
    expect(result.data?.artifactPath).toBe("artifacts/PLA-56/call-001/artifact.step");

    const putCalls = fetchMock.mock.calls.filter((c) => (c[1] as RequestInit | undefined)?.method === "PUT");
    expect(putCalls).toHaveLength(0);
  });

  it("AC2+AC5+AC8: successful render+commit returns commitSha, permalink, artifactPath", async () => {
    const artifactId = await stageArtifact();
    const fetchMock = vi.mocked(globalThis.fetch);
    fetchMock.mockReset();

    fetchMock.mockResolvedValueOnce(ok200());    // 1. prereq
    fetchMock.mockResolvedValueOnce(notFound()); // 2. idempotency → not found
    fetchMock.mockResolvedValueOnce(notFound()); // 3. push GET → 404 (new file)
    fetchMock.mockResolvedValueOnce(putOk("deadbeef1234")); // 4. PUT

    const result = (await exportArtifact({ ...BASE_PARAMS, artifactId })) as {
      data?: { commitSha?: string; permalink?: string; artifactPath?: string; error?: string };
    };
    expect(result.data?.error).toBeUndefined();
    expect(result.data?.commitSha).toBe("deadbeef1234");
    expect(result.data?.permalink).toContain("deadbeef1234");
    expect(result.data?.permalink).toContain("artifacts/PLA-56/call-001/artifact.step");
    expect(result.data?.artifactPath).toBe("artifacts/PLA-56/call-001/artifact.step");
  });

  it("AC3: PAT not present in returned data", async () => {
    const artifactId = await stageArtifact();
    const fetchMock = vi.mocked(globalThis.fetch);
    fetchMock.mockReset();
    fetchMock.mockResolvedValueOnce(ok200());
    fetchMock.mockResolvedValueOnce(notFound());
    fetchMock.mockResolvedValueOnce(notFound());
    fetchMock.mockResolvedValueOnce(putOk("sha9999"));

    const result = await exportArtifact({ ...BASE_PARAMS, artifactId });
    expect(JSON.stringify(result)).not.toContain("ghp_fake_token_pla56");
  });

  it("AC5: commit message format: ticket=... tool=cad:export call=...", async () => {
    const artifactId = await stageArtifact();
    const fetchMock = vi.mocked(globalThis.fetch);
    fetchMock.mockReset();
    fetchMock.mockResolvedValueOnce(ok200());
    fetchMock.mockResolvedValueOnce(notFound());
    fetchMock.mockResolvedValueOnce(notFound());
    fetchMock.mockResolvedValueOnce(putOk("sha-msg-test"));

    await exportArtifact({ artifactId, format: "step", paperclipTicketId: "PLA-999", toolCallId: "tc-abc123" });

    const putCall = fetchMock.mock.calls.find((c) => (c[1] as RequestInit | undefined)?.method === "PUT");
    const body = JSON.parse((putCall![1] as RequestInit).body as string) as { message?: string };
    expect(body.message).toBe("CAD artifact: ticket=PLA-999 tool=cad:export call=tc-abc123");
    expect(body.message).not.toContain("ghp_");
  });

  it("AC8: result has exactly commitSha, permalink, artifactPath", async () => {
    const artifactId = await stageArtifact();
    const fetchMock = vi.mocked(globalThis.fetch);
    fetchMock.mockReset();
    fetchMock.mockResolvedValueOnce(ok200());
    fetchMock.mockResolvedValueOnce(notFound());
    fetchMock.mockResolvedValueOnce(notFound());
    fetchMock.mockResolvedValueOnce(putOk("final-sha"));

    const result = (await exportArtifact({ ...BASE_PARAMS, artifactId })) as { data?: Record<string, unknown> };
    expect(Object.keys(result.data!).sort()).toEqual(["artifactPath", "commitSha", "permalink"]);
  });

  it("auth error (403 on PUT) → returns { error: 'auth' }", async () => {
    const artifactId = await stageArtifact();
    const fetchMock = vi.mocked(globalThis.fetch);
    fetchMock.mockReset();
    fetchMock.mockResolvedValueOnce(ok200());
    fetchMock.mockResolvedValueOnce(notFound());
    fetchMock.mockResolvedValueOnce(notFound());
    fetchMock.mockResolvedValueOnce({ ok: false, status: 403, json: async () => ({}), text: async () => "" } as Response);

    const result = (await exportArtifact({ ...BASE_PARAMS, artifactId })) as { data?: { error?: string } };
    expect(result.data?.error).toBe("auth");
  });

  it("network error (503 on PUT) → returns { error: 'network' }", async () => {
    const artifactId = await stageArtifact();
    const fetchMock = vi.mocked(globalThis.fetch);
    fetchMock.mockReset();
    fetchMock.mockResolvedValueOnce(ok200());
    fetchMock.mockResolvedValueOnce(notFound());
    fetchMock.mockResolvedValueOnce(notFound());
    fetchMock.mockResolvedValueOnce({ ok: false, status: 503, json: async () => ({}), text: async () => "unavailable" } as Response);

    const result = (await exportArtifact({ ...BASE_PARAMS, artifactId })) as { data?: { error?: string } };
    expect(result.data?.error).toBe("network");
  });

  it("conflict (409) → retries once and succeeds", { timeout: 15000 }, async () => {
    const artifactId = await stageArtifact();
    const fetchMock = vi.mocked(globalThis.fetch);
    fetchMock.mockReset();

    fetchMock.mockResolvedValueOnce(ok200());     // prereq
    fetchMock.mockResolvedValueOnce(notFound());  // idempotency
    fetchMock.mockResolvedValueOnce(notFound());  // push attempt 1: GET
    fetchMock.mockResolvedValueOnce({ ok: false, status: 409, json: async () => ({}), text: async () => "conflict" } as Response); // PUT → 409
    fetchMock.mockResolvedValueOnce(ok200({ sha: "existingsha" })); // push attempt 2: GET → sha
    fetchMock.mockResolvedValueOnce(putOk("retrysha789")); // PUT → success

    const result = (await exportArtifact({ ...BASE_PARAMS, artifactId })) as { data?: { commitSha?: string; error?: string } };
    expect(result.data?.error).toBeUndefined();
    expect(result.data?.commitSha).toBe("retrysha789");
  });

  it("conflict (409) → retries once, fails again → { error: 'conflict' }", { timeout: 15000 }, async () => {
    const artifactId = await stageArtifact();
    const fetchMock = vi.mocked(globalThis.fetch);
    fetchMock.mockReset();

    fetchMock.mockResolvedValueOnce(ok200());
    fetchMock.mockResolvedValueOnce(notFound());
    fetchMock.mockResolvedValueOnce(notFound());
    fetchMock.mockResolvedValueOnce({ ok: false, status: 409, json: async () => ({}), text: async () => "conflict" } as Response);
    fetchMock.mockResolvedValueOnce(notFound());
    fetchMock.mockResolvedValueOnce({ ok: false, status: 409, json: async () => ({}), text: async () => "conflict" } as Response);

    const result = (await exportArtifact({ ...BASE_PARAMS, artifactId })) as { data?: { error?: string } };
    expect(result.data?.error).toBe("conflict");
  });

  it("AC6: uses config.artifactRepoUrl when set", async () => {
    vi.resetModules();
    const { ctx: customCtx, handlers } = buildMockCtx("ghp_custom", {
      githubPatSecretId: "secret-custom",
      artifactRepoUrl: "https://github.com/my-org/my-artifacts.git",
    });
    vi.stubGlobal("fetch", vi.fn());
    const plugin2 = (await import("./worker.js")) as { default?: { setup?: (ctx: unknown) => Promise<void> } };
    await plugin2.default?.setup?.(customCtx);

    const runResult = (await handlers["cad:run_script"]({ script: "x=1" }, DEFAULT_RUN_CTX)) as { data?: { artifactId?: string } };
    const artifactId = runResult.data?.artifactId!;

    const fetchMock = vi.mocked(globalThis.fetch);
    fetchMock.mockReset();
    fetchMock.mockResolvedValueOnce(ok200());
    fetchMock.mockResolvedValueOnce(notFound());
    fetchMock.mockResolvedValueOnce(notFound());
    fetchMock.mockResolvedValueOnce(putOk("sha-custom"));

    await handlers["cad:export"]({ ...BASE_PARAMS, artifactId }, DEFAULT_RUN_CTX);

    const allUrls = fetchMock.mock.calls.map((c) =>
      typeof c[0] === "string" ? c[0] : (c[0] as Request).url,
    );
    expect(allUrls.every((u) => u.includes("my-org/my-artifacts"))).toBe(true);

    vi.resetModules();
  });

  it("deterministic path: artifacts/{ticketId}/{callId}/{filename}", { timeout: 15000 }, async () => {
    const artifactId = await stageArtifact();
    const fetchMock = vi.mocked(globalThis.fetch);
    fetchMock.mockReset();
    fetchMock.mockResolvedValueOnce(ok200());
    fetchMock.mockResolvedValueOnce(notFound());
    fetchMock.mockResolvedValueOnce(notFound());
    fetchMock.mockResolvedValueOnce(putOk("pathtest-sha"));

    const result = (await exportArtifact({
      artifactId, format: "stl" as const,
      paperclipTicketId: "PLA-42", toolCallId: "tc-xyz", filename: "part.stl",
    })) as { data?: { artifactPath?: string } };
    expect(result.data?.artifactPath).toBe("artifacts/PLA-42/tc-xyz/part.stl");

    const putCall = fetchMock.mock.calls.find((c) => (c[1] as RequestInit | undefined)?.method === "PUT");
    expect(typeof putCall![0] === "string" ? putCall![0] : "").toContain("artifacts/PLA-42/tc-xyz/part.stl");
  });

  // -------------------------------------------------------------------------
  // PLA-80 (F6): tenant-scoped staging map regression tests.
  //
  // The CAD plugin worker process is shared across all agents and companies on
  // a host. The staging map must be keyed by (companyId, agentId, artifactId)
  // sourced from the runCtx so a leaked artifactId is not enough to read back
  // another tenant's staged artifact.
  // -------------------------------------------------------------------------

  it("F6: agent A stages and reads back its own artifact (sanity)", async () => {
    const ctxA = { companyId: "co-A", agentId: "agent-A", runId: "r-1", projectId: "p-A" };
    const artifactId = await stageArtifact(BOX_SCRIPT, ctxA);

    const fetchMock = vi.mocked(globalThis.fetch);
    fetchMock.mockReset();
    // Local-file path (no GitHub params) — tests the staging-map lookup only.
    const result = (await exportArtifact({ artifactId, format: "step" as const }, ctxA)) as {
      data?: { filePath?: string; error?: string; code?: string };
    };
    expect(result.data?.error).toBeUndefined();
    expect(result.data?.code).toBeUndefined();
    expect(result.data?.filePath).toBeDefined();
  });

  it("F6: agent B (same companyId, different agentId) cannot read agent A's artifact", async () => {
    const ctxA = { companyId: "co-shared", agentId: "agent-A", runId: "r-A", projectId: "p" };
    const ctxB = { companyId: "co-shared", agentId: "agent-B", runId: "r-B", projectId: "p" };
    const artifactId = await stageArtifact(BOX_SCRIPT, ctxA);

    const fetchMock = vi.mocked(globalThis.fetch);
    fetchMock.mockReset();
    const result = (await exportArtifact({ artifactId, format: "step" as const }, ctxB)) as {
      data?: { code?: string; statusCode?: number; message?: string };
    };
    // Same response shape as a genuinely missing artifactId — no oracle.
    expect(result.data?.code).toBe("worker_internal");
    expect(result.data?.statusCode).toBe(500);
    expect(result.data?.message).toMatch(/No staged artifact/);
    // No GitHub calls should have been issued — the lookup short-circuits.
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("F6: agent in different companyId cannot read agent A's artifact", async () => {
    const ctxA = { companyId: "co-X", agentId: "agent-X", runId: "r-X", projectId: "p" };
    const ctxOtherCo = { companyId: "co-Y", agentId: "agent-X", runId: "r-Y", projectId: "p" };
    const artifactId = await stageArtifact(BOX_SCRIPT, ctxA);

    const fetchMock = vi.mocked(globalThis.fetch);
    fetchMock.mockReset();
    const result = (await exportArtifact({ artifactId, format: "step" as const }, ctxOtherCo)) as {
      data?: { code?: string; statusCode?: number; message?: string };
    };
    expect(result.data?.code).toBe("worker_internal");
    expect(result.data?.statusCode).toBe(500);
    expect(result.data?.message).toMatch(/No staged artifact/);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("F6: cad:run_script rejects when runCtx is missing tenant context", async () => {
    const result = (await cadRunScript({ script: BOX_SCRIPT }, {})) as {
      error?: string;
      data?: { code?: string };
    };
    expect(result.error).toBe("validation_error");
    expect(result.data?.code).toBe("validation_error");
  });

  it("F6: cad:export with missing tenant runCtx is treated as not-found (no oracle)", async () => {
    // First, stage as agent A.
    const ctxA = { companyId: "co-A", agentId: "agent-A", runId: "r-A", projectId: "p" };
    const artifactId = await stageArtifact(BOX_SCRIPT, ctxA);

    const fetchMock = vi.mocked(globalThis.fetch);
    fetchMock.mockReset();
    // Now call cad:export with empty runCtx — must look exactly like missing.
    const result = (await cadExport({ artifactId, format: "step" as const }, {})) as {
      data?: { code?: string; statusCode?: number; message?: string };
    };
    expect(result.data?.code).toBe("worker_internal");
    expect(result.data?.statusCode).toBe(500);
    expect(result.data?.message).toMatch(/No staged artifact/);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
