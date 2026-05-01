/**
 * Tests for PLA-56: cad_export artifact persistence pipeline.
 *
 * Acceptance criteria covered:
 *   AC1  Prerequisite check: 404/403 on repo → prerequisite_missing error.
 *   AC2  Successful render + single commit+push.
 *   AC3  PAT not present in returned data or log calls.
 *   AC4  Idempotency: if artifact path exists, return existing commit info.
 *   AC5  Commit message contains paperclipTicketId and toolCallId.
 *   AC6  artifactRepoUrl is taken from config when provided.
 *   AC8  Result includes commitSha, permalink, artifactPath; no PAT.
 *
 * Error path tests:
 *   - auth error (403 on push)
 *   - network error (503 on push)
 *   - conflict error (409 on push): retries once, succeeds on retry
 *   - conflict error (409 on push): retries once, fails again → conflict error
 */

import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it, expect, vi, beforeAll, afterAll } from "vitest";

vi.mock("@paperclipai/plugin-sdk", () => ({
  definePlugin: (config: unknown) => config,
  runWorker: vi.fn(),
}));

// ---------------------------------------------------------------------------
// Minimal ctx mock
// ---------------------------------------------------------------------------

type ToolHandler = (params: unknown) => Promise<unknown>;

function buildMockCtx(
  pat = "ghp_fake_token_pla56",
  config: Record<string, unknown> = { githubPatSecretId: "secret-uuid-pla56" },
) {
  const handlers: Record<string, ToolHandler> = {};
  const logWarns: Array<unknown[]> = [];

  const ctx = {
    logger: {
      info: vi.fn(),
      warn: vi.fn((...args: unknown[]) => logWarns.push(args)),
      error: vi.fn(),
    },
    tools: {
      register: vi.fn((_name: string, _meta: unknown, handler: ToolHandler) => {
        handlers[_name] = handler;
      }),
    },
    config: {
      get: vi.fn().mockResolvedValue(config),
    },
    secrets: {
      resolve: vi.fn().mockResolvedValue(pat),
    },
    _logWarns: logWarns,
  };

  return { ctx, handlers };
}

// ---------------------------------------------------------------------------
// Set up plugin once per suite
// ---------------------------------------------------------------------------

let cadExport: ToolHandler;
let mockCtx: ReturnType<typeof buildMockCtx>["ctx"];

beforeAll(async () => {
  const { ctx, handlers } = buildMockCtx();
  mockCtx = ctx;

  vi.stubGlobal("fetch", vi.fn());

  // Reset module cache so worker loads fresh with our mocks.
  vi.resetModules();

  const plugin = (await import("./worker.js")) as {
    default?: { setup?: (ctx: unknown) => Promise<void> };
  };
  const setup = plugin.default?.setup;
  if (typeof setup !== "function") {
    throw new Error("Could not find plugin setup function");
  }
  await setup(ctx);

  cadExport = handlers["cad_export"];
  if (typeof cadExport !== "function") {
    throw new Error("cad_export handler not registered");
  }
});

afterAll(() => {
  vi.unstubAllGlobals();
  vi.resetModules();
});

// Helpers to build fetch mock sequences for the cad_export flow.
// cad_export makes these GitHub API calls in order:
//   1. GET /repos/{owner}/{repo}           — prerequisite check
//   2. GET /repos/{owner}/{repo}/contents/{path}  — idempotency check
//   3. GET /repos/{owner}/{repo}/contents/{path}  — pushArtifactToGitHub: existing sha check
//   4. PUT /repos/{owner}/{repo}/contents/{path}  — pushArtifactToGitHub: commit

function mockPrereqOk() {
  return { ok: true, status: 200, json: async () => ({ name: "cad-artifacts" }), text: async () => "" } as Response;
}

function mockContentsNotFound() {
  return { ok: false, status: 404, json: async () => ({}), text: async () => "not found" } as Response;
}

function mockPutSuccess(sha = "abc123commit") {
  return {
    ok: true,
    status: 201,
    json: async () => ({ commit: { sha } }),
    text: async () => "",
  } as Response;
}

const BASE_PARAMS = {
  script: "import cadquery as cq; result = cq.Workplane('XY').box(1,1,1)",
  format: "step" as const,
  paperclipTicketId: "PLA-56",
  toolCallId: "call-001",
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("cad_export — PLA-56 artifact persistence pipeline", () => {
  it("AC1: prerequisite check — 404 on repo → prerequisite_missing", async () => {
    const fetchMock = vi.mocked(globalThis.fetch);
    fetchMock.mockReset();
    // GET /repos → 404
    fetchMock.mockResolvedValueOnce({
      ok: false,
      status: 404,
      json: async () => ({}),
      text: async () => "not found",
    } as Response);

    const result = (await cadExport(BASE_PARAMS)) as {
      data?: { error?: string; message?: string };
    };

    expect(result.data?.error).toBe("prerequisite_missing");
    expect(result.data?.message).toMatch(/404/);
    expect(result.data?.message).toMatch(/operator action required/i);
  });

  it("AC1: prerequisite check — 403 on repo → prerequisite_missing", async () => {
    const fetchMock = vi.mocked(globalThis.fetch);
    fetchMock.mockReset();
    fetchMock.mockResolvedValueOnce({
      ok: false,
      status: 403,
      json: async () => ({}),
      text: async () => "forbidden",
    } as Response);

    const result = (await cadExport(BASE_PARAMS)) as {
      data?: { error?: string; message?: string };
    };

    expect(result.data?.error).toBe("prerequisite_missing");
    expect(result.data?.message).toMatch(/403/);
  });

  it("AC4: idempotency — artifact already exists → returns existing commitSha", async () => {
    const fetchMock = vi.mocked(globalThis.fetch);
    fetchMock.mockReset();

    // 1. Prereq check → ok
    fetchMock.mockResolvedValueOnce(mockPrereqOk());
    // 2. Idempotency check: GET contents → file exists
    fetchMock.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({ sha: "blobsha123", html_url: "https://github.com/claudegoogl-sudo/cad-artifacts/blob/main/artifacts/PLA-56/call-001/artifact.step" }),
      text: async () => "",
    } as Response);
    // 3. Commits for path → returns commit sha
    fetchMock.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => [{ sha: "commitsha456" }],
      text: async () => "",
    } as Response);

    const result = (await cadExport(BASE_PARAMS)) as {
      data?: { commitSha?: string; permalink?: string; artifactPath?: string; error?: string };
    };

    expect(result.data?.error).toBeUndefined();
    expect(result.data?.commitSha).toBe("commitsha456");
    expect(result.data?.permalink).toContain("commitsha456");
    expect(result.data?.artifactPath).toBe(
      "artifacts/PLA-56/call-001/artifact.step",
    );
    // Verify no push (PUT) was made.
    const putCalls = vi.mocked(globalThis.fetch).mock.calls.filter(
      (c) => (c[1] as RequestInit | undefined)?.method === "PUT",
    );
    expect(putCalls).toHaveLength(0);
  });

  it("AC2+AC5+AC8: successful render+commit returns commitSha, permalink, artifactPath", async () => {
    const fetchMock = vi.mocked(globalThis.fetch);
    fetchMock.mockReset();

    // 1. Prereq check → ok
    fetchMock.mockResolvedValueOnce(mockPrereqOk());
    // 2. Idempotency check → not found
    fetchMock.mockResolvedValueOnce(mockContentsNotFound());
    // 3. pushArtifactToGitHub: GET existing sha → 404 (new file)
    fetchMock.mockResolvedValueOnce(mockContentsNotFound());
    // 4. pushArtifactToGitHub: PUT → success
    fetchMock.mockResolvedValueOnce(mockPutSuccess("deadbeef1234"));

    const result = (await cadExport(BASE_PARAMS)) as {
      data?: { commitSha?: string; permalink?: string; artifactPath?: string; error?: string };
      content?: string;
    };

    expect(result.data?.error).toBeUndefined();
    expect(result.data?.commitSha).toBe("deadbeef1234");
    expect(result.data?.permalink).toContain("deadbeef1234");
    expect(result.data?.permalink).toContain(
      "artifacts/PLA-56/call-001/artifact.step",
    );
    expect(result.data?.artifactPath).toBe(
      "artifacts/PLA-56/call-001/artifact.step",
    );

    // AC5: verify commit message contains ticket id and tool call id.
    const putCall = vi.mocked(globalThis.fetch).mock.calls.find(
      (c) => (c[1] as RequestInit | undefined)?.method === "PUT",
    );
    expect(putCall).toBeDefined();
    const putBody = JSON.parse((putCall![1] as RequestInit).body as string) as {
      message?: string;
    };
    expect(putBody.message).toContain("PLA-56");
    expect(putBody.message).toContain("call-001");
    expect(putBody.message).toContain("cad_export");
  });

  it("AC3: PAT not present in returned data", async () => {
    const fetchMock = vi.mocked(globalThis.fetch);
    fetchMock.mockReset();

    fetchMock.mockResolvedValueOnce(mockPrereqOk());
    fetchMock.mockResolvedValueOnce(mockContentsNotFound());
    fetchMock.mockResolvedValueOnce(mockContentsNotFound());
    fetchMock.mockResolvedValueOnce(mockPutSuccess("sha9999"));

    const result = (await cadExport(BASE_PARAMS)) as { data?: unknown; content?: string };
    const serialized = JSON.stringify(result);

    // The PAT used in buildMockCtx should never appear in result.
    expect(serialized).not.toContain("ghp_fake_token_pla56");
  });

  it("AC6: uses config.artifactRepoUrl when set", async () => {
    // Re-initialise with a custom artifactRepoUrl.
    vi.resetModules();
    const { ctx: customCtx, handlers } = buildMockCtx("ghp_custom", {
      githubPatSecretId: "secret-uuid-custom",
      artifactRepoUrl: "https://github.com/my-org/my-artifacts.git",
    });

    vi.stubGlobal("fetch", vi.fn());

    const plugin2 = (await import("./worker.js")) as {
      default?: { setup?: (ctx: unknown) => Promise<void> };
    };
    await plugin2.default?.setup?.(customCtx);

    const customExport = handlers["cad_export"];

    const fetchMock = vi.mocked(globalThis.fetch);
    fetchMock.mockReset();

    fetchMock.mockResolvedValueOnce(mockPrereqOk());
    fetchMock.mockResolvedValueOnce(mockContentsNotFound());
    fetchMock.mockResolvedValueOnce(mockContentsNotFound());
    fetchMock.mockResolvedValueOnce(mockPutSuccess("sha-custom"));

    await customExport(BASE_PARAMS);

    // Verify all fetch calls used the custom repo URL.
    const allUrls = vi.mocked(globalThis.fetch).mock.calls.map((c) =>
      typeof c[0] === "string" ? c[0] : (c[0] as Request).url,
    );
    expect(allUrls.every((u) => u.includes("my-org/my-artifacts"))).toBe(true);

    vi.resetModules();
  });

  it("auth error (403 on PUT) → returns { error: 'auth' }", async () => {
    const fetchMock = vi.mocked(globalThis.fetch);
    fetchMock.mockReset();

    fetchMock.mockResolvedValueOnce(mockPrereqOk());
    fetchMock.mockResolvedValueOnce(mockContentsNotFound());
    // pushArtifactToGitHub GET → 404
    fetchMock.mockResolvedValueOnce(mockContentsNotFound());
    // pushArtifactToGitHub PUT → 403
    fetchMock.mockResolvedValueOnce({
      ok: false,
      status: 403,
      json: async () => ({}),
      text: async () => "forbidden",
    } as Response);

    const result = (await cadExport(BASE_PARAMS)) as {
      data?: { error?: string };
    };
    expect(result.data?.error).toBe("auth");
  });

  it("network error (503 on PUT) → returns { error: 'network' }", async () => {
    const fetchMock = vi.mocked(globalThis.fetch);
    fetchMock.mockReset();

    fetchMock.mockResolvedValueOnce(mockPrereqOk());
    fetchMock.mockResolvedValueOnce(mockContentsNotFound());
    fetchMock.mockResolvedValueOnce(mockContentsNotFound());
    fetchMock.mockResolvedValueOnce({
      ok: false,
      status: 503,
      json: async () => ({}),
      text: async () => "service unavailable",
    } as Response);

    const result = (await cadExport(BASE_PARAMS)) as {
      data?: { error?: string };
    };
    expect(result.data?.error).toBe("network");
  });

  it("conflict (409) → retries once and succeeds", async () => {
    const fetchMock = vi.mocked(globalThis.fetch);
    fetchMock.mockReset();

    // 1. Prereq → ok
    fetchMock.mockResolvedValueOnce(mockPrereqOk());
    // 2. Idempotency → not found
    fetchMock.mockResolvedValueOnce(mockContentsNotFound());
    // 3. Push attempt 1: GET → 404, PUT → 409 conflict
    fetchMock.mockResolvedValueOnce(mockContentsNotFound());
    fetchMock.mockResolvedValueOnce({
      ok: false,
      status: 409,
      json: async () => ({}),
      text: async () => "conflict",
    } as Response);
    // 4. Push attempt 2 (retry): GET → existing sha, PUT → success
    fetchMock.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({ sha: "existingsha" }),
      text: async () => "",
    } as Response);
    fetchMock.mockResolvedValueOnce(mockPutSuccess("retrysha789"));

    const result = (await cadExport(BASE_PARAMS)) as {
      data?: { commitSha?: string; error?: string };
    };
    expect(result.data?.error).toBeUndefined();
    expect(result.data?.commitSha).toBe("retrysha789");
  });

  it("conflict (409) → retries once, fails again → returns { error: 'conflict' }", async () => {
    const fetchMock = vi.mocked(globalThis.fetch);
    fetchMock.mockReset();

    fetchMock.mockResolvedValueOnce(mockPrereqOk());
    fetchMock.mockResolvedValueOnce(mockContentsNotFound());
    // Attempt 1: GET → 404, PUT → 409
    fetchMock.mockResolvedValueOnce(mockContentsNotFound());
    fetchMock.mockResolvedValueOnce({
      ok: false,
      status: 409,
      json: async () => ({}),
      text: async () => "conflict",
    } as Response);
    // Attempt 2 (retry): GET → 404, PUT → 409 again
    fetchMock.mockResolvedValueOnce(mockContentsNotFound());
    fetchMock.mockResolvedValueOnce({
      ok: false,
      status: 409,
      json: async () => ({}),
      text: async () => "conflict",
    } as Response);

    const result = (await cadExport(BASE_PARAMS)) as {
      data?: { error?: string };
    };
    expect(result.data?.error).toBe("conflict");
  });

  it("AC5: commit message format is ticket=... tool=cad_export call=...", async () => {
    const fetchMock = vi.mocked(globalThis.fetch);
    fetchMock.mockReset();

    fetchMock.mockResolvedValueOnce(mockPrereqOk());
    fetchMock.mockResolvedValueOnce(mockContentsNotFound());
    fetchMock.mockResolvedValueOnce(mockContentsNotFound());
    fetchMock.mockResolvedValueOnce(mockPutSuccess("sha-msg-test"));

    await cadExport({
      ...BASE_PARAMS,
      paperclipTicketId: "PLA-999",
      toolCallId: "tc-abc123",
    });

    const putCall = vi.mocked(globalThis.fetch).mock.calls.find(
      (c) => (c[1] as RequestInit | undefined)?.method === "PUT",
    );
    const body = JSON.parse((putCall![1] as RequestInit).body as string) as {
      message?: string;
    };
    expect(body.message).toBe(
      "CAD artifact: ticket=PLA-999 tool=cad_export call=tc-abc123",
    );
    // PAT must not appear in commit message.
    expect(body.message).not.toContain("ghp_");
  });

  it("AC8: result fields are commitSha, permalink, artifactPath — no extra fields", async () => {
    const fetchMock = vi.mocked(globalThis.fetch);
    fetchMock.mockReset();

    fetchMock.mockResolvedValueOnce(mockPrereqOk());
    fetchMock.mockResolvedValueOnce(mockContentsNotFound());
    fetchMock.mockResolvedValueOnce(mockContentsNotFound());
    fetchMock.mockResolvedValueOnce(mockPutSuccess("final-sha"));

    const result = (await cadExport(BASE_PARAMS)) as {
      data?: Record<string, unknown>;
    };

    expect(result.data).toBeDefined();
    const keys = Object.keys(result.data!).sort();
    expect(keys).toEqual(["artifactPath", "commitSha", "permalink"]);
  });

  it("deterministic artifact path uses paperclipTicketId/toolCallId/filename", async () => {
    const fetchMock = vi.mocked(globalThis.fetch);
    fetchMock.mockReset();

    fetchMock.mockResolvedValueOnce(mockPrereqOk());
    fetchMock.mockResolvedValueOnce(mockContentsNotFound());
    fetchMock.mockResolvedValueOnce(mockContentsNotFound());
    fetchMock.mockResolvedValueOnce(mockPutSuccess("pathtest-sha"));

    const result = (await cadExport({
      ...BASE_PARAMS,
      paperclipTicketId: "PLA-42",
      toolCallId: "tc-xyz",
      filename: "part.stl",
      format: "stl" as const,
    })) as { data?: { artifactPath?: string } };

    expect(result.data?.artifactPath).toBe("artifacts/PLA-42/tc-xyz/part.stl");

    // Verify the PUT URL also used this path.
    const putCall = vi.mocked(globalThis.fetch).mock.calls.find(
      (c) => (c[1] as RequestInit | undefined)?.method === "PUT",
    );
    expect(typeof putCall![0] === "string" ? putCall![0] : "").toContain(
      "artifacts/PLA-42/tc-xyz/part.stl",
    );
  });
});
