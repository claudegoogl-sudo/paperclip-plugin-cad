/**
 * Regression tests for PLA-50: artifactPath path-traversal guard in cad_commit.
 *
 * Acceptance criteria covered:
 *   AC1  artifactPath is resolved and checked against os.tmpdir() + "/" prefix.
 *   AC2  Out-of-bounds paths return a structured error; no throw.
 *   AC3  pushArtifactToGitHub is never called with an out-of-bounds path.
 *   AC4  cad_commit("/etc/passwd") returns the error response.
 *   AC5  cad_commit(valid tmpdir path) proceeds (GitHub fetch is mocked).
 */

import { tmpdir } from "node:os";
import { join } from "node:path";
import { writeFile, unlink } from "node:fs/promises";
import { describe, it, expect, vi, beforeAll, afterAll } from "vitest";

// ---------------------------------------------------------------------------
// Mock the plugin SDK so runWorker is a no-op and definePlugin is transparent.
// This must be declared before the dynamic import of worker.ts.
// ---------------------------------------------------------------------------

vi.mock("@paperclipai/plugin-sdk", () => ({
  definePlugin: (config: unknown) => config,
  runWorker: vi.fn(),
}));

// ---------------------------------------------------------------------------
// Minimal ctx mock that captures registered tool handlers.
// ---------------------------------------------------------------------------

type ToolHandler = (params: unknown) => Promise<unknown>;

function buildMockCtx(pat = "ghp_fake_token", githubPatSecretId = "secret-uuid-123") {
  const handlers: Record<string, ToolHandler> = {};

  const ctx = {
    logger: {
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
    },
    tools: {
      register: vi.fn((_name: string, _meta: unknown, handler: ToolHandler) => {
        handlers[_name] = handler;
      }),
    },
    config: {
      get: vi.fn().mockResolvedValue({ githubPatSecretId }),
    },
    secrets: {
      resolve: vi.fn().mockResolvedValue(pat),
    },
  };

  return { ctx, handlers };
}

// ---------------------------------------------------------------------------
// Set up the plugin once for the whole suite.
// ---------------------------------------------------------------------------

let cadCommit: ToolHandler;

beforeAll(async () => {
  const { ctx, handlers } = buildMockCtx();

  // Stub global fetch before importing so pushArtifactToGitHub uses the stub.
  vi.stubGlobal("fetch", vi.fn());

  // Import worker — runWorker is mocked so the module loads cleanly.
  // definePlugin returns the config object directly, so plugin.setup === setup fn.
  const plugin = (await import("./worker.js")) as {
    default?: { setup?: (ctx: unknown) => Promise<void> };
  };
  const setup = plugin.default?.setup;
  if (typeof setup !== "function") {
    throw new Error("Could not find plugin setup function in worker module");
  }
  await setup(ctx);

  cadCommit = handlers["cad_commit"];
  if (typeof cadCommit !== "function") {
    throw new Error("cad_commit handler not registered");
  }
});

afterAll(() => {
  vi.unstubAllGlobals();
  vi.resetModules();
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("cad_commit — artifactPath path-traversal guard (PLA-50)", () => {
  it("AC4: rejects /etc/passwd with a structured error and never calls fetch", async () => {
    const fetchMock = vi.mocked(globalThis.fetch);
    fetchMock.mockClear();

    const result = (await cadCommit({
      artifactPath: "/etc/passwd",
      repoPath: "models/part.step",
      commitMessage: "add part",
    })) as { data?: { error?: string } };

    expect(result.data?.error).toMatch(/temp directory/i);
    // AC3: pushArtifactToGitHub (which uses fetch) must NOT have been called.
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("AC4 variant: rejects dot-dot traversal through tmpdir", async () => {
    const fetchMock = vi.mocked(globalThis.fetch);
    fetchMock.mockClear();

    const result = (await cadCommit({
      artifactPath: `${tmpdir()}/../../../etc/shadow`,
      repoPath: "models/part.step",
      commitMessage: "exfil",
    })) as { data?: { error?: string } };

    expect(result.data?.error).toMatch(/temp directory/i);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("AC4 variant: rejects relative path that escapes tmpdir", async () => {
    const fetchMock = vi.mocked(globalThis.fetch);
    fetchMock.mockClear();

    const result = (await cadCommit({
      artifactPath: "../../etc/hosts",
      repoPath: "models/part.step",
      commitMessage: "test",
    })) as { data?: { error?: string } };

    expect(result.data?.error).toMatch(/temp directory/i);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("AC5: accepts a valid tmpdir path and calls GitHub API", async () => {
    const validPath = join(tmpdir(), "cad-test-pla50.step");
    await writeFile(validPath, "; stub content");

    const fetchMock = vi.mocked(globalThis.fetch);
    fetchMock.mockReset();
    // GET (file check) → 404 (new file).
    fetchMock.mockResolvedValueOnce({
      ok: false,
      status: 404,
      text: async () => "not found",
      json: async () => ({}),
    } as Response);
    // PUT → success.
    fetchMock.mockResolvedValueOnce({
      ok: true,
      status: 201,
      text: async () => "",
      json: async () => ({ commit: { sha: "abc123def456" } }),
    } as Response);

    const result = (await cadCommit({
      artifactPath: validPath,
      repoPath: "models/part.step",
      commitMessage: "add part",
    })) as { data?: { commitSha?: string; error?: string } };

    // No error — commit should have succeeded.
    expect(result.data?.error).toBeUndefined();
    expect(result.data?.commitSha).toBe("abc123def456");
    // AC3 (positive): fetch was called because the path was valid.
    expect(fetchMock).toHaveBeenCalled();

    await unlink(validPath).catch(() => undefined);
  });
});
