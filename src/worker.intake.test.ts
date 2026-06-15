/**
 * End-to-end test for PLA-1089 Ask 1 — scan intake-fetch through cad.run_script.
 *
 * Drives the real handler: mocks the GitHub raw fetch to return a binary STL,
 * calls cad.run_script with inputArtifacts, and renders in the REAL bwrap+seccomp
 * sandbox with a script that reads inputs/scan.stl via StlAPI_Reader. A successful
 * render (artifactId returned) proves the host fetched the bytes, staged them at
 * inputs/<basename> in the sandbox workdir, and the script read them.
 *
 * Acceptance criterion 1 (intake → StlAPI_Reader round-trip) + structured-error
 * paths for over-allowlist repoPath and 404.
 */

import { describe, it, expect, vi, beforeAll, afterAll } from "vitest";

vi.mock("@paperclipai/plugin-sdk", () => ({
  definePlugin: (config: unknown) => config,
  runWorker: vi.fn(),
}));

type ToolHandler = (params: unknown, runCtx?: unknown) => Promise<unknown>;

const DEFAULT_RUN_CTX = { companyId: "company-A", agentId: "agent-A", runId: "run-A", projectId: "project-A" };

function buildMockCtx() {
  const handlers: Record<string, ToolHandler> = {};
  const ctx = {
    logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
    metrics: { write: vi.fn(async () => {}) },
    tools: {
      register: vi.fn((_name: string, _meta: unknown, handler: ToolHandler) => {
        handlers[_name] = handler;
      }),
    },
    config: { get: vi.fn().mockResolvedValue({ githubPatSecretId: "secret-uuid" }) },
    secrets: { resolve: vi.fn().mockResolvedValue("ghp_fake") },
  };
  return { ctx, handlers };
}

/** Build a minimal valid binary STL (1 triangle) as a Buffer. */
function makeBinaryStl(): Buffer {
  const header = Buffer.alloc(80);
  const count = Buffer.alloc(4);
  count.writeUInt32LE(1, 0);
  const tri = Buffer.alloc(50);
  const floats = [0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0]; // normal + 3 verts
  floats.forEach((v, i) => tri.writeFloatLE(v, i * 4));
  tri.writeUInt16LE(0, 48);
  return Buffer.concat([header, count, tri]);
}

function rawResponse(body: Buffer): Response {
  return {
    ok: true,
    status: 200,
    headers: { get: (k: string) => (k.toLowerCase() === "content-length" ? String(body.byteLength) : null) },
    arrayBuffer: async () => body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength),
  } as unknown as Response;
}

// Reads the staged scan; asserts it is present + readable before producing a
// trivially-valid result so the STEP export can't fail for an unrelated reason.
const READ_SCAN_SCRIPT = [
  "import cadquery as cq",
  "from OCP.StlAPI import StlAPI_Reader",
  "from OCP.TopoDS import TopoDS_Shape",
  "s = TopoDS_Shape()",
  "r = StlAPI_Reader()",
  'ok = r.Read(s, "inputs/scan.stl")',
  'assert ok and not s.IsNull(), "scan not staged/readable in sandbox"',
  'result = cq.Workplane("XY").box(1, 1, 1)',
].join("\n");

let cadRunScript: ToolHandler;

beforeAll(async () => {
  const { ctx, handlers } = buildMockCtx();
  vi.stubGlobal("fetch", vi.fn());
  vi.resetModules();
  const plugin = (await import("./worker.js")) as { default?: { setup?: (ctx: unknown) => Promise<void> } };
  await plugin.default?.setup?.(ctx);
  cadRunScript = handlers["cad.run_script"];
  if (typeof cadRunScript !== "function") throw new Error("cad.run_script not registered");
});

afterAll(() => {
  vi.unstubAllGlobals();
  vi.resetModules();
});

describe("cad.run_script intake-fetch (PLA-1089 Ask 1)", () => {
  it("AC1: fetches a scan, stages it, and the script reads it via StlAPI_Reader", async () => {
    const fetchMock = vi.mocked(globalThis.fetch);
    fetchMock.mockReset();
    fetchMock.mockResolvedValueOnce(rawResponse(makeBinaryStl()));

    const result = (await cadRunScript(
      { script: READ_SCAN_SCRIPT, inputArtifacts: [{ repoPath: "user-uploads/scan.stl" }] },
      DEFAULT_RUN_CTX,
    )) as { data?: { artifactId?: string }; error?: string };

    expect(result.data?.artifactId, JSON.stringify(result)).toBeTruthy();

    // Confirm the fetch used the raw media type against the contents endpoint.
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(String(url)).toContain("/contents/user-uploads/scan.stl");
    expect((init.headers as Record<string, string>)["Accept"]).toBe("application/vnd.github.raw");
  }, 60_000);

  it("rejects an out-of-allowlist repoPath with a structured validation error (no fetch)", async () => {
    const fetchMock = vi.mocked(globalThis.fetch);
    fetchMock.mockReset();
    const result = (await cadRunScript(
      { script: READ_SCAN_SCRIPT, inputArtifacts: [{ repoPath: "../../etc/passwd" }] },
      DEFAULT_RUN_CTX,
    )) as { error?: string };
    expect(result.error).toBe("validation_error");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("surfaces a 404 from GitHub as a structured not_found tool error", async () => {
    const fetchMock = vi.mocked(globalThis.fetch);
    fetchMock.mockReset();
    fetchMock.mockResolvedValueOnce({
      ok: false,
      status: 404,
      headers: { get: () => null },
      arrayBuffer: async () => new ArrayBuffer(0),
    } as unknown as Response);
    const result = (await cadRunScript(
      { script: READ_SCAN_SCRIPT, inputArtifacts: [{ repoPath: "user-uploads/missing.stl" }] },
      DEFAULT_RUN_CTX,
    )) as { data?: { error?: string } };
    expect(result.data?.error).toBe("not_found");
  });
});
