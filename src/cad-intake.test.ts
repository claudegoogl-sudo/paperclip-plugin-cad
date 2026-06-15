/**
 * Tests for PLA-1089 Ask 1 — scan intake-fetch.
 *
 * Covers acceptance criteria 1 & 2:
 *   - Path allowlist rejects traversal / absolute / out-of-allowlist repoPath
 *     with a structured error (assertSafeIntakePath + parseInputArtifacts).
 *   - Per-file + total + count caps enforced (fetchInputArtifact / fetchInputArtifacts).
 *   - Binary-safe fetch (raw media type, non-UTF-8 bytes survive round-trip).
 *   - Basename-only staging into <workdir>/inputs/<basename>, no directory
 *     components honored (stageInputFiles).
 */

import { describe, it, expect } from "vitest";
import { mkdtemp, readFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  assertSafeIntakePath,
  parseInputArtifacts,
  fetchInputArtifact,
  fetchInputArtifacts,
  stageInputFiles,
  IntakeError,
  MAX_INPUT_FILES,
  type FetchImpl,
  type InputFile,
} from "./cad-intake.js";

const REPO = "https://github.com/claudegoogl-sudo/cad-artifacts.git";

// Minimal Response-like stub for the injected fetch.
function fakeResponse(opts: {
  status?: number;
  ok?: boolean;
  contentLength?: number | null;
  body?: Uint8Array;
}): Response {
  const status = opts.status ?? 200;
  const headers = new Map<string, string>();
  if (opts.contentLength !== null && opts.contentLength !== undefined) {
    headers.set("content-length", String(opts.contentLength));
  }
  return {
    ok: opts.ok ?? (status >= 200 && status < 300),
    status,
    headers: { get: (k: string) => headers.get(k.toLowerCase()) ?? null },
    arrayBuffer: async () => {
      const b = opts.body ?? new Uint8Array();
      return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength);
    },
  } as unknown as Response;
}

describe("assertSafeIntakePath", () => {
  it("accepts allowlisted file paths", () => {
    expect(assertSafeIntakePath("user-uploads/scan.stl")).toBeNull();
    expect(assertSafeIntakePath("artifacts/PLA-1/call-1/out.3mf")).toBeNull();
    expect(assertSafeIntakePath("user-uploads/sub/dir/mesh.ply")).toBeNull();
  });

  it("rejects traversal, absolute, and out-of-allowlist paths", () => {
    for (const bad of [
      "../etc/passwd",
      "/etc/passwd",
      "user-uploads/../../secrets/x",
      "user-uploads/../artifacts/x", // normalizes differently
      "secrets/leak.stl", // not under an allowed prefix
      "user-uploads//double.stl", // normalize-inequality
      "user-uploads/./dot.stl",
      "user-uploads\\win.stl", // backslash
      "user-uploads/", // directory, no basename
      "", // empty
    ]) {
      expect(assertSafeIntakePath(bad), `expected reject: ${JSON.stringify(bad)}`).not.toBeNull();
    }
  });

  it("rejects NUL and non-string", () => {
    expect(assertSafeIntakePath("user-uploads/a\x00b.stl")).not.toBeNull();
    expect(assertSafeIntakePath(42 as unknown)).not.toBeNull();
    expect(assertSafeIntakePath(undefined as unknown)).not.toBeNull();
  });

  it("rejects a basename with disallowed characters", () => {
    expect(assertSafeIntakePath("user-uploads/.hidden")).not.toBeNull();
    expect(assertSafeIntakePath("user-uploads/a b.stl")).not.toBeNull();
  });
});

describe("parseInputArtifacts", () => {
  it("treats undefined/null/empty as no inputs", () => {
    expect(parseInputArtifacts(undefined)).toEqual({ repoPaths: [] });
    expect(parseInputArtifacts(null)).toEqual({ repoPaths: [] });
    expect(parseInputArtifacts([])).toEqual({ repoPaths: [] });
  });

  it("accepts a valid list", () => {
    const r = parseInputArtifacts([{ repoPath: "user-uploads/a.stl" }, { repoPath: "artifacts/x/b.stl" }]);
    expect(r).toEqual({ repoPaths: ["user-uploads/a.stl", "artifacts/x/b.stl"] });
  });

  it("rejects over the count cap", () => {
    const many = Array.from({ length: MAX_INPUT_FILES + 1 }, (_, i) => ({ repoPath: `user-uploads/f${i}.stl` }));
    expect("error" in parseInputArtifacts(many)).toBe(true);
  });

  it("rejects non-array, bad item shape, and extra keys", () => {
    expect("error" in parseInputArtifacts("nope")).toBe(true);
    expect("error" in parseInputArtifacts([42])).toBe(true);
    expect("error" in parseInputArtifacts([{ repoPath: "user-uploads/a.stl", extra: 1 }])).toBe(true);
  });

  it("propagates the path allowlist error", () => {
    const r = parseInputArtifacts([{ repoPath: "../escape" }]);
    expect("error" in r).toBe(true);
  });

  it("rejects duplicate basenames that would clobber", () => {
    const r = parseInputArtifacts([{ repoPath: "user-uploads/a.stl" }, { repoPath: "artifacts/x/a.stl" }]);
    expect("error" in r).toBe(true);
  });
});

describe("fetchInputArtifact", () => {
  it("fetches raw bytes binary-safe and stages by basename", async () => {
    const body = new Uint8Array([0x00, 0xff, 0x10, 0x80, 0x00, 0x53, 0x54, 0x4c]); // non-UTF-8
    let calledUrl = "";
    let calledAccept = "";
    const fetchImpl: FetchImpl = async (url, init) => {
      calledUrl = String(url);
      calledAccept = ((init?.headers as Record<string, string>) ?? {})["Accept"] ?? "";
      return fakeResponse({ body, contentLength: body.byteLength });
    };
    const file = await fetchInputArtifact("ghp_x", REPO, "main", "user-uploads/scan.stl", fetchImpl);
    expect(file.basename).toBe("scan.stl");
    expect(Array.from(file.bytes)).toEqual(Array.from(body));
    expect(calledAccept).toBe("application/vnd.github.raw");
    expect(calledUrl).toContain("/contents/user-uploads/scan.stl");
    expect(calledUrl).toContain("ref=main");
  });

  it("maps 404 → not_found, 401/403 → auth, 5xx → network", async () => {
    const mk = (status: number): FetchImpl => async () => fakeResponse({ status, ok: false });
    await expect(fetchInputArtifact("p", REPO, "main", "user-uploads/a.stl", mk(404))).rejects.toMatchObject({ kind: "not_found" });
    await expect(fetchInputArtifact("p", REPO, "main", "user-uploads/a.stl", mk(403))).rejects.toMatchObject({ kind: "auth" });
    await expect(fetchInputArtifact("p", REPO, "main", "user-uploads/a.stl", mk(503))).rejects.toMatchObject({ kind: "network" });
  });

  it("rejects over the per-file cap via Content-Length (pre-download, no big alloc)", async () => {
    // Tiny injected cap; Content-Length claims over-cap so we reject before reading.
    const caps = { maxFileBytes: 8, maxTotalBytes: 100 };
    const fetchImpl: FetchImpl = async () => fakeResponse({ contentLength: 9, body: new Uint8Array(1) });
    await expect(
      fetchInputArtifact("p", REPO, "main", "user-uploads/big.stl", fetchImpl, caps),
    ).rejects.toMatchObject({ kind: "too_large" });
  });

  it("rejects over the per-file cap via actual bytes (lying/absent Content-Length)", async () => {
    const caps = { maxFileBytes: 4, maxTotalBytes: 100 };
    const body = new Uint8Array([1, 2, 3, 4, 5]); // 5 > 4, no content-length header
    const fetchImpl: FetchImpl = async () => fakeResponse({ contentLength: null, body });
    await expect(
      fetchInputArtifact("p", REPO, "main", "user-uploads/big.stl", fetchImpl, caps),
    ).rejects.toMatchObject({ kind: "too_large" });
  });

  it("rejects a non-github.com repo URL", async () => {
    const fetchImpl: FetchImpl = async () => fakeResponse({ body: new Uint8Array(1) });
    await expect(
      fetchInputArtifact("p", "https://evil.example/o/r.git", "main", "user-uploads/a.stl", fetchImpl),
    ).rejects.toBeInstanceOf(IntakeError);
  });
});

describe("fetchInputArtifacts total cap", () => {
  it("rejects when combined size exceeds the total cap (tiny injected caps)", async () => {
    // Each file 6 bytes (< per-file 8), two of them = 12 > total 10.
    const caps = { maxFileBytes: 8, maxTotalBytes: 10 };
    const body = new Uint8Array(6);
    const fetchImpl: FetchImpl = async () => fakeResponse({ contentLength: 6, body });
    await expect(
      fetchInputArtifacts("p", REPO, "main", ["user-uploads/a.stl", "user-uploads/b.stl"], fetchImpl, caps),
    ).rejects.toMatchObject({ kind: "too_large" });
  });
});

describe("stageInputFiles", () => {
  it("writes inputs/<basename> with a binary round-trip", async () => {
    const workdir = await mkdtemp(join(tmpdir(), "cad-intake-test-"));
    const bytes = Buffer.from([0x00, 0xff, 0x42, 0x00]);
    await stageInputFiles(workdir, [{ basename: "scan.stl", bytes }]);
    const read = await readFile(join(workdir, "inputs", "scan.stl"));
    expect(Array.from(read)).toEqual(Array.from(bytes));
  });

  it("re-derives basename and never honors directory components", async () => {
    const workdir = await mkdtemp(join(tmpdir(), "cad-intake-test-"));
    // A maliciously-shaped basename field with a path is reduced to its basename.
    const file: InputFile = { basename: "../../etc/evil.stl", bytes: Buffer.from([1, 2, 3]) };
    await stageInputFiles(workdir, [file]);
    const read = await readFile(join(workdir, "inputs", "evil.stl"));
    expect(Array.from(read)).toEqual([1, 2, 3]);
    // The traversal target must NOT exist.
    await expect(stat(join(workdir, "..", "..", "etc", "evil.stl"))).rejects.toBeTruthy();
  });
});
