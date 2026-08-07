/**
 * 1101 — residual cross-tenant DoS after 1089 SE-2.
 *
 * SE-2's enforceRetainedInputCap bounds only retained `.inputs` bytes; it never
 * removes a whole entry, so the shared staging map's ENTRY COUNT and retained
 * `script` bytes were still unbounded. This covers the two residual fixes:
 *   1. enforceStagingEntryCap — whole-entry eviction caps the map's entry count.
 *   2. MAX_SCRIPT_BYTES — oversized scripts are rejected at intake before staging.
 */

import { describe, it, expect, vi, beforeAll, afterAll } from "vitest";
import {
  enforceStagingEntryCap,
  MAX_STAGING_ENTRIES,
  MAX_SCRIPT_BYTES,
  type StagingEntry,
} from "./worker.js";

function entry(label: string): StagingEntry {
  return { script: `# ${label}`, stepPath: `/tmp/${label}.step` };
}

describe("TEST-1101 — staging-map entry-count cap", () => {
  it("evicts whole oldest entries until size <= cap", () => {
    const cap = 10;
    const map = new Map<string, StagingEntry>();
    for (let i = 0; i < 25; i++) map.set(`run-${i}`, entry(`run-${i}`));
    expect(map.size).toBe(25);

    enforceStagingEntryCap(map, cap);

    expect(map.size).toBe(cap);
    // Oldest were deleted entirely (not just .inputs nulled).
    expect(map.has("run-0")).toBe(false);
    expect(map.has("run-14")).toBe(false);
    // Newest survive.
    expect(map.has("run-24")).toBe(true);
    expect(map.has("run-15")).toBe(true);
  });

  it("never evicts the just-inserted newest entry (handoff invariant)", () => {
    const cap = 5;
    const map = new Map<string, StagingEntry>();
    for (let i = 0; i < 100; i++) {
      map.set(`run-${i}`, entry(`run-${i}`));
      enforceStagingEntryCap(map, cap);
      expect(map.size).toBeLessThanOrEqual(cap);
      // The entry staged on this iteration must still be exportable.
      expect(map.has(`run-${i}`)).toBe(true);
    }
  });

  it("stays bounded in entry count across many runs (the SE-2 residual)", () => {
    const cap = 8;
    const map = new Map<string, StagingEntry>();
    // Zero-input, script-only runs — exactly the vector SE-2's byte cap misses.
    for (let i = 0; i < 1000; i++) {
      map.set(`run-${i}`, entry(`run-${i}`));
      enforceStagingEntryCap(map, cap);
    }
    expect(map.size).toBe(cap);
  });

  it("is a no-op when entry count is at or under the cap", () => {
    const map = new Map<string, StagingEntry>();
    map.set("a", entry("a"));
    map.set("b", entry("b"));
    enforceStagingEntryCap(map, 10);
    expect(map.size).toBe(2);
    expect(map.has("a")).toBe(true);
    expect(map.has("b")).toBe(true);
  });

  it("production cap is positive so the newest entry is always retained", () => {
    expect(MAX_STAGING_ENTRIES).toBeGreaterThanOrEqual(1);
  });
});

// ---------------------------------------------------------------------------
// MAX_SCRIPT_BYTES intake validation (through the registered cad.run_script).
// ---------------------------------------------------------------------------

vi.mock("@paperclipai/plugin-sdk", () => ({
  definePlugin: (config: unknown) => config,
  runWorker: vi.fn(),
}));

type ToolHandler = (params: unknown, runCtx?: unknown) => Promise<unknown>;
const RUN_CTX = { companyId: "company-A", agentId: "agent-A", runId: "run-A" };

function buildMockCtx() {
  const handlers: Record<string, ToolHandler> = {};
  const ctx = {
    logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
    metrics: { write: vi.fn(async () => {}) },
    tools: {
      register: vi.fn((name: string, _meta: unknown, handler: ToolHandler) => {
        handlers[name] = handler;
      }),
    },
    config: { get: vi.fn().mockResolvedValue({ githubPatSecretId: "secret-uuid" }) },
    secrets: { resolve: vi.fn().mockResolvedValue("ghp_fake") },
  };
  return { ctx, handlers };
}

describe("TEST-1101 — MAX_SCRIPT_BYTES intake cap", () => {
  let cadRunScript: ToolHandler;

  beforeAll(async () => {
    const { ctx, handlers } = buildMockCtx();
    vi.resetModules();
    const plugin = (await import("./worker.js")) as { default?: { setup?: (ctx: unknown) => Promise<void> } };
    await plugin.default?.setup?.(ctx);
    cadRunScript = handlers["cad.run_script"];
    if (typeof cadRunScript !== "function") throw new Error("cad.run_script not registered");
  });

  afterAll(() => {
    vi.resetModules();
  });

  it("rejects an oversized script with a validation_error before rendering", async () => {
    const huge = "x".repeat(MAX_SCRIPT_BYTES + 1);
    const result = (await cadRunScript({ script: huge }, RUN_CTX)) as {
      error?: string;
      data?: { code?: string; message?: string };
    };
    expect(result.error).toBe("validation_error");
    expect(result.data?.message).toContain("maximum size");
  });

  it("measures the cap in UTF-8 bytes, not JS string length", async () => {
    // "€" is 3 UTF-8 bytes but length 1; a string of length MAX_SCRIPT_BYTES is
    // ~3x over the byte cap and must be rejected.
    const multibyte = "€".repeat(MAX_SCRIPT_BYTES);
    expect(Buffer.byteLength(multibyte, "utf8")).toBeGreaterThan(MAX_SCRIPT_BYTES);
    const result = (await cadRunScript({ script: multibyte }, RUN_CTX)) as { error?: string };
    expect(result.error).toBe("validation_error");
  });
});
