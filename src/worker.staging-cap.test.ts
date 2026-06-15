/**
 * PLA-1089 SE-2 — bound retained-input memory on the shared staging map.
 *
 * The Node plugin-worker is long-lived and shared across all tenants; each
 * cad.run_script staging entry can retain up to MAX_TOTAL_INPUT_BYTES of fetched
 * scan bytes for a later cad.export re-render. `enforceRetainedInputCap` caps the
 * *total* retained bytes across the whole map and evicts oldest-first so a loop
 * of large-input runs cannot grow host RSS without bound (cross-tenant DoS).
 */

import { describe, it, expect } from "vitest";
import {
  enforceRetainedInputCap,
  MAX_RETAINED_INPUT_BYTES,
  type StagingEntry,
} from "./worker.js";
import { MAX_TOTAL_INPUT_BYTES } from "./cad-intake.js";

function entry(label: string, inputBytes: number): StagingEntry {
  return {
    script: `# ${label}`,
    stepPath: `/tmp/${label}.step`,
    inputs: inputBytes > 0 ? [{ basename: `${label}.stl`, bytes: Buffer.alloc(inputBytes) }] : undefined,
  };
}

function retained(map: Map<string, StagingEntry>): number {
  let n = 0;
  for (const e of map.values()) for (const f of e.inputs ?? []) n += f.bytes.byteLength;
  return n;
}

describe("PLA-1089 SE-2 — retained-input cap", () => {
  it("evicts oldest entries' inputs until total retained <= cap", () => {
    const cap = 1000;
    const map = new Map<string, StagingEntry>();
    // 5 staged runs, 400 bytes of input each = 2000 total, 2x over cap.
    for (let i = 0; i < 5; i++) map.set(`run-${i}`, entry(`run-${i}`, 400));
    expect(retained(map)).toBe(2000);

    enforceRetainedInputCap(map, cap);

    expect(retained(map)).toBeLessThanOrEqual(cap);
    // Newest entry is never stripped of its own inputs (insertion-order eviction).
    expect(map.get("run-4")!.inputs).toBeTruthy();
    // Oldest was evicted first.
    expect(map.get("run-0")!.inputs).toBeUndefined();
    // Eviction drops only `.inputs`; the tiny script/stepPath entry survives so
    // step-format exports still work.
    expect(map.get("run-0")!.script).toBe("# run-0");
    expect(map.get("run-0")!.stepPath).toBe("/tmp/run-0.step");
  });

  it("stays bounded after many staged runs (no unbounded growth)", () => {
    const cap = 1000;
    const map = new Map<string, StagingEntry>();
    for (let i = 0; i < 100; i++) {
      map.set(`run-${i}`, entry(`run-${i}`, 300));
      enforceRetainedInputCap(map, cap);
      expect(retained(map)).toBeLessThanOrEqual(cap);
    }
    // The most recent run always retains its inputs for re-export.
    expect(map.get("run-99")!.inputs).toBeTruthy();
  });

  it("is a no-op when total retained is under the cap", () => {
    const map = new Map<string, StagingEntry>();
    map.set("a", entry("a", 100));
    map.set("b", entry("b", 100));
    enforceRetainedInputCap(map, 1000);
    expect(map.get("a")!.inputs).toBeTruthy();
    expect(map.get("b")!.inputs).toBeTruthy();
  });

  it("never strips the newest entry when it alone fits the cap (prod invariant)", () => {
    // Production cap (240 MiB) is 2x the max single-call input total (120 MiB),
    // so the active call's inputs are always preserved.
    expect(MAX_RETAINED_INPUT_BYTES).toBeGreaterThan(MAX_TOTAL_INPUT_BYTES);
  });
});
