/**
 * Regression coverage for the release-time manifest gate.
 *
 * Proves the gate (`scripts/validate-manifest.mjs`) catches the exact
 * v0.1.1 incident: a tool name containing `:`, which the tightened
 * host plugin-manifest validator rejects. If this test ever starts
 * passing the offending manifest, the gate has regressed and the
 * v0.1.1-class incident can re-occur.
 */
import { describe, it, expect } from "vitest";

// @ts-expect-error — .mjs has no .d.ts; the helper is plain JS by design
import { validateManifest } from "../scripts/validate-manifest.mjs";

/**
 * Minimal manifest fixture that satisfies pluginManifestV1Schema's
 * structural requirements. We mutate `tools[0].name` per test to exercise
 * the failure mode without dragging in the full cad manifest (which
 * carries fork-specific `worker`/`runtimeRequirements` extensions that
 * the schema strips silently).
 */
function fixture(toolName: string) {
  return {
    id: "platform.cad-test",
    apiVersion: 1 as const,
    version: "0.1.0",
    displayName: "CAD Test Plugin",
    description: "fixture for manifest-gate regression coverage",
    author: "Platform",
    categories: ["connector"] as const,
    capabilities: ["agent.tools.register"] as const,
    entrypoints: { worker: "./dist/worker.js" },
    tools: [
      {
        name: toolName,
        displayName: "Tool",
        description: "fixture tool",
        parametersSchema: { type: "object" },
      },
    ],
  };
}

describe("validate-manifest gate", () => {
  it("rejects a manifest with a colon in tools[].name (the v0.1.1 incident)", () => {
    const result = validateManifest(fixture("bad:name"));
    expect(result.ok).toBe(false);
    if (result.ok) return; // narrowing
    // Surfaces both the field path and the offending value so the build
    // log makes the fix obvious without grepping the validator source.
    const msg = result.errors.join("\n");
    expect(msg).toMatch(/tools\[0\]\.name/);
    expect(msg).toMatch(/"bad:name"/);
  });

  it("rejects the historical cad:run_script name (v0.1.1 was here)", () => {
    const result = validateManifest(fixture("cad:run_script"));
    expect(result.ok).toBe(false);
  });

  it("rejects whitespace, uppercase, and path separators in tools[].name", () => {
    for (const bad of ["BadName", "name with space", "name/with/slash", "name\twith\ttab"]) {
      const result = validateManifest(fixture(bad));
      expect(
        result.ok,
        `expected gate to reject ${JSON.stringify(bad)}, got ok=true`,
      ).toBe(false);
    }
  });

  it("accepts dotted, hyphenated, and underscored lowercase names", () => {
    for (const good of ["cad.run_script", "cad-export", "run_script", "run.script.v2", "x"]) {
      const result = validateManifest(fixture(good));
      expect(
        result.ok,
        `expected gate to accept ${JSON.stringify(good)}, errors=${
          result.ok ? "" : result.errors.join("; ")
        }`,
      ).toBe(true);
    }
  });

  it("rejects manifest missing required pluginManifestV1Schema fields", () => {
    // No tools, but also no capabilities/entrypoints/etc. — exercises the
    // upstream zod schema branch (not just the mirrored validator).
    const result = validateManifest({ id: "x" } as unknown as ReturnType<typeof fixture>);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    const msg = result.errors.join("\n");
    // At minimum, apiVersion must be present.
    expect(msg).toMatch(/\[zod\]/);
  });
});
