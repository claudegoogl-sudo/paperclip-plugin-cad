/**
 * Unit tests for the secret-ref call-shape normalize
 * (src/secretRefBinding.ts).
 *
 * Contract under test:
 *   - legacy bare-UUID STRING config value → canonical binding object with
 *     version "latest";
 *   - object-shaped config value → validated passthrough (NO double-wrap:
 *     the returned binding must be flat, never a binding inside a binding);
 *   - version passthrough ("latest" / positive integer);
 *   - invalid values throw OPAQUE errors that never echo the raw value.
 */
import { describe, it, expect, vi } from "vitest";
import { toSecretRefBinding, type SecretRefBinding } from "./secretRefBinding.js";

const UUID = "679b5cb9-079e-45a2-9423-c1720172131a";
const UUID2 = "12345678-90ab-4cde-8f01-234567890abc";

describe("toSecretRefBinding — legacy string shape", () => {
  it("wraps a bare-UUID string into the canonical binding with version latest", () => {
    expect(toSecretRefBinding(UUID)).toEqual({
      type: "secret_ref",
      secretId: UUID,
      version: "latest",
    });
  });

  it("accepts surrounding whitespace on the legacy string", () => {
    expect(toSecretRefBinding(`  ${UUID}  `).secretId).toBe(UUID);
  });

  it("rejects a non-UUID string with an opaque error that does not echo the value", () => {
    const raw = "not-a-uuid-secret-string";
    expect(() => toSecretRefBinding(raw)).toThrowError(/invalid secret ref/);
    try {
      toSecretRefBinding(raw);
      expect.unreachable("must throw");
    } catch (err) {
      const msg = (err as Error).message;
      expect(msg).not.toContain(raw);
    }
  });

  it("rejects an empty string", () => {
    expect(() => toSecretRefBinding("")).toThrowError(/invalid secret ref/);
  });
});

describe("toSecretRefBinding — object shape", () => {
  it("passes a canonical binding through WITHOUT double-wrapping", () => {
    const stored: SecretRefBinding = { type: "secret_ref", secretId: UUID, version: "latest" };
    const out = toSecretRefBinding(stored);
    expect(out).toEqual({ type: "secret_ref", secretId: UUID, version: "latest" });
    // The fatal double-wrap shape — a binding nested inside a binding — must
    // be structurally impossible: the output's secretId is the UUID itself.
    expect((out.secretId as unknown as { type?: string }).type).toBeUndefined();
  });

  it("drops an explicit undefined version rather than carrying it", () => {
    const out = toSecretRefBinding({ type: "secret_ref", secretId: UUID, version: undefined });
    expect(out).toEqual({ type: "secret_ref", secretId: UUID });
    expect("version" in out).toBe(false);
  });

  it("preserves a pinned integer version", () => {
    expect(toSecretRefBinding({ type: "secret_ref", secretId: UUID, version: 3 })).toEqual({
      type: "secret_ref",
      secretId: UUID,
      version: 3,
    });
  });

  it("normalizes a different stored secret through the same shape", () => {
    expect(toSecretRefBinding({ type: "secret_ref", secretId: UUID2 }).secretId).toBe(UUID2);
  });

  it("rejects a binding with a wrong type discriminator", () => {
    expect(() =>
      toSecretRefBinding({ type: "plain" as "secret_ref", secretId: UUID }),
    ).toThrowError(/invalid secret ref/);
  });

  it("rejects a binding with a non-UUID secretId without echoing it", () => {
    const bad = "leak-me-please";
    try {
      toSecretRefBinding({ type: "secret_ref", secretId: bad });
      expect.unreachable("must throw");
    } catch (err) {
      expect((err as Error).message).not.toContain(bad);
    }
  });

  it("rejects a binding with a zero/negative/fractional version", () => {
    expect(() => toSecretRefBinding({ type: "secret_ref", secretId: UUID, version: 0 })).toThrowError(/version/);
    expect(() => toSecretRefBinding({ type: "secret_ref", secretId: UUID, version: -1 })).toThrowError(/version/);
    expect(() => toSecretRefBinding({ type: "secret_ref", secretId: UUID, version: 1.5 })).toThrowError(/version/);
  });
});

describe("toSecretRefBinding — non-value shapes", () => {
  it("rejects null, numbers, and arrays opaquely", () => {
    for (const bad of [null, 42, [UUID], true]) {
      expect(() => toSecretRefBinding(bad as unknown as string)).toThrowError(/invalid secret ref/);
    }
  });
});

describe("resolveSecretRef — resolve seam", () => {
  it("calls ctx.secrets.resolve with the canonical binding for a string value", async () => {
    const { resolveSecretRef } = await import("./secretRefBinding.js");
    const resolve = vi.fn(async () => "pat");
    await resolveSecretRef({ resolve }, UUID);
    expect(resolve).toHaveBeenCalledTimes(1);
    expect(resolve).toHaveBeenCalledWith({ type: "secret_ref", secretId: UUID, version: "latest" });
  });

  it("calls ctx.secrets.resolve with the same binding for the equivalent object value", async () => {
    const { resolveSecretRef } = await import("./secretRefBinding.js");
    const resolve = vi.fn(async () => "pat");
    await resolveSecretRef({ resolve }, { type: "secret_ref", secretId: UUID, version: "latest" });
    expect(resolve).toHaveBeenCalledWith({ type: "secret_ref", secretId: UUID, version: "latest" });
  });

  it("propagates resolver rejections unchanged", async () => {
    const { resolveSecretRef } = await import("./secretRefBinding.js");
    const resolve = vi.fn(async () => {
      throw new Error("denied");
    });
    await expect(resolveSecretRef({ resolve }, UUID)).rejects.toThrowError("denied");
  });
});
