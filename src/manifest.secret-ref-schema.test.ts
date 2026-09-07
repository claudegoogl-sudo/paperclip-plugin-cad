/**
 * Manifest schema invariant tests for the secret-ref config fields.
 *
 * The host's secret-ref collector keys on `format: "secret-ref"` sitting
 * DIRECTLY on the property schema: its walker checks each property node's
 * own `format` and recurses into oneOf/anyOf/allOf branches, but never reads
 * a branch's own `format` as a property. A schema refactor that moves the
 * union into a bare `oneOf` (dropping the property-level `format`) would
 * therefore silently hide githubPatSecretId / intakePatSecretId from
 * host-side secret binding sync while the manifest still validates — the
 * worst failure mode available. These tests pin the discovery contract.
 */
import { describe, it, expect } from "vitest";
import manifest from "./manifest.js";

const SECRET_FIELDS = ["githubPatSecretId", "intakePatSecretId"] as const;

function fieldSchema(name: (typeof SECRET_FIELDS)[number]): Record<string, unknown> {
  const schema = manifest.instanceConfigSchema as {
    properties?: Record<string, Record<string, unknown>>;
    required?: string[];
  };
  const props = schema.properties ?? {};
  return props[name] ?? {};
}

describe("instanceConfigSchema secret-ref discovery contract", () => {
  it("every secret-ref field carries format directly on the property node", () => {
    for (const field of SECRET_FIELDS) {
      expect(fieldSchema(field).format, `${field} must keep property-level format`).toBe("secret-ref");
    }
  });

  it("githubPatSecretId stays required (config cannot drop the export PAT)", () => {
    const schema = manifest.instanceConfigSchema as { required?: string[] };
    expect(schema.required).toContain("githubPatSecretId");
  });

  it("each field unions the legacy string shape with the binding-object shape", () => {
    for (const field of SECRET_FIELDS) {
      const oneOf = fieldSchema(field).oneOf as Array<Record<string, unknown>> | undefined;
      expect(Array.isArray(oneOf), `${field} must be a union`).toBe(true);
      const stringBranch = oneOf?.find((b) => b.type === "string");
      const objectBranch = oneOf?.find((b) => b.type === "object");
      expect(stringBranch, `${field} must accept the legacy string`).toBeTruthy();
      expect(objectBranch, `${field} must accept the binding object`).toBeTruthy();
      expect(stringBranch?.format).toBe("secret-ref");
    }
  });

  it("binding-object branch requires type=secret_ref + UUID secretId, closed to extras", () => {
    for (const field of SECRET_FIELDS) {
      const oneOf = fieldSchema(field).oneOf as Array<Record<string, unknown>>;
      const objectBranch = oneOf.find((b) => b.type === "object") as {
        properties: Record<string, unknown>;
        required?: string[];
        additionalProperties?: boolean;
      };
      expect(objectBranch.required).toEqual(["type", "secretId"]);
      expect(objectBranch.additionalProperties).toBe(false);
      const props = objectBranch.properties as Record<string, Record<string, unknown>>;
      expect(props.type).toEqual({ const: "secret_ref" });
      expect(props.secretId?.format).toBe("uuid");
      // version, when present, is "latest" or a positive integer
      const version = props.version?.oneOf as Array<Record<string, unknown>>;
      expect(version).toContainEqual({ const: "latest" });
      expect(version).toContainEqual({ type: "integer", minimum: 1 });
    }
  });
});
