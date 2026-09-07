/**
 * Secret-ref call-shape normalize for `ctx.secrets.resolve`.
 *
 * The host's company-context resolve path (in-dispatch, runId attached)
 * requires the shared `{ type: "secret_ref", secretId, version? }` binding
 * object and rejects a bare secret-id string outright. The instance config,
 * however, may hold EITHER shape: legacy rows store a bare secret UUID
 * string, while new operator writes use the binding object (the manifest
 * schema accepts both — see instanceConfigSchema in manifest.ts).
 *
 * The vendored plugin SDK is pinned at 2026.428.0, whose
 * `PluginSecretsClient.resolve` types only the legacy string (the pin is
 * deliberate — see the SDK-vendoring commit). The host forwards the resolve
 * argument verbatim to the resolver, so the binding object round-trips
 * correctly; the single cast below is the pinned-SDK type seam and must
 * stay in this one place.
 */

/** Canonical binding object accepted by the host's resolve path. */
export interface SecretRefBinding {
  type: "secret_ref";
  secretId: string;
  version?: "latest" | number;
}

/** Shape a secret-ref config field may hold (legacy string OR binding). */
export type SecretRefValue = string | SecretRefBinding;

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Normalize a config value (legacy bare-UUID string OR binding object) into
 * the canonical binding object for in-dispatch resolve.
 *
 * - string: must be a bare secret UUID (the legacy stored shape); wrapped
 *   with `version: "latest"`.
 * - object: validated passthrough — `type` must be "secret_ref", `secretId`
 *   a UUID; `version`, when present, "latest" or a positive integer.
 *
 * Anything else throws an opaque error that never echoes the raw value
 * (secret material must not leak into tool errors).
 */
export function toSecretRefBinding(value: SecretRefValue): SecretRefBinding {
  if (typeof value === "string") {
    const secretId = value.trim();
    if (!UUID_RE.test(secretId)) {
      throw new Error(
        'invalid secret ref: expected a secret UUID string or a { type: "secret_ref", secretId, version? } object',
      );
    }
    return { type: "secret_ref", secretId, version: "latest" };
  }
  if (value !== null && typeof value === "object") {
    const { type, secretId, version } = value as Partial<SecretRefBinding>;
    const trimmedId = typeof secretId === "string" ? secretId.trim() : "";
    if (type !== "secret_ref" || !UUID_RE.test(trimmedId)) {
      throw new Error(
        'invalid secret ref: binding object must be { type: "secret_ref", secretId, version? } with a UUID secretId',
      );
    }
    const binding: SecretRefBinding = { type: "secret_ref", secretId: trimmedId };
    if (version !== undefined) {
      if (version !== "latest" && !(typeof version === "number" && Number.isInteger(version) && version > 0)) {
        throw new Error('invalid secret ref: version must be "latest" or a positive integer');
      }
      binding.version = version;
    }
    return binding;
  }
  throw new Error(
    'invalid secret ref: expected a secret UUID string or a { type: "secret_ref", secretId, version? } object',
  );
}

/**
 * Resolve a config secret-ref value through `ctx.secrets` with the canonical
 * call shape. Both accepted config shapes converge on the same binding
 * object, so a legacy string row and a migrated object row resolve
 * identically (no double-wrap of an object-shaped stored value).
 */
export function resolveSecretRef(
  secrets: { resolve: (secretRef: string) => Promise<string> },
  value: SecretRefValue,
): Promise<string> {
  const resolveBinding = secrets.resolve as unknown as (binding: SecretRefBinding) => Promise<string>;
  return resolveBinding(toSecretRefBinding(value));
}
