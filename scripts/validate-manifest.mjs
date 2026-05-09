#!/usr/bin/env node
/**
 * PLA-376 — release-time plugin manifest validation gate.
 *
 * Runs the host's plugin-manifest validator against the built
 * `dist/manifest.js` BEFORE a tarball can be packed/published. Catches
 * schema violations (e.g. the `cad:run_script` tool name regression
 * in v0.1.1, which slipped past CI and reached operator hands before
 * the install attempt revealed it) at release time, on the developer's
 * machine and in CI, instead of after the install fails on the host.
 *
 * Resolves the manifest module via `package.json`'s
 * `paperclipPlugin.manifest` field (per PLUGIN_SPEC §10.1), so any
 * future relocation of the build output is followed automatically.
 *
 * Wired into:
 *   - `npm run validate:manifest` (developer ergonomic)
 *   - `prepack` lifecycle hook (blocks `npm pack` / `npm publish`)
 *   - `.github/workflows/manifest-validate.yml` (PR + push gate)
 *
 * Exits non-zero on any failure, with a clear list of offending fields.
 */
import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { pluginManifestV1Schema } from "@paperclipai/shared/validators/plugin";

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(SCRIPT_DIR, "..");

/**
 * PLA-163 tool-name allowlist — mirrored from the host fork's
 * `pluginToolDeclarationSchema.name` regex. Tool names are namespaced at
 * runtime as `<plugin-id>:<tool-name>`, so the bare name must not contain
 * `:`. A lowercase alnum allowlist also keeps whitespace, control chars,
 * path separators, and unicode lookalikes out of the registry key.
 *
 * The published `@paperclipai/shared@2026.428.0` does not yet carry this
 * regex on `pluginToolDeclarationSchema`; the fork host validator does
 * (packages/shared/src/validators/plugin.ts in upstream-paperclip). We
 * mirror the rule here so the gate matches the host's actual install-time
 * behaviour even before the shared package re-publishes. When the regex
 * lands in the shared package proper, this block becomes a redundant
 * (but still correct) belt-and-braces check.
 */
const TOOL_NAME_REGEX = /^[a-z0-9][a-z0-9._-]*$/;
const TOOL_NAME_REGEX_MESSAGE =
  "Tool name must start with a lowercase alphanumeric and contain only " +
  "lowercase letters, digits, dots, hyphens, or underscores (no ':' — see PLA-163)";

/**
 * Run the gate against an already-loaded manifest object. Exposed so the
 * regression test (tests/validate-manifest.test.ts) can drive the same
 * code path with a synthetic manifest.
 *
 * @param {unknown} manifest
 * @returns {{ ok: true } | { ok: false; errors: string[] }}
 */
export function validateManifest(manifest) {
  /** @type {string[]} */
  const errors = [];

  const parsed = pluginManifestV1Schema.safeParse(manifest);
  if (!parsed.success) {
    for (const issue of parsed.error.issues) {
      const path = issue.path.length > 0 ? issue.path.join(".") : "<root>";
      errors.push(`[zod] ${path}: ${issue.message}`);
    }
  }

  // Defensive layer: even when the upstream zod schema accepts a tool
  // name, enforce the PLA-163 allowlist directly so a stale published
  // shared package does not silently let bad names through this gate.
  const m = /** @type {{ tools?: Array<{ name?: unknown }> }} */ (
    typeof manifest === "object" && manifest !== null ? manifest : {}
  );
  if (Array.isArray(m.tools)) {
    m.tools.forEach((tool, idx) => {
      const name = tool && typeof tool === "object" ? tool.name : undefined;
      if (typeof name !== "string" || !TOOL_NAME_REGEX.test(name)) {
        errors.push(
          `[pla-163] tools[${idx}].name=${JSON.stringify(name)}: ${TOOL_NAME_REGEX_MESSAGE}`,
        );
      }
    });
  }

  return errors.length === 0 ? { ok: true } : { ok: false, errors };
}

async function loadManifestFromPackageJson() {
  const pkgPath = resolve(REPO_ROOT, "package.json");
  const pkgRaw = await readFile(pkgPath, "utf8");
  const pkg = JSON.parse(pkgRaw);
  const manifestRel = pkg?.paperclipPlugin?.manifest;
  if (typeof manifestRel !== "string" || manifestRel.length === 0) {
    throw new Error(
      `package.json is missing 'paperclipPlugin.manifest' (got ${JSON.stringify(manifestRel)}). ` +
        "Add it per PLUGIN_SPEC §10.1 so the release gate can resolve the built manifest.",
    );
  }
  const manifestAbs = resolve(REPO_ROOT, manifestRel);
  if (!existsSync(manifestAbs)) {
    throw new Error(
      `Built manifest not found at ${manifestAbs}. ` +
        "Run `npm run build` before validating, or ensure your release script builds before packing.",
    );
  }
  const mod = await import(pathToFileURL(manifestAbs).href);
  const manifest = mod?.default ?? mod;
  return { manifest, manifestAbs };
}

async function main() {
  const { manifest, manifestAbs } = await loadManifestFromPackageJson();
  const result = validateManifest(manifest);
  if (result.ok) {
    const toolCount = Array.isArray(manifest?.tools) ? manifest.tools.length : 0;
    // eslint-disable-next-line no-console
    console.log(
      `[validate-manifest] OK — ${manifestAbs} passes pluginManifestV1Schema ` +
        `(tools: ${toolCount}).`,
    );
    return 0;
  }
  // eslint-disable-next-line no-console
  console.error(
    `[validate-manifest] FAILED — ${manifestAbs} violates the host plugin-manifest validator:`,
  );
  for (const err of result.errors) {
    // eslint-disable-next-line no-console
    console.error(`  - ${err}`);
  }
  // eslint-disable-next-line no-console
  console.error(
    "\nHost validator source: packages/shared/src/validators/plugin.ts " +
      "(pluginManifestV1Schema). Fix the offending field(s) above and rebuild.",
  );
  return 1;
}

const isDirectInvocation = (() => {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    return pathToFileURL(resolve(entry)).href === import.meta.url;
  } catch {
    return false;
  }
})();

if (isDirectInvocation) {
  main()
    .then((code) => {
      process.exit(code);
    })
    .catch((err) => {
      // eslint-disable-next-line no-console
      console.error("[validate-manifest] unexpected error:", err);
      process.exit(2);
    });
}
