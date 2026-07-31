/**
 * Manifest/package.json version parity gate.
 *
 * v0.1.3 shipped with package.json.version="0.1.3" but src/manifest.ts
 * still carrying version: "0.1.2". The tarball filename and git tag
 * read 0.1.3 correctly, but the host registers the plugin row using
 * manifest.version, so `paperclipai plugin inspect` reported 0.1.2
 * after a clean install of the v0.1.3 tarball.
 *
 * This test fails the build if the two literals drift again.
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import manifest from "./manifest.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(
  readFileSync(join(__dirname, "..", "package.json"), "utf8"),
);

describe("manifest/package.json version parity", () => {
  it("manifest.version === package.json.version", () => {
    expect(manifest.version).toBe(pkg.version);
  });
});
