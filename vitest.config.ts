import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

// PLA-526 — mirror esbuild's `define` so vitest can import `src/manifest.ts`
// without a `ReferenceError` on the build-time-injected `__PLUGIN_VERSION__`
// global. Vitest's `define` uses the same JSON-literal substitution
// semantics as esbuild, so `JSON.stringify` is required for string values.
const REPO_ROOT = dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(readFileSync(resolve(REPO_ROOT, "package.json"), "utf8"));

export default defineConfig({
  define: {
    __PLUGIN_VERSION__: JSON.stringify(pkg.version),
  },
  test: {
    environment: "node",
    testTimeout: 30_000,
    // Default the unit-test runtime to dev_direct mode (in-process layer
    // only). The PLA-114 bwrap integration matrix and perf gates clear
    // this flag in their own beforeAll() to force the kernel-sandbox
    // path. Production code paths (NODE_ENV=production) ignore this var
    // — see selectSpawnMode() in src/cad-worker-client.ts.
    env: {
      CAD_WORKER_UNSAFE_DEV: "1",
    },
  },
});
