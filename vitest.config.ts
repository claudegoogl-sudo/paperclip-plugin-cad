import { defineConfig } from "vitest/config";

export default defineConfig({
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
