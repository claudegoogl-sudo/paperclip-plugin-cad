/**
 * Invocation-id echo regression: drives a worker->host call INSIDE a
 * dispatched tool call against the BUILT dist/worker.js (the bytes that
 * ship), with a stub host that enforces the invocation id the way the real
 * host does once a worker declares `echoesInvocationId`: any worker->host
 * request that does not echo the active `paperclipInvocationId` is rejected
 * with -32005 ("missing, expired, or unknown invocation scope").
 *
 * Path driven: cad.run_script with inputArtifacts, which calls config.get and
 * then secrets.resolve before any CAD toolchain is touched. The stub fails the
 * resolve with a non-scope error after checking the id, so no network fetch
 * happens. Requires `npm run build` first (the fast CI gate builds before it
 * runs unit tests).
 */
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const WORKER = fileURLToPath(new URL("../dist/worker.js", import.meta.url));
const CO = "11111111-1111-4111-8111-111111111111";
const AGENT = "22222222-2222-4222-8222-222222222222";
const RUN = "33333333-3333-4333-8333-333333333333";
const SECRET = "44444444-4444-4444-8444-444444444444";
const INVOCATION_ID = "inv-echo-test-1";
const SCOPE_ERR = -32005;

type Msg = Record<string, any>;

describe("dist/worker.js echoes the invocation id on in-dispatch host calls", () => {
  it("config.get and secrets.resolve carry paperclipInvocationId", async () => {
    expect(existsSync(WORKER), "run `npm run build` first").toBe(true);
    const child = spawn(process.execPath, [WORKER], { stdio: ["pipe", "pipe", "inherit"] });
    const send = (m: Msg) => child.stdin.write(JSON.stringify(m) + "\n");
    const workerCalls: Msg[] = [];
    const responses = new Map<number | string, (m: Msg) => void>();
    const rl = createInterface({ input: child.stdout });
    rl.on("line", (line) => {
      let m: Msg;
      try { m = JSON.parse(line); } catch { return; }
      if (m.method && m.id !== undefined) {
        // worker -> host request: enforce the echo like the real host.
        workerCalls.push(m);
        if (m.paperclipInvocationId !== INVOCATION_ID) {
          send({ jsonrpc: "2.0", id: m.id, error: { code: SCOPE_ERR, message: "missing, expired, or unknown invocation scope" } });
        } else if (m.method === "config.get") {
          send({ jsonrpc: "2.0", id: m.id, result: { githubPatSecretId: SECRET } });
        } else if (m.method === "secrets.resolve") {
          send({ jsonrpc: "2.0", id: m.id, error: { code: -32000, message: "stub: resolve reached with valid scope" } });
        } else {
          send({ jsonrpc: "2.0", id: m.id, result: null });
        }
      } else if (m.id !== undefined && responses.has(m.id)) {
        responses.get(m.id)!(m);
      }
    });
    const call = (id: number, method: string, params: unknown, extra: Msg = {}) =>
      new Promise<Msg>((resolve) => { responses.set(id, resolve); send({ jsonrpc: "2.0", id, method, params, ...extra }); });

    try {
      const init = await call(1, "initialize", {
        manifest: { id: "platform.cad" }, config: {},
        instanceInfo: { instanceId: "test", hostVersion: "0.0.0" }, apiVersion: 1,
      });
      expect(init.result?.echoesInvocationId).toBe(true);

      const res = await call(2, "executeTool", {
        toolName: "cad.run_script",
        parameters: { script: "result = None", inputArtifacts: [{ repoPath: "user-uploads/scan.stl" }] },
        runContext: { agentId: AGENT, runId: RUN, companyId: CO },
      }, { paperclipInvocation: { id: INVOCATION_ID, scope: { companyId: CO, runId: RUN } } });

      const byMethod = (name: string) => workerCalls.filter((c) => c.method === name);
      expect(byMethod("config.get").length).toBeGreaterThan(0);
      expect(byMethod("secrets.resolve").length).toBeGreaterThan(0);
      for (const c of [...byMethod("config.get"), ...byMethod("secrets.resolve")]) {
        expect(c.paperclipInvocationId).toBe(INVOCATION_ID);
      }
      expect(JSON.stringify(res)).not.toMatch(/invocation scope/);
    } finally {
      rl.close();
      child.kill();
    }
  }, 30_000);
});
