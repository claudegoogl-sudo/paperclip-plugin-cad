/**
 * CadQuery sandbox client — PLA-54.
 *
 * Spawns src/cad_worker.py as an isolated subprocess for each script invocation.
 * One subprocess per request; no persistent worker pool; no shared filesystem
 * state between invocations.
 *
 * ## Process model (PLA-54 design choice)
 *
 * stdin/stdout pipe (option (a) variant — named pipe, not Unix socket file).
 *
 * Rationale:
 *   - No port allocation surface at all (AC2 satisfied trivially — no TCP listener).
 *   - No socket file to clean up on crash.
 *   - Node.js `child_process.spawn` provides buffered stdout / stdin pipes
 *     natively; no binary framing protocol needed (stdin EOF = end-of-input).
 *   - Simpler than a length-prefixed framing scheme while meeting all AC.
 *
 * ## Isolation model
 *
 * Each call to `invokeWorker()`:
 *   1. Creates a fresh `tmpdir` for the invocation.
 *   2. Spawns a new `python3 cad_worker.py` process with that tmpdir.
 *   3. Sends the job JSON to the worker's stdin and closes the pipe.
 *   4. Reads the result JSON from stdout.
 *   5. SIGKILL the worker (if still alive) after `timeoutSeconds + GRACE_SECONDS`.
 *   6. Always waits for the process to exit (no zombies — AC3).
 *   7. The tmpdir and its contents are owned by the caller;
 *      the caller is responsible for cleanup.
 *
 * ## Network restriction (AC6)
 *
 * Enforced inside cad_worker.py by replacing socket / urllib / http.client
 * and related modules with blocking stubs before exec()ing user code.
 * The worker env also strips PATH to `/usr/bin:/bin` to prevent accidental
 * subprocess launches from inside the CadQuery script.
 */

import { spawn } from "node:child_process";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

// Re-export shared types and error classes from the stub so callers import from
// one place regardless of which implementation is active.
export type {
  CadWorker,
  RunScriptResult,
  ExportResult,
  ExportFormat,
} from "./stub-cad-worker.js";
export {
  CadWorkerTimeoutError,
  CadWorkerInternalError,
  ARTIFACT_STAGING_DIR,
} from "./stub-cad-worker.js";

import type { CadWorker, ExportFormat } from "./stub-cad-worker.js";
import { CadWorkerTimeoutError, CadWorkerInternalError } from "./stub-cad-worker.js";
import { randomUUID } from "node:crypto";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Extra seconds the parent waits beyond the user-facing timeout before SIGKILL. */
const GRACE_SECONDS = 5;

/** Maximum per-request timeout ceiling (seconds). */
export const MAX_TIMEOUT_SECONDS = 300;

/** Default per-request timeout (seconds). */
export const DEFAULT_TIMEOUT_SECONDS = 30;

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const WORKER_PY = join(__dirname, "cad_worker.py");

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

interface WorkerJob {
  script: string;
  format: string;
  workdir: string;
}

/** Structured result from the Python worker process. */
export type WorkerResult =
  | { ok: true; artifactPath: string }
  | {
      ok: false;
      error: "script_error" | "worker_internal" | "worker_oom" | "worker_timeout";
      message: string;
    };

// ---------------------------------------------------------------------------
// Core subprocess invocation
// ---------------------------------------------------------------------------

/**
 * Spawn one Python worker process for a single job.
 *
 * @param job            Script, format, and isolated workdir.
 * @param timeoutSeconds Hard timeout for the script (user-facing ceiling).
 * @param pythonBin      Python interpreter path. Defaults to "python3".
 * @returns              WorkerResult from the subprocess.
 */
export async function invokeWorker(
  job: WorkerJob,
  timeoutSeconds: number,
  pythonBin = "python3",
): Promise<WorkerResult> {
  return new Promise((resolve) => {
    const child = spawn(pythonBin, [WORKER_PY], {
      stdio: ["pipe", "pipe", "pipe"],
      env: {
        // Minimal environment to reduce attack surface.
        // PYTHONDONTWRITEBYTECODE: avoids .pyc files in the workdir.
        // PYTHONUNBUFFERED: ensures stdout is flushed immediately.
        PATH: "/usr/bin:/bin",
        PYTHONDONTWRITEBYTECODE: "1",
        PYTHONUNBUFFERED: "1",
      },
    });

    let stdout = "";
    let stderr = "";
    let settled = false;
    let killTimer: ReturnType<typeof setTimeout> | null = null;

    // Once settled, nothing else modifies `resolved`.
    const settle = (result: WorkerResult) => {
      if (settled) return;
      settled = true;
      if (killTimer !== null) clearTimeout(killTimer);
      resolve(result);
    };

    // Hard deadline: SIGKILL + resolve as worker_timeout.
    killTimer = setTimeout(() => {
      if (settled) return;
      settled = true; // block the close handler from double-settling
      try {
        child.kill("SIGKILL");
      } catch {
        // Process may have already exited; ignore.
      }
      // We still wait for the close event to reap the process, but we have
      // already resolved.  The close handler checks `settled` and is a no-op.
      resolve({
        ok: false,
        error: "worker_timeout",
        message: `CAD script timed out after ${timeoutSeconds}s`,
      });
    }, (timeoutSeconds + GRACE_SECONDS) * 1000);

    child.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString("utf8");
    });

    child.stderr.on("data", (chunk: Buffer) => {
      stderr += chunk.toString("utf8");
    });

    child.on("close", (_code: number | null) => {
      if (settled) return; // killed or error-settled already
      if (killTimer !== null) clearTimeout(killTimer);
      // Do NOT set settled = true here — let settle() do it.
      // Setting it before calling settle() would cause settle() to bail early
      // (it checks `if (settled) return`) and the promise would never resolve.

      const line = stdout.trim();
      if (!line) {
        settle({
          ok: false,
          error: "worker_internal",
          message:
            `Worker produced no output on stdout. ` +
            `stderr: ${stderr.slice(0, 500)}`,
        });
        return;
      }

      // The worker always writes exactly one JSON line.
      const newlineIdx = line.indexOf("\n");
      const firstLine = newlineIdx === -1 ? line : line.slice(0, newlineIdx);

      try {
        const result = JSON.parse(firstLine) as WorkerResult;
        settle(result);
      } catch {
        settle({
          ok: false,
          error: "worker_internal",
          message: `Worker output was not valid JSON: ${firstLine.slice(0, 200)}`,
        });
      }
    });

    child.on("error", (err: Error) => {
      settle({
        ok: false,
        error: "worker_internal",
        message: `Failed to spawn worker process: ${err.message}`,
      });
    });

    // Deliver job to the worker via stdin.
    const jobJson = JSON.stringify(job as WorkerJob);
    child.stdin.write(jobJson, "utf8", () => {
      child.stdin.end();
    });
  });
}

// ---------------------------------------------------------------------------
// Public API: renderCadQuery
// ---------------------------------------------------------------------------

/**
 * Run a CadQuery script in an isolated subprocess and return the artifact path.
 *
 * Creates a fresh tmpdir per invocation (AC4: no shared filesystem state).
 * Enforces a hard SIGKILL timeout (AC3).
 * No TCP listener (AC2 satisfied by design — stdin/stdout only).
 *
 * @param script         CadQuery Python source.  Must assign to `result`.
 * @param format         Output format: "step" | "stl" | "3mf".
 * @param timeoutSeconds Per-request timeout in seconds.  Capped at MAX_TIMEOUT_SECONDS.
 * @returns              WorkerResult with artifactPath on success or error code.
 */
export async function renderCadQuery(
  script: string,
  format: "step" | "stl" | "3mf",
  timeoutSeconds: number = DEFAULT_TIMEOUT_SECONDS,
): Promise<WorkerResult> {
  const effectiveTimeout = Math.min(
    Math.max(1, timeoutSeconds),
    MAX_TIMEOUT_SECONDS,
  );

  // AC4: fresh isolated tmpdir per request — no shared state between invocations.
  const workdir = await mkdtemp(join(tmpdir(), "cad-worker-"));

  return invokeWorker({ script, format, workdir }, effectiveTimeout);
}

// ---------------------------------------------------------------------------
// CadWorker factory (integration switch target from worker.ts)
// ---------------------------------------------------------------------------

/**
 * Artifact registry entry — maps an artifactId to the script that produced it.
 * The script is re-run for each format conversion so the Python worker stays
 * format-agnostic (no STEP-import round-trip needed).
 *
 * Registry is process-scoped; cleared on worker restart.
 */
interface ArtifactEntry {
  script: string;
}

/**
 * Create the real CadQuery worker client.
 *
 * Satisfies the same `CadWorker` interface as the stub in stub-cad-worker.ts.
 * The integration switch in worker.ts is a single import line change.
 *
 * runScript():
 *   - Spawns an isolated Python subprocess per invocation (AC4).
 *   - Enforces hard SIGKILL timeout (AC3).
 *   - Maps worker error codes to CadWorkerTimeoutError / CadWorkerInternalError.
 *   - Stores (artifactId → script) in process memory so export() can re-run it.
 *
 * export():
 *   - Retrieves the stored script by artifactId and re-runs the worker with
 *     the requested format (avoids a STEP-import round-trip, keeps the worker
 *     Python simple, and supports step/stl/3mf uniformly).
 */
export function createCadWorker(): CadWorker {
  const registry = new Map<string, ArtifactEntry>();

  return {
    async runScript(script: string, timeoutSeconds: number) {
      const result = await renderCadQuery(script, "step", timeoutSeconds);

      if (!result.ok) {
        if (result.error === "worker_timeout") {
          throw new CadWorkerTimeoutError(timeoutSeconds);
        }
        throw new CadWorkerInternalError(
          `[${result.error}] ${result.message}`,
        );
      }

      const artifactId = randomUUID();
      registry.set(artifactId, { script });

      return {
        artifactId,
        summary: `CadQuery script executed successfully. Artifact staged at ${result.artifactPath}`,
      };
    },

    async export(artifactId: string, format: ExportFormat) {
      const entry = registry.get(artifactId);
      if (!entry) {
        throw new CadWorkerInternalError(
          `Unknown artifactId: ${artifactId}. Ensure cad:run_script was called first.`,
        );
      }

      const result = await renderCadQuery(entry.script, format, DEFAULT_TIMEOUT_SECONDS);

      if (!result.ok) {
        if (result.error === "worker_timeout") {
          throw new CadWorkerTimeoutError(DEFAULT_TIMEOUT_SECONDS);
        }
        throw new CadWorkerInternalError(
          `[${result.error}] ${result.message}`,
        );
      }

      return { filePath: result.artifactPath };
    },
  };
}
