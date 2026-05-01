/**
 * stub-cad-worker.ts — stub implementation of the CAD worker interface.
 *
 * This module stands in for the real CadQuery worker process until sub-goal 2
 * (PLA-xx) lands. The integration switch in worker.ts is a single import line:
 *
 *   // INTEGRATION SWITCH (sub-goal 2) — change this one import:
 *   import { createCadWorker } from "./stub-cad-worker.js";
 *   // → import { createCadWorker } from "./cad-worker-client.js";
 *
 * Both modules export the same `createCadWorker()` factory returning a `CadWorker`.
 */

import { randomUUID } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { mkdir, writeFile } from "node:fs/promises";

// ---------------------------------------------------------------------------
// Shared type contract — both stub and real worker must satisfy this interface
// ---------------------------------------------------------------------------

export interface RunScriptResult {
  artifactId: string;
  summary: string;
}

export interface ExportResult {
  /** Absolute path within the plugin's artifact-staging area. */
  filePath: string;
}

export type ExportFormat = "step" | "stl" | "3mf";

export interface CadWorker {
  /**
   * Execute a CadQuery Python script.
   * @throws CadWorkerTimeoutError  when the script exceeds the timeout
   * @throws CadWorkerInternalError when execution fails unexpectedly
   */
  runScript(script: string, timeoutSeconds: number): Promise<RunScriptResult>;

  /**
   * Export a staged artifact to the requested file format.
   * @throws CadWorkerInternalError when the artifactId is unknown or export fails
   */
  export(artifactId: string, format: ExportFormat): Promise<ExportResult>;
}

// ---------------------------------------------------------------------------
// Error types — used by worker.ts for the error taxonomy (AC5)
// ---------------------------------------------------------------------------

export class CadWorkerTimeoutError extends Error {
  readonly code = "worker_timeout" as const;
  constructor(timeoutSeconds: number) {
    super(`CAD script execution timed out after ${timeoutSeconds}s`);
    this.name = "CadWorkerTimeoutError";
  }
}

export class CadWorkerInternalError extends Error {
  readonly code = "worker_internal" as const;
  constructor(message: string) {
    super(message);
    this.name = "CadWorkerInternalError";
  }
}

// ---------------------------------------------------------------------------
// Artifact staging area
// ---------------------------------------------------------------------------

/** Absolute path to the plugin's artifact-staging directory. */
export const ARTIFACT_STAGING_DIR = join(tmpdir(), "paperclip-cad-staging");

// ---------------------------------------------------------------------------
// Stub implementation
// ---------------------------------------------------------------------------

/** In-memory artifact registry (process-scoped; cleared on worker restart). */
const artifactRegistry = new Map<string, { scriptDigest: string }>();

/**
 * Create the stub CAD worker.
 *
 * The returned object satisfies the `CadWorker` interface so worker.ts needs
 * no changes when the real worker client is swapped in.
 */
export function createCadWorker(): CadWorker {
  return {
    async runScript(script, _timeoutSeconds) {
      // Stub: register a new artifactId, return immediately without running Python.
      const artifactId = randomUUID();
      artifactRegistry.set(artifactId, {
        scriptDigest: `len=${script.length}`,
      });

      return {
        artifactId,
        summary: `[stub] Script accepted (${script.length} chars). Real CadQuery execution wires in with sub-goal 2.`,
      };
    },

    async export(artifactId, format) {
      const entry = artifactRegistry.get(artifactId);
      if (!entry) {
        throw new CadWorkerInternalError(
          `Unknown artifactId: ${artifactId}. Ensure cad:run_script was called first.`,
        );
      }

      // Ensure staging directory exists.
      await mkdir(ARTIFACT_STAGING_DIR, { recursive: true });

      const filePath = join(ARTIFACT_STAGING_DIR, `${artifactId}.${format}`);
      // Write a stub file so callers get a real path they can stat/read.
      await writeFile(
        filePath,
        `; CAD stub artifact\n; id=${artifactId}\n; format=${format}\n; script=${entry.scriptDigest}\n`,
      );

      return { filePath };
    },
  };
}
