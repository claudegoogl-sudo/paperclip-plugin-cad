/**
 * CAD plugin worker — sub-goal 3 (PLA-55): cad:run_script + cad:export tool API surface.
 *
 * Tools registered (v0.1.0 surface, operator-confirmed via approval f420bc31):
 *   cad:run_script  — execute a CadQuery Python script; return { artifactId, summary }
 *   cad:export      — export a staged artifact to step|stl|3mf; return { filePath }
 *
 * Cross-cutting requirements (PLA-55 ACs):
 *   AC2  JSON-schema input validation → structured error, no stack traces
 *   AC3  ctx.metrics: tool.calls counter, tool.errors counter, tool.duration_ms histogram
 *   AC4  ctx.logger.info correlation log: correlationId, tool, agentId, status, durationMs.
 *        Payload contents NOT logged — only digests/lengths.
 *   AC5  Error taxonomy: validation_error, worker_timeout, worker_internal, auth.
 *        No silent swallowing.
 *   AC6  Stub worker wired via one-line integration switch (see comment below).
 *   AC7  cad:hello removed in manifest.ts.
 *
 * INTEGRATION SWITCH (sub-goal 2 handoff) — change this one import line when real worker lands:
 */
// --- INTEGRATION SWITCH (sub-goal 2) — change this one line: ---
import {
  createCadWorker,
  CadWorkerTimeoutError,
  CadWorkerInternalError,
} from "./stub-cad-worker.js";
// When sub-goal 2 (real CadQuery worker client) is ready, replace with:
//   import { createCadWorker, CadWorkerTimeoutError, CadWorkerInternalError } from "./cad-worker-client.js";
// ---------------------------------------------------------------

import { definePlugin, runWorker } from "@paperclipai/plugin-sdk";
import type { PluginContext, ToolRunContext, ToolResult } from "@paperclipai/plugin-sdk";
import { createHash } from "node:crypto";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Digest a string for safe logging — never log raw payload content (AC4). */
function shortDigest(s: string): string {
  return `sha256:${createHash("sha256").update(s).digest("hex").slice(0, 16)}`;
}

/** Error taxonomy codes (AC5). */
type ErrorCode = "validation_error" | "worker_timeout" | "worker_internal" | "auth";

function errorStatusCode(code: ErrorCode): number {
  switch (code) {
    case "validation_error": return 400;
    case "auth":             return 403;
    case "worker_internal":  return 500;
    case "worker_timeout":   return 504;
  }
}

/**
 * Build a structured error ToolResult (AC2/AC5).
 * No stack traces in the message. statusCode in data for host HTTP mapping.
 */
function makeError(code: ErrorCode, message: string): ToolResult {
  return {
    error: `${code}: ${message}`,
    data: { code, message, statusCode: errorStatusCode(code) },
  };
}

// ---------------------------------------------------------------------------
// Observability wrapper — emits metrics + correlation log for every call (AC3/AC4)
// ---------------------------------------------------------------------------

async function withObservability(
  ctx: PluginContext,
  runCtx: ToolRunContext,
  toolName: string,
  fn: () => Promise<ToolResult>,
): Promise<ToolResult> {
  const start = Date.now();
  const correlationId = runCtx.runId;
  let status = "ok";
  let result: ToolResult;

  await ctx.metrics.write("tool.calls", 1, { tool: toolName });

  try {
    result = await fn();
    if (result.error) {
      const data = result.data as { code?: string } | undefined;
      status = data?.code ?? "error";
    }
  } catch (err) {
    // AC5: no silent swallowing
    const message = err instanceof Error ? err.message : "Unexpected error in tool handler";
    result = makeError("worker_internal", message);
    status = "worker_internal";
  }

  const durationMs = Date.now() - start;

  if (status !== "ok") {
    await ctx.metrics.write("tool.errors", 1, { tool: toolName });
  }
  await ctx.metrics.write("tool.duration_ms", durationMs, { tool: toolName });

  // AC4: correlation log — no payload content
  ctx.logger.info("tool call complete", {
    correlationId,
    tool: toolName,
    agentId: runCtx.agentId,
    status,
    durationMs,
  });

  return result;
}

// ---------------------------------------------------------------------------
// Input validators (AC2: structured error, no stack traces)
// ---------------------------------------------------------------------------

type ValidationResult<T> = { ok: true; params: T } | { ok: false; message: string };

function validateRunScript(
  raw: unknown,
): ValidationResult<{ script: string; timeout?: number }> {
  if (typeof raw !== "object" || raw === null) {
    return { ok: false, message: "params must be an object" };
  }
  const p = raw as Record<string, unknown>;
  if (typeof p.script !== "string" || p.script.length === 0) {
    return { ok: false, message: "'script' is required and must be a non-empty string" };
  }
  if (p.timeout !== undefined) {
    const t = Number(p.timeout);
    if (!Number.isInteger(t) || t < 1 || t > 300) {
      return { ok: false, message: "'timeout' must be an integer between 1 and 300" };
    }
  }
  return { ok: true, params: { script: p.script as string, timeout: p.timeout as number | undefined } };
}

function validateExport(
  raw: unknown,
): ValidationResult<{ artifactId: string; format: "step" | "stl" | "3mf" }> {
  if (typeof raw !== "object" || raw === null) {
    return { ok: false, message: "params must be an object" };
  }
  const p = raw as Record<string, unknown>;
  if (typeof p.artifactId !== "string" || p.artifactId.length === 0) {
    return { ok: false, message: "'artifactId' is required and must be a non-empty string" };
  }
  const validFormats = ["step", "stl", "3mf"];
  if (!validFormats.includes(p.format as string)) {
    return { ok: false, message: `'format' must be one of: ${validFormats.join(", ")}` };
  }
  return {
    ok: true,
    params: {
      artifactId: p.artifactId as string,
      format: p.format as "step" | "stl" | "3mf",
    },
  };
}

// ---------------------------------------------------------------------------
// Plugin definition
// ---------------------------------------------------------------------------

const DEFAULT_TIMEOUT_S = 30;

const plugin = definePlugin({
  async setup(ctx: PluginContext) {
    ctx.logger.info("CAD plugin worker starting (v0.1.0 — cad:run_script + cad:export)");

    // INTEGRATION SWITCH: createCadWorker() is the only call that changes
    // when sub-goal 2 (real worker) lands. Everything below is worker-agnostic.
    const cadWorker = createCadWorker();

    // ------------------------------------------------------------------
    // cad:run_script — execute a CadQuery Python script (AC1)
    // ------------------------------------------------------------------
    ctx.tools.register(
      "cad:run_script",
      {
        displayName: "CAD Run Script",
        description: "Execute a CadQuery Python script. Returns { artifactId, summary }.",
        parametersSchema: {
          type: "object",
          properties: {
            script: { type: "string" },
            timeout: { type: "integer", minimum: 1, maximum: 300 },
          },
          required: ["script"],
          additionalProperties: false,
        },
      },
      async (rawParams: unknown, runCtx: ToolRunContext): Promise<ToolResult> => {
        return withObservability(ctx, runCtx, "cad:run_script", async () => {
          const validation = validateRunScript(rawParams);
          if (!validation.ok) {
            return makeError("validation_error", validation.message);
          }
          const { script, timeout = DEFAULT_TIMEOUT_S } = validation.params;

          // AC4: log digest/length, not content
          ctx.logger.info("cad:run_script dispatching to worker", {
            correlationId: runCtx.runId,
            agentId: runCtx.agentId,
            scriptDigest: shortDigest(script),
            scriptLen: script.length,
            timeoutSeconds: timeout,
          });

          try {
            const workerResult = await cadWorker.runScript(script, timeout);
            return {
              content: `Artifact created: ${workerResult.artifactId}\n${workerResult.summary}`,
              data: { artifactId: workerResult.artifactId, summary: workerResult.summary },
            };
          } catch (err) {
            if (err instanceof CadWorkerTimeoutError) return makeError("worker_timeout", err.message);
            if (err instanceof CadWorkerInternalError) return makeError("worker_internal", err.message);
            return makeError("worker_internal", err instanceof Error ? err.message : "Unknown worker error");
          }
        });
      },
    );

    // ------------------------------------------------------------------
    // cad:export — export a staged artifact to a file (AC1)
    // ------------------------------------------------------------------
    ctx.tools.register(
      "cad:export",
      {
        displayName: "CAD Export",
        description:
          "Export a staged artifact to step|stl|3mf. " +
          "Returns { filePath } within the plugin artifact-staging area.",
        parametersSchema: {
          type: "object",
          properties: {
            artifactId: { type: "string" },
            format: { type: "string", enum: ["step", "stl", "3mf"] },
          },
          required: ["artifactId", "format"],
          additionalProperties: false,
        },
      },
      async (rawParams: unknown, runCtx: ToolRunContext): Promise<ToolResult> => {
        return withObservability(ctx, runCtx, "cad:export", async () => {
          const validation = validateExport(rawParams);
          if (!validation.ok) {
            return makeError("validation_error", validation.message);
          }
          const { artifactId, format } = validation.params;

          // AC4: artifactId is an opaque ID, safe to log
          ctx.logger.info("cad:export dispatching to worker", {
            correlationId: runCtx.runId,
            agentId: runCtx.agentId,
            artifactId,
            format,
          });

          try {
            const workerResult = await cadWorker.export(artifactId, format);
            return {
              content: `Exported ${artifactId} as ${format}: ${workerResult.filePath}`,
              data: { filePath: workerResult.filePath, artifactId, format },
            };
          } catch (err) {
            if (err instanceof CadWorkerTimeoutError) return makeError("worker_timeout", err.message);
            if (err instanceof CadWorkerInternalError) return makeError("worker_internal", err.message);
            return makeError("worker_internal", err instanceof Error ? err.message : "Unknown worker error");
          }
        });
      },
    );

    ctx.logger.info("CAD plugin worker setup complete", { tools: ["cad:run_script", "cad:export"] });
  },

  async onHealth() {
    return { status: "ok", message: "CAD plugin worker is running (stub worker — PLA-55 sub-goal 3)" };
  },
});

export default plugin;
runWorker(plugin, import.meta.url);
