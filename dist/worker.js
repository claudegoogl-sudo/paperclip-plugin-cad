// src/stub-cad-worker.ts
import { randomUUID } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { mkdir, writeFile } from "node:fs/promises";
var CadWorkerTimeoutError = class extends Error {
  code = "worker_timeout";
  constructor(timeoutSeconds) {
    super(`CAD script execution timed out after ${timeoutSeconds}s`);
    this.name = "CadWorkerTimeoutError";
  }
};
var CadWorkerInternalError = class extends Error {
  code = "worker_internal";
  constructor(message) {
    super(message);
    this.name = "CadWorkerInternalError";
  }
};
var ARTIFACT_STAGING_DIR = join(tmpdir(), "paperclip-cad-staging");
var artifactRegistry = /* @__PURE__ */ new Map();
function createCadWorker() {
  return {
    async runScript(script, _timeoutSeconds) {
      const artifactId = randomUUID();
      artifactRegistry.set(artifactId, {
        scriptDigest: `len=${script.length}`
      });
      return {
        artifactId,
        summary: `[stub] Script accepted (${script.length} chars). Real CadQuery execution wires in with sub-goal 2.`
      };
    },
    async export(artifactId, format) {
      const entry = artifactRegistry.get(artifactId);
      if (!entry) {
        throw new CadWorkerInternalError(
          `Unknown artifactId: ${artifactId}. Ensure cad:run_script was called first.`
        );
      }
      await mkdir(ARTIFACT_STAGING_DIR, { recursive: true });
      const filePath = join(ARTIFACT_STAGING_DIR, `${artifactId}.${format}`);
      await writeFile(
        filePath,
        `; CAD stub artifact
; id=${artifactId}
; format=${format}
; script=${entry.scriptDigest}
`
      );
      return { filePath };
    }
  };
}

// src/worker.ts
import { definePlugin, runWorker } from "@paperclipai/plugin-sdk";
import { createHash } from "node:crypto";
function shortDigest(s) {
  return `sha256:${createHash("sha256").update(s).digest("hex").slice(0, 16)}`;
}
function errorStatusCode(code) {
  switch (code) {
    case "validation_error":
      return 400;
    case "auth":
      return 403;
    case "worker_internal":
      return 500;
    case "worker_timeout":
      return 504;
  }
}
function makeError(code, message) {
  return {
    error: `${code}: ${message}`,
    data: { code, message, statusCode: errorStatusCode(code) }
  };
}
async function withObservability(ctx, runCtx, toolName, fn) {
  const start = Date.now();
  const correlationId = runCtx.runId;
  let status = "ok";
  let result;
  await ctx.metrics.write("tool.calls", 1, { tool: toolName });
  try {
    result = await fn();
    if (result.error) {
      const data = result.data;
      status = data?.code ?? "error";
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : "Unexpected error in tool handler";
    result = makeError("worker_internal", message);
    status = "worker_internal";
  }
  const durationMs = Date.now() - start;
  if (status !== "ok") {
    await ctx.metrics.write("tool.errors", 1, { tool: toolName });
  }
  await ctx.metrics.write("tool.duration_ms", durationMs, { tool: toolName });
  ctx.logger.info("tool call complete", {
    correlationId,
    tool: toolName,
    agentId: runCtx.agentId,
    status,
    durationMs
  });
  return result;
}
function validateRunScript(raw) {
  if (typeof raw !== "object" || raw === null) {
    return { ok: false, message: "params must be an object" };
  }
  const p = raw;
  if (typeof p.script !== "string" || p.script.length === 0) {
    return { ok: false, message: "'script' is required and must be a non-empty string" };
  }
  if (p.timeout !== void 0) {
    const t = Number(p.timeout);
    if (!Number.isInteger(t) || t < 1 || t > 300) {
      return { ok: false, message: "'timeout' must be an integer between 1 and 300" };
    }
  }
  return { ok: true, params: { script: p.script, timeout: p.timeout } };
}
function validateExport(raw) {
  if (typeof raw !== "object" || raw === null) {
    return { ok: false, message: "params must be an object" };
  }
  const p = raw;
  if (typeof p.artifactId !== "string" || p.artifactId.length === 0) {
    return { ok: false, message: "'artifactId' is required and must be a non-empty string" };
  }
  const validFormats = ["step", "stl", "3mf"];
  if (!validFormats.includes(p.format)) {
    return { ok: false, message: `'format' must be one of: ${validFormats.join(", ")}` };
  }
  return {
    ok: true,
    params: {
      artifactId: p.artifactId,
      format: p.format
    }
  };
}
var DEFAULT_TIMEOUT_S = 30;
var plugin = definePlugin({
  async setup(ctx) {
    ctx.logger.info("CAD plugin worker starting (v0.1.0 \u2014 cad:run_script + cad:export)");
    const cadWorker = createCadWorker();
    ctx.tools.register(
      "cad:run_script",
      {
        displayName: "CAD Run Script",
        description: "Execute a CadQuery Python script. Returns { artifactId, summary }.",
        parametersSchema: {
          type: "object",
          properties: {
            script: { type: "string" },
            timeout: { type: "integer", minimum: 1, maximum: 300 }
          },
          required: ["script"],
          additionalProperties: false
        }
      },
      async (rawParams, runCtx) => {
        return withObservability(ctx, runCtx, "cad:run_script", async () => {
          const validation = validateRunScript(rawParams);
          if (!validation.ok) {
            return makeError("validation_error", validation.message);
          }
          const { script, timeout = DEFAULT_TIMEOUT_S } = validation.params;
          ctx.logger.info("cad:run_script dispatching to worker", {
            correlationId: runCtx.runId,
            agentId: runCtx.agentId,
            scriptDigest: shortDigest(script),
            scriptLen: script.length,
            timeoutSeconds: timeout
          });
          try {
            const workerResult = await cadWorker.runScript(script, timeout);
            return {
              content: `Artifact created: ${workerResult.artifactId}
${workerResult.summary}`,
              data: { artifactId: workerResult.artifactId, summary: workerResult.summary }
            };
          } catch (err) {
            if (err instanceof CadWorkerTimeoutError) return makeError("worker_timeout", err.message);
            if (err instanceof CadWorkerInternalError) return makeError("worker_internal", err.message);
            return makeError("worker_internal", err instanceof Error ? err.message : "Unknown worker error");
          }
        });
      }
    );
    ctx.tools.register(
      "cad:export",
      {
        displayName: "CAD Export",
        description: "Export a staged artifact to step|stl|3mf. Returns { filePath } within the plugin artifact-staging area.",
        parametersSchema: {
          type: "object",
          properties: {
            artifactId: { type: "string" },
            format: { type: "string", enum: ["step", "stl", "3mf"] }
          },
          required: ["artifactId", "format"],
          additionalProperties: false
        }
      },
      async (rawParams, runCtx) => {
        return withObservability(ctx, runCtx, "cad:export", async () => {
          const validation = validateExport(rawParams);
          if (!validation.ok) {
            return makeError("validation_error", validation.message);
          }
          const { artifactId, format } = validation.params;
          ctx.logger.info("cad:export dispatching to worker", {
            correlationId: runCtx.runId,
            agentId: runCtx.agentId,
            artifactId,
            format
          });
          try {
            const workerResult = await cadWorker.export(artifactId, format);
            return {
              content: `Exported ${artifactId} as ${format}: ${workerResult.filePath}`,
              data: { filePath: workerResult.filePath, artifactId, format }
            };
          } catch (err) {
            if (err instanceof CadWorkerTimeoutError) return makeError("worker_timeout", err.message);
            if (err instanceof CadWorkerInternalError) return makeError("worker_internal", err.message);
            return makeError("worker_internal", err instanceof Error ? err.message : "Unknown worker error");
          }
        });
      }
    );
    ctx.logger.info("CAD plugin worker setup complete", { tools: ["cad:run_script", "cad:export"] });
  },
  async onHealth() {
    return { status: "ok", message: "CAD plugin worker is running (stub worker \u2014 PLA-55 sub-goal 3)" };
  }
});
var worker_default = plugin;
runWorker(plugin, import.meta.url);
export {
  worker_default as default
};
//# sourceMappingURL=worker.js.map
