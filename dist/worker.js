// src/worker.ts
import { definePlugin, runWorker } from "@paperclipai/plugin-sdk";

// src/cad-worker-client.ts
import { spawn } from "node:child_process";
import { mkdtemp } from "node:fs/promises";
import { tmpdir as tmpdir2 } from "node:os";
import { join as join2, dirname } from "node:path";
import { fileURLToPath } from "node:url";

// src/stub-cad-worker.ts
import { tmpdir } from "node:os";
import { join } from "node:path";
var ARTIFACT_STAGING_DIR = join(tmpdir(), "paperclip-cad-staging");

// src/cad-worker-client.ts
var GRACE_SECONDS = 5;
var MAX_TIMEOUT_SECONDS = 300;
var DEFAULT_TIMEOUT_SECONDS = 30;
var __filename = fileURLToPath(import.meta.url);
var __dirname = dirname(__filename);
var WORKER_PY = join2(__dirname, "cad_worker.py");
async function invokeWorker(job, timeoutSeconds, pythonBin = "python3") {
  return new Promise((resolve) => {
    const child = spawn(pythonBin, [WORKER_PY], {
      stdio: ["pipe", "pipe", "pipe"],
      env: {
        // Minimal environment to reduce attack surface.
        // PYTHONDONTWRITEBYTECODE: avoids .pyc files in the workdir.
        // PYTHONUNBUFFERED: ensures stdout is flushed immediately.
        PATH: "/usr/bin:/bin",
        PYTHONDONTWRITEBYTECODE: "1",
        PYTHONUNBUFFERED: "1"
      }
    });
    let stdout = "";
    let stderr = "";
    let settled = false;
    let killTimer = null;
    const settle = (result) => {
      if (settled) return;
      settled = true;
      if (killTimer !== null) clearTimeout(killTimer);
      resolve(result);
    };
    killTimer = setTimeout(() => {
      if (settled) return;
      settled = true;
      try {
        child.kill("SIGKILL");
      } catch {
      }
      resolve({
        ok: false,
        error: "worker_timeout",
        message: `CAD script timed out after ${timeoutSeconds}s`
      });
    }, (timeoutSeconds + GRACE_SECONDS) * 1e3);
    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString("utf8");
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString("utf8");
    });
    child.on("close", (_code) => {
      if (settled) return;
      if (killTimer !== null) clearTimeout(killTimer);
      const line = stdout.trim();
      if (!line) {
        settle({
          ok: false,
          error: "worker_internal",
          message: `Worker produced no output on stdout. stderr: ${stderr.slice(0, 500)}`
        });
        return;
      }
      const newlineIdx = line.indexOf("\n");
      const firstLine = newlineIdx === -1 ? line : line.slice(0, newlineIdx);
      try {
        const result = JSON.parse(firstLine);
        settle(result);
      } catch {
        settle({
          ok: false,
          error: "worker_internal",
          message: `Worker output was not valid JSON: ${firstLine.slice(0, 200)}`
        });
      }
    });
    child.on("error", (err) => {
      settle({
        ok: false,
        error: "worker_internal",
        message: `Failed to spawn worker process: ${err.message}`
      });
    });
    const jobJson = JSON.stringify(job);
    child.stdin.write(jobJson, "utf8", () => {
      child.stdin.end();
    });
  });
}
async function renderCadQuery(script, format, timeoutSeconds = DEFAULT_TIMEOUT_SECONDS) {
  const effectiveTimeout = Math.min(
    Math.max(1, timeoutSeconds),
    MAX_TIMEOUT_SECONDS
  );
  const workdir = await mkdtemp(join2(tmpdir2(), "cad-worker-"));
  return invokeWorker({ script, format, workdir }, effectiveTimeout);
}

// src/worker.ts
var DEFAULT_ARTIFACT_REPO_URL = "https://github.com/claudegoogl-sudo/cad-artifacts.git";
var DEFAULT_ARTIFACT_BRANCH = "main";
var artifactStagingMap = /* @__PURE__ */ new Map();
var PushError = class extends Error {
  kind;
  httpStatus;
  constructor(kind, message, httpStatus) {
    super(message);
    this.name = "PushError";
    this.kind = kind;
    this.httpStatus = httpStatus;
  }
};
function validationError(message) {
  return { error: "validation_error", data: { code: "validation_error", statusCode: 400, message } };
}
function workerInternalError(message) {
  return { data: { code: "worker_internal", statusCode: 500, message } };
}
async function emitMetrics(ctx, tool, durationMs, isError) {
  await ctx.metrics?.write("tool.calls", 1, { tool });
  await ctx.metrics?.write("tool.duration_ms", durationMs, { tool });
  if (isError) await ctx.metrics?.write("tool.errors", 1, { tool });
}
function logCompletion(ctx, tool, runCtx, durationMs, status) {
  ctx.logger.info("tool call complete", {
    correlationId: runCtx.runId,
    tool,
    agentId: runCtx.agentId,
    status,
    durationMs
  });
}
function githubHeaders(pat) {
  return {
    Authorization: `Bearer ${pat}`,
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "Content-Type": "application/json",
    "User-Agent": "paperclip-plugin-cad/0.1.0"
  };
}
function parseGitHubUrl(repoUrl) {
  const match = repoUrl.match(/github\.com\/([^/]+)\/([^/]+?)(?:\.git)?$/);
  if (!match) throw new PushError("prerequisite_missing", `Cannot parse GitHub URL: ${repoUrl}`);
  return [match[1], match[2]];
}
async function checkRepoPrerequisite(pat, repoUrl) {
  const [owner, repo] = parseGitHubUrl(repoUrl);
  const headers = githubHeaders(pat);
  let resp;
  try {
    resp = await fetch(`https://api.github.com/repos/${owner}/${repo}`, { headers });
  } catch (err) {
    throw new PushError("network", `Network error reaching ${owner}/${repo}: ${err.message}`);
  }
  if (resp.status === 404) {
    throw new PushError(
      "prerequisite_missing",
      `Artifact repo not found (404): ${owner}/${repo}. Operator must pre-create the repo and grant PAT access. See PLA-56 AC#1.`,
      404
    );
  }
  if (resp.status === 401 || resp.status === 403) {
    throw new PushError(
      "prerequisite_missing",
      `Artifact repo not accessible (${resp.status}): ${owner}/${repo}. Verify PAT has repo scope. See PLA-56 AC#1.`,
      resp.status
    );
  }
  if (!resp.ok) {
    throw new PushError("network", `Unexpected ${resp.status} checking ${owner}/${repo}. Retry later.`, resp.status);
  }
}
async function checkArtifactExists(pat, repoUrl, repoPath) {
  let owner, repo;
  try {
    [owner, repo] = parseGitHubUrl(repoUrl);
  } catch {
    return null;
  }
  const headers = githubHeaders(pat);
  let contentsResp;
  try {
    contentsResp = await fetch(`https://api.github.com/repos/${owner}/${repo}/contents/${repoPath}`, { headers });
  } catch {
    return null;
  }
  if (!contentsResp.ok) return null;
  const contentsData = await contentsResp.json();
  try {
    const commitResp = await fetch(
      `https://api.github.com/repos/${owner}/${repo}/commits?path=${encodeURIComponent(repoPath)}&per_page=1`,
      { headers }
    );
    if (commitResp.ok) {
      const commits = await commitResp.json();
      const sha = commits[0]?.sha;
      if (sha) return { commitSha: sha, permalink: `https://github.com/${owner}/${repo}/blob/${sha}/${repoPath}` };
    }
  } catch {
  }
  return {
    commitSha: contentsData.sha ?? "unknown",
    permalink: contentsData.html_url ?? `https://github.com/${owner}/${repo}/blob/main/${repoPath}`
  };
}
async function pushArtifactToGitHub(pat, repoUrl, branch, localFile, repoPath, message) {
  const [owner, repo] = parseGitHubUrl(repoUrl);
  const { readFile } = await import("node:fs/promises");
  const contentBase64 = (await readFile(localFile)).toString("base64");
  const apiBase = `https://api.github.com/repos/${owner}/${repo}/contents/${repoPath}`;
  const headers = githubHeaders(pat);
  let existingSha;
  let getResp;
  try {
    getResp = await fetch(apiBase, { headers });
  } catch (err) {
    throw new PushError("network", `Network error fetching ${repoPath}: ${err.message}`);
  }
  if (getResp.ok) {
    existingSha = (await getResp.json()).sha;
  } else if (getResp.status === 401 || getResp.status === 403) {
    throw new PushError("auth", `Auth failed (${getResp.status}) reading ${repoPath}. Rotate PAT.`, getResp.status);
  } else if (getResp.status >= 500) {
    throw new PushError("network", `API ${getResp.status} reading ${repoPath}. Retry.`, getResp.status);
  }
  const body = { message, content: contentBase64, branch };
  if (existingSha) body.sha = existingSha;
  let putResp;
  try {
    putResp = await fetch(apiBase, { method: "PUT", headers, body: JSON.stringify(body) });
  } catch (err) {
    throw new PushError("network", `Network error pushing ${repoPath}: ${err.message}`);
  }
  if (!putResp.ok) {
    const s = putResp.status;
    if (s === 401 || s === 403) throw new PushError("auth", `Push auth failed (${s}). Rotate PAT.`, s);
    if (s === 409 || s === 422) throw new PushError("conflict", `Conflict (${s}) on ${repoPath}.`, s);
    if (s >= 500) throw new PushError("network", `API ${s} pushing ${repoPath}. Retry.`, s);
    throw new PushError("network", `API error ${s}: ${await putResp.text()}`, s);
  }
  const result = await putResp.json();
  const commitSha = result.commit?.sha ?? "";
  return { commitSha, permalink: `https://github.com/${owner}/${repo}/blob/${commitSha}/${repoPath}` };
}
async function renderCadScript(script, timeoutSeconds = DEFAULT_TIMEOUT_SECONDS) {
  const result = await renderCadQuery(script, "step", timeoutSeconds);
  if (!result.ok) throw new Error(`[${result.error}] ${result.message}`);
  return result.artifactPath;
}
async function exportToFormat(entry, format) {
  if (format === "step") return entry.stepPath;
  const result = await renderCadQuery(entry.script, format, DEFAULT_TIMEOUT_SECONDS);
  if (!result.ok) throw new Error(`[${result.error}] Export to ${format} failed: ${result.message}`);
  return result.artifactPath;
}
var plugin = definePlugin({
  async setup(ctx) {
    ctx.logger.info("CAD plugin worker starting");
    const anyCtx = ctx;
    ctx.tools.register(
      "cad:run_script",
      {
        displayName: "CAD Run Script",
        description: "Execute a CadQuery Python script. Returns { artifactId, summary }.",
        parametersSchema: {
          type: "object",
          properties: {
            script: { type: "string", description: "CadQuery Python script." },
            timeout: { type: "integer", minimum: 1, maximum: 300, description: "Timeout (seconds, default 30)." }
          },
          required: ["script"],
          additionalProperties: false
        }
      },
      async (params, runCtxRaw) => {
        const runCtx = runCtxRaw ?? {};
        const tool = "cad:run_script";
        const t0 = Date.now();
        if (typeof params !== "object" || params === null) {
          const ms2 = Date.now() - t0;
          await emitMetrics(anyCtx, tool, ms2, true);
          logCompletion(ctx, tool, runCtx, ms2, "error");
          return validationError("params must be an object");
        }
        const p = params;
        if (typeof p.script !== "string" || p.script.length === 0) {
          const ms2 = Date.now() - t0;
          await emitMetrics(anyCtx, tool, ms2, true);
          logCompletion(ctx, tool, runCtx, ms2, "error");
          return validationError("script is required and must be a non-empty string");
        }
        if (p.timeout !== void 0) {
          const t = p.timeout;
          if (typeof t !== "number" || !Number.isInteger(t) || t < 1 || t > 300) {
            const ms2 = Date.now() - t0;
            await emitMetrics(anyCtx, tool, ms2, true);
            logCompletion(ctx, tool, runCtx, ms2, "error");
            return validationError("timeout must be an integer between 1 and 300");
          }
        }
        const script = p.script;
        const timeoutSeconds = typeof p.timeout === "number" ? p.timeout : DEFAULT_TIMEOUT_SECONDS;
        ctx.logger.info("cad:run_script: rendering", { scriptLength: script.length, timeoutSeconds });
        let stepPath;
        try {
          stepPath = await renderCadScript(script, timeoutSeconds);
        } catch (err) {
          const msg = err instanceof Error ? err.message : "Unknown worker error";
          ctx.logger.warn("cad:run_script: worker error", { error: msg });
          const ms2 = Date.now() - t0;
          await emitMetrics(anyCtx, tool, ms2, true);
          logCompletion(ctx, tool, runCtx, ms2, "error");
          return workerInternalError(msg);
        }
        const artifactId = `cad-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
        artifactStagingMap.set(artifactId, { script, stepPath });
        ctx.logger.info("cad:run_script: staged", { artifactId });
        const ms = Date.now() - t0;
        await emitMetrics(anyCtx, tool, ms, false);
        logCompletion(ctx, tool, runCtx, ms, "ok");
        return {
          content: `Artifact staged: ${artifactId}`,
          data: { artifactId, summary: `CadQuery script executed successfully (${script.length} chars)` }
        };
      }
    );
    ctx.tools.register(
      "cad:export",
      {
        displayName: "CAD Export",
        description: "Export a staged CAD artifact to the configured GitHub artifact repo. Returns { commitSha, permalink, artifactPath }. Idempotent per toolCallId.",
        parametersSchema: {
          type: "object",
          properties: {
            artifactId: { type: "string", description: "Artifact ID from cad:run_script." },
            format: { type: "string", enum: ["step", "stl", "3mf"], description: "Output format." },
            paperclipTicketId: { type: "string", description: "Paperclip ticket ID for path/commit message." },
            toolCallId: { type: "string", description: "Tool-call ID for deterministic path and idempotency." },
            filename: { type: "string", description: "Optional filename override. Default: artifact.<format>." }
          },
          required: ["artifactId", "format", "paperclipTicketId", "toolCallId"]
        }
      },
      async (params, runCtxRaw) => {
        const runCtx = runCtxRaw ?? {};
        const tool = "cad:export";
        const t0 = Date.now();
        if (typeof params !== "object" || params === null) {
          const ms = Date.now() - t0;
          await emitMetrics(anyCtx, tool, ms, true);
          logCompletion(ctx, tool, runCtx, ms, "error");
          return validationError("params must be an object");
        }
        const p = params;
        if (typeof p.artifactId !== "string" || p.artifactId.length === 0) {
          const ms = Date.now() - t0;
          await emitMetrics(anyCtx, tool, ms, true);
          logCompletion(ctx, tool, runCtx, ms, "error");
          return validationError("artifactId is required and must be a non-empty string");
        }
        const validFormats = ["step", "stl", "3mf"];
        if (typeof p.format !== "string" || !validFormats.includes(p.format)) {
          const ms = Date.now() - t0;
          await emitMetrics(anyCtx, tool, ms, true);
          logCompletion(ctx, tool, runCtx, ms, "error");
          return validationError(`format must be one of: ${validFormats.join(", ")}`);
        }
        const { artifactId, format, paperclipTicketId, toolCallId, filename } = p;
        ctx.logger.info("cad:export: starting", { artifactId, format });
        const stagingEntry = artifactStagingMap.get(artifactId);
        if (!stagingEntry) {
          ctx.logger.warn("cad:export: unknown artifactId", { artifactId });
          const ms = Date.now() - t0;
          await emitMetrics(anyCtx, tool, ms, true);
          logCompletion(ctx, tool, runCtx, ms, "error");
          return workerInternalError(`No staged artifact for artifactId: ${artifactId}. Call cad:run_script first.`);
        }
        if (!paperclipTicketId || !toolCallId) {
          try {
            const filePath = await exportToFormat(stagingEntry, format);
            const ms = Date.now() - t0;
            await emitMetrics(anyCtx, tool, ms, false);
            logCompletion(ctx, tool, runCtx, ms, "ok");
            return { data: { filePath, artifactId, format } };
          } catch (err) {
            const msg = err instanceof Error ? err.message : "Export failed";
            const ms = Date.now() - t0;
            await emitMetrics(anyCtx, tool, ms, true);
            logCompletion(ctx, tool, runCtx, ms, "error");
            return workerInternalError(msg);
          }
        }
        const config = await ctx.config.get();
        if (!config.githubPatSecretId) {
          const ms = Date.now() - t0;
          await emitMetrics(anyCtx, tool, ms, true);
          logCompletion(ctx, tool, runCtx, ms, "error");
          return { data: { error: "prerequisite_missing", message: "githubPatSecretId not configured." } };
        }
        const repoUrl = config.artifactRepoUrl ?? DEFAULT_ARTIFACT_REPO_URL;
        const branch = config.artifactRepoBranch ?? DEFAULT_ARTIFACT_BRANCH;
        const resolvedFilename = filename ?? `artifact.${format}`;
        const repoPath = `artifacts/${paperclipTicketId}/${toolCallId}/${resolvedFilename}`;
        ctx.logger.info("cad:export: resolving GitHub PAT");
        const pat = await ctx.secrets.resolve(config.githubPatSecretId);
        try {
          await checkRepoPrerequisite(pat, repoUrl);
        } catch (err) {
          if (err instanceof PushError && err.kind === "prerequisite_missing") {
            ctx.logger.warn("cad:export: prerequisite failed", { repoUrl, httpStatus: err.httpStatus });
            const ms = Date.now() - t0;
            await emitMetrics(anyCtx, tool, ms, true);
            logCompletion(ctx, tool, runCtx, ms, "error");
            return { data: { error: "prerequisite_missing", message: err.message } };
          }
          throw err;
        }
        ctx.logger.info("cad:export: idempotency check", { repoPath });
        const existing = await checkArtifactExists(pat, repoUrl, repoPath);
        if (existing) {
          ctx.logger.info("cad:export: already exists", { repoPath, commitSha: existing.commitSha });
          const ms = Date.now() - t0;
          await emitMetrics(anyCtx, tool, ms, false);
          logCompletion(ctx, tool, runCtx, ms, "ok");
          return {
            content: `Artifact already present at ${repoPath} (${existing.commitSha})`,
            data: { commitSha: existing.commitSha, permalink: existing.permalink, artifactPath: repoPath }
          };
        }
        let localFile;
        try {
          localFile = await exportToFormat(stagingEntry, format);
        } catch (err) {
          const msg = err instanceof Error ? err.message : "Export failed";
          const ms = Date.now() - t0;
          await emitMetrics(anyCtx, tool, ms, true);
          logCompletion(ctx, tool, runCtx, ms, "error");
          return workerInternalError(msg);
        }
        const commitMessage = `CAD artifact: ticket=${paperclipTicketId} tool=cad:export call=${toolCallId}`;
        const doPush = () => pushArtifactToGitHub(pat, repoUrl, branch, localFile, repoPath, commitMessage);
        ctx.logger.info("cad:export: pushing", { repoPath, branch });
        try {
          let pushResult;
          try {
            pushResult = await doPush();
          } catch (firstErr) {
            if (firstErr instanceof PushError && firstErr.kind === "conflict") {
              ctx.logger.warn("cad:export: conflict, retrying once", { repoPath });
              pushResult = await doPush();
            } else {
              throw firstErr;
            }
          }
          ctx.logger.info("cad:export: committed", { repoPath, commitSha: pushResult.commitSha });
          const ms = Date.now() - t0;
          await emitMetrics(anyCtx, tool, ms, false);
          logCompletion(ctx, tool, runCtx, ms, "ok");
          return {
            content: `Artifact committed: ${pushResult.permalink}`,
            data: { commitSha: pushResult.commitSha, permalink: pushResult.permalink, artifactPath: repoPath }
          };
        } catch (err) {
          if (err instanceof PushError) {
            ctx.logger.warn("cad:export: push failed", { kind: err.kind, httpStatus: err.httpStatus });
            const ms = Date.now() - t0;
            await emitMetrics(anyCtx, tool, ms, true);
            logCompletion(ctx, tool, runCtx, ms, "error");
            return { data: { error: err.kind, message: err.message } };
          }
          throw err;
        }
      }
    );
    ctx.logger.info("CAD plugin worker setup complete");
  },
  async onHealth() {
    return { status: "ok", message: "CAD plugin worker is running" };
  }
});
var worker_default = plugin;
runWorker(plugin, import.meta.url);
export {
  worker_default as default
};
//# sourceMappingURL=worker.js.map
