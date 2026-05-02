/**
 * CAD plugin worker — sub-goals 3 (PLA-55) + 5 (PLA-56)
 *
 * Tool surface (operator-confirmed via approval f420bc31):
 *   cad:run_script  — execute CadQuery Python → staged artifact
 *   cad:export      — staged artifact → GitHub commit + permalink
 *
 * PLA-55 framework (AC2–AC6):
 *   - Input validation: structured validation_error (400) with no stack traces.
 *   - Metrics: ctx.metrics.write for tool.calls, tool.errors, tool.duration_ms.
 *   - Correlation log: "tool call complete" with correlationId/tool/agentId/status/durationMs.
 *   - No payload content in any log call.
 *
 * PLA-56 security rules:
 *   - PAT resolved via ctx.secrets.resolve(config.githubPatSecretId) per call.
 *   - PAT never logged, stored, returned, or tagged in metrics.
 *   - PAT goes out of scope at function return.
 *
 * Push error taxonomy (PLA-56 AC4):
 *   "auth"                 — 401/403: rotate PAT, no retry.
 *   "network"              — 5xx / network error: transient, surface to agent.
 *   "conflict"             — 409/422: re-fetch SHA and retry once (inline).
 *   "prerequisite_missing" — repo 404/403: operator must pre-create repo.
 */

import { definePlugin, runWorker } from "@paperclipai/plugin-sdk";
import type { PluginContext } from "@paperclipai/plugin-sdk";

// INTEGRATION SWITCH (sub-goal 2 / PLA-54): real CadQuery sandbox client.
import {
  renderCadQuery,
  selectSpawnMode,
  DEFAULT_TIMEOUT_SECONDS as WORKER_DEFAULT_TIMEOUT,
} from "./cad-worker-client.js";

// PLA-137 deploy-time clone-fallback self-test.
import { runCloneFallbackProbe } from "./clone-fallback-probe.js";

// ---------------------------------------------------------------------------
// Config shape
// ---------------------------------------------------------------------------

interface CadPluginConfig {
  githubPatSecretId: string;
  artifactRepoUrl?: string;
  artifactRepoBranch?: string;
}

const DEFAULT_ARTIFACT_REPO_URL =
  "https://github.com/claudegoogl-sudo/cad-artifacts.git";
const DEFAULT_ARTIFACT_BRANCH = "main";

// ---------------------------------------------------------------------------
// Artifact staging map (cad:run_script → cad:export handoff)
//
// PLA-80 (F6): plugin workers are shared across all agents/companies on a host
// (one worker per plugin per Paperclip instance — see plugin-worker-manager and
// PLUGIN_SPEC.md §12). Keying the staging map by `artifactId` alone would let
// agent B in company Y read agent A in company X's staged artifact if the id
// ever leaks (logs, comments, brute force on the ~32-bit id space). Compose the
// map key from `companyId:agentId:artifactId` sourced from the runCtx so the
// caller's identity is part of the lookup. Mismatched callers fall through to
// the same "not found" error path as missing entries (no oracle).
// ---------------------------------------------------------------------------

interface StagingEntry {
  script: string;
  stepPath: string;
}

const artifactStagingMap = new Map<string, StagingEntry>();

function stagingMapKey(companyId: string, agentId: string, artifactId: string): string {
  return `${companyId}:${agentId}:${artifactId}`;
}

// ---------------------------------------------------------------------------
// Typed push errors (PLA-56)
// ---------------------------------------------------------------------------

type PushErrorKind = "auth" | "network" | "conflict" | "prerequisite_missing";

class PushError extends Error {
  readonly kind: PushErrorKind;
  readonly httpStatus?: number;
  constructor(kind: PushErrorKind, message: string, httpStatus?: number) {
    super(message);
    this.name = "PushError";
    this.kind = kind;
    this.httpStatus = httpStatus;
  }
}

// ---------------------------------------------------------------------------
// PLA-55 structured error helpers
// ---------------------------------------------------------------------------

function validationError(message: string) {
  return { error: "validation_error", data: { code: "validation_error", statusCode: 400, message } };
}

function workerInternalError(message: string) {
  return { data: { code: "worker_internal", statusCode: 500, message } };
}

// ---------------------------------------------------------------------------
// PLA-55 metrics + correlation-log helpers
// ---------------------------------------------------------------------------

interface RunCtx {
  agentId?: string;
  runId?: string;
  companyId?: string;
  projectId?: string;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type AnyCtx = PluginContext & { metrics?: { write: (name: string, value: number, tags?: Record<string, string>) => Promise<void> } };

async function emitMetrics(ctx: AnyCtx, tool: string, durationMs: number, isError: boolean) {
  await ctx.metrics?.write("tool.calls", 1, { tool });
  await ctx.metrics?.write("tool.duration_ms", durationMs, { tool });
  if (isError) await ctx.metrics?.write("tool.errors", 1, { tool });
}

function logCompletion(ctx: PluginContext, tool: string, runCtx: RunCtx, durationMs: number, status: "ok" | "error") {
  ctx.logger.info("tool call complete", {
    correlationId: runCtx.runId,
    tool,
    agentId: runCtx.agentId,
    status,
    durationMs,
  });
}

// ---------------------------------------------------------------------------
// GitHub API helpers (PLA-56)
// ---------------------------------------------------------------------------

function githubHeaders(pat: string): Record<string, string> {
  return {
    Authorization: `Bearer ${pat}`,
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "Content-Type": "application/json",
    "User-Agent": "paperclip-plugin-cad/0.1.0",
  };
}

function parseGitHubUrl(repoUrl: string): [string, string] {
  const match = repoUrl.match(/github\.com\/([^/]+)\/([^/]+?)(?:\.git)?$/);
  if (!match) throw new PushError("prerequisite_missing", `Cannot parse GitHub URL: ${repoUrl}`);
  return [match[1], match[2]];
}

async function checkRepoPrerequisite(pat: string, repoUrl: string): Promise<void> {
  const [owner, repo] = parseGitHubUrl(repoUrl);
  const headers = githubHeaders(pat);
  let resp: Response;
  try {
    resp = await fetch(`https://api.github.com/repos/${owner}/${repo}`, { headers });
  } catch (err) {
    throw new PushError("network", `Network error reaching ${owner}/${repo}: ${(err as Error).message}`);
  }
  if (resp.status === 404) {
    throw new PushError("prerequisite_missing",
      `Artifact repo not found (404): ${owner}/${repo}. Operator must pre-create the repo and grant PAT access. See PLA-56 AC#1.`, 404);
  }
  if (resp.status === 401 || resp.status === 403) {
    throw new PushError("prerequisite_missing",
      `Artifact repo not accessible (${resp.status}): ${owner}/${repo}. Verify PAT has repo scope. See PLA-56 AC#1.`, resp.status);
  }
  if (!resp.ok) {
    throw new PushError("network", `Unexpected ${resp.status} checking ${owner}/${repo}. Retry later.`, resp.status);
  }
}

interface PushResult {
  commitSha: string;
  permalink: string;
}

async function checkArtifactExists(pat: string, repoUrl: string, repoPath: string): Promise<PushResult | null> {
  let owner: string, repo: string;
  try { [owner, repo] = parseGitHubUrl(repoUrl); } catch { return null; }
  const headers = githubHeaders(pat);
  let contentsResp: Response;
  try {
    contentsResp = await fetch(`https://api.github.com/repos/${owner}/${repo}/contents/${repoPath}`, { headers });
  } catch { return null; }
  if (!contentsResp.ok) return null;
  const contentsData = (await contentsResp.json()) as { sha?: string; html_url?: string };
  try {
    const commitResp = await fetch(
      `https://api.github.com/repos/${owner}/${repo}/commits?path=${encodeURIComponent(repoPath)}&per_page=1`,
      { headers });
    if (commitResp.ok) {
      const commits = (await commitResp.json()) as Array<{ sha?: string }>;
      const sha = commits[0]?.sha;
      if (sha) return { commitSha: sha, permalink: `https://github.com/${owner}/${repo}/blob/${sha}/${repoPath}` };
    }
  } catch { /* fall through */ }
  return {
    commitSha: contentsData.sha ?? "unknown",
    permalink: contentsData.html_url ?? `https://github.com/${owner}/${repo}/blob/main/${repoPath}`,
  };
}

async function pushArtifactToGitHub(
  pat: string, repoUrl: string, branch: string,
  localFile: string, repoPath: string, message: string,
): Promise<PushResult> {
  const [owner, repo] = parseGitHubUrl(repoUrl);
  const { readFile } = await import("node:fs/promises");
  const contentBase64 = (await readFile(localFile)).toString("base64");
  const apiBase = `https://api.github.com/repos/${owner}/${repo}/contents/${repoPath}`;
  const headers = githubHeaders(pat);

  let existingSha: string | undefined;
  let getResp: Response;
  try { getResp = await fetch(apiBase, { headers }); }
  catch (err) { throw new PushError("network", `Network error fetching ${repoPath}: ${(err as Error).message}`); }
  if (getResp.ok) {
    existingSha = ((await getResp.json()) as { sha?: string }).sha;
  } else if (getResp.status === 401 || getResp.status === 403) {
    throw new PushError("auth", `Auth failed (${getResp.status}) reading ${repoPath}. Rotate PAT.`, getResp.status);
  } else if (getResp.status >= 500) {
    throw new PushError("network", `API ${getResp.status} reading ${repoPath}. Retry.`, getResp.status);
  }

  const body: Record<string, unknown> = { message, content: contentBase64, branch };
  if (existingSha) body.sha = existingSha;

  let putResp: Response;
  try { putResp = await fetch(apiBase, { method: "PUT", headers, body: JSON.stringify(body) }); }
  catch (err) { throw new PushError("network", `Network error pushing ${repoPath}: ${(err as Error).message}`); }

  if (!putResp.ok) {
    const s = putResp.status;
    if (s === 401 || s === 403) throw new PushError("auth", `Push auth failed (${s}). Rotate PAT.`, s);
    if (s === 409 || s === 422) throw new PushError("conflict", `Conflict (${s}) on ${repoPath}.`, s);
    if (s >= 500) throw new PushError("network", `API ${s} pushing ${repoPath}. Retry.`, s);
    throw new PushError("network", `API error ${s}: ${await putResp.text()}`, s);
  }

  const result = (await putResp.json()) as { commit?: { sha?: string } };
  const commitSha = result.commit?.sha ?? "";
  return { commitSha, permalink: `https://github.com/${owner}/${repo}/blob/${commitSha}/${repoPath}` };
}

// ---------------------------------------------------------------------------
// CadQuery render helpers
// ---------------------------------------------------------------------------

async function renderCadScript(script: string, timeoutSeconds = WORKER_DEFAULT_TIMEOUT): Promise<string> {
  const result = await renderCadQuery(script, "step", timeoutSeconds);
  if (!result.ok) throw new Error(`[${result.error}] ${result.message}`);
  return result.artifactPath;
}

async function exportToFormat(entry: StagingEntry, format: "step" | "stl" | "3mf"): Promise<string> {
  if (format === "step") return entry.stepPath;
  const result = await renderCadQuery(entry.script, format, WORKER_DEFAULT_TIMEOUT);
  if (!result.ok) throw new Error(`[${result.error}] Export to ${format} failed: ${result.message}`);
  return result.artifactPath;
}

// ---------------------------------------------------------------------------
// Plugin definition
// ---------------------------------------------------------------------------

const plugin = definePlugin({
  async setup(ctx: PluginContext) {
    ctx.logger.info("CAD plugin worker starting");
    const anyCtx = ctx as AnyCtx;

    // ------------------------------------------------------------------
    // PLA-137 — deploy-time clone3-fallback self-test (Path B).
    //
    // Runs once at boot, BEFORE any tool is registered, against the
    // production seccomp filter. Asserts:
    //   1. clone3 returns errno=ENOSYS on this host's glibc.
    //   2. clone(SIGCHLD) is killed with SIGSYS by the filter.
    // On failure: log error and process.exit(1) (fail-closed).
    // Gated to bwrap+seccomp mode; dev_direct (CAD_WORKER_UNSAFE_DEV=1,
    // non-prod) skips the probe with a WARN line.
    // ------------------------------------------------------------------
    {
      const decision = selectSpawnMode();
      if (decision.mode !== "bwrap+seccomp") {
        ctx.logger.warn(
          "sandbox.clone_fallback_probe skipped (kernel sandbox not active)",
          { mode: decision.mode },
        );
      } else {
        const probe = await runCloneFallbackProbe(decision);
        if (!probe.ok) {
          ctx.logger.error(
            "sandbox.clone_fallback_probe FAILED — refusing to register tools",
            {
              step: probe.step,
              message: probe.message,
              observed: probe.observed,
            },
          );
          // Fail-closed: exit non-zero before accepting any plugin work.
          // No tool registration runs after this line.
          process.exit(1);
        }
        ctx.logger.info("sandbox.clone_fallback_probe ok", {
          glibc: probe.glibc,
          python: probe.python,
          arch: probe.arch,
          clone3Errno: probe.clone3Errno,
          clone3ErrnoName: probe.clone3ErrnoName,
          clone2ExitSignal: probe.clone2ExitSignal,
        });
      }
    }

    // ------------------------------------------------------------------
    // cad:run_script
    // ------------------------------------------------------------------
    ctx.tools.register(
      "cad:run_script",
      {
        displayName: "CAD Run Script",
        description: "Execute a CadQuery Python script. Returns { artifactId, summary }.",
        parametersSchema: {
          type: "object",
          properties: {
            script: { type: "string", description: "CadQuery Python script." },
            timeout: { type: "integer", minimum: 1, maximum: 300, description: "Timeout (seconds, default 30)." },
          },
          required: ["script"],
          additionalProperties: false,
        },
      },
      async (params, runCtxRaw?: unknown) => {
        const runCtx = (runCtxRaw as RunCtx | undefined) ?? {};
        const tool = "cad:run_script";
        const t0 = Date.now();

        if (typeof params !== "object" || params === null) {
          const ms = Date.now() - t0;
          await emitMetrics(anyCtx, tool, ms, true);
          logCompletion(ctx, tool, runCtx, ms, "error");
          return validationError("params must be an object");
        }
        const p = params as Record<string, unknown>;
        if (typeof p.script !== "string" || p.script.length === 0) {
          const ms = Date.now() - t0;
          await emitMetrics(anyCtx, tool, ms, true);
          logCompletion(ctx, tool, runCtx, ms, "error");
          return validationError("script is required and must be a non-empty string");
        }
        if (p.timeout !== undefined) {
          const t = p.timeout;
          if (typeof t !== "number" || !Number.isInteger(t) || t < 1 || t > 300) {
            const ms = Date.now() - t0;
            await emitMetrics(anyCtx, tool, ms, true);
            logCompletion(ctx, tool, runCtx, ms, "error");
            return validationError("timeout must be an integer between 1 and 300");
          }
        }

        const script = p.script as string;
        const timeoutSeconds = typeof p.timeout === "number" ? p.timeout : WORKER_DEFAULT_TIMEOUT;

        // PLA-80 (F6): companyId+agentId are required to scope the staging map
        // entry to the calling tenant. Without them we cannot safely store the
        // artifact, since any later caller would match the un-scoped key.
        if (typeof runCtx.companyId !== "string" || runCtx.companyId.length === 0 ||
            typeof runCtx.agentId !== "string" || runCtx.agentId.length === 0) {
          ctx.logger.warn("cad:run_script: missing tenant context on runCtx");
          const ms = Date.now() - t0;
          await emitMetrics(anyCtx, tool, ms, true);
          logCompletion(ctx, tool, runCtx, ms, "error");
          return validationError("missing tenant context (companyId/agentId) on runCtx");
        }

        ctx.logger.info("cad:run_script: rendering", { scriptLength: script.length, timeoutSeconds });

        let stepPath: string;
        try {
          stepPath = await renderCadScript(script, timeoutSeconds);
        } catch (err) {
          const msg = err instanceof Error ? err.message : "Unknown worker error";
          ctx.logger.warn("cad:run_script: worker error", { error: msg });
          const ms = Date.now() - t0;
          await emitMetrics(anyCtx, tool, ms, true);
          logCompletion(ctx, tool, runCtx, ms, "error");
          return workerInternalError(msg);
        }

        const artifactId = `cad-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
        // PLA-80 (F6): key by tuple sourced from runCtx, never from agent input.
        artifactStagingMap.set(
          stagingMapKey(runCtx.companyId, runCtx.agentId, artifactId),
          { script, stepPath },
        );
        ctx.logger.info("cad:run_script: staged", { artifactId });

        const ms = Date.now() - t0;
        await emitMetrics(anyCtx, tool, ms, false);
        logCompletion(ctx, tool, runCtx, ms, "ok");

        return {
          content: `Artifact staged: ${artifactId}`,
          data: { artifactId, summary: `CadQuery script executed successfully (${script.length} chars)` },
        };
      },
    );

    // ------------------------------------------------------------------
    // cad:export  (PLA-55 tool surface + PLA-56 GitHub commit pipeline)
    // ------------------------------------------------------------------
    ctx.tools.register(
      "cad:export",
      {
        displayName: "CAD Export",
        description:
          "Export a staged CAD artifact to the configured GitHub artifact repo. " +
          "Returns { commitSha, permalink, artifactPath }. Idempotent per toolCallId.",
        parametersSchema: {
          type: "object",
          properties: {
            artifactId: { type: "string", description: "Artifact ID from cad:run_script." },
            format: { type: "string", enum: ["step", "stl", "3mf"], description: "Output format." },
            paperclipTicketId: { type: "string", description: "Paperclip ticket ID for path/commit message." },
            toolCallId: { type: "string", description: "Tool-call ID for deterministic path and idempotency." },
            filename: { type: "string", description: "Optional filename override. Default: artifact.<format>." },
          },
          required: ["artifactId", "format", "paperclipTicketId", "toolCallId"],
        },
      },
      async (params, runCtxRaw?: unknown) => {
        const runCtx = (runCtxRaw as RunCtx | undefined) ?? {};
        const tool = "cad:export";
        const t0 = Date.now();

        if (typeof params !== "object" || params === null) {
          const ms = Date.now() - t0;
          await emitMetrics(anyCtx, tool, ms, true);
          logCompletion(ctx, tool, runCtx, ms, "error");
          return validationError("params must be an object");
        }
        const p = params as Record<string, unknown>;
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

        const { artifactId, format, paperclipTicketId, toolCallId, filename } = p as {
          artifactId: string;
          format: "step" | "stl" | "3mf";
          paperclipTicketId?: string;
          toolCallId?: string;
          filename?: string;
        };

        ctx.logger.info("cad:export: starting", { artifactId, format });

        // PLA-80 (F6): scoped lookup by (companyId, agentId, artifactId). If the
        // calling runCtx does not match the entry's caller, fall through to the
        // SAME error response as a genuinely missing entry — do not distinguish,
        // to avoid an oracle that lets one tenant probe another's id space.
        // Missing tenant context on runCtx is treated identically.
        const hasTenantCtx =
          typeof runCtx.companyId === "string" && runCtx.companyId.length > 0 &&
          typeof runCtx.agentId === "string" && runCtx.agentId.length > 0;
        const stagingEntry = hasTenantCtx
          ? artifactStagingMap.get(stagingMapKey(runCtx.companyId!, runCtx.agentId!, artifactId))
          : undefined;
        if (!stagingEntry) {
          ctx.logger.warn("cad:export: unknown artifactId", { artifactId });
          const ms = Date.now() - t0;
          await emitMetrics(anyCtx, tool, ms, true);
          logCompletion(ctx, tool, runCtx, ms, "error");
          return workerInternalError(`No staged artifact for artifactId: ${artifactId}. Call cad:run_script first.`);
        }

        // Local-file export path (no GitHub params — pre-PLA-56 compat / PLA-55 tests).
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

        // --- PLA-56 GitHub commit pipeline ---
        const config = (await ctx.config.get()) as unknown as CadPluginConfig;
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
            data: { commitSha: existing.commitSha, permalink: existing.permalink, artifactPath: repoPath },
          };
        }

        let localFile: string;
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
        const doPush = (): Promise<PushResult> =>
          pushArtifactToGitHub(pat, repoUrl, branch, localFile, repoPath, commitMessage);

        ctx.logger.info("cad:export: pushing", { repoPath, branch });

        try {
          let pushResult: PushResult;
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
            data: { commitSha: pushResult.commitSha, permalink: pushResult.permalink, artifactPath: repoPath },
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
      },
    );

    ctx.logger.info("CAD plugin worker setup complete");
  },

  async onHealth() {
    return { status: "ok", message: "CAD plugin worker is running" };
  },
});

export default plugin;
runWorker(plugin, import.meta.url);
