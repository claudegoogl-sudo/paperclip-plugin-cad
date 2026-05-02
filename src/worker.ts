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
 *   "network"              — 5xx / network error / fetch timeout: transient, surface to agent.
 *   "conflict"             — 409/422: re-fetch SHA and retry once (inline).
 *   "prerequisite_missing" — repo 404/403: operator must pre-create repo.
 *
 * PLA-56 / PLA-74 SecurityEngineer review fixes (commit ba36ef1 review):
 *   F1 — Path-traversal allowlist on paperclipTicketId/toolCallId/filename,
 *        post-build path normalization assertion, per-segment URL encoding.
 *   F2 — Subsumed by F1 (allowlist excludes newlines + commit-message trailers).
 *   F3 — additionalProperties:false on instanceConfigSchema and cad:export schema.
 *   F4 — Strict URL parsing for parseGitHubUrl with host === "github.com".
 *   F5 — AbortSignal.timeout(30_000) on every outbound fetch.
 */

import { definePlugin, runWorker } from "@paperclipai/plugin-sdk";
import type { PluginContext } from "@paperclipai/plugin-sdk";
import * as path from "node:path";

// INTEGRATION SWITCH (sub-goal 2 / PLA-54): real CadQuery sandbox client.
import {
  renderCadQuery,
  DEFAULT_TIMEOUT_SECONDS as WORKER_DEFAULT_TIMEOUT,
} from "./cad-worker-client.js";

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
// F1 / F2 — input allowlists (path-traversal + commit-message-injection defence)
//
// Defence-in-depth in three independent layers:
//   1. Allowlist regex per component before building the repo path.
//   2. After building the path, assert path.posix.normalize is an identity AND
//      that the result starts with "artifacts/". Either failure is fail-closed.
//   3. Per-segment URL encoding when building the GitHub Contents API URL so
//      any residual oddity is rendered inert.
//
// Each layer is sufficient on its own; together they form the F1 fix.
// ---------------------------------------------------------------------------

const TICKET_ID_RE = /^[A-Z][A-Z0-9]{1,9}-[0-9]{1,9}$/;
const TOOL_CALL_ID_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;
const FILENAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

function validateTicketId(value: string): string | null {
  if (!TICKET_ID_RE.test(value)) {
    return "paperclipTicketId must match ^[A-Z][A-Z0-9]{1,9}-[0-9]{1,9}$ (e.g. PLA-56)";
  }
  return null;
}

function validateToolCallId(value: string): string | null {
  if (!TOOL_CALL_ID_RE.test(value)) {
    return "toolCallId must match ^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$";
  }
  return null;
}

function validateFilename(value: string): string | null {
  if (value.startsWith(".") || value.includes("..")) {
    return "filename must not start with '.' or contain '..'";
  }
  if (!FILENAME_RE.test(value)) {
    return "filename must match ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$";
  }
  return null;
}

/**
 * F1 layer 2: post-build assertion. Any input that survives the per-component
 * allowlist must, after POSIX normalization, still start with "artifacts/" and
 * be byte-identical to the un-normalized form. Fail-closed on any drift.
 */
function assertSafeRepoPath(repoPath: string): string | null {
  const normalized = path.posix.normalize(repoPath);
  if (normalized !== repoPath) return "internal: repoPath would normalize differently (path traversal blocked)";
  if (!normalized.startsWith("artifacts/")) return "internal: repoPath must start with 'artifacts/'";
  return null;
}

/**
 * F1 layer 3: encode each segment so reserved characters cannot affect the URL
 * structure. Path separators stay as `/`; segments are encodeURIComponent-d.
 */
function encodeRepoPathForUrl(repoPath: string): string {
  return repoPath.split("/").map(encodeURIComponent).join("/");
}

// ---------------------------------------------------------------------------
// F5 — fetch timeout (30s) on every outbound call
//
// AbortSignal.timeout aborts the request after N ms; we surface the abort as
// a "network" PushError so the agent treats it as transient.
// ---------------------------------------------------------------------------

const FETCH_TIMEOUT_MS = 30_000;

function fetchSignal(): AbortSignal {
  return AbortSignal.timeout(FETCH_TIMEOUT_MS);
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

/**
 * F4 — strict URL parsing. The previous regex accepted any URL whose path
 * happened to contain `github.com/<owner>/<repo>` (e.g. attacker-controlled
 * `https://attacker.example/path/github.com/o/r.git`). Replace with WHATWG
 * URL parsing + `host === "github.com"` so a future refactor that derives the
 * request host from the configured URL cannot be redirected off-platform.
 */
function parseGitHubUrl(repoUrl: string): [string, string] {
  let u: URL;
  try {
    u = new URL(repoUrl);
  } catch {
    throw new PushError("prerequisite_missing", `Cannot parse GitHub URL: ${repoUrl}`);
  }
  if (u.protocol !== "https:" || u.host !== "github.com") {
    throw new PushError("prerequisite_missing",
      `artifactRepoUrl must be an https://github.com/<owner>/<repo>(.git) URL. Got: ${repoUrl}`);
  }
  const segs = u.pathname.replace(/^\/+/, "").replace(/\.git\/?$/, "").replace(/\/+$/, "").split("/");
  if (segs.length !== 2 || !segs[0] || !segs[1]) {
    throw new PushError("prerequisite_missing", `Cannot parse owner/repo from ${repoUrl}`);
  }
  return [segs[0], segs[1]];
}

async function checkRepoPrerequisite(pat: string, repoUrl: string): Promise<void> {
  const [owner, repo] = parseGitHubUrl(repoUrl);
  const headers = githubHeaders(pat);
  let resp: Response;
  try {
    resp = await fetch(
      `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`,
      { headers, signal: fetchSignal() },
    );
  } catch (err) {
    // F5: AbortSignal.timeout aborts trigger TimeoutError; surface as network.
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
  const encodedPath = encodeRepoPathForUrl(repoPath); // F1 layer 3
  const ownerEnc = encodeURIComponent(owner);
  const repoEnc = encodeURIComponent(repo);
  let contentsResp: Response;
  try {
    contentsResp = await fetch(
      `https://api.github.com/repos/${ownerEnc}/${repoEnc}/contents/${encodedPath}`,
      { headers, signal: fetchSignal() },
    );
  } catch { return null; }
  if (!contentsResp.ok) return null;
  const contentsData = (await contentsResp.json()) as { sha?: string; html_url?: string };
  try {
    const commitResp = await fetch(
      `https://api.github.com/repos/${ownerEnc}/${repoEnc}/commits?path=${encodeURIComponent(repoPath)}&per_page=1`,
      { headers, signal: fetchSignal() });
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
  // F1 layer 3: per-segment encoding when building the Contents API URL.
  const encodedPath = encodeRepoPathForUrl(repoPath);
  const apiBase = `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/contents/${encodedPath}`;
  const headers = githubHeaders(pat);

  let existingSha: string | undefined;
  let getResp: Response;
  try { getResp = await fetch(apiBase, { headers, signal: fetchSignal() }); }
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
  try { putResp = await fetch(apiBase, { method: "PUT", headers, body: JSON.stringify(body), signal: fetchSignal() }); }
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
            paperclipTicketId: {
              type: "string",
              pattern: "^[A-Z][A-Z0-9]{1,9}-[0-9]{1,9}$",
              description: "Paperclip ticket ID (e.g. PLA-56) for path/commit message.",
            },
            toolCallId: {
              type: "string",
              pattern: "^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$",
              description: "Tool-call ID for deterministic path and idempotency.",
            },
            filename: {
              type: "string",
              pattern: "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$",
              description: "Optional filename override. Default: artifact.<format>.",
            },
          },
          required: ["artifactId", "format", "paperclipTicketId", "toolCallId"],
          additionalProperties: false,
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
          paperclipTicketId?: unknown;
          toolCallId?: unknown;
          filename?: unknown;
        };

        // F1 — when GitHub-pipeline params are present, run them through a
        // strict allowlist BEFORE building the repo path. Reject newlines,
        // path-traversal sequences, commit-message-injection trailers, and any
        // character that could escape the artifacts/ subtree.
        if (paperclipTicketId !== undefined) {
          if (typeof paperclipTicketId !== "string") {
            const ms = Date.now() - t0;
            await emitMetrics(anyCtx, tool, ms, true);
            logCompletion(ctx, tool, runCtx, ms, "error");
            return validationError("paperclipTicketId must be a string");
          }
          const tErr = validateTicketId(paperclipTicketId);
          if (tErr) {
            const ms = Date.now() - t0;
            await emitMetrics(anyCtx, tool, ms, true);
            logCompletion(ctx, tool, runCtx, ms, "error");
            return validationError(tErr);
          }
        }
        if (toolCallId !== undefined) {
          if (typeof toolCallId !== "string") {
            const ms = Date.now() - t0;
            await emitMetrics(anyCtx, tool, ms, true);
            logCompletion(ctx, tool, runCtx, ms, "error");
            return validationError("toolCallId must be a string");
          }
          const cErr = validateToolCallId(toolCallId);
          if (cErr) {
            const ms = Date.now() - t0;
            await emitMetrics(anyCtx, tool, ms, true);
            logCompletion(ctx, tool, runCtx, ms, "error");
            return validationError(cErr);
          }
        }
        if (filename !== undefined) {
          if (typeof filename !== "string") {
            const ms = Date.now() - t0;
            await emitMetrics(anyCtx, tool, ms, true);
            logCompletion(ctx, tool, runCtx, ms, "error");
            return validationError("filename must be a string");
          }
          const fErr = validateFilename(filename);
          if (fErr) {
            const ms = Date.now() - t0;
            await emitMetrics(anyCtx, tool, ms, true);
            logCompletion(ctx, tool, runCtx, ms, "error");
            return validationError(fErr);
          }
        }

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
        // Cast back to narrowed string types — the F1 allowlist above proved them.
        const ticketIdStr = paperclipTicketId as string;
        const toolCallIdStr = toolCallId as string;
        const filenameRaw = filename as string | undefined;
        // Default filename: artifact.<format>. format is enum-validated.
        const resolvedFilename = filenameRaw ?? `artifact.${format}`;
        // resolvedFilename was either explicit (validated) or derived from the
        // enum format ("artifact.step" / "artifact.stl" / "artifact.3mf"); the
        // derived form is allowlist-safe by construction.
        const repoPath = `artifacts/${ticketIdStr}/${toolCallIdStr}/${resolvedFilename}`;
        // F1 layer 2 — fail-closed if anything would normalize to a different
        // path or escape the artifacts/ subtree. Defence-in-depth: should be
        // unreachable after the allowlist regexes, but the assertion is the
        // authoritative guard.
        const pathErr = assertSafeRepoPath(repoPath);
        if (pathErr) {
          ctx.logger.warn("cad:export: repoPath assertion failed", { pathErr });
          const ms = Date.now() - t0;
          await emitMetrics(anyCtx, tool, ms, true);
          logCompletion(ctx, tool, runCtx, ms, "error");
          return validationError(pathErr);
        }

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

        // F2 — uses already-allowlisted strings; no newlines, no commit-message
        // trailers can land here because TICKET_ID_RE and TOOL_CALL_ID_RE
        // exclude every character that isn't alphanumeric / dash / underscore.
        const commitMessage = `CAD artifact: ticket=${ticketIdStr} tool=cad:export call=${toolCallIdStr}`;
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
