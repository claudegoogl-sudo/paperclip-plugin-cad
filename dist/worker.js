// src/worker.ts
import { definePlugin, runWorker } from "@paperclipai/plugin-sdk";

// src/cad-worker-client.ts
import { spawn } from "node:child_process";
import { mkdtemp } from "node:fs/promises";
import { existsSync, openSync, closeSync, statSync } from "node:fs";
import { tmpdir as tmpdir2 } from "node:os";
import { join as join2, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { execSync } from "node:child_process";

// src/stub-cad-worker.ts
import { tmpdir } from "node:os";
import { join } from "node:path";
var CadWorkerInternalError = class extends Error {
  code = "worker_internal";
  constructor(message) {
    super(message);
    this.name = "CadWorkerInternalError";
  }
};
var ARTIFACT_STAGING_DIR = join(tmpdir(), "paperclip-cad-staging");

// src/cad-worker-client.ts
var GRACE_SECONDS = 5;
var BWRAP_OVERHEAD_GRACE_MS = 100;
var MAX_TIMEOUT_SECONDS = 300;
var DEFAULT_TIMEOUT_SECONDS = 30;
var __filename = fileURLToPath(import.meta.url);
var __dirname = dirname(__filename);
var WORKER_PY = join2(__dirname, "cad_worker.py");
var SECCOMP_FILTER_PATH = join2(__dirname, "..", "worker", "seccomp_filter.bpf");
var PREEXEC_PATH = join2(__dirname, "..", "worker", "cad_preexec");
function defaultRlimits(timeoutSeconds) {
  return {
    asBytes: 2 * 1024 ** 3,
    nproc: 64,
    nofile: 256,
    fsizeBytes: 256 * 1024 ** 2,
    cpuSeconds: timeoutSeconds + 5,
    coreBytes: 0
  };
}
function which(bin) {
  try {
    const out = execSync(`command -v ${bin}`, {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"]
    }).trim();
    return out || null;
  } catch {
    return null;
  }
}
function bwrapVersionOf(bwrapPath) {
  try {
    const out = execSync(`${bwrapPath} --version`, {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"]
    }).trim();
    const m = /(\d+)\.(\d+)/.exec(out);
    if (!m) return null;
    return { major: Number(m[1]), minor: Number(m[2]) };
  } catch {
    return null;
  }
}
function selectSpawnMode(env = process.env, platform = process.platform) {
  const unsafeDev = env.CAD_WORKER_UNSAFE_DEV === "1";
  const isProd = env.NODE_ENV === "production";
  if (unsafeDev && !isProd) {
    return { mode: "dev_direct" };
  }
  if (platform !== "linux") {
    throw new CadWorkerInternalError(
      "Option B sandbox unavailable: requires Linux + bwrap. Set CAD_WORKER_UNSAFE_DEV=1 (NODE_ENV must NOT be 'production') to run with the in-process layer only on developer machines."
    );
  }
  const bwrapPath = which("bwrap");
  if (!bwrapPath) {
    throw new CadWorkerInternalError(
      "Option B sandbox unavailable: 'bwrap' not on PATH. Install bubblewrap on the deploy host (apt-get install bubblewrap). Set CAD_WORKER_UNSAFE_DEV=1 (non-production only) to run direct."
    );
  }
  if (!existsSync(SECCOMP_FILTER_PATH)) {
    throw new CadWorkerInternalError(
      `Option B sandbox unavailable: seccomp filter blob not found at ${SECCOMP_FILTER_PATH}. Build it with \`make -C worker seccomp_filter.bpf\` (requires libseccomp-dev).`
    );
  }
  const v = bwrapVersionOf(bwrapPath);
  const native = v != null && (v.major > 0 || v.major === 0 && v.minor >= 6);
  if (!native && !existsSync(PREEXEC_PATH)) {
    throw new CadWorkerInternalError(
      `bwrap ${v?.major}.${v?.minor} predates --rlimit-* (need 0.6+). Build the preexec wrapper with \`make -C worker cad_preexec\`, or upgrade bubblewrap on the deploy host.`
    );
  }
  return {
    mode: "bwrap+seccomp",
    bwrapPath,
    bwrapVersion: v ?? void 0,
    bwrapHasNativeRlimits: native,
    seccompFilterPath: SECCOMP_FILTER_PATH,
    preexecPath: native ? void 0 : PREEXEC_PATH
  };
}
function buildSpawnInvocation(opts) {
  const pythonBin = opts.pythonBin ?? "python3";
  const env = {
    PATH: "/usr/bin:/bin",
    PYTHONDONTWRITEBYTECODE: "1",
    PYTHONUNBUFFERED: "1"
  };
  if (opts.decision.mode === "dev_direct") {
    return {
      command: pythonBin,
      args: [WORKER_PY],
      env,
      stdio: ["pipe", "pipe", "pipe"]
    };
  }
  if (opts.seccompFd === void 0) {
    throw new CadWorkerInternalError(
      "buildSpawnInvocation(bwrap+seccomp): seccompFd is required"
    );
  }
  const bwrap = opts.decision.bwrapPath;
  const venvPython = pythonBin;
  const args = [
    "--unshare-all",
    "--share-net=false",
    "--die-with-parent",
    "--new-session",
    "--clearenv",
    "--setenv",
    "PATH",
    "/usr/bin:/bin",
    "--setenv",
    "HOME",
    "/tmp",
    "--setenv",
    "LANG",
    "C.UTF-8",
    "--setenv",
    "PYTHONDONTWRITEBYTECODE",
    "1",
    "--setenv",
    "PYTHONHASHSEED",
    "random",
    "--setenv",
    "PYTHONUNBUFFERED",
    "1",
    "--uid",
    "65534",
    "--gid",
    "65534",
    "--hostname",
    "cad-worker",
    "--proc",
    "/proc",
    "--dev",
    "/dev",
    "--ro-bind",
    "/usr",
    "/usr",
    "--ro-bind",
    "/lib",
    "/lib",
    "--ro-bind",
    "/lib64",
    "/lib64",
    "--ro-bind",
    "/bin",
    "/bin",
    "--ro-bind",
    "/etc/ld.so.cache",
    "/etc/ld.so.cache",
    "--ro-bind",
    WORKER_PY,
    WORKER_PY,
    "--tmpfs",
    "/tmp",
    "--bind",
    opts.workdir,
    opts.workdir,
    "--chdir",
    opts.workdir,
    "--cap-drop",
    "ALL",
    // Filter FD: the parent-side FD lives at child FD 3 (first `stdio` extra).
    "--seccomp",
    "3"
  ];
  if (opts.decision.bwrapHasNativeRlimits) {
    args.push(
      "--rlimit-as",
      String(opts.rlimits.asBytes),
      "--rlimit-nproc",
      String(opts.rlimits.nproc),
      "--rlimit-nofile",
      String(opts.rlimits.nofile),
      "--rlimit-fsize",
      String(opts.rlimits.fsizeBytes),
      "--rlimit-cpu",
      String(opts.rlimits.cpuSeconds),
      "--rlimit-core",
      String(opts.rlimits.coreBytes)
    );
    args.push("--", venvPython, WORKER_PY);
  } else {
    const preexec = opts.decision.preexecPath;
    args.push("--ro-bind", preexec, preexec);
    args.push("--setenv", "CAD_PREEXEC_RLIMIT_AS", String(opts.rlimits.asBytes));
    args.push("--setenv", "CAD_PREEXEC_RLIMIT_NPROC", String(opts.rlimits.nproc));
    args.push("--setenv", "CAD_PREEXEC_RLIMIT_NOFILE", String(opts.rlimits.nofile));
    args.push("--setenv", "CAD_PREEXEC_RLIMIT_FSIZE", String(opts.rlimits.fsizeBytes));
    args.push("--setenv", "CAD_PREEXEC_RLIMIT_CPU", String(opts.rlimits.cpuSeconds));
    args.push("--setenv", "CAD_PREEXEC_RLIMIT_CORE", String(opts.rlimits.coreBytes));
    args.push("--", preexec, venvPython, WORKER_PY);
  }
  const stdio = [
    "pipe",
    "pipe",
    "pipe",
    { type: "fd", fd: opts.seccompFd }
  ];
  return {
    command: bwrap,
    args,
    env,
    stdio
  };
}
async function invokeWorker(job, timeoutSeconds, decision = selectSpawnMode(), pythonBin = "python3") {
  const rlimits = defaultRlimits(timeoutSeconds);
  let seccompFd;
  if (decision.mode === "bwrap+seccomp") {
    seccompFd = openSync(decision.seccompFilterPath, "r");
  }
  let invocation;
  try {
    invocation = buildSpawnInvocation({
      decision,
      workdir: job.workdir,
      pythonBin,
      seccompFd,
      rlimits
    });
  } catch (err) {
    if (seccompFd !== void 0) closeSync(seccompFd);
    throw err;
  }
  return new Promise((resolve) => {
    const child = spawn(invocation.command, invocation.args, {
      stdio: invocation.stdio,
      env: invocation.env
    });
    if (seccompFd !== void 0) {
      try {
        closeSync(seccompFd);
      } catch {
      }
    }
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
    const overheadMs = decision.mode === "bwrap+seccomp" ? BWRAP_OVERHEAD_GRACE_MS : 0;
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
    }, timeoutSeconds * 1e3 + overheadMs + GRACE_SECONDS * 1e3);
    if (child.stdout) {
      child.stdout.on("data", (chunk) => {
        stdout += chunk.toString("utf8");
      });
    }
    if (child.stderr) {
      child.stderr.on("data", (chunk) => {
        stderr += chunk.toString("utf8");
      });
    }
    child.on("close", (code, signal) => {
      if (settled) return;
      if (killTimer !== null) clearTimeout(killTimer);
      if (signal === "SIGSYS") {
        settle({
          ok: false,
          error: "sandbox_violation",
          message: `Worker killed by seccomp (SIGSYS). stderr: ${stderr.slice(0, 500)}`,
          exitSignal: signal,
          exitCode: code
        });
        return;
      }
      if (signal === "SIGKILL" && /seccomp/i.test(stderr)) {
        settle({
          ok: false,
          error: "sandbox_violation",
          message: `Worker killed by kernel (SIGKILL with seccomp audit line). stderr: ${stderr.slice(0, 500)}`,
          exitSignal: signal,
          exitCode: code
        });
        return;
      }
      const line = stdout.trim();
      if (!line) {
        settle({
          ok: false,
          error: "worker_internal",
          message: `Worker produced no output on stdout. code=${code} signal=${signal} stderr: ${stderr.slice(0, 500)}`,
          exitSignal: signal,
          exitCode: code
        });
        return;
      }
      const newlineIdx = line.indexOf("\n");
      const firstLine = newlineIdx === -1 ? line : line.slice(0, newlineIdx);
      try {
        const parsed = JSON.parse(firstLine);
        if (!parsed.ok) {
          parsed.exitSignal = signal;
          parsed.exitCode = code;
        }
        settle(parsed);
      } catch {
        settle({
          ok: false,
          error: "worker_internal",
          message: `Worker output was not valid JSON: ${firstLine.slice(0, 200)}`,
          exitSignal: signal,
          exitCode: code
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
    if (child.stdin) {
      child.stdin.write(jobJson, "utf8", () => {
        child.stdin?.end();
      });
    }
  });
}
async function renderCadQuery(script, format, timeoutSeconds = DEFAULT_TIMEOUT_SECONDS, decision = selectSpawnMode()) {
  const effectiveTimeout = Math.min(
    Math.max(1, timeoutSeconds),
    MAX_TIMEOUT_SECONDS
  );
  const workdir = await mkdtemp(join2(tmpdir2(), "cad-worker-"));
  return invokeWorker({ script, format, workdir }, effectiveTimeout, decision);
}

// src/worker.ts
var DEFAULT_ARTIFACT_REPO_URL = "https://github.com/claudegoogl-sudo/cad-artifacts.git";
var DEFAULT_ARTIFACT_BRANCH = "main";
var artifactStagingMap = /* @__PURE__ */ new Map();
function stagingMapKey(companyId, agentId, artifactId) {
  return `${companyId}:${agentId}:${artifactId}`;
}
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
        if (typeof runCtx.companyId !== "string" || runCtx.companyId.length === 0 || typeof runCtx.agentId !== "string" || runCtx.agentId.length === 0) {
          ctx.logger.warn("cad:run_script: missing tenant context on runCtx");
          const ms2 = Date.now() - t0;
          await emitMetrics(anyCtx, tool, ms2, true);
          logCompletion(ctx, tool, runCtx, ms2, "error");
          return validationError("missing tenant context (companyId/agentId) on runCtx");
        }
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
        artifactStagingMap.set(
          stagingMapKey(runCtx.companyId, runCtx.agentId, artifactId),
          { script, stepPath }
        );
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
        const hasTenantCtx = typeof runCtx.companyId === "string" && runCtx.companyId.length > 0 && typeof runCtx.agentId === "string" && runCtx.agentId.length > 0;
        const stagingEntry = hasTenantCtx ? artifactStagingMap.get(stagingMapKey(runCtx.companyId, runCtx.agentId, artifactId)) : void 0;
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
