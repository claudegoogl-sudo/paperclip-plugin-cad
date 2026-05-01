/**
 * CAD plugin worker — sub-goal 5: artifact persistence pipeline
 *
 * Security rules (enforced here, reviewed in PLA-36/PLA-41/PLA-56):
 *   - PAT is resolved via ctx.secrets.resolve(config.githubPatSecretId).
 *     config.githubPatSecretId must be the UUID from the Paperclip secrets DB,
 *     not a string name.  A name string throws InvalidSecretRefError at
 *     plugin-secrets-handler.js:172–174.
 *   - PAT is never logged (no ctx.logger.* calls that include the pat value).
 *   - PAT is never stored in ctx.state, ctx.data, or any persistent store.
 *   - PAT is never returned from a tool route.
 *   - PAT is used only within the function scope that resolves it; no module-
 *     level caching.
 *
 * Push error taxonomy (AC4/PLA-56):
 *   - "auth"                 — 401/403: rotate PAT, no retry.
 *   - "network"              — 5xx / network error: transient, surface to agent.
 *   - "conflict"             — 409/422: re-fetch SHA and retry once (inline).
 *   - "prerequisite_missing" — 404 or 403 on repo-existence check: operator must
 *                              pre-create the repo and verify PAT scope.
 */

import { definePlugin, runWorker } from "@paperclipai/plugin-sdk";
import type { PluginContext } from "@paperclipai/plugin-sdk";

// ---------------------------------------------------------------------------
// Config shape (matches instanceConfigSchema in manifest.ts)
// ---------------------------------------------------------------------------

interface CadPluginConfig {
  /** UUID of the Paperclip secret that holds the GitHub PAT. */
  githubPatSecretId: string;
  /**
   * HTTPS clone URL of the artifact repo. Defaults to DEFAULT_ARTIFACT_REPO_URL.
   * Operator-overridable per install (AC6/PLA-56).
   */
  artifactRepoUrl?: string;
  /**
   * Branch to push artifacts to. Defaults to "main".
   */
  artifactRepoBranch?: string;
}

const DEFAULT_ARTIFACT_REPO_URL =
  "https://github.com/claudegoogl-sudo/cad-artifacts.git";
const DEFAULT_ARTIFACT_BRANCH = "main";

// ---------------------------------------------------------------------------
// Typed push errors (AC4/PLA-56)
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
// Shared GitHub API headers
// The PAT is accepted as a parameter; do NOT log it.
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

/** Parse "owner/repo" from an HTTPS GitHub URL. Throws PushError on failure. */
function parseGitHubUrl(repoUrl: string): [string, string] {
  const match = repoUrl.match(/github\.com\/([^/]+)\/([^/]+?)(?:\.git)?$/);
  if (!match) {
    throw new PushError(
      "prerequisite_missing",
      `Cannot parse GitHub URL: ${repoUrl}`,
    );
  }
  return [match[1], match[2]];
}

// ---------------------------------------------------------------------------
// AC1: Prerequisite check — repo exists and PAT can reach it
// ---------------------------------------------------------------------------

/**
 * Verify the artifact repo exists and is accessible under the provided PAT.
 * Throws PushError("prerequisite_missing") with operator-facing remediation text
 * if the repo is missing or the PAT has no access.
 * Never logs the PAT.
 */
async function checkRepoPrerequisite(
  pat: string,
  repoUrl: string,
): Promise<void> {
  const [owner, repo] = parseGitHubUrl(repoUrl);
  const headers = githubHeaders(pat);

  let resp: Response;
  try {
    resp = await fetch(`https://api.github.com/repos/${owner}/${repo}`, {
      headers,
    });
  } catch (err) {
    throw new PushError(
      "network",
      `Network error reaching artifact repo ${owner}/${repo}: ${(err as Error).message}`,
    );
  }

  if (resp.status === 404) {
    throw new PushError(
      "prerequisite_missing",
      `Artifact repo not found (404): ${owner}/${repo}. ` +
        "Operator action required: pre-create the repo and ensure the PAT has " +
        "'repo' (or 'public_repo') scope. See PLA-56 AC#1.",
      404,
    );
  }
  if (resp.status === 401 || resp.status === 403) {
    throw new PushError(
      "prerequisite_missing",
      `Artifact repo not accessible (${resp.status}): ${owner}/${repo}. ` +
        "Operator action required: verify the PAT has 'repo' (or 'public_repo') " +
        "scope and correct org membership. See PLA-56 AC#1.",
      resp.status,
    );
  }
  if (!resp.ok) {
    throw new PushError(
      "network",
      `Unexpected ${resp.status} checking artifact repo ${owner}/${repo}. Retry later.`,
      resp.status,
    );
  }
}

// ---------------------------------------------------------------------------
// AC4: Idempotency — check if artifact already committed
// ---------------------------------------------------------------------------

interface PushResult {
  commitSha: string;
  permalink: string;
}

/**
 * Return the existing commit SHA + permalink if the artifact path is already
 * present in the repo, or null if it is not.
 *
 * This implements the AC4 requirement: before any retry, check for the
 * deterministic path; if found, resolve as success without re-pushing.
 */
async function checkArtifactExists(
  pat: string,
  repoUrl: string,
  repoPath: string,
): Promise<PushResult | null> {
  let owner: string, repo: string;
  try {
    [owner, repo] = parseGitHubUrl(repoUrl);
  } catch {
    return null;
  }
  const headers = githubHeaders(pat);

  let contentsResp: Response;
  try {
    contentsResp = await fetch(
      `https://api.github.com/repos/${owner}/${repo}/contents/${repoPath}`,
      { headers },
    );
  } catch {
    // Network error — treat as not found; push attempt will surface the issue.
    return null;
  }

  if (!contentsResp.ok) return null;

  const contentsData = (await contentsResp.json()) as {
    sha?: string;
    html_url?: string;
  };

  // Fetch the commit SHA for this path (most recent commit that touched it).
  try {
    const commitResp = await fetch(
      `https://api.github.com/repos/${owner}/${repo}/commits?path=${encodeURIComponent(repoPath)}&per_page=1`,
      { headers },
    );
    if (commitResp.ok) {
      const commits = (await commitResp.json()) as Array<{ sha?: string }>;
      const commitSha = commits[0]?.sha;
      if (commitSha) {
        return {
          commitSha,
          permalink: `https://github.com/${owner}/${repo}/blob/${commitSha}/${repoPath}`,
        };
      }
    }
  } catch {
    // Ignore — fall through to blob-sha fallback.
  }

  // Fallback: use blob sha from contents response.
  return {
    commitSha: contentsData.sha ?? "unknown",
    permalink:
      contentsData.html_url ??
      `https://github.com/${owner}/${repo}/blob/main/${repoPath}`,
  };
}

// ---------------------------------------------------------------------------
// GitHub PUT /contents helper
// ---------------------------------------------------------------------------

/**
 * Push a file to the GitHub repository using the Contents API.
 *
 * Choice rationale (per PLA-56 spec: "document the choice in the PR"):
 *   GitHub REST PUT /repos/{owner}/{repo}/contents/{path} is used instead of
 *   raw git-over-HTTPS because:
 *   1. No git binary dependency in the worker sandbox.
 *   2. Atomic single-file commits within the 100 MB GitHub API file size limit
 *      (CAD artifacts are typically < 50 MB STEP/STL files).
 *   3. Simpler auth: Bearer token in headers, no credential helper.
 *   The trade-off is the 100 MB per-file ceiling; if larger artifacts are
 *   needed in future, switch to git-over-HTTPS or the Git Data API (blobs +
 *   trees + commits).
 *
 * The PAT is passed as a parameter so the caller controls its lifetime.
 * It is never stored beyond this function's stack frame and never logged.
 *
 * @param pat         Resolved GitHub PAT (never log this value).
 * @param repoUrl     HTTPS clone URL of the target repository.
 * @param branch      Branch to commit to (e.g. "main").
 * @param localFile   Absolute path to the file to commit.
 * @param repoPath    Target path inside the repository.
 * @param message     Commit message (must not contain the PAT).
 * @returns           { commitSha, permalink } on success.
 * @throws PushError  With kind "auth" | "network" | "conflict" on failure.
 */
async function pushArtifactToGitHub(
  pat: string,
  repoUrl: string,
  branch: string,
  localFile: string,
  repoPath: string,
  message: string,
): Promise<PushResult> {
  const [owner, repo] = parseGitHubUrl(repoUrl);

  const { readFile } = await import("node:fs/promises");
  const content = await readFile(localFile);
  const contentBase64 = content.toString("base64");

  const apiBase = `https://api.github.com/repos/${owner}/${repo}/contents/${repoPath}`;
  const headers = githubHeaders(pat);

  // Check if the file already exists (needed for the update SHA).
  let existingSha: string | undefined;
  let getResp: Response;
  try {
    getResp = await fetch(apiBase, { headers });
  } catch (err) {
    throw new PushError(
      "network",
      `Network error fetching existing file at ${repoPath}: ${(err as Error).message}`,
    );
  }

  if (getResp.ok) {
    const existing = (await getResp.json()) as { sha?: string };
    existingSha = existing.sha;
  } else if (getResp.status === 401 || getResp.status === 403) {
    throw new PushError(
      "auth",
      `GitHub auth failed (${getResp.status}) reading ${repoPath}. ` +
        "Rotate the PAT stored in the secret referenced by config.githubPatSecretId.",
      getResp.status,
    );
  } else if (getResp.status >= 500) {
    throw new PushError(
      "network",
      `GitHub API ${getResp.status} reading ${repoPath}. Retry this call.`,
      getResp.status,
    );
  }
  // 404 → new file, proceed without existingSha.

  const body: Record<string, unknown> = {
    message,
    content: contentBase64,
    branch,
  };
  if (existingSha) body.sha = existingSha;

  let putResp: Response;
  try {
    putResp = await fetch(apiBase, {
      method: "PUT",
      headers,
      body: JSON.stringify(body),
    });
  } catch (err) {
    throw new PushError(
      "network",
      `Network error during push of ${repoPath}: ${(err as Error).message}`,
    );
  }

  if (!putResp.ok) {
    const status = putResp.status;
    if (status === 401 || status === 403) {
      throw new PushError(
        "auth",
        `GitHub push auth failed (${status}). ` +
          "Rotate the PAT stored in the secret referenced by config.githubPatSecretId.",
        status,
      );
    }
    if (status === 409 || status === 422) {
      throw new PushError(
        "conflict",
        `GitHub returned ${status} conflict on ${repoPath}. ` +
          "Re-fetch the file SHA and retry once.",
        status,
      );
    }
    if (status >= 500) {
      throw new PushError(
        "network",
        `GitHub API ${status} during push of ${repoPath}. Retry this call.`,
        status,
      );
    }
    const errText = await putResp.text();
    throw new PushError(
      "network",
      `GitHub API error ${status} pushing ${repoPath}: ${errText}`,
      status,
    );
  }

  const result = (await putResp.json()) as { commit?: { sha?: string } };
  const commitSha = result.commit?.sha ?? "";
  const permalink = `https://github.com/${owner}/${repo}/blob/${commitSha}/${repoPath}`;

  return { commitSha, permalink };
}

// ---------------------------------------------------------------------------
// CadQuery render helper (placeholder — full implementation is sub-goal 2)
// ---------------------------------------------------------------------------

/**
 * Execute a CadQuery script in an isolated subprocess.
 *
 * Full implementation (worker sandbox, timeout, stdout/stderr capture) is
 * tracked under sub-goal 2.  This stub validates the call surface without
 * running real CadQuery so sub-goal 4/5 can be verified independently.
 */
async function renderCadScript(
  script: string,
  format: "step" | "stl",
): Promise<string> {
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const artifactPath = join(tmpdir(), `cad-${Date.now()}.${format}`);
  const { writeFile } = await import("node:fs/promises");
  await writeFile(artifactPath, `; CAD stub — script hash: ${script.length}`);
  return artifactPath;
}

// ---------------------------------------------------------------------------
// Plugin definition
// ---------------------------------------------------------------------------

const plugin = definePlugin({
  async setup(ctx: PluginContext) {
    ctx.logger.info("CAD plugin worker starting");

    // ------------------------------------------------------------------
    // cad_render — execute a CadQuery script, return artifact path
    // ------------------------------------------------------------------
    ctx.tools.register(
      "cad_render",
      {
        displayName: "CAD Render",
        description:
          "Execute a CadQuery Python script and return the resulting 3D model artifact path.",
        parametersSchema: {
          type: "object",
          properties: {
            script: { type: "string", description: "CadQuery Python script." },
            format: {
              type: "string",
              enum: ["step", "stl"],
              description: "Output format. Defaults to 'step'.",
            },
          },
          required: ["script"],
        },
      },
      async (params) => {
        const { script, format = "step" } = params as {
          script: string;
          format?: "step" | "stl";
        };

        ctx.logger.info("cad_render: starting render", { format });

        const artifactPath = await renderCadScript(script, format);

        ctx.logger.info("cad_render: render complete", { artifactPath, format });

        return { content: artifactPath, data: { artifactPath, format } };
      },
    );

    // ------------------------------------------------------------------
    // cad_commit — commit a rendered artifact to the project GitHub repo.
    //
    // Security contract (PLA-36 / PLA-41 remediation #1):
    //   1. Resolve PAT from config.githubPatSecretId (UUID from secrets DB).
    //   2. Pass PAT directly into pushArtifactToGitHub — do not log it,
    //      do not store it, do not return it.
    //   3. PAT goes out of scope at the end of this handler.
    // ------------------------------------------------------------------
    ctx.tools.register(
      "cad_commit",
      {
        displayName: "CAD Commit Artifact",
        description:
          "Commit a previously rendered CAD artifact to the project GitHub repository.",
        parametersSchema: {
          type: "object",
          properties: {
            artifactPath: {
              type: "string",
              description: "Local artifact path from cad_render.",
            },
            repoPath: {
              type: "string",
              description: "Target path in the repository.",
            },
            commitMessage: {
              type: "string",
              description: "Git commit message.",
            },
          },
          required: ["artifactPath", "repoPath", "commitMessage"],
        },
      },
      async (params) => {
        const { artifactPath, repoPath, commitMessage } = params as {
          artifactPath: string;
          repoPath: string;
          commitMessage: string;
        };

        // SEC (PLA-50): validate artifactPath against tmpdir prefix to prevent
        // path-traversal / data-exfiltration via agent-supplied paths.
        const { resolve } = await import("node:path");
        const { tmpdir } = await import("node:os");
        const resolvedArtifactPath = resolve(artifactPath);
        const allowedPrefix = tmpdir();
        if (!resolvedArtifactPath.startsWith(allowedPrefix + "/")) {
          ctx.logger.warn("cad_commit: rejected out-of-bounds artifactPath", {
            resolvedArtifactPath,
          });
          return {
            data: { error: "artifactPath must be within the temp directory." },
          };
        }

        const config = (await ctx.config.get()) as unknown as CadPluginConfig;

        if (!config.githubPatSecretId) {
          return {
            data: {
              error:
                "githubPatSecretId is not configured. Set it in plugin instance config.",
            },
          };
        }

        ctx.logger.info("cad_commit: resolving GitHub PAT from secrets DB");

        const pat = await ctx.secrets.resolve(config.githubPatSecretId);

        ctx.logger.info("cad_commit: pushing artifact", { repoPath });

        const repoUrl =
          "https://github.com/claudegoogl-sudo/paperclip-plugin-cad.git";

        const { commitSha } = await pushArtifactToGitHub(
          pat,
          repoUrl,
          DEFAULT_ARTIFACT_BRANCH,
          resolvedArtifactPath,
          repoPath,
          commitMessage,
        );

        ctx.logger.info("cad_commit: artifact committed", {
          repoPath,
          commitSha,
        });

        return {
          content: `Artifact committed to ${repoPath} (${commitSha})`,
          data: { repoPath, commitSha },
        };
      },
    );

    // ------------------------------------------------------------------
    // cad_export — render a CadQuery script AND commit the artifact to
    // the configured artifact GitHub repo in a single tool call.
    //
    // Implements PLA-56 (sub-goal 5): full artifact persistence pipeline.
    //
    // AC1  Prerequisite check: verify repo exists + PAT is push-accessible.
    // AC2  Single commit+push per tool call.
    // AC3  PAT resolved per call; never logged, tagged, or returned.
    // AC4  Idempotent on retry: if the deterministic path is already present
    //      at HEAD, returns existing commitSha without re-pushing.
    // AC5  Commit message: ticket={paperclipTicketId} tool=cad_export call={toolCallId}.
    // AC6  artifactRepoUrl is operator-configurable in instanceConfig.
    // AC8  Result: { commitSha, permalink, artifactPath } — no secrets.
    // ------------------------------------------------------------------
    ctx.tools.register(
      "cad_export",
      {
        displayName: "CAD Export & Commit",
        description:
          "Render a CadQuery script and commit the artifact to the configured GitHub artifact repo. " +
          "Returns commitSha, permalink, and artifactPath. " +
          "Idempotent: if the same toolCallId was already pushed, returns the existing commit info without re-pushing.",
        parametersSchema: {
          type: "object",
          properties: {
            script: {
              type: "string",
              description: "CadQuery Python script to render.",
            },
            format: {
              type: "string",
              enum: ["step", "stl"],
              description: "Output format. Defaults to 'step'.",
            },
            paperclipTicketId: {
              type: "string",
              description:
                "Paperclip ticket ID (e.g. PLA-56). Included in artifact path and commit message.",
            },
            toolCallId: {
              type: "string",
              description:
                "Unique ID for this tool call. Used for deterministic artifact path and idempotency.",
            },
            filename: {
              type: "string",
              description:
                "Optional artifact filename. Defaults to 'artifact.<format>'.",
            },
          },
          required: ["script", "paperclipTicketId", "toolCallId"],
        },
      },
      async (params) => {
        const {
          script,
          format = "step",
          paperclipTicketId,
          toolCallId,
          filename,
        } = params as {
          script: string;
          format?: "step" | "stl";
          paperclipTicketId: string;
          toolCallId: string;
          filename?: string;
        };

        ctx.logger.info("cad_export: starting", {
          format,
          paperclipTicketId,
          toolCallId,
        });

        const config = (await ctx.config.get()) as unknown as CadPluginConfig;

        if (!config.githubPatSecretId) {
          return {
            data: {
              error: "prerequisite_missing",
              message:
                "githubPatSecretId is not configured. Set it in plugin instance config.",
            },
          };
        }

        const repoUrl = config.artifactRepoUrl ?? DEFAULT_ARTIFACT_REPO_URL;
        const branch = config.artifactRepoBranch ?? DEFAULT_ARTIFACT_BRANCH;

        // AC5: Deterministic artifact path.
        const resolvedFilename = filename ?? `artifact.${format}`;
        const repoPath = `artifacts/${paperclipTicketId}/${toolCallId}/${resolvedFilename}`;

        ctx.logger.info("cad_export: resolving GitHub PAT");
        const pat = await ctx.secrets.resolve(config.githubPatSecretId);
        // PAT is now in scope. Must not be logged or passed to logger.

        // AC1: Prerequisite check — verify repo exists and PAT can access it.
        try {
          await checkRepoPrerequisite(pat, repoUrl);
        } catch (err) {
          if (err instanceof PushError && err.kind === "prerequisite_missing") {
            ctx.logger.warn(
              "cad_export: artifact repo prerequisite check failed",
              {
                repoUrl,
                httpStatus: err.httpStatus,
                // PAT intentionally omitted from this log.
              },
            );
            return {
              data: {
                error: "prerequisite_missing",
                message: err.message,
              },
            };
          }
          throw err;
        }

        // AC4: Idempotency check — return existing result if already pushed.
        ctx.logger.info("cad_export: checking idempotency", { repoPath });
        const existing = await checkArtifactExists(pat, repoUrl, repoPath);
        if (existing) {
          ctx.logger.info("cad_export: artifact already exists (idempotent)", {
            repoPath,
            commitSha: existing.commitSha,
          });
          return {
            content: `Artifact already present at ${repoPath} (${existing.commitSha})`,
            data: {
              commitSha: existing.commitSha,
              permalink: existing.permalink,
              artifactPath: repoPath,
            },
          };
        }

        // Render the CAD script.
        ctx.logger.info("cad_export: rendering CAD script", { format });
        const localFile = await renderCadScript(script, format);
        ctx.logger.info("cad_export: render complete", { localFile, format });

        // AC5: Commit message — ticket id + tool name + tool-call id.
        //      No PAT, no agent id, no payload content.
        const commitMessage = `CAD artifact: ticket=${paperclipTicketId} tool=cad_export call=${toolCallId}`;

        // Push with inline conflict retry (spec: "re-fetch and retry once").
        const doPush = (): Promise<PushResult> =>
          pushArtifactToGitHub(
            pat,
            repoUrl,
            branch,
            localFile,
            repoPath,
            commitMessage,
          );

        ctx.logger.info("cad_export: pushing artifact", { repoPath, branch });

        try {
          let pushResult: PushResult;
          try {
            pushResult = await doPush();
          } catch (firstErr) {
            if (
              firstErr instanceof PushError &&
              firstErr.kind === "conflict"
            ) {
              // Conflict: re-fetch SHA on next call and retry once (no infinite loop).
              ctx.logger.warn(
                "cad_export: conflict on push, retrying once",
                { repoPath },
              );
              pushResult = await doPush();
            } else {
              throw firstErr;
            }
          }

          // PAT goes out of scope here.
          ctx.logger.info("cad_export: artifact committed", {
            repoPath,
            commitSha: pushResult.commitSha,
          });

          // AC8: Return commitSha, permalink, artifactPath — no PAT, no secret data.
          return {
            content: `Artifact committed: ${pushResult.permalink}`,
            data: {
              commitSha: pushResult.commitSha,
              permalink: pushResult.permalink,
              artifactPath: repoPath,
            },
          };
        } catch (err) {
          if (err instanceof PushError) {
            ctx.logger.warn("cad_export: push failed", {
              kind: err.kind,
              httpStatus: err.httpStatus,
              // PAT intentionally omitted from this log.
            });
            return {
              data: {
                error: err.kind,
                message: err.message,
              },
            };
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
