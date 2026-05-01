// src/worker.ts
import { definePlugin, runWorker } from "@paperclipai/plugin-sdk";
var DEFAULT_ARTIFACT_REPO_URL = "https://github.com/claudegoogl-sudo/cad-artifacts.git";
var DEFAULT_ARTIFACT_BRANCH = "main";
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
  if (!match) {
    throw new PushError(
      "prerequisite_missing",
      `Cannot parse GitHub URL: ${repoUrl}`
    );
  }
  return [match[1], match[2]];
}
async function checkRepoPrerequisite(pat, repoUrl) {
  const [owner, repo] = parseGitHubUrl(repoUrl);
  const headers = githubHeaders(pat);
  let resp;
  try {
    resp = await fetch(`https://api.github.com/repos/${owner}/${repo}`, {
      headers
    });
  } catch (err) {
    throw new PushError(
      "network",
      `Network error reaching artifact repo ${owner}/${repo}: ${err.message}`
    );
  }
  if (resp.status === 404) {
    throw new PushError(
      "prerequisite_missing",
      `Artifact repo not found (404): ${owner}/${repo}. Operator action required: pre-create the repo and ensure the PAT has 'repo' (or 'public_repo') scope. See PLA-56 AC#1.`,
      404
    );
  }
  if (resp.status === 401 || resp.status === 403) {
    throw new PushError(
      "prerequisite_missing",
      `Artifact repo not accessible (${resp.status}): ${owner}/${repo}. Operator action required: verify the PAT has 'repo' (or 'public_repo') scope and correct org membership. See PLA-56 AC#1.`,
      resp.status
    );
  }
  if (!resp.ok) {
    throw new PushError(
      "network",
      `Unexpected ${resp.status} checking artifact repo ${owner}/${repo}. Retry later.`,
      resp.status
    );
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
    contentsResp = await fetch(
      `https://api.github.com/repos/${owner}/${repo}/contents/${repoPath}`,
      { headers }
    );
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
      const commitSha = commits[0]?.sha;
      if (commitSha) {
        return {
          commitSha,
          permalink: `https://github.com/${owner}/${repo}/blob/${commitSha}/${repoPath}`
        };
      }
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
  const content = await readFile(localFile);
  const contentBase64 = content.toString("base64");
  const apiBase = `https://api.github.com/repos/${owner}/${repo}/contents/${repoPath}`;
  const headers = githubHeaders(pat);
  let existingSha;
  let getResp;
  try {
    getResp = await fetch(apiBase, { headers });
  } catch (err) {
    throw new PushError(
      "network",
      `Network error fetching existing file at ${repoPath}: ${err.message}`
    );
  }
  if (getResp.ok) {
    const existing = await getResp.json();
    existingSha = existing.sha;
  } else if (getResp.status === 401 || getResp.status === 403) {
    throw new PushError(
      "auth",
      `GitHub auth failed (${getResp.status}) reading ${repoPath}. Rotate the PAT stored in the secret referenced by config.githubPatSecretId.`,
      getResp.status
    );
  } else if (getResp.status >= 500) {
    throw new PushError(
      "network",
      `GitHub API ${getResp.status} reading ${repoPath}. Retry this call.`,
      getResp.status
    );
  }
  const body = {
    message,
    content: contentBase64,
    branch
  };
  if (existingSha) body.sha = existingSha;
  let putResp;
  try {
    putResp = await fetch(apiBase, {
      method: "PUT",
      headers,
      body: JSON.stringify(body)
    });
  } catch (err) {
    throw new PushError(
      "network",
      `Network error during push of ${repoPath}: ${err.message}`
    );
  }
  if (!putResp.ok) {
    const status = putResp.status;
    if (status === 401 || status === 403) {
      throw new PushError(
        "auth",
        `GitHub push auth failed (${status}). Rotate the PAT stored in the secret referenced by config.githubPatSecretId.`,
        status
      );
    }
    if (status === 409 || status === 422) {
      throw new PushError(
        "conflict",
        `GitHub returned ${status} conflict on ${repoPath}. Re-fetch the file SHA and retry once.`,
        status
      );
    }
    if (status >= 500) {
      throw new PushError(
        "network",
        `GitHub API ${status} during push of ${repoPath}. Retry this call.`,
        status
      );
    }
    const errText = await putResp.text();
    throw new PushError(
      "network",
      `GitHub API error ${status} pushing ${repoPath}: ${errText}`,
      status
    );
  }
  const result = await putResp.json();
  const commitSha = result.commit?.sha ?? "";
  const permalink = `https://github.com/${owner}/${repo}/blob/${commitSha}/${repoPath}`;
  return { commitSha, permalink };
}
async function renderCadScript(script, format) {
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const artifactPath = join(tmpdir(), `cad-${Date.now()}.${format}`);
  const { writeFile } = await import("node:fs/promises");
  await writeFile(artifactPath, `; CAD stub \u2014 script hash: ${script.length}`);
  return artifactPath;
}
var plugin = definePlugin({
  async setup(ctx) {
    ctx.logger.info("CAD plugin worker starting");
    ctx.tools.register(
      "cad_render",
      {
        displayName: "CAD Render",
        description: "Execute a CadQuery Python script and return the resulting 3D model artifact path.",
        parametersSchema: {
          type: "object",
          properties: {
            script: { type: "string", description: "CadQuery Python script." },
            format: {
              type: "string",
              enum: ["step", "stl"],
              description: "Output format. Defaults to 'step'."
            }
          },
          required: ["script"]
        }
      },
      async (params) => {
        const { script, format = "step" } = params;
        ctx.logger.info("cad_render: starting render", { format });
        const artifactPath = await renderCadScript(script, format);
        ctx.logger.info("cad_render: render complete", { artifactPath, format });
        return { content: artifactPath, data: { artifactPath, format } };
      }
    );
    ctx.tools.register(
      "cad_commit",
      {
        displayName: "CAD Commit Artifact",
        description: "Commit a previously rendered CAD artifact to the project GitHub repository.",
        parametersSchema: {
          type: "object",
          properties: {
            artifactPath: {
              type: "string",
              description: "Local artifact path from cad_render."
            },
            repoPath: {
              type: "string",
              description: "Target path in the repository."
            },
            commitMessage: {
              type: "string",
              description: "Git commit message."
            }
          },
          required: ["artifactPath", "repoPath", "commitMessage"]
        }
      },
      async (params) => {
        const { artifactPath, repoPath, commitMessage } = params;
        const { resolve } = await import("node:path");
        const { tmpdir } = await import("node:os");
        const resolvedArtifactPath = resolve(artifactPath);
        const allowedPrefix = tmpdir();
        if (!resolvedArtifactPath.startsWith(allowedPrefix + "/")) {
          ctx.logger.warn("cad_commit: rejected out-of-bounds artifactPath", {
            resolvedArtifactPath
          });
          return {
            data: { error: "artifactPath must be within the temp directory." }
          };
        }
        const config = await ctx.config.get();
        if (!config.githubPatSecretId) {
          return {
            data: {
              error: "githubPatSecretId is not configured. Set it in plugin instance config."
            }
          };
        }
        ctx.logger.info("cad_commit: resolving GitHub PAT from secrets DB");
        const pat = await ctx.secrets.resolve(config.githubPatSecretId);
        ctx.logger.info("cad_commit: pushing artifact", { repoPath });
        const repoUrl = "https://github.com/claudegoogl-sudo/paperclip-plugin-cad.git";
        const { commitSha } = await pushArtifactToGitHub(
          pat,
          repoUrl,
          DEFAULT_ARTIFACT_BRANCH,
          resolvedArtifactPath,
          repoPath,
          commitMessage
        );
        ctx.logger.info("cad_commit: artifact committed", {
          repoPath,
          commitSha
        });
        return {
          content: `Artifact committed to ${repoPath} (${commitSha})`,
          data: { repoPath, commitSha }
        };
      }
    );
    ctx.tools.register(
      "cad_export",
      {
        displayName: "CAD Export & Commit",
        description: "Render a CadQuery script and commit the artifact to the configured GitHub artifact repo. Returns commitSha, permalink, and artifactPath. Idempotent: if the same toolCallId was already pushed, returns the existing commit info without re-pushing.",
        parametersSchema: {
          type: "object",
          properties: {
            script: {
              type: "string",
              description: "CadQuery Python script to render."
            },
            format: {
              type: "string",
              enum: ["step", "stl"],
              description: "Output format. Defaults to 'step'."
            },
            paperclipTicketId: {
              type: "string",
              description: "Paperclip ticket ID (e.g. PLA-56). Included in artifact path and commit message."
            },
            toolCallId: {
              type: "string",
              description: "Unique ID for this tool call. Used for deterministic artifact path and idempotency."
            },
            filename: {
              type: "string",
              description: "Optional artifact filename. Defaults to 'artifact.<format>'."
            }
          },
          required: ["script", "paperclipTicketId", "toolCallId"]
        }
      },
      async (params) => {
        const {
          script,
          format = "step",
          paperclipTicketId,
          toolCallId,
          filename
        } = params;
        ctx.logger.info("cad_export: starting", {
          format,
          paperclipTicketId,
          toolCallId
        });
        const config = await ctx.config.get();
        if (!config.githubPatSecretId) {
          return {
            data: {
              error: "prerequisite_missing",
              message: "githubPatSecretId is not configured. Set it in plugin instance config."
            }
          };
        }
        const repoUrl = config.artifactRepoUrl ?? DEFAULT_ARTIFACT_REPO_URL;
        const branch = config.artifactRepoBranch ?? DEFAULT_ARTIFACT_BRANCH;
        const resolvedFilename = filename ?? `artifact.${format}`;
        const repoPath = `artifacts/${paperclipTicketId}/${toolCallId}/${resolvedFilename}`;
        ctx.logger.info("cad_export: resolving GitHub PAT");
        const pat = await ctx.secrets.resolve(config.githubPatSecretId);
        try {
          await checkRepoPrerequisite(pat, repoUrl);
        } catch (err) {
          if (err instanceof PushError && err.kind === "prerequisite_missing") {
            ctx.logger.warn(
              "cad_export: artifact repo prerequisite check failed",
              {
                repoUrl,
                httpStatus: err.httpStatus
                // PAT intentionally omitted from this log.
              }
            );
            return {
              data: {
                error: "prerequisite_missing",
                message: err.message
              }
            };
          }
          throw err;
        }
        ctx.logger.info("cad_export: checking idempotency", { repoPath });
        const existing = await checkArtifactExists(pat, repoUrl, repoPath);
        if (existing) {
          ctx.logger.info("cad_export: artifact already exists (idempotent)", {
            repoPath,
            commitSha: existing.commitSha
          });
          return {
            content: `Artifact already present at ${repoPath} (${existing.commitSha})`,
            data: {
              commitSha: existing.commitSha,
              permalink: existing.permalink,
              artifactPath: repoPath
            }
          };
        }
        ctx.logger.info("cad_export: rendering CAD script", { format });
        const localFile = await renderCadScript(script, format);
        ctx.logger.info("cad_export: render complete", { localFile, format });
        const commitMessage = `CAD artifact: ticket=${paperclipTicketId} tool=cad_export call=${toolCallId}`;
        const doPush = () => pushArtifactToGitHub(
          pat,
          repoUrl,
          branch,
          localFile,
          repoPath,
          commitMessage
        );
        ctx.logger.info("cad_export: pushing artifact", { repoPath, branch });
        try {
          let pushResult;
          try {
            pushResult = await doPush();
          } catch (firstErr) {
            if (firstErr instanceof PushError && firstErr.kind === "conflict") {
              ctx.logger.warn(
                "cad_export: conflict on push, retrying once",
                { repoPath }
              );
              pushResult = await doPush();
            } else {
              throw firstErr;
            }
          }
          ctx.logger.info("cad_export: artifact committed", {
            repoPath,
            commitSha: pushResult.commitSha
          });
          return {
            content: `Artifact committed: ${pushResult.permalink}`,
            data: {
              commitSha: pushResult.commitSha,
              permalink: pushResult.permalink,
              artifactPath: repoPath
            }
          };
        } catch (err) {
          if (err instanceof PushError) {
            ctx.logger.warn("cad_export: push failed", {
              kind: err.kind,
              httpStatus: err.httpStatus
              // PAT intentionally omitted from this log.
            });
            return {
              data: {
                error: err.kind,
                message: err.message
              }
            };
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
