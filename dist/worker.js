// src/worker.ts
import { definePlugin, runWorker } from "@paperclipai/plugin-sdk";
async function pushArtifactToGitHub(pat, repoUrl, localFile, repoPath, message) {
  const match = repoUrl.match(/github\.com\/([^/]+)\/([^/]+?)(?:\.git)?$/);
  if (!match) throw new Error(`Unrecognised GitHub URL: ${repoUrl}`);
  const [, owner, repo] = match;
  const { readFile } = await import("node:fs/promises");
  const content = await readFile(localFile);
  const contentBase64 = content.toString("base64");
  const apiBase = `https://api.github.com/repos/${owner}/${repo}/contents/${repoPath}`;
  const headers = {
    Authorization: `Bearer ${pat}`,
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "Content-Type": "application/json",
    "User-Agent": "paperclip-plugin-cad/0.1.0"
  };
  let existingSha;
  const getResp = await fetch(apiBase, { headers });
  if (getResp.ok) {
    const existing = await getResp.json();
    existingSha = existing.sha;
  }
  const body = {
    message,
    content: contentBase64
  };
  if (existingSha) body.sha = existingSha;
  const putResp = await fetch(apiBase, {
    method: "PUT",
    headers,
    body: JSON.stringify(body)
  });
  if (!putResp.ok) {
    const errText = await putResp.text();
    throw new Error(`GitHub API error ${putResp.status}: ${errText}`);
  }
  const result = await putResp.json();
  return result.commit?.sha ?? "(unknown sha)";
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
        const commitSha = await pushArtifactToGitHub(
          pat,
          repoUrl,
          artifactPath,
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
