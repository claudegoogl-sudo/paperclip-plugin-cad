/**
 * CAD plugin worker — sub-goal 4: secrets integration
 *
 * Security rules (enforced here, reviewed in PLA-36/PLA-41):
 *   - PAT is resolved via ctx.secrets.resolve(config.githubPatSecretId).
 *     config.githubPatSecretId must be the UUID from the Paperclip secrets DB,
 *     not a string name.  A name string throws InvalidSecretRefError at
 *     plugin-secrets-handler.js:172–174.
 *   - PAT is never logged (no ctx.logger.* calls that include the pat value).
 *   - PAT is never stored in ctx.state, ctx.data, or any persistent store.
 *   - PAT is never returned from a tool route.
 *   - PAT is used only within the function scope that resolves it; no module-
 *     level caching.
 */

import { definePlugin, runWorker } from "@paperclipai/plugin-sdk";
import type { PluginContext } from "@paperclipai/plugin-sdk";

// ---------------------------------------------------------------------------
// Config shape (matches instanceConfigSchema in manifest.ts)
// ---------------------------------------------------------------------------

interface CadPluginConfig {
  /** UUID of the Paperclip secret that holds the GitHub PAT. */
  githubPatSecretId: string;
}

// ---------------------------------------------------------------------------
// Git helper — uses PAT within the call, does not persist or log it
// ---------------------------------------------------------------------------

/**
 * Push a file to the GitHub repository.
 *
 * The PAT is passed as a parameter so the caller controls its lifetime.
 * It is used only to build the authenticated remote URL and is never stored
 * beyond this function's stack frame.
 *
 * @param pat    Resolved GitHub PAT (never log this value).
 * @param repoUrl  HTTPS clone URL of the target repository.
 * @param localFile  Absolute path to the file to commit.
 * @param repoPath   Target path inside the repository.
 * @param message  Commit message.
 * @returns Commit SHA from the GitHub API response.
 */
async function pushArtifactToGitHub(
  pat: string,
  repoUrl: string,
  localFile: string,
  repoPath: string,
  message: string,
): Promise<string> {
  // Parse owner/repo from the HTTPS URL.
  const match = repoUrl.match(/github\.com\/([^/]+)\/([^/]+?)(?:\.git)?$/);
  if (!match) throw new Error(`Unrecognised GitHub URL: ${repoUrl}`);
  const [, owner, repo] = match;

  const { readFile } = await import("node:fs/promises");
  const content = await readFile(localFile);
  const contentBase64 = content.toString("base64");

  // Check if the file already exists (needed for the update sha).
  const apiBase = `https://api.github.com/repos/${owner}/${repo}/contents/${repoPath}`;
  const headers: Record<string, string> = {
    Authorization: `Bearer ${pat}`,
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "Content-Type": "application/json",
    "User-Agent": "paperclip-plugin-cad/0.1.0",
  };

  let existingSha: string | undefined;
  const getResp = await fetch(apiBase, { headers });
  if (getResp.ok) {
    const existing = (await getResp.json()) as { sha?: string };
    existingSha = existing.sha;
  }

  const body: Record<string, unknown> = {
    message,
    content: contentBase64,
  };
  if (existingSha) body.sha = existingSha;

  const putResp = await fetch(apiBase, {
    method: "PUT",
    headers,
    body: JSON.stringify(body),
  });

  if (!putResp.ok) {
    const errText = await putResp.text();
    throw new Error(`GitHub API error ${putResp.status}: ${errText}`);
  }

  const result = (await putResp.json()) as { commit?: { sha?: string } };
  return result.commit?.sha ?? "(unknown sha)";
}

// ---------------------------------------------------------------------------
// CadQuery render helper (placeholder — full implementation is sub-goal 5)
// ---------------------------------------------------------------------------

/**
 * Execute a CadQuery script in an isolated subprocess.
 *
 * Full implementation (worker sandbox, timeout, stdout/stderr capture) is
 * tracked under sub-goal 2/5.  This stub validates the call surface without
 * running real CadQuery so sub-goal 4 (secrets integration) can be verified
 * independently.
 */
async function renderCadScript(
  script: string,
  format: "step" | "stl",
): Promise<string> {
  // Placeholder: return a deterministic temp path.
  // Real impl (sub-goal 5) will spawn `python3 -c "<script>"` via
  // child_process with a timeout and write the output file.
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const artifactPath = join(tmpdir(), `cad-${Date.now()}.${format}`);
  // Placeholder: write a minimal valid file so sub-goal 4 tests can proceed.
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

        // Return only the artifact path — never return secrets or PAT.
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

        // Fetch current config to obtain the secret UUID.
        const config = (await ctx.config.get()) as CadPluginConfig;

        if (!config.githubPatSecretId) {
          return {
            data: {
              error:
                "githubPatSecretId is not configured. Set it in plugin instance config.",
            },
          };
        }

        ctx.logger.info("cad_commit: resolving GitHub PAT from secrets DB");

        // CRITICAL (PLA-41 #1): pass UUID from config, not a string name.
        // A name string throws InvalidSecretRefError at
        // plugin-secrets-handler.js:172-174.
        const pat = await ctx.secrets.resolve(config.githubPatSecretId);

        // PAT is now in scope. Use it immediately, do not log it.
        ctx.logger.info("cad_commit: pushing artifact", { repoPath });

        const repoUrl = "https://github.com/claudegoogl-sudo/paperclip-plugin-cad.git";

        const commitSha = await pushArtifactToGitHub(
          pat,
          repoUrl,
          artifactPath,
          repoPath,
          commitMessage,
        );

        // PAT goes out of scope here.
        ctx.logger.info("cad_commit: artifact committed", {
          repoPath,
          commitSha,
        });

        // Return commit info only — never return the PAT.
        return {
          content: `Artifact committed to ${repoPath} (${commitSha})`,
          data: { repoPath, commitSha },
        };
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
