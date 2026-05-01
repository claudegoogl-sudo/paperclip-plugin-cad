import type { PaperclipPluginManifestV1 } from "@paperclipai/plugin-sdk";

const manifest: PaperclipPluginManifestV1 = {
  id: "platform.cad",
  apiVersion: 1,
  version: "0.1.0",
  displayName: "CAD (CadQuery)",
  description:
    "Lets agents design and render 3D CAD models via CadQuery tool calls, " +
    "and commit the resulting artifacts to a project GitHub repository.",
  author: "Platform",
  categories: ["connector"],

  // Capabilities required by this plugin:
  //   secrets.read-ref       — ctx.secrets.resolve for GitHub PAT
  //   agent.tools.register   — register CAD tool handlers for agents
  //   http.outbound          — CAD worker subprocess + git push to GitHub
  //   metrics.write          — push error/success counters (PLA-56 observability)
  capabilities: [
    "secrets.read-ref",
    "agent.tools.register",
    "http.outbound",
    "metrics.write",
  ],

  entrypoints: {
    worker: "./dist/worker.js",
  },

  // instanceConfigSchema ties secret-scope strictly to githubPatSecretId.
  // Without this the host uses a wider heuristic ("any UUID in config is
  // resolvable"). Declaring it here means only the field below is eligible
  // for ctx.secrets.resolve calls.  — PLA-41 remediation #2
  instanceConfigSchema: {
    type: "object",
    properties: {
      githubPatSecretId: {
        type: "string",
        format: "secret-ref",
        description:
          "Paperclip secret UUID for the GitHub PAT used to push CAD artifacts. " +
          "Create the secret in the board UI and paste its UUID here.",
      },
      artifactRepoUrl: {
        type: "string",
        description:
          "HTTPS clone URL of the GitHub repository where CAD artifacts are stored. " +
          "Defaults to https://github.com/claudegoogl-sudo/cad-artifacts.git. " +
          "Operator must pre-create this repo; the plugin is push-only (PLA-56 AC#2).",
      },
      artifactRepoBranch: {
        type: "string",
        description: "Branch to commit artifacts to. Defaults to 'main'.",
      },
    },
    required: ["githubPatSecretId"],
  },

  tools: [
    {
      name: "cad_render",
      displayName: "CAD Render",
      description:
        "Execute a CadQuery Python script and return the resulting 3D model " +
        "as a STEP/STL artifact URL. The script runs in an isolated subprocess.",
      parametersSchema: {
        type: "object",
        properties: {
          script: {
            type: "string",
            description:
              "CadQuery Python script to execute. Must produce a final Shape " +
              "object assigned to `result`.",
          },
          format: {
            type: "string",
            enum: ["step", "stl"],
            description: "Output file format. Defaults to 'step'.",
          },
        },
        required: ["script"],
      },
    },
    {
      name: "cad_commit",
      displayName: "CAD Commit Artifact",
      description:
        "Commit a previously rendered CAD artifact to the project GitHub repository " +
        "and return the commit URL.",
      parametersSchema: {
        type: "object",
        properties: {
          artifactPath: {
            type: "string",
            description: "Local artifact path returned by cad_render.",
          },
          repoPath: {
            type: "string",
            description:
              "Target path within the repository (e.g. 'parts/bracket.step').",
          },
          commitMessage: {
            type: "string",
            description: "Git commit message.",
          },
        },
        required: ["artifactPath", "repoPath", "commitMessage"],
      },
    },
    {
      name: "cad_export",
      displayName: "CAD Export & Commit",
      description:
        "Render a CadQuery script and commit the artifact to the configured GitHub " +
        "artifact repository in a single call. " +
        "Artifact path is deterministic: artifacts/{paperclipTicketId}/{toolCallId}/{filename}. " +
        "Idempotent: re-calling with the same toolCallId returns the existing commit info. " +
        "Returns commitSha, permalink, and artifactPath on success.",
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
            description: "Output file format. Defaults to 'step'.",
          },
          paperclipTicketId: {
            type: "string",
            description:
              "Paperclip ticket ID (e.g. PLA-56). Used in the artifact path and commit message.",
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
  ],
};

export default manifest;
