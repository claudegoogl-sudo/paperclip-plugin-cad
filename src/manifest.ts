import type { PaperclipPluginManifestV1 } from "@paperclipai/plugin-sdk";

const manifest: PaperclipPluginManifestV1 = {
  id: "platform.cad",
  apiVersion: 1,
  version: "0.1.0",
  displayName: "CAD (CadQuery)",
  description:
    "Lets agents design and export 3D CAD models via CadQuery tool calls. " +
    "v0.1.0 surface: cad:run_script (execute Python → staged artifact) and " +
    "cad:export (staged artifact → GitHub commit + permalink). " +
    "Operator-confirmed via approval f420bc31.",
  author: "Platform",
  categories: ["connector"],

  // Capabilities (v0.1.0):
  //   agent.tools.register — register cad:run_script and cad:export
  //   http.outbound        — GitHub Contents API push (PLA-56)
  //   secrets.read-ref     — ctx.secrets.resolve for GitHub PAT (PLA-47)
  //   metrics.write        — ctx.metrics counters + duration histograms
  capabilities: [
    "agent.tools.register",
    "http.outbound",
    "secrets.read-ref",
    "metrics.write",
  ],

  entrypoints: {
    worker: "./dist/worker.js",
  },

  // instanceConfigSchema — ties secret-scope strictly to githubPatSecretId
  // (PLA-41 remediation #2). Fields validated by the host before plugin load.
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

  // v0.1.0 tool surface — operator-confirmed via approval f420bc31 (2026-05-01).
  tools: [
    {
      name: "cad:run_script",
      displayName: "CAD Run Script",
      description:
        "Execute a CadQuery Python script string. " +
        "Returns { artifactId, summary }. The artifact is staged locally; " +
        "use cad:export to commit it to the GitHub artifact repo.",
      parametersSchema: {
        type: "object",
        properties: {
          script: {
            type: "string",
            description:
              "CadQuery Python script to execute. Must define a CadQuery shape.",
          },
          timeout: {
            type: "integer",
            minimum: 1,
            maximum: 300,
            description:
              "Execution timeout in seconds (1–300, default: 30). " +
              "Enforced by the CAD worker (sub-goal 2); stub accepts but ignores.",
          },
        },
        required: ["script"],
        additionalProperties: false,
      },
    },
    {
      name: "cad:export",
      displayName: "CAD Export",
      description:
        "Export a previously staged CAD artifact to a specific file format and " +
        "commit it to the configured GitHub artifact repository. " +
        "Artifact path is deterministic: artifacts/{paperclipTicketId}/{toolCallId}/{filename}. " +
        "Idempotent: re-calling with the same toolCallId returns the existing commit info. " +
        "Returns { commitSha, permalink, artifactPath } on success.",
      parametersSchema: {
        type: "object",
        properties: {
          artifactId: {
            type: "string",
            description: "Artifact ID returned by cad:run_script.",
          },
          format: {
            type: "string",
            enum: ["step", "stl", "3mf"],
            description: "Output file format.",
          },
          paperclipTicketId: {
            type: "string",
            description:
              "Paperclip ticket ID (e.g. PLA-56). Used in artifact path and commit message.",
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
        required: ["artifactId", "format", "paperclipTicketId", "toolCallId"],
      },
    },
  ],
};

export default manifest;
