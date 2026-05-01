// src/manifest.ts
var manifest = {
  id: "platform.cad",
  apiVersion: 1,
  version: "0.1.0",
  displayName: "CAD (CadQuery)",
  // Purpose: enable agents to design and export 3D CAD models programmatically
  // using CadQuery (Python), then commit the resulting artifacts (STEP/STL) to
  // a project GitHub repository in a single, auditable workflow.
  //
  // Scope (v0.1.0): two production tools (cad_render, cad_commit) plus a
  // stub verification tool (cad:hello). Full CadQuery subprocess sandboxing,
  // configurable repo URL, and additional export targets are out of scope for
  // v0.1.0 — see CHANGELOG.md for known limitations.
  description: "Lets agents design and render 3D CAD models via CadQuery tool calls, and commit the resulting artifacts to a project GitHub repository. v0.1.0 scope: cad_render (script to artifact path) and cad_commit (artifact path to GitHub commit). See SKILL.md for invocation schemas.",
  author: "Platform",
  categories: ["connector"],
  // Capability rationale:
  //   secrets.read-ref     -- resolve the GitHub PAT from the Paperclip secrets
  //                          store on each cad_commit call (no caching).
  //   agent.tools.register -- register cad_render, cad_commit, and cad:hello on
  //                          every agent this plugin is enabled for.
  //   http.outbound        -- push rendered artifacts to the GitHub Contents API
  //                          (api.github.com). No other outbound targets used.
  //   metrics.write        -- emit tool-call counters and latency via
  //                          ctx.metrics.write for observability.
  capabilities: [
    "secrets.read-ref",
    "agent.tools.register",
    "http.outbound",
    "metrics.write"
  ],
  entrypoints: {
    worker: "./dist/worker.js"
  },
  // instanceConfigSchema ties secret-scope strictly to githubPatSecretId.
  // Without this the host uses a wider heuristic ("any UUID in config is
  // resolvable"). Declaring it here means only the field below is eligible
  // for ctx.secrets.resolve calls.  -- PLA-41 remediation #2
  instanceConfigSchema: {
    type: "object",
    properties: {
      githubPatSecretId: {
        type: "string",
        format: "secret-ref",
        description: "Paperclip secret UUID for the GitHub PAT used to push CAD artifacts. Create the secret in the board UI and paste its UUID here."
      }
    },
    required: ["githubPatSecretId"]
  },
  tools: [
    {
      name: "cad:hello",
      displayName: "CAD Hello",
      description: "Stub tool -- returns a canned OK response with no side effects. Used for end-to-end verification of the plugin tool dispatch path (PLA-53).",
      parametersSchema: {
        type: "object",
        properties: {
          name: {
            type: "string",
            description: "Optional greeting name. Defaults to 'world'."
          }
        },
        required: [],
        additionalProperties: false
      }
    },
    {
      name: "cad_render",
      displayName: "CAD Render",
      description: "Execute a CadQuery Python script and return the resulting 3D model as a STEP/STL artifact path. The script runs in an isolated subprocess.",
      parametersSchema: {
        type: "object",
        properties: {
          script: {
            type: "string",
            description: "CadQuery Python script to execute. Must produce a final Shape object assigned to `result`."
          },
          format: {
            type: "string",
            enum: ["step", "stl"],
            description: "Output file format. Defaults to 'step'."
          }
        },
        required: ["script"]
      }
    },
    {
      name: "cad_commit",
      displayName: "CAD Commit Artifact",
      description: "Commit a previously rendered CAD artifact to the project GitHub repository and return the commit SHA. artifactPath must be inside the system temp directory.",
      parametersSchema: {
        type: "object",
        properties: {
          artifactPath: {
            type: "string",
            description: "Local artifact path returned by cad_render."
          },
          repoPath: {
            type: "string",
            description: "Target path within the repository (e.g. 'parts/bracket.step')."
          },
          commitMessage: {
            type: "string",
            description: "Git commit message."
          }
        },
        required: ["artifactPath", "repoPath", "commitMessage"]
      }
    }
  ]
};
var manifest_default = manifest;
export {
  manifest_default as default
};
//# sourceMappingURL=manifest.js.map
