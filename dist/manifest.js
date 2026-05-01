// src/manifest.ts
var manifest = {
  id: "platform.cad",
  apiVersion: 1,
  version: "0.1.0",
  displayName: "CAD (CadQuery)",
  description: "Lets agents design and export 3D CAD models via CadQuery tool calls. v0.1.0 surface: cad:run_script (execute Python \u2192 staged artifact) and cad:export (staged artifact \u2192 local file). Operator-confirmed via approval f420bc31.",
  author: "Platform",
  categories: ["connector"],
  // Capabilities (v0.1.0):
  //   agent.tools.register — register cad:run_script and cad:export
  //   http.outbound        — reserved; real CadQuery worker (sub-goal 2)
  //   secrets.read-ref     — reserved; future worker auth flows (sub-goal 2)
  //   metrics.write        — ctx.metrics counters + duration histograms (AC3)
  capabilities: [
    "agent.tools.register",
    "http.outbound",
    "secrets.read-ref",
    "metrics.write"
  ],
  entrypoints: {
    worker: "./dist/worker.js"
  },
  // v0.1.0 tool surface — operator-confirmed via approval f420bc31 (2026-05-01).
  // cad:hello (PLA-39 scaffold stub) intentionally removed here (AC7).
  // cad_render / cad_commit / cad_export (intermediate work) also removed.
  tools: [
    {
      name: "cad:run_script",
      displayName: "CAD Run Script",
      description: "Execute a CadQuery Python script string. Returns { artifactId, summary }. The artifact is staged locally; use cad:export to retrieve it in a specific file format.",
      parametersSchema: {
        type: "object",
        properties: {
          script: {
            type: "string",
            description: "CadQuery Python script to execute. Must define a CadQuery shape."
          },
          timeout: {
            type: "integer",
            minimum: 1,
            maximum: 300,
            description: "Execution timeout in seconds (1\u2013300, default: 30). Enforced by the CAD worker (sub-goal 2); stub accepts but ignores."
          }
        },
        required: ["script"],
        additionalProperties: false
      }
    },
    {
      name: "cad:export",
      displayName: "CAD Export",
      description: "Export a previously staged CAD artifact to a specific file format. Returns { filePath } within the plugin artifact-staging area. NOT a URL \u2014 sub-goal 5 wires the artifact-persistence pipeline.",
      parametersSchema: {
        type: "object",
        properties: {
          artifactId: {
            type: "string",
            description: "Artifact ID returned by cad:run_script."
          },
          format: {
            type: "string",
            enum: ["step", "stl", "3mf"],
            description: "Output file format."
          }
        },
        required: ["artifactId", "format"],
        additionalProperties: false
      }
    }
  ]
};
var manifest_default = manifest;
export {
  manifest_default as default
};
//# sourceMappingURL=manifest.js.map
