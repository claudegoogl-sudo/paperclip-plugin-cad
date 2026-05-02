import type { PaperclipPluginManifestV1 } from "@paperclipai/plugin-sdk";

/**
 * PLA-114 / PLA-106 §5.2 — declare the kernel-sandbox requirement in the
 * manifest. The host capability negotiation refuses to install the plugin
 * on a host that does not advertise this requirement met (bubblewrap on
 * PATH). The SDK manifest type does not yet model this field, so we extend
 * locally; the JSON emitted at build time carries the field through to the
 * host loader as documented in the spec.
 */
type ManifestWithRuntimeRequirements = PaperclipPluginManifestV1 & {
  runtimeRequirements: {
    /** "bubblewrap" — kernel-enforced sandbox required for the CAD worker. */
    kernelSandbox: "bubblewrap";
  };
  /**
   * Build-manifest pin for the seccomp filter blob AND the python-side
   * loader shim (PLA-114 / PLA-106 §5.2 rev 4: pins **both**
   * `seccomp_filter.bpf` AND `seccomp_load.py`; runtime hard-errors on
   * either mismatch). The dual pin closes the substitution-attack window
   * where an attacker swaps the loader (which calls `prctl(PR_SET_SECCOMP)`)
   * for a no-op while leaving the filter blob unchanged. The build script
   * substitutes the real digests at `dist/manifest.js` build time; the
   * placeholders below are what ship in source. An unsubstituted
   * placeholder failing a sha256 length check at startup is the intended
   * fail-closed signal.
   */
  worker?: {
    seccompFilterPath: string;
    seccompFilterSha256: string;
    seccompLoaderPath: string;
    seccompLoaderSha256: string;
  };
};

const manifest: ManifestWithRuntimeRequirements = {
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

  // PLA-114 §5.2 — host-side kernel-sandbox capability negotiation.
  runtimeRequirements: {
    kernelSandbox: "bubblewrap",
  },

  // PLA-114 acceptance — pin the seccomp filter blob digest AND the
  // python-side loader shim digest (rev-4 §5.2 dual pin). The build
  // script reads `worker/seccomp_filter.bpf.sha256` (produced by
  // `make -C worker`) and computes sha256 of `worker/seccomp_load.py`,
  // substituting both values at build time. Literals below are
  // placeholders; an unsubstituted placeholder failing a sha256 length
  // check at startup is the intended fail-closed signal. The dual pin
  // closes the substitution-attack window where an attacker swaps the
  // loader (which calls prctl(PR_SET_SECCOMP)) for a no-op while leaving
  // the filter blob unchanged.
  worker: {
    seccompFilterPath: "./worker/seccomp_filter.bpf",
    seccompFilterSha256: "__PLA114_SECCOMP_FILTER_SHA256__",
    seccompLoaderPath: "./worker/seccomp_load.py",
    seccompLoaderSha256: "__PLA114_SECCOMP_LOADER_SHA256__",
  },

  // instanceConfigSchema — ties secret-scope strictly to githubPatSecretId
  // (PLA-41 remediation #2). Fields validated by the host before plugin load.
  // PLA-74 F3: additionalProperties:false so unknown keys are rejected at host
  // load time rather than silently ignored (fail-closed).
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
    additionalProperties: false,
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
            // PLA-74 F1/F2 — allowlist regex; rejects path traversal and
            // commit-message injection at the host's schema-validation gate.
            pattern: "^[A-Z][A-Z0-9]{1,9}-[0-9]{1,9}$",
            description:
              "Paperclip ticket ID (e.g. PLA-56). Used in artifact path and commit message.",
          },
          toolCallId: {
            type: "string",
            pattern: "^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$",
            description:
              "Unique ID for this tool call. Used for deterministic artifact path and idempotency.",
          },
          filename: {
            type: "string",
            pattern: "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$",
            description:
              "Optional artifact filename. Defaults to 'artifact.<format>'.",
          },
        },
        required: ["artifactId", "format", "paperclipTicketId", "toolCallId"],
        // PLA-74 F3 — fail-closed on unknown fields; matches cad:run_script.
        additionalProperties: false,
      },
    },
  ],
};

export default manifest;
