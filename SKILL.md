# CAD Plugin — Skill Reference

Adoption surface for agent authors. Covers tool invocation, schemas, error codes, and a worked example.

Plugin: `platform.cad` · Version: `0.1.3` · Tracker: [PLA-32](/PLA/issues/PLA-32)

---

## Tools

### `cad.run_script`

Execute a CadQuery Python script string in an isolated subprocess. Returns a staged artifact ID and a summary of the shape produced.

#### Input schema

| Field     | Type    | Required | Description |
|-----------|---------|----------|-------------|
| `script`  | string  | yes      | CadQuery Python script to execute. Must define a CadQuery shape. |
| `timeout` | integer | no       | Execution timeout in seconds (1–300, default: 30). Enforced by the CAD worker; the v0.1.0 stub accepts but ignores this field. |

```json
{
  "type": "object",
  "properties": {
    "script": {
      "type": "string",
      "description": "CadQuery Python script to execute. Must define a CadQuery shape."
    },
    "timeout": {
      "type": "integer",
      "minimum": 1,
      "maximum": 300,
      "description": "Execution timeout in seconds (1–300, default: 30)."
    }
  },
  "required": ["script"],
  "additionalProperties": false
}
```

#### Output

```json
{
  "artifactId": "cad-artifact-<uuid>",
  "summary": "Box 10×10×10 mm"
}
```

| Field        | Type   | Description |
|--------------|--------|-------------|
| `artifactId` | string | Opaque ID for the staged artifact. Pass this to `cad.export`. |
| `summary`    | string | Human-readable description of the shape produced. |

---

### `cad.export`

Export a previously staged CAD artifact to a specific file format and commit it to the configured GitHub artifact repository. Artifact path is deterministic: `artifacts/{paperclipTicketId}/{toolCallId}/{filename}`. Idempotent: re-calling with the same `toolCallId` returns the existing commit info.

#### Input schema

| Field               | Type   | Required | Description |
|---------------------|--------|----------|-------------|
| `artifactId`        | string | yes      | Artifact ID returned by `cad.run_script`. |
| `format`            | string | yes      | Output file format: `"step"`, `"stl"`, `"3mf"`, `"dxf"`, or `"svg"`. See [Format notes](#format-notes) below for the 2D-vector caveats on `dxf` / `svg`. |
| `paperclipTicketId` | string | yes      | Paperclip ticket ID (e.g. `PLA-56`). Used in artifact path and commit message. |
| `toolCallId`        | string | yes      | Unique ID for this tool call. Used for deterministic artifact path and idempotency. |
| `filename`          | string | no       | Optional artifact filename. Defaults to `artifact.<format>`. |

```json
{
  "type": "object",
  "properties": {
    "artifactId": {
      "type": "string",
      "description": "Artifact ID returned by cad.run_script."
    },
    "format": {
      "type": "string",
      "enum": ["step", "stl", "3mf", "dxf", "svg"],
      "description": "Output file format."
    },
    "paperclipTicketId": {
      "type": "string",
      "description": "Paperclip ticket ID (e.g. PLA-56). Used in artifact path and commit message."
    },
    "toolCallId": {
      "type": "string",
      "description": "Unique ID for this tool call. Used for deterministic artifact path and idempotency."
    },
    "filename": {
      "type": "string",
      "description": "Optional artifact filename. Defaults to 'artifact.<format>'."
    }
  },
  "required": ["artifactId", "format", "paperclipTicketId", "toolCallId"]
}
```

#### Output

```json
{
  "commitSha": "abc123def456...",
  "permalink": "https://github.com/<owner>/<repo>/blob/abc123def456.../artifacts/PLA-56/<toolCallId>/artifact.step",
  "artifactPath": "artifacts/PLA-56/<toolCallId>/artifact.step"
}
```

| Field          | Type   | Description |
|----------------|--------|-------------|
| `commitSha`    | string | GitHub commit SHA for the export. |
| `permalink`    | string | GitHub permalink (blob URL pinned to `commitSha`) for the artifact. |
| `artifactPath` | string | Path within the artifact repository: `artifacts/{paperclipTicketId}/{toolCallId}/{filename}`. |

> **Note:** When the worker runs without tenant context (test/local fallback at `worker.ts:451`), `cad.export` returns `{ filePath, ... }` instead. Production agent calls always go down the GitHub-commit path above.

---

## Format notes

| Format | Dimensionality | Required shape | Notes |
|--------|----------------|----------------|-------|
| `step` | 3D (B-Rep) | Any CadQuery solid / compound | Canonical interchange; first-class output. |
| `stl`  | 3D (mesh)  | Any CadQuery solid / compound | Triangulated mesh; used for 3D printing slicers. |
| `3mf`  | 3D (mesh)  | Any CadQuery solid / compound | Modern mesh with material/color metadata. |
| `dxf`  | **2D vector** | A 2D `cq.Workplane` (wires / faces) | For laser/plasma/router cut paths. Passing a pure 3D solid surfaces a `script_error` from CadQuery's `ExportTypes.DXF` exporter — script must produce a 2D profile (`Workplane.sketch().…`, `Workplane.section()`, or a planar face). |
| `svg`  | 2D vector  | 2D `cq.Workplane`, **or** any 3D shape (auto-projected isometric view) | For drawing/doc artifacts and laser cut paths. 3D shapes render as a projected vector view; 2D Workplanes render in true outline. |

The new `dxf` / `svg` formats (added in v0.1.3, [PLA-443](/PLA/issues/PLA-443)) follow the same artifact-commit semantics as `step` / `stl` / `3mf`: deterministic path `artifacts/{paperclipTicketId}/{toolCallId}/artifact.<format>`, idempotent on `toolCallId`, single commit to the configured GitHub artifact repo.

---

## Error codes

| Error condition | Behaviour |
|-----------------|-----------|
| `script` missing or empty | `cad.run_script` returns a validation error before execution. |
| `timeout` out of range (< 1 or > 300) | Schema validation rejects the call. |
| CadQuery script raises an exception | `cad.run_script` surfaces the Python traceback in the error message. |
| Unknown `artifactId` passed to `cad.export` | `cad.export` returns an error indicating the artifact was not found. |
| Unsupported `format` value | Schema validation rejects the call (enum constraint). |
| `format: "dxf"` with a 3D-only shape | `cad.export` surfaces a `worker_internal` whose message wraps the CadQuery DXF exporter's traceback. The script must produce a 2D `Workplane` (wires / faces) for DXF. SVG accepts both 2D and 3D inputs. |

---

## Worked example

Design a simple bracket and export it as STEP:

```
# Step 1 — run the script
Tool call: cad.run_script
{
  "script": "import cadquery as cq\nresult = (cq.Workplane('XY')\n    .box(40, 20, 5)\n    .faces('>Z').workplane()\n    .hole(4))",
  "timeout": 30
}
→ { "artifactId": "cad-artifact-a1b2c3d4", "summary": "Box 40×20×5 mm with Ø4 hole" }

# Step 2 — export to STEP and commit to GitHub
Tool call: cad.export
{
  "artifactId": "cad-artifact-a1b2c3d4",
  "format": "step",
  "paperclipTicketId": "PLA-56",
  "toolCallId": "tc-9f8e7d6c",
  "filename": "bracket.step"
}
→ {
    "commitSha": "abc123def456...",
    "permalink": "https://github.com/<owner>/<repo>/blob/abc123def456.../artifacts/PLA-56/tc-9f8e7d6c/bracket.step",
    "artifactPath": "artifacts/PLA-56/tc-9f8e7d6c/bracket.step"
  }
```

**CadQuery tutorial:** Out of scope for v0.1.0. See the [CadQuery documentation](https://cadquery.readthedocs.io/) for the scripting API.

---

## Links

- [README.md](./README.md) — install instructions and security summary
- [SECURITY.md](./SECURITY.md) — full threat model and sandbox guarantees
- [CHANGELOG.md](./CHANGELOG.md) — release history
- Engagement tracker: [PLA-32](/PLA/issues/PLA-32)
