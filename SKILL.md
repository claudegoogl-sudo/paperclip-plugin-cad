# CAD Plugin — Skill Reference

Adoption surface for agent authors. Covers tool invocation, schemas, error codes, and a worked example.

Plugin: `platform.cad` · Version: `0.1.0` · Tracker: [PLA-32](/PLA/issues/PLA-32)

---

## Tools

### `cad:run_script`

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
| `artifactId` | string | Opaque ID for the staged artifact. Pass this to `cad:export`. |
| `summary`    | string | Human-readable description of the shape produced. |

---

### `cad:export`

Export a previously staged CAD artifact to a specific file format. Returns the file path within the plugin artifact-staging area.

> **Note:** `filePath` is a local staging path, not a URL. The artifact-persistence pipeline (sub-goal 5 of [PLA-32](/PLA/issues/PLA-32)) will wire download/commit flows.

#### Input schema

| Field        | Type   | Required | Description |
|--------------|--------|----------|-------------|
| `artifactId` | string | yes      | Artifact ID returned by `cad:run_script`. |
| `format`     | string | yes      | Output file format: `"step"`, `"stl"`, or `"3mf"`. |

```json
{
  "type": "object",
  "properties": {
    "artifactId": {
      "type": "string",
      "description": "Artifact ID returned by cad:run_script."
    },
    "format": {
      "type": "string",
      "enum": ["step", "stl", "3mf"],
      "description": "Output file format."
    }
  },
  "required": ["artifactId", "format"],
  "additionalProperties": false
}
```

#### Output

```json
{
  "filePath": "/var/paperclip/artifacts/cad-artifact-<uuid>.step"
}
```

| Field      | Type   | Description |
|------------|--------|-------------|
| `filePath` | string | Absolute path to the exported file in the plugin artifact-staging area. |

---

## Error codes

| Error condition | Behaviour |
|-----------------|-----------|
| `script` missing or empty | `cad:run_script` returns a validation error before execution. |
| `timeout` out of range (< 1 or > 300) | Schema validation rejects the call. |
| CadQuery script raises an exception | `cad:run_script` surfaces the Python traceback in the error message. |
| Unknown `artifactId` passed to `cad:export` | `cad:export` returns an error indicating the artifact was not found. |
| Unsupported `format` value | Schema validation rejects the call (enum constraint). |

---

## Worked example

Design a simple bracket and export it as STEP:

```
# Step 1 — run the script
Tool call: cad:run_script
{
  "script": "import cadquery as cq\nresult = (cq.Workplane('XY')\n    .box(40, 20, 5)\n    .faces('>Z').workplane()\n    .hole(4))",
  "timeout": 30
}
→ { "artifactId": "cad-artifact-a1b2c3d4", "summary": "Box 40×20×5 mm with Ø4 hole" }

# Step 2 — export to STEP
Tool call: cad:export
{
  "artifactId": "cad-artifact-a1b2c3d4",
  "format": "step"
}
→ { "filePath": "/var/paperclip/artifacts/cad-artifact-a1b2c3d4.step" }
```

**CadQuery tutorial:** Out of scope for v0.1.0. See the [CadQuery documentation](https://cadquery.readthedocs.io/) for the scripting API.

---

## Links

- [README.md](./README.md) — install instructions and security summary
- [SECURITY.md](./SECURITY.md) — full threat model and sandbox guarantees
- [CHANGELOG.md](./CHANGELOG.md) — release history
- Engagement tracker: [PLA-32](/PLA/issues/PLA-32)
