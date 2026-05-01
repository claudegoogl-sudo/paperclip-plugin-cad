# CAD Plugin — Skill Reference

Adoption surface for agent authors. Covers tool invocation, schemas, error codes, and a worked example.

Plugin: `platform.cad` · Version: `0.1.0` · Tracker: [PLA-32](/PLA/issues/PLA-32)

---

## Tools

### `cad_render`

Execute a CadQuery Python script in an isolated subprocess and return the resulting 3D model artifact path.

#### Input schema

| Field    | Type   | Required | Description |
|----------|--------|----------|-------------|
| `script` | string | yes      | CadQuery Python script. Must produce a final shape assigned to `result`. |
| `format` | string | no       | Output format: `"step"` (default) or `"stl"`. |

```json
{
  "type": "object",
  "properties": {
    "script": {
      "type": "string",
      "description": "CadQuery Python script."
    },
    "format": {
      "type": "string",
      "enum": ["step", "stl"],
      "description": "Output format. Defaults to 'step'."
    }
  },
  "required": ["script"]
}
```

#### Output

```json
{
  "artifactPath": "/tmp/cad-1714000000000.step",
  "format": "step"
}
```

| Field          | Type   | Description |
|----------------|--------|-------------|
| `artifactPath` | string | Absolute path to the rendered file in the system temp directory. Pass this to `cad_commit`. |
| `format`       | string | The format that was used. |

---

### `cad_commit`

Commit a previously rendered CAD artifact to the project GitHub repository and return the commit SHA.

#### Input schema

| Field           | Type   | Required | Description |
|-----------------|--------|----------|-------------|
| `artifactPath`  | string | yes      | Local artifact path returned by `cad_render`. Must be inside the system temp directory. |
| `repoPath`      | string | yes      | Target path within the repository, e.g. `parts/bracket.step`. |
| `commitMessage` | string | yes      | Git commit message. |

```json
{
  "type": "object",
  "properties": {
    "artifactPath": {
      "type": "string",
      "description": "Local artifact path from cad_render."
    },
    "repoPath": {
      "type": "string",
      "description": "Target path in the repository."
    },
    "commitMessage": {
      "type": "string",
      "description": "Git commit message."
    }
  },
  "required": ["artifactPath", "repoPath", "commitMessage"]
}
```

#### Output

```json
{
  "repoPath": "parts/bracket.step",
  "commitSha": "abc123def456..."
}
```

| Field       | Type   | Description |
|-------------|--------|-------------|
| `repoPath`  | string | The path the artifact was committed to. |
| `commitSha` | string | GitHub commit SHA. |

---

### `cad:hello` (test/stub only)

Returns a canned OK response with no side effects. Used for end-to-end verification of the plugin tool dispatch path. Not intended for production agent workflows.

#### Input schema

| Field  | Type   | Required | Description |
|--------|--------|----------|-------------|
| `name` | string | no       | Optional greeting name. Defaults to `"world"`. |

---

## Error codes

| Error condition | Behaviour |
|-----------------|-----------|
| `artifactPath` outside temp directory | `cad_commit` returns `{ "error": "artifactPath must be within the temp directory." }` and does not push. |
| `githubPatSecretId` missing from config | `cad_commit` returns `{ "error": "githubPatSecretId is not configured. Set it in plugin instance config." }` |
| GitHub API non-2xx response | `cad_commit` throws; the tool call surfaces the error message from the GitHub API. |
| CadQuery script error (v0.1.0) | `cad_render` propagates the subprocess exit error. The full render sandbox is tracked in sub-goal 5. |

---

## Worked example

Design a simple mounting bracket and commit it:

```
# Step 1 — render
Tool call: cad_render
{
  "script": "import cadquery as cq\nresult = (cq.Workplane('XY')\n    .box(40, 20, 5)\n    .faces('>Z').workplane()\n    .hole(4))",
  "format": "step"
}
→ { "artifactPath": "/tmp/cad-1714000000000.step", "format": "step" }

# Step 2 — commit
Tool call: cad_commit
{
  "artifactPath": "/tmp/cad-1714000000000.step",
  "repoPath": "parts/mounting-bracket.step",
  "commitMessage": "Add mounting bracket (40×20×5mm, Ø4 hole)"
}
→ { "repoPath": "parts/mounting-bracket.step", "commitSha": "abc123…" }
```

**CadQuery tutorial:** Out of scope for v0.1.0. See the [CadQuery documentation](https://cadquery.readthedocs.io/) for the scripting API.

---

## Links

- [README.md](./README.md) — install instructions and security summary
- [SECURITY.md](./SECURITY.md) — full threat model and sandbox guarantees
- [CHANGELOG.md](./CHANGELOG.md) — release history
- Engagement tracker: [PLA-32](/PLA/issues/PLA-32)
