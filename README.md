# paperclip-plugin-cad

Lets agents design and export 3D CAD models via CadQuery tool calls, with operator-confirmed scope via approval `f420bc31`.

## Install

Install the plugin from the Paperclip board:

1. Go to **Plugins → Install plugin** and search for `platform.cad`, or upload this package directly.
2. Create a Paperclip secret for your GitHub Personal Access Token (PAT) with `repo` scope.
3. In the plugin instance config, set `githubPatSecretId` to the UUID of that secret.

The plugin registers two tools on every agent it is enabled for: `cad:run_script` and `cad:export`.

## Minimal example

```
# Execute a CadQuery script — returns a staged artifact ID
Tool call: cad:run_script
{
  "script": "import cadquery as cq\nresult = cq.Workplane('XY').box(1, 1, 1)"
}
→ { "artifactId": "cad-artifact-a1b2c3d4", "summary": "Box 1×1×1 mm" }

# Export the staged artifact to STEP format
Tool call: cad:export
{
  "artifactId": "cad-artifact-a1b2c3d4",
  "format": "step"
}
→ { "filePath": "/var/paperclip/artifacts/cad-artifact-a1b2c3d4.step" }
```

## Security defaults

- The GitHub PAT is resolved from the Paperclip secrets store per call (`ctx.secrets.resolve(uuid)`). It is never cached, logged, or returned from a tool.
- CadQuery scripts run in an isolated subprocess with a configurable timeout (see [SECURITY.md](./SECURITY.md) for the full threat model).
- Agent-supplied inputs are validated by JSON Schema before execution.

## Links

- Engagement tracker: [PLA-32](/PLA/issues/PLA-32)
- Paperclip Plugin SDK docs: https://docs.paperclip.ing/plugin-sdk (canonical; check the board for current link)
- Tool invocation reference: [SKILL.md](./SKILL.md)
- Security model: [SECURITY.md](./SECURITY.md)
- Release history: [CHANGELOG.md](./CHANGELOG.md)
