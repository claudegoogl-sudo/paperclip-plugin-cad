# paperclip-plugin-cad

Lets agents design and render 3D CAD models via CadQuery tool calls, and commit the resulting artifacts to a project GitHub repository.

## Install

Install the plugin from the Paperclip board:

1. Go to **Plugins → Install plugin** and search for `platform.cad`, or upload this package directly.
2. Create a Paperclip secret for your GitHub Personal Access Token (PAT) with `repo` scope.
3. In the plugin instance config, set `githubPatSecretId` to the UUID of that secret.

The plugin registers two tools on every agent it is enabled for: `cad_render` and `cad_commit`.

## Minimal example

```
Tool call: cad_render
{
  "script": "import cadquery as cq\nresult = cq.Workplane('XY').box(1, 1, 1)",
  "format": "step"
}
→ { "artifactPath": "/tmp/cad-1234567890.step", "format": "step" }

Tool call: cad_commit
{
  "artifactPath": "/tmp/cad-1234567890.step",
  "repoPath": "parts/cube.step",
  "commitMessage": "Add 1mm cube example"
}
→ { "repoPath": "parts/cube.step", "commitSha": "abc123…" }
```

## Security defaults

- The GitHub PAT is resolved from the Paperclip secrets store on each call (`ctx.secrets.resolve(uuid)`). It is never cached, logged, or returned from a tool.
- The `artifactPath` accepted by `cad_commit` is validated against the system temp directory. Agent-supplied paths outside `tmpdir()` are rejected to prevent path-traversal.
- CadQuery scripts run in an isolated subprocess with a timeout (see [SECURITY.md](./SECURITY.md) for the full threat model).

## Links

- Engagement tracker: [PLA-32](/PLA/issues/PLA-32)
- Paperclip Plugin SDK docs: https://docs.paperclip.ing/plugin-sdk (canonical; check the board for current link)
- Tool invocation reference: [SKILL.md](./SKILL.md)
- Security model: [SECURITY.md](./SECURITY.md)
- Release history: [CHANGELOG.md](./CHANGELOG.md)
