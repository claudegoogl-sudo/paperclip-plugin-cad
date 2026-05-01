# Changelog — paperclip-plugin-cad

Tracker: [PLA-32](/PLA/issues/PLA-32)

---

## v0.1.0 — 2026-05-01

### Tools

| Tool | Description |
|------|-------------|
| `cad:run_script` | Execute a CadQuery Python script string in an isolated subprocess; return `{ artifactId, summary }`. The artifact is staged locally. |
| `cad:export` | Export a previously staged artifact to a specific format (`step`, `stl`, `3mf`); return `{ filePath }` within the plugin artifact-staging area. |

### Capabilities declared

| Capability | Why |
|------------|-----|
| `agent.tools.register` | Register `cad:run_script` and `cad:export` on enabled agents. |
| `http.outbound` | Reserved for the real CadQuery worker (sub-goal 2 of [PLA-32](/PLA/issues/PLA-32)). |
| `secrets.read-ref` | Reserved for future worker auth flows (sub-goal 2). |
| `metrics.write` | Emit tool-call counters and duration histograms via `ctx.metrics`. |

### Known limitations

- CadQuery subprocess sandbox (timeout enforcement, stdout/stderr capture, resource limits) is a stub in v0.1.0. Full implementation is tracked in sub-goal 2/5 of [PLA-32](/PLA/issues/PLA-32).
- `cad:run_script` accepts the `timeout` field but does not enforce it in the v0.1.0 stub.
- `filePath` returned by `cad:export` is a local staging path, not a URL. The artifact-persistence pipeline (download/commit to GitHub) is wired in sub-goal 5.
- Only three export formats are supported: `step`, `stl`, `3mf`.
