# Changelog — paperclip-plugin-cad

Tracker: [PLA-32](/PLA/issues/PLA-32)

---

## v0.1.0 — 2026-05-01

### Tools

| Tool | Description |
|------|-------------|
| `cad_render` | Execute a CadQuery Python script in an isolated subprocess; return the artifact path in the system temp directory. |
| `cad_commit` | Commit a rendered artifact to the project GitHub repository via the GitHub Contents API; return the commit SHA. |
| `cad:hello` | Stub tool for end-to-end dispatch verification; no side effects. |

### Capabilities declared

| Capability | Why |
|------------|-----|
| `agent.tools.register` | Register `cad_render`, `cad_commit`, and `cad:hello` on enabled agents. |
| `http.outbound` | Push artifacts to the GitHub Contents API. |
| `secrets.read-ref` | Resolve the GitHub PAT from the Paperclip secrets store per call. |
| `metrics.write` | Emit tool-call counters and latency metrics via `ctx.metrics.write`. |

### Known limitations

- CadQuery subprocess sandbox (timeout, stdout/stderr capture, resource limits) is a placeholder in v0.1.0. Full implementation is tracked in sub-goal 2/5 of [PLA-32](/PLA/issues/PLA-32).
- `cad_render` writes a stub file in v0.1.0; the real CadQuery execution engine is pending the same sub-goal.
- Only the GitHub Contents API is supported for artifact storage. Other VCS hosts or object stores are out of scope for v0.1.0.
- The target repository URL is currently hardcoded in the worker; a configurable `repoUrl` field is a planned extension.
