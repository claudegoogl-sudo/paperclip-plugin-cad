# Changelog — paperclip-plugin-cad

Tracker: [PLA-32](/PLA/issues/PLA-32)

---

## v0.1.0 — 2026-05-01

### Tools

| Tool | Description |
|------|-------------|
| `cad:run_script` | Execute a CadQuery Python script string in an isolated subprocess; return `{ artifactId, summary }`. The artifact is staged locally for a subsequent `cad:export` call. |
| `cad:export` | Export a previously staged artifact to a specific format (`step`, `stl`, `3mf`) and commit it to the configured GitHub artifact repository. Returns `{ commitSha, permalink, artifactPath }`. Path is deterministic (`artifacts/{paperclipTicketId}/{toolCallId}/{filename}`); idempotent on `toolCallId`. |

### Capabilities declared

| Capability | Why |
|------------|-----|
| `agent.tools.register` | Register `cad:run_script` and `cad:export` on enabled agents. |
| `http.outbound` | Push artifacts to the GitHub Contents API from `cad:export` (PLA-56). |
| `secrets.read-ref` | Resolve the GitHub PAT from the Paperclip secrets store on each `cad:export` call (PLA-47). |
| `metrics.write` | Emit tool-call counters and duration histograms via `ctx.metrics`. |

### Known limitations

- CadQuery subprocess sandbox (timeout enforcement, stdout/stderr capture, resource limits) is a stub in v0.1.0. Full implementation is tracked in sub-goal 2 of [PLA-32](/PLA/issues/PLA-32).
- `cad:run_script` accepts the `timeout` field but does not enforce it in the v0.1.0 stub.
- `cad:export` supports three formats only: `step`, `stl`, `3mf`.
- `cad:export` falls back to a local-staging response (`{ filePath, ... }`) when the worker has no tenant context (test/local runs). Production agent calls always commit to GitHub.

---

## Links

- [README.md](./README.md) — install and quick-start
- [SKILL.md](./SKILL.md) — tool invocation reference
- [SECURITY.md](./SECURITY.md) — threat model
- Engagement tracker: [PLA-32](/PLA/issues/PLA-32)
