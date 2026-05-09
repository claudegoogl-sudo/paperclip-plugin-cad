# Changelog — paperclip-plugin-cad

Tracker: [PLA-32](/PLA/issues/PLA-32)

---

## v0.1.2 — 2026-05-09

### Fixed

- **Plugin install rejected on hosts carrying [PLA-163](/PLA/issues/PLA-163)'s
  tightened tool-name validator.** The v0.1.1 manifest declared
  `tools[].name` as `cad:run_script` and `cad:export`, but the host validator
  enforces `/^[a-z0-9][a-z0-9._-]*$/` — the colon is rejected. Renamed the
  tool surface from `cad:<verb>` to `cad.<verb>`:
  - `cad:run_script` → `cad.run_script`
  - `cad:export` → `cad.export`
  Worker dispatch keys (`ctx.tools.register(...)`) and the metric/log `tool`
  label values follow the manifest names. The host parses the namespaced
  full name `platform.cad:cad.run_script` via `lastIndexOf(":")` and
  RPC-dispatches the worker with bare key `cad.run_script`
  (see `plugin-tool-registry.ts:247`). ([PLA-374](/PLA/issues/PLA-374),
  unblocks [PLA-368](/PLA/issues/PLA-368))

### Notes

- Tool *behaviour*, parameter shapes, and return shapes are unchanged —
  this is a pure rename. Agents currently invoking `cad:run_script` /
  `cad:export` must update their tool-call sites.
- The commit-message format produced by `cad.export` now reads
  `CAD artifact: ticket=<id> tool=cad.export call=<id>` (was `tool=cad:export`).
  Past commits remain valid; only new artifacts use the new label.
- Observability dashboards/alerts that key on `tool=cad:run_script` /
  `tool=cad:export` must be updated to the dot form.

---

## v0.1.1 — 2026-05-09

### Fixed

- **Tool dispatch returned HTTP 500 for every `platform.cad:run_script` and
  `platform.cad:export` call.** The worker registered tool handlers under
  the literal keys `"cad:run_script"` / `"cad:export"`, but the host parses
  the namespaced name `platform.cad:<tool>` and RPCs the worker with the
  bare tool name (`run_script` / `export`). The worker therefore looked up
  a key that did not exist and threw
  `No tool handler registered for "<bare-name>"`. Worker `register(...)`
  keys are now bare (`"run_script"`, `"export"`), matching the host RPC
  contract. ([PLA-354](/PLA/issues/PLA-354),
  [plugin-cad#7](https://github.com/claudegoogl-sudo/paperclip-plugin-cad/issues/7))

No tool surface or schema changes — same two tools, same parameters,
same return shapes. Operator install of v0.1.1 unblocks the AC chain
on PLA-308 and PLA-353.

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
