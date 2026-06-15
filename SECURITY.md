# Security Model — paperclip-plugin-cad v0.1.10

Tracker: [PLA-32](/PLA/issues/PLA-32) · Per-tenant scoping: [PLA-1099](/PLA/issues/PLA-1099)

---

## PAT handling

The GitHub Personal Access Token (PAT) is a sensitive credential. The plugin follows a strict per-call, no-cache pattern:

1. The PAT is stored as a Paperclip secret. Its UUID is the only thing held in plugin instance config (`githubPatSecretId`).
2. On each `cad.export` call, the worker resolves the PAT with `ctx.secrets.resolve(config.githubPatSecretId)`. The UUID is passed directly — a string name would throw `InvalidSecretRefError` at the secrets handler boundary.
3. The resolved PAT is passed immediately into `pushArtifactToGitHub` and used within that function's stack frame only.
4. The PAT is **never** logged, cached in `ctx.state`, stored in any persistent store, or returned from a tool call.
5. After `pushArtifactToGitHub` returns, the PAT goes out of scope and is eligible for GC.

This pattern was reviewed in [PLA-41](/PLA/issues/PLA-41) (secrets-integration security review).

---

## Worker sandbox guarantees

### Network isolation

The worker runs in the Paperclip plugin runtime. Outbound HTTP is gated by the `http.outbound` capability declared in the manifest. The only outbound target used by the plugin is the GitHub Contents API (`api.github.com`). No inbound listener is opened; no internal hosts are contacted.

### CadQuery subprocess

CadQuery scripts supplied by agents run in a per-request subprocess spawned by the plugin worker. The subprocess:

- Runs as the same OS user as the worker (no privilege escalation).
- Is subject to a configurable execution timeout (implementation tracked in sub-goal 2/5 of [PLA-32](/PLA/issues/PLA-32)).
- Writes output only to the system temp directory. Artifact paths are verified against `tmpdir()` before any further processing.

### Path-traversal prevention

`cad.export` resolves the agent-supplied `artifactPath` to an absolute path and checks that it begins with the OS temp directory prefix (`os.tmpdir() + "/"`). Paths outside that prefix are rejected and a descriptive error is returned to the agent — no file read or push occurs. This control was added in [PLA-50](/PLA/issues/PLA-50).

---

## Per-tenant artifact scoping ([PLA-1099](/PLA/issues/PLA-1099) SE-1)

The cad-artifacts repo is shared across every company on the host, and its
contents are tenant-confidential proprietary CAD IP (data classification
[PLA-1098](/PLA/issues/PLA-1098)). A read or write that crosses a company
boundary is a confidentiality breach. Both the intake (read) and export
(write) paths are therefore confined to the caller's own tenant subtree.

### Tenant identity is host-derived, never caller-supplied

`companyId` is read from the `ToolRunContext` (`runCtx.companyId`) that the
host injects, not from any tool parameter. A `cad.run_script` /
`cad.export` call with missing or empty tenant context is rejected with a
structured `validation_error` before any fetch or render (see the F6
tenant-context gate in `src/worker.ts`). The value is shape-validated with
`assertSafeCompanyId` (`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`, no leading dot)
so it cannot itself inject path segments or traversal.

### Export confinement (`cad.export`)

Artifacts are written under `artifacts/<companyId>/<ticket>/<toolCallId>/<file>`.
The `<companyId>` segment is derived from `runCtx`; the per-call
`assertSafeRepoPath` re-checks that the normalized path begins with
`artifacts/<companyId>/` before any GitHub write, so a tenant can only ever
commit into its own subtree.

### Intake confinement (`cad.run_script` `inputArtifacts`)

`assertSafeIntakePath` (in `src/cad-intake.ts`) runs after the existing
traversal/allowlist checks. Any `repoPath` normalizing under `artifacts/`
that is **not** within `artifacts/<companyId>/` is rejected with a structured
validation error and **no fetch is issued** — cross-tenant reads fail closed.

### Back-compat posture for legacy flat `artifacts/<ticket>/...` permalinks

Artifacts committed before this change live at the flat path
`artifacts/<ticket>/<call>/<file>` with **no tenant segment**, so they cannot
be attributed to an owning company. Confidentiality-first, these legacy
permalinks are **rejected** by intake (they do not match any
`artifacts/<companyId>/` prefix) rather than left readable across tenants.
This is a deliberate, documented break: an unattributable artifact path is
treated as out-of-tenant. Operators needing a legacy artifact must re-stage it
under the owning tenant's `artifacts/<companyId>/` subtree. New exports already
write the tenant-scoped layout, so the legacy shape only affects pre-existing
commits.

### Phase 2 — `user-uploads/` scoping (gated, not yet enforced)

`user-uploads/` is the operator/agent upload surface. Per-tenant enforcement
for it is implemented but **disabled** behind
`ENFORCE_USER_UPLOADS_TENANT_SCOPING = false` until the cross-team upload-side
migration to `user-uploads/<companyId>/` lands ([PLA-1098](/PLA/issues/PLA-1098)).
Flipping the flag before the upload layout migrates would break legitimate
intake. Until then `user-uploads/` paths keep the pre-existing allowlist-only
behavior. Do not enable enforcement without CTO confirmation that the upload
side has migrated.

---

## Supported attack model

### In-scope (plugin defends against)

| Threat | Control |
|--------|---------|
| Malicious agent-supplied `artifactPath` (path traversal) | Validated against `tmpdir()` prefix before use |
| Agent attempting to extract PAT via tool response | PAT never returned from tool calls |
| Agent attempting to log PAT | No `ctx.logger` calls include the PAT value |
| Agent supplying malformed `githubPatSecretId` (string name instead of UUID) | Validated at Paperclip secrets handler; throws `InvalidSecretRefError` |
| Agent reading another tenant's CAD scan via `inputArtifacts` `repoPath` | Intake confined to `artifacts/<companyId>/`; cross-tenant + unattributable legacy paths rejected, no fetch ([PLA-1099](/PLA/issues/PLA-1099)) |
| Agent writing into another tenant's subtree via `cad.export` | Export path derives `<companyId>` from `runCtx`; `assertSafeRepoPath` re-checks tenant prefix before push ([PLA-1099](/PLA/issues/PLA-1099)) |

### Out-of-scope (operator responsibility)

| Threat | Rationale |
|--------|-----------|
| Malicious **operator** modifying plugin config or secrets | Operators are trusted principals in the Paperclip model; plugin cannot defend against a compromised operator |
| Sandbox escape from CadQuery subprocess | OS-level isolation is the responsibility of the host environment |
| PAT with excessive GitHub scopes | Operators should provision a PAT with the minimum required scopes (`repo` write for the target repository only) |

---

## Public repository

This repository is public per Discovery R4 and operator approval `f420bc31` (item 4). As a result:

- No secrets, credentials, or internal hostnames appear in this repository or its documentation.
- All config examples use placeholder UUIDs or descriptive names.
- The threat model above is designed with public visibility in mind.

---

## Dependency audit

Worker Python dependencies (`worker/requirements-cad.txt`) are scanned for known CVEs on every pull request and every push to `main` via the `pip-audit` CI merge gate defined in `.github/workflows/pip-audit.yml`.

**What runs:**

```bash
pip install pip-audit
pip-audit -r worker/requirements-cad.txt
```

The step fails the build on any known CVE found in the PyPI advisory database. All pins use `==` (exact versions) to make the scan deterministic.

**Baseline scan (2026-05-01):** clean — no known vulnerabilities against the pinned versions listed in `worker/requirements-cad.txt`.

This gate was added in [PLA-77](/PLA/issues/PLA-77) as a remediation for finding LOW-1 in security review [PLA-73](/PLA/issues/PLA-73).

---

## Links

- [README.md](./README.md) — install and quick-start
- [SKILL.md](./SKILL.md) — tool invocation reference
- [CHANGELOG.md](./CHANGELOG.md) — release history
- Engagement tracker: [PLA-32](/PLA/issues/PLA-32)
