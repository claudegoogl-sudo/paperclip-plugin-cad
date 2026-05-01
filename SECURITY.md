# Security Model — paperclip-plugin-cad v0.1.0

Tracker: [PLA-32](/PLA/issues/PLA-32)

---

## PAT handling

The GitHub Personal Access Token (PAT) is a sensitive credential. The plugin follows a strict per-call, no-cache pattern:

1. The PAT is stored as a Paperclip secret. Its UUID is the only thing held in plugin instance config (`githubPatSecretId`).
2. On each `cad:export` call, the worker resolves the PAT with `ctx.secrets.resolve(config.githubPatSecretId)`. The UUID is passed directly — a string name would throw `InvalidSecretRefError` at the secrets handler boundary.
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

`cad:export` resolves the agent-supplied `artifactPath` to an absolute path and checks that it begins with the OS temp directory prefix (`os.tmpdir() + "/"`). Paths outside that prefix are rejected and a descriptive error is returned to the agent — no file read or push occurs. This control was added in [PLA-50](/PLA/issues/PLA-50).

---

## Supported attack model

### In-scope (plugin defends against)

| Threat | Control |
|--------|---------|
| Malicious agent-supplied `artifactPath` (path traversal) | Validated against `tmpdir()` prefix before use |
| Agent attempting to extract PAT via tool response | PAT never returned from tool calls |
| Agent attempting to log PAT | No `ctx.logger` calls include the PAT value |
| Agent supplying malformed `githubPatSecretId` (string name instead of UUID) | Validated at Paperclip secrets handler; throws `InvalidSecretRefError` |

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
