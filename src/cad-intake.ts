/**
 * CAD scan intake-fetch — 1089 Ask 1 (cross-company request DPR-192/196).
 *
 * The cad sandbox has no network, no creds, python `open()` is hardened off, and
 * `cad.export` is write-only — so a CadQuery script cannot read an uploaded scan
 * on its own. This module is the host-mediated intake: it fetches files from the
 * cad-artifacts repo with the already-resolved export PAT and stages them into the
 * per-run sandbox workdir at `inputs/<basename>`, where the script reads them via
 * OCC's `StlAPI_Reader` (a C-level fopen that bypasses the python `open()` block).
 *
 * ## Security surface (BLOCKING SecurityEngineer review — 1089 gate)
 *
 * This expands the export PAT blast radius from write-`artifacts/` to
 * read-arbitrary-path-in-repo. Defences, in order:
 *
 *   1. **Path allowlist** distinct from `cad.export`'s `assertSafeRepoPath`
 *      (which forces an `artifacts/` prefix). Uploads land at
 *      `cad-artifacts/user-uploads/<file>`, so intake permits `user-uploads/`
 *      and `artifacts/` only. Rejects `..`, absolute paths, backslashes, NUL,
 *      and any input that does not survive `path.posix.normalize` as an
 *      identity (normalize-equality, mirroring the export allowlist).
 *   2. **Basename-only staging.** Directory components of `repoPath` are NEVER
 *      honored when writing into the sandbox — we stage `inputs/<basename>`.
 *      Re-derived defensively in `stageInputFiles` too (defence in depth).
 *   3. **Size / count caps** (DoS / tmpfs): per-file byte cap, total byte cap,
 *      and file-count cap. Over-cap is a structured error, never silent.
 *   4. **Binary-safe fetch.** Scans are STL/3MF/PLY binary, not UTF-8. We request
 *      the GitHub `raw` media type and read the body as bytes
 *      (`Buffer.from(arrayBuffer)`) — no base64 round-trip, and (unlike the
 *      Contents-API JSON `content` field) no >1 MiB truncation.
 *
 * Caps below are the 1089 proposal (~50 MiB/file, ~3 files); the total cap is
 * set so a full complement of max-size files cannot blow the sandbox tmpfs.
 * Confirm with SecurityEngineer before merge.
 */

import * as path from "node:path";
import { mkdir, writeFile } from "node:fs/promises";

// ---------------------------------------------------------------------------
// Caps (1089 — confirm with SecurityEngineer)
// ---------------------------------------------------------------------------

/** Max bytes for a single staged input file. */
export const MAX_INPUT_FILE_BYTES = 50 * 1024 * 1024; // 50 MiB
/** Max number of input files per run_script call. */
export const MAX_INPUT_FILES = 3;
/** Max combined bytes across all input files in one call (tmpfs guard). */
export const MAX_TOTAL_INPUT_BYTES = 120 * 1024 * 1024; // 120 MiB
/** Defensive ceiling on a repoPath string length. */
const MAX_REPO_PATH_LEN = 512;

/** Byte caps, injectable so tests can exercise the cap logic without 50 MiB allocations. */
export interface IntakeCaps {
  maxFileBytes: number;
  maxTotalBytes: number;
}

export const DEFAULT_INTAKE_CAPS: IntakeCaps = {
  maxFileBytes: MAX_INPUT_FILE_BYTES,
  maxTotalBytes: MAX_TOTAL_INPUT_BYTES,
};

/**
 * Intake-only allowlist. Distinct from cad.export's `artifacts/`-only rule:
 * operator uploads land under `user-uploads/`. `artifacts/` is also permitted so
 * a prior export can be re-read as an input.
 */
export const INTAKE_ALLOWED_PREFIXES = ["user-uploads/", "artifacts/"] as const;

// ---------------------------------------------------------------------------
// 1099 SE-1 — per-tenant scoping
//
// `cad-artifacts` content is tenant-confidential proprietary CAD IP (CTO
// data-classification call, 1098), NOT shared staging. A caller in company X
// must never read company Y's scan, and export permalinks must not be a
// cross-tenant discovery surface. The caller's tenant (`companyId`) is already
// required at the fetch site (`worker.ts`), so we thread it through and confine
// every intake/export to the caller's own `<companyId>/` subtree.
// ---------------------------------------------------------------------------

/**
 * Phase 2 flag (1099). When `true`, `user-uploads/` reads are confined to
 * `user-uploads/<companyId>/`. GATED OFF until the upload-side (3d-printing /
 * DPR) migration writes per-company first — flipping early would 404 every
 * current flat `user-uploads/<file>` upload. Do NOT flip until CTO confirms the
 * upload-side migration has landed (1098). Phase 1 (`artifacts/`) scoping is
 * always on and independent of this flag.
 */
export const ENFORCE_USER_UPLOADS_TENANT_SCOPING = false;

/** Companies are referenced as a single path segment; mirror the basename class. */
const COMPANY_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

/**
 * Validate the caller's `companyId` before it is interpolated into a repo-path
 * prefix. Fail-closed: a malformed companyId means we cannot safely scope, so the
 * caller turns this into a rejection rather than reading an unscoped path.
 */
export function assertSafeCompanyId(companyId: unknown): string | null {
  if (typeof companyId !== "string" || companyId.length === 0) {
    return "callerCompanyId must be a non-empty string";
  }
  if (!COMPANY_ID_RE.test(companyId)) {
    return "callerCompanyId has disallowed characters (allowed: A-Za-z0-9._-, no leading dot)";
  }
  return null;
}

/** Options for the per-tenant scoping checks. */
export interface IntakeScopeOptions {
  /** Override the Phase-2 `user-uploads/` enforcement flag (tests). */
  enforceUserUploadsScoping?: boolean;
}

/** A fetched, validated input file ready to stage into a sandbox workdir. */
export interface InputFile {
  /** Basename only — never a path with directory components. */
  basename: string;
  bytes: Buffer;
}

// ---------------------------------------------------------------------------
// Structured intake errors (surfaced as tool errors, never silent)
// ---------------------------------------------------------------------------

export type IntakeErrorKind =
  | "validation" // bad shape / path allowlist / over-count
  | "too_large" // per-file or total byte cap exceeded
  | "not_found" // 404 from GitHub
  | "auth" // 401/403 from GitHub
  | "network" // 5xx / network / timeout
  | "prerequisite_missing"; // bad repo URL / unparseable

export class IntakeError extends Error {
  readonly kind: IntakeErrorKind;
  readonly httpStatus?: number;
  constructor(kind: IntakeErrorKind, message: string, httpStatus?: number) {
    super(message);
    this.name = "IntakeError";
    this.kind = kind;
    this.httpStatus = httpStatus;
  }
}

// ---------------------------------------------------------------------------
// Path allowlist
// ---------------------------------------------------------------------------

const BASENAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

/**
 * Validate an intake `repoPath` for a caller in `callerCompanyId`. Returns an
 * error string (caller turns it into a structured tool error) or `null` if safe.
 * Mirrors the export allowlist's normalize-equality check, then applies SE-1
 * per-tenant scoping:
 *
 *   - `artifacts/...` (Phase 1, always on): must be under
 *     `artifacts/<callerCompanyId>/`. Legacy flat `artifacts/<ticket>/...`
 *     permalinks (pre-0.1.9 exports) are REJECTED — they cannot be attributed to
 *     a tenant, so we cannot prove the caller could have written them. (Chosen
 *     back-compat posture; see `SECURITY.md`, SE sign-off on 1099.)
 *   - `user-uploads/...` (Phase 2, gated by `ENFORCE_USER_UPLOADS_TENANT_SCOPING`):
 *     when enabled, must be under `user-uploads/<callerCompanyId>/`; otherwise
 *     the existing flat behavior is preserved until the upload-side migration
 *     lands (1098).
 */
export function assertSafeIntakePath(
  repoPath: unknown,
  callerCompanyId: string,
  opts: IntakeScopeOptions = {},
): string | null {
  if (typeof repoPath !== "string" || repoPath.length === 0) {
    return "repoPath must be a non-empty string";
  }
  if (repoPath.length > MAX_REPO_PATH_LEN) {
    return `repoPath exceeds ${MAX_REPO_PATH_LEN} characters`;
  }
  if (repoPath.includes("\0")) return "repoPath must not contain NUL";
  if (repoPath.includes("\\")) return "repoPath must use forward slashes ('/'), not backslashes";
  if (repoPath.startsWith("/")) return "repoPath must be relative (no leading '/')";
  // Trailing slash → directory reference; basename() would strip it and let a
  // bare prefix dir ("user-uploads/") masquerade as a file. Reject outright.
  if (repoPath.endsWith("/")) return "repoPath must reference a file, not a directory (no trailing '/')";
  // normalize-equality: any input that collapses to a different string under
  // POSIX normalization (./, //, ../) is rejected outright.
  const normalized = path.posix.normalize(repoPath);
  if (normalized !== repoPath) {
    return "repoPath would normalize differently (path traversal blocked)";
  }
  if (repoPath.split("/").some((seg) => seg === "..")) {
    return "repoPath must not contain '..' segments";
  }
  if (!INTAKE_ALLOWED_PREFIXES.some((p) => normalized.startsWith(p))) {
    return `repoPath must be under one of: ${INTAKE_ALLOWED_PREFIXES.join(", ")}`;
  }
  const base = path.posix.basename(normalized);
  if (!base || base === "." || base === "..") {
    return "repoPath must reference a file, not a directory";
  }
  if (!BASENAME_RE.test(base)) {
    return "repoPath basename has disallowed characters (allowed: A-Za-z0-9._-, no leading dot)";
  }
  // 1099 SE-1: per-tenant scoping. Fail-closed if the caller's tenant is
  // missing/malformed — without a safe companyId we cannot prove ownership.
  const cidErr = assertSafeCompanyId(callerCompanyId);
  if (cidErr) return `internal: ${cidErr}`;
  if (normalized.startsWith("artifacts/")) {
    const tenantPrefix = `artifacts/${callerCompanyId}/`;
    if (!normalized.startsWith(tenantPrefix)) {
      return `repoPath under 'artifacts/' must be within your tenant subtree '${tenantPrefix}' (cross-tenant read blocked)`;
    }
  } else if (normalized.startsWith("user-uploads/")) {
    const enforce = opts.enforceUserUploadsScoping ?? ENFORCE_USER_UPLOADS_TENANT_SCOPING;
    if (enforce) {
      const tenantPrefix = `user-uploads/${callerCompanyId}/`;
      if (!normalized.startsWith(tenantPrefix)) {
        return `repoPath under 'user-uploads/' must be within your tenant subtree '${tenantPrefix}' (cross-tenant read blocked)`;
      }
    }
  }
  return null;
}

/**
 * Validate the `inputArtifacts` array shape + per-entry allowlist + count cap.
 * Returns the list of repoPaths on success, or an error string on failure.
 * Rejects duplicate basenames (two distinct repoPaths that would stage to the
 * same `inputs/<basename>`), which would otherwise silently clobber.
 */
export function parseInputArtifacts(
  raw: unknown,
  callerCompanyId: string,
  opts: IntakeScopeOptions = {},
): { repoPaths: string[] } | { error: string } {
  if (raw === undefined || raw === null) return { repoPaths: [] };
  if (!Array.isArray(raw)) return { error: "inputArtifacts must be an array" };
  if (raw.length === 0) return { repoPaths: [] };
  if (raw.length > MAX_INPUT_FILES) {
    return { error: `inputArtifacts may contain at most ${MAX_INPUT_FILES} files` };
  }
  const repoPaths: string[] = [];
  const seenBasenames = new Set<string>();
  for (let i = 0; i < raw.length; i++) {
    const item = raw[i];
    if (typeof item !== "object" || item === null || Array.isArray(item)) {
      return { error: `inputArtifacts[${i}] must be an object { repoPath }` };
    }
    const keys = Object.keys(item as Record<string, unknown>);
    if (keys.some((k) => k !== "repoPath")) {
      return { error: `inputArtifacts[${i}] has unexpected keys (only 'repoPath' allowed)` };
    }
    const repoPath = (item as { repoPath?: unknown }).repoPath;
    const err = assertSafeIntakePath(repoPath, callerCompanyId, opts);
    if (err) return { error: `inputArtifacts[${i}].${err}` };
    const base = path.posix.basename(repoPath as string);
    if (seenBasenames.has(base)) {
      return { error: `inputArtifacts[${i}] basename '${base}' collides with an earlier entry` };
    }
    seenBasenames.add(base);
    repoPaths.push(repoPath as string);
  }
  return { repoPaths };
}

// ---------------------------------------------------------------------------
// GitHub raw fetch (binary-safe, size-capped)
// ---------------------------------------------------------------------------

/**
 * Strict GitHub URL parse — host must be exactly `github.com` over https. Mirrors
 * worker.ts's `parseGitHubUrl` (kept self-contained here so intake throws its own
 * `IntakeError` taxonomy rather than the push-error taxonomy).
 */
function parseGitHubUrl(repoUrl: string): [string, string] {
  let u: URL;
  try {
    u = new URL(repoUrl);
  } catch {
    throw new IntakeError("prerequisite_missing", `Cannot parse artifact repo URL: ${repoUrl}`);
  }
  if (u.protocol !== "https:" || u.host !== "github.com") {
    throw new IntakeError(
      "prerequisite_missing",
      `artifactRepoUrl must be an https://github.com/<owner>/<repo>(.git) URL. Got: ${repoUrl}`,
    );
  }
  const segs = u.pathname.replace(/^\/+/, "").replace(/\.git\/?$/, "").replace(/\/+$/, "").split("/");
  if (segs.length !== 2 || !segs[0] || !segs[1]) {
    throw new IntakeError("prerequisite_missing", `Cannot parse owner/repo from ${repoUrl}`);
  }
  return [segs[0], segs[1]];
}

function encodeRepoPathForUrl(repoPath: string): string {
  return repoPath.split("/").map(encodeURIComponent).join("/");
}

const FETCH_TIMEOUT_MS = 30_000;

/** Injectable for tests; defaults to the global fetch. */
export type FetchImpl = typeof fetch;

/**
 * Fetch one input artifact from the cad-artifacts repo via the GitHub Contents
 * API using the `raw` media type (binary-safe; no base64; no >1 MiB truncation).
 * Enforces the per-file byte cap both pre-download (Content-Length) and
 * post-download (actual length). Throws `IntakeError` on every failure mode.
 *
 * Caller is responsible for the path allowlist (`assertSafeIntakePath`) and the
 * total/count caps; this function trusts `repoPath` is already allowlisted.
 */
export async function fetchInputArtifact(
  pat: string,
  repoUrl: string,
  branch: string,
  repoPath: string,
  fetchImpl: FetchImpl = fetch,
  caps: IntakeCaps = DEFAULT_INTAKE_CAPS,
): Promise<InputFile> {
  const [owner, repo] = parseGitHubUrl(repoUrl);
  const encodedPath = encodeRepoPathForUrl(repoPath);
  const url =
    `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}` +
    `/contents/${encodedPath}?ref=${encodeURIComponent(branch)}`;
  const headers: Record<string, string> = {
    Authorization: `Bearer ${pat}`,
    // raw media type → bytes, not the base64-in-JSON envelope.
    Accept: "application/vnd.github.raw",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "paperclip-plugin-cad/intake",
  };

  let resp: Response;
  try {
    resp = await fetchImpl(url, { headers, signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
  } catch (err) {
    throw new IntakeError("network", `Network error fetching input '${repoPath}': ${(err as Error).message}`);
  }

  if (resp.status === 404) {
    throw new IntakeError("not_found", `Input artifact not found (404): ${repoPath}`, 404);
  }
  if (resp.status === 401 || resp.status === 403) {
    throw new IntakeError(
      "auth",
      `Not authorized (${resp.status}) reading input '${repoPath}'. Verify the export PAT has read access to the artifact repo.`,
      resp.status,
    );
  }
  if (!resp.ok) {
    throw new IntakeError("network", `Unexpected ${resp.status} fetching input '${repoPath}'. Retry later.`, resp.status);
  }

  // Pre-download cap from Content-Length (best effort — header may be absent).
  const clHeader = resp.headers.get("content-length");
  if (clHeader !== null) {
    const cl = Number(clHeader);
    if (Number.isFinite(cl) && cl > caps.maxFileBytes) {
      throw new IntakeError(
        "too_large",
        `Input '${repoPath}' is ${cl} bytes, over the ${caps.maxFileBytes}-byte per-file cap.`,
      );
    }
  }

  const bytes = Buffer.from(await resp.arrayBuffer());
  // Post-download cap (authoritative — covers a missing/lying Content-Length).
  if (bytes.byteLength > caps.maxFileBytes) {
    throw new IntakeError(
      "too_large",
      `Input '${repoPath}' is ${bytes.byteLength} bytes, over the ${caps.maxFileBytes}-byte per-file cap.`,
    );
  }

  // Stage by basename only — directory components are dropped here.
  return { basename: path.posix.basename(repoPath), bytes };
}

/**
 * Fetch all input artifacts, enforcing the total-bytes cap as they accumulate.
 * Stops and throws on the first failure (fail-closed; partial staging would let
 * a script run against a partial input set).
 */
export async function fetchInputArtifacts(
  pat: string,
  repoUrl: string,
  branch: string,
  repoPaths: string[],
  fetchImpl: FetchImpl = fetch,
  caps: IntakeCaps = DEFAULT_INTAKE_CAPS,
): Promise<InputFile[]> {
  const files: InputFile[] = [];
  let total = 0;
  for (const repoPath of repoPaths) {
    const file = await fetchInputArtifact(pat, repoUrl, branch, repoPath, fetchImpl, caps);
    total += file.bytes.byteLength;
    if (total > caps.maxTotalBytes) {
      throw new IntakeError(
        "too_large",
        `Combined input size ${total} bytes exceeds the ${caps.maxTotalBytes}-byte total cap.`,
      );
    }
    files.push(file);
  }
  return files;
}

// ---------------------------------------------------------------------------
// Sandbox workdir staging
// ---------------------------------------------------------------------------

/**
 * Write each input file into `<workdir>/inputs/<basename>`. The basename is
 * re-derived here (defence in depth) so a caller can never smuggle a path with
 * directory components into the sandbox. Verifies each resolved destination stays
 * within the `inputs/` dir before writing.
 */
export async function stageInputFiles(workdir: string, files: InputFile[]): Promise<void> {
  if (!files.length) return;
  const inputsDir = path.join(workdir, "inputs");
  await mkdir(inputsDir, { recursive: true });
  const inputsResolved = path.resolve(inputsDir);
  for (const f of files) {
    // Re-derive basename — never honor any directory component.
    const base = path.basename(f.basename);
    if (!base || base === "." || base === "..") {
      throw new IntakeError("validation", `refusing to stage input with unsafe basename '${f.basename}'`);
    }
    const dest = path.join(inputsDir, base);
    const destResolved = path.resolve(dest);
    if (destResolved !== path.join(inputsResolved, base)) {
      throw new IntakeError("validation", `refusing to stage input outside inputs/ dir: '${f.basename}'`);
    }
    await writeFile(dest, f.bytes);
  }
}
