/**
 * Seccomp build/load chain — silent-failure hardening regression tests.
 *
 * PLA-216 closes two "fail loudly when the filter isn't what you think it
 * is" gaps in the seccomp build chain:
 *
 *   Obs 1 — `worker/Makefile` MIN_SOCK_FILTER_COUNT floor: a rule silently
 *     dropped from `worker/seccomp_filter.c` (editor accident, bad merge
 *     resolve, refactor) used to build green; the §5.2 dual sha pin only
 *     catches *substitution*, not *attrition*. The Makefile now asserts
 *     the compiled blob has at least N `sock_filter` instructions and
 *     fails with an "expected at least N — did a rule get deleted?"
 *     diagnostic if it doesn't.
 *
 *   Obs 2 — `seccomp_rule_add` rc checks: the `kill_syscall` helper used
 *     to log-and-continue on libseccomp failure (duplicate-rule conflict,
 *     allocator failure, arch resolution failure, unresolvable syscall
 *     name). On failure the rule was silently absent from the compiled
 *     filter. The helper now aborts with errno context naming the
 *     syscall and action; the mbind / personality direct call sites do
 *     the same.
 *
 * Each test reproduces the failure mode by patching a copy of the worker/
 * source tree in a tmpdir, runs the real Makefile against it, and asserts
 * the build aborts with the expected diagnostic.
 *
 * Suite is gated on the host having `cc` plus `libseccomp` headers. CI
 * runs this — see .github/workflows/sandbox.yml — but local dev machines
 * without libseccomp-dev will skip cleanly.
 */

import { describe, it, expect } from "vitest";
import { mkdtempSync, readFileSync, writeFileSync, cpSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync, spawnSync } from "node:child_process";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, "..");
const WORKER_DIR = join(REPO_ROOT, "worker");

// ---------------------------------------------------------------------------
// Capability gate. Skip the suite if the host doesn't have a C compiler or
// libseccomp headers — there's nothing useful we can assert about a build
// chain we can't run.
// ---------------------------------------------------------------------------

function canBuildSeccompFilter(): boolean {
  try {
    execFileSync("cc", ["--version"], { stdio: "ignore" });
  } catch {
    return false;
  }
  // Probe for libseccomp by attempting to compile a single-line program
  // that includes <seccomp.h>. We don't need to link, just to see the
  // header.
  const probe = spawnSync(
    "cc",
    ["-x", "c", "-E", "-include", "seccomp.h", "-"],
    { input: "", stdio: ["pipe", "ignore", "ignore"] },
  );
  return probe.status === 0;
}

const HAS_BUILD_DEPS = canBuildSeccompFilter();

// Files in worker/ the build needs. cad_preexec.c is included so `make all`
// would also work; we only invoke the seccomp_filter.bpf target so it's not
// strictly required, but copying the whole tree keeps the regression
// scenarios faithful.
const WORKER_BUILD_INPUTS = [
  "Makefile",
  "seccomp_filter.c",
  "cad_preexec.c",
];

function makeWorkerCopy(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), `pla216-${prefix}-`));
  for (const f of WORKER_BUILD_INPUTS) {
    cpSync(join(WORKER_DIR, f), join(dir, f));
  }
  return dir;
}

function runMake(
  cwd: string,
  args: string[] = ["seccomp_filter.bpf"],
): { status: number | null; stdout: string; stderr: string } {
  const r = spawnSync("make", args, {
    cwd,
    encoding: "utf8",
    env: { ...process.env, MAKEFLAGS: "" },
  });
  return { status: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
}

// ---------------------------------------------------------------------------

describe.skipIf(!HAS_BUILD_DEPS)(
  "PLA-216: seccomp build/load chain silent-failure hardening",
  () => {
    // -----------------------------------------------------------------------
    // Sanity gate. The canonical build must succeed and the resulting blob
    // must clear the floor — otherwise the floor is stale and every other
    // test in this suite is meaningless. This is the positive control for
    // the negative regression tests below.
    // -----------------------------------------------------------------------
    it("canonical build produces a blob at or above MIN_SOCK_FILTER_COUNT", () => {
      const dir = makeWorkerCopy("sanity");
      const r = runMake(dir);
      expect(
        r.status,
        `make failed: stdout=${r.stdout} stderr=${r.stderr}`,
      ).toBe(0);
      const bpfPath = join(dir, "seccomp_filter.bpf");
      expect(existsSync(bpfPath)).toBe(true);
      const bytes = readFileSync(bpfPath).length;
      // Each `struct sock_filter` is 8 bytes on Linux.
      expect(bytes % 8).toBe(0);
      const instructions = bytes / 8;
      const floor = readFloorFromMakefile();
      expect(
        instructions,
        `canonical build emitted ${instructions} sock_filter instructions, below floor ${floor} — bump MIN_SOCK_FILTER_COUNT or recover the deleted rule`,
      ).toBeGreaterThanOrEqual(floor);
    });

    // -----------------------------------------------------------------------
    // Obs 1 regression: deleting one rule from seccomp_filter.c MUST fail
    // the build with an expected-vs-actual diagnostic. The exact wording is
    // Coder's call; the AC requires both numbers to appear and a hint that
    // a rule may have been deleted.
    // -----------------------------------------------------------------------
    it("Obs 1 — deleting one kill_syscall row aborts the build with expected-vs-actual diagnostic", () => {
      const dir = makeWorkerCopy("obs1");
      const srcPath = join(dir, "seccomp_filter.c");
      const original = readFileSync(srcPath, "utf8");
      // Delete the io_uring_register kill — chosen because it's a leaf rule
      // with no peers depending on its placement, so the remaining filter
      // is still well-formed C and libseccomp will happily compile it.
      const patched = original.replace(
        /\n\s*kill_syscall\(ctx, "io_uring_register"\);\n/,
        "\n",
      );
      expect(
        patched,
        "fixture invariant: io_uring_register kill_syscall must be present in canonical seccomp_filter.c",
      ).not.toBe(original);
      writeFileSync(srcPath, patched);

      const r = runMake(dir);
      expect(r.status, `expected non-zero exit, got ${r.status}`).not.toBe(0);
      const merged = `${r.stdout}\n${r.stderr}`;
      expect(merged, "diagnostic must name the floor literally").toMatch(
        /expected at least \d+/,
      );
      expect(merged, "diagnostic must show actual instruction count").toMatch(
        /has \d+ sock_filter instructions/,
      );
      expect(
        merged,
        "diagnostic must hint that a rule may have been deleted",
      ).toMatch(/rule.*deleted/i);
      // Canonical floor is 99; with one rule removed we must observe a
      // strictly lower count than the floor literal.
      const actual = matchOrThrow(merged, /has (\d+) sock_filter/, 1);
      const expected = matchOrThrow(
        merged,
        /expected at least (\d+)/,
        1,
      );
      expect(Number(actual)).toBeLessThan(Number(expected));
    });

    // -----------------------------------------------------------------------
    // Obs 2 regression: a libseccomp rule_add failure (here: an
    // unresolvable syscall name routed through `kill_syscall`) MUST abort
    // the build, not silently log-and-continue. The pre-fix kill_syscall
    // helper specifically swallowed this case — see the "Don't abort"
    // comment removed in this PR. We use an unresolvable name rather than
    // a duplicate-action conflict because libseccomp 2.5.x merges or
    // dedupes some same-syscall conflicts silently rather than returning
    // negative; an unresolvable name is the simplest reliable trigger for
    // a negative `seccomp_rule_add` return.
    // -----------------------------------------------------------------------
    it("Obs 2 — unresolvable syscall name in kill_syscall aborts the build with errno context", () => {
      const dir = makeWorkerCopy("obs2");
      const srcPath = join(dir, "seccomp_filter.c");
      const original = readFileSync(srcPath, "utf8");
      const FAKE = "_pla216_unresolvable_syscall_xyzzy_";
      const inject = `    kill_syscall(ctx, "${FAKE}"); /* PLA-216 test injection */\n`;
      // Insert just after the execve-family region so the failing call
      // sits in the canonical denylist body, exercising the same code path
      // every other kill_syscall does.
      const marker = '    /* ===== execve family ===== */\n';
      expect(
        original.includes(marker),
        "fixture invariant: execve family marker must be present",
      ).toBe(true);
      const patched = original.replace(marker, marker + inject);
      writeFileSync(srcPath, patched);

      const r = runMake(dir);
      expect(r.status, `expected non-zero exit, got ${r.status}`).not.toBe(0);
      const merged = `${r.stdout}\n${r.stderr}`;
      expect(merged, "diagnostic must name the failing syscall").toContain(
        FAKE,
      );
      expect(
        merged,
        "diagnostic must name the seccomp_rule_add helper",
      ).toMatch(/seccomp_rule_add/);
      expect(merged, "diagnostic must include the failing action").toMatch(
        /KILL_PROCESS/,
      );
      // The build must NOT have left a usable .bpf in place (a partial
      // .tmp may exist from the failed compile run, but the final
      // artifact must be absent).
      expect(existsSync(join(dir, "seccomp_filter.bpf"))).toBe(false);
    });

    // -----------------------------------------------------------------------
    // Obs 2 second-instance: the mbind rule (rev-5 §2 EPERM carve-out) was
    // a direct `seccomp_rule_add` with the return value discarded. The fix
    // wraps it with an rc check that aborts on failure. We force the
    // failure by swapping the action to one that conflicts at libseccomp's
    // arg-encoding layer — passing `SCMP_ACT_TRACE(0)` which the kernel
    // requires CAP_SYS_ADMIN to install. libseccomp will accept it at
    // user-level but reject it later; the simpler reliable trigger here is
    // the same unresolvable-name pattern, applied via a one-line direct
    // injection that bypasses kill_syscall entirely. This proves the mbind
    // call site itself has a working rc check, distinct from the helper.
    // -----------------------------------------------------------------------
    it("Obs 2 — direct seccomp_rule_add at the mbind site aborts on failure", () => {
      const dir = makeWorkerCopy("obs2-mbind");
      const srcPath = join(dir, "seccomp_filter.c");
      const original = readFileSync(srcPath, "utf8");
      // Replace the mbind rule's syscall macro with a guaranteed-bad
      // negative pseudo-syscall (-1 == __NR_SCMP_ERROR). libseccomp
      // returns -EINVAL for this. With the fix, the rc check at the
      // mbind call site aborts the build; without the fix, the bad
      // syscall is silently dropped and the build is green.
      const before =
        "seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM),\n                                  SCMP_SYS(mbind), 0)";
      expect(
        original.includes(before),
        "fixture invariant: mbind rule_add call must be present",
      ).toBe(true);
      const patched = original.replace(
        before,
        "seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM),\n                                  -1 /* PLA-216 test: forces -EINVAL */, 0)",
      );
      writeFileSync(srcPath, patched);

      const r = runMake(dir);
      expect(r.status, `expected non-zero exit, got ${r.status}`).not.toBe(0);
      const merged = `${r.stdout}\n${r.stderr}`;
      expect(merged, "diagnostic must name the mbind site").toMatch(
        /seccomp_rule_add\(mbind/,
      );
      expect(existsSync(join(dir, "seccomp_filter.bpf"))).toBe(false);
    });
  },
);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function matchOrThrow(s: string, re: RegExp, group: number): string {
  const m = s.match(re);
  if (!m) {
    throw new Error(`regex ${re} did not match. Input was:\n${s}`);
  }
  return m[group];
}

function readFloorFromMakefile(): number {
  const mk = readFileSync(join(WORKER_DIR, "Makefile"), "utf8");
  const m = mk.match(/MIN_SOCK_FILTER_COUNT\s*\?=\s*(\d+)/);
  if (!m) {
    throw new Error(
      "MIN_SOCK_FILTER_COUNT not found in worker/Makefile — did the variable get renamed?",
    );
  }
  return Number(m[1]);
}
