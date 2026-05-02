# Clone-flag and ENOSYS-fallback evidence — PLA-114 / PLA-106 §2.1 + §6.4

This file records two independent pieces of empirical evidence required by
spec [PLA-106](/PLA/issues/PLA-106) revision 3 (`3ffe6af0-4ee7-4d82-b01a-fa08414d950b`)
before the seccomp filter blob is locked for a release:

1. **§2.1 clone-flag evidence** — the `clone` / `clone3` flag set Python's
   `threading` module issues on the deploy host, captured via `strace -e
   clone,clone3`. This determines the `PTHREAD_CLONE_FLAGS` constant in
   `worker/seccomp_filter.c`.
2. **§6.4 ENOSYS-fallback validation experiment** — a 3-step measurement,
   under the production seccomp filter, that confirms (a) `clone3` returns
   `-ENOSYS`, (b) `threading.Thread(...).start()` still succeeds, and (c)
   the measured `(clone3_count, clone_count)` ratio for N=4 sequential
   thread-creates. The third step's outcome determines whether Option 5
   (the chosen rev 3 mechanism) is empirically valid on this glibc.

Spec rev 3 selected **Option 5: `clone3 → SCMP_ACT_ERRNO(ENOSYS)`** — see
`worker/seccomp_filter.c` for the implementation. The mechanism rests on
glibc's documented `clone3 → ENOSYS → clone(2)` fallback path. NEW14 (the
positive threading control in §4) is the durable canary that fails loudly
if a future glibc removes the fallback.

## Capture procedure

Run on the deploy host (Debian 12 / Ubuntu 22.04 / 24.04) with the same
Python interpreter and CadQuery venv that production uses:

```bash
strace -e clone,clone3 -f python3 \
  -c "import threading; threading.Thread(target=lambda: None).start()" \
  2>&1 | tail -25
```

Record the output verbatim below. Note **whether the call is `clone` or
`clone3`** — that determines whether the BPF filter blocks threading or not.

---

## Capture: agent workstation (2026-05-02)

- Host: `srv1405293`, Linux 6.8.0-111-generic x86_64
- Python: `/usr/bin/python3` (Python 3.12 from Ubuntu 24.04 packages)
- glibc: provides `pthread_create` via `clone3` on this kernel/glibc combo
- Capture command: as documented above

```
clone3({flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID, child_tid=0x744c92fff990, parent_tid=0x744c92fff990, exit_signal=0, stack=0x744c927ff000, stack_size=0x7fff80, tls=0x744c92fff6c0}strace: Process 242711 attached
 => {parent_tid=[242711]}, 88) = 242711
[pid 242711] +++ exited with 0 +++
+++ exited with 0 +++
```

**Observed flag set (verbal):**

```
CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD |
CLONE_SYSVSEM | CLONE_SETTLS | CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID
```

**Numeric bitmask (x86_64 / `<linux/sched.h>`):** `0x3D0F00`

This matches the `PTHREAD_CLONE_FLAGS` macro in `worker/seccomp_filter.c`.

**Syscall used:** `clone3` (NOT `clone`).

## Implication for the seccomp filter (rev 3 — Option 5)

- The filter encodes the `clone(2)` allow-rule as documented (any flag
  mismatch → `SCMP_ACT_KILL_PROCESS`). This rule is **load-bearing**: it
  is the actual enforcement of the "no namespace creation, no process
  replication" invariant. Every task-creation reaches the kernel as
  `clone(2)` once `clone3` has returned `-ENOSYS`.
- The filter encodes `clone3` as **`SCMP_ACT_ERRNO(ENOSYS)`** per spec §2.1
  rev 3 (Option 5). The kernel never enters `clone3`; the syscall returns
  `-1` with `errno=ENOSYS` to userspace. glibc's nptl pthread path and the
  fork path check for `ENOSYS` from the `clone3` wrapper and fall back to
  `clone(2)` with equivalent flags.
- The mechanism's correctness rests on glibc continuing to emit a `clone(2)`
  fallback when `clone3` returns `ENOSYS`. The §6.4 measurement experiment
  below records this as a measured fact on the deploy-host glibc — not an
  asserted claim from the glibc source.
- NEW14 (the positive threading control in §4) is the durable canary: a
  CadQuery box+sphere+cylinder smoke test that uses pthreads and asserts
  the worker emitted N `clone3` calls + N `clone(2)` calls (or 1 `clone3`
  + N `clone(2)` if glibc caches the ENOSYS process-wide). NEW14 fails
  loudly on the next glibc upgrade if the fallback is ever removed.
  **Necessary, not sufficient** — does not prove security; proves the
  mechanism is still functioning.

## §2.1 Re-capture log (clone-flag evidence)

| Date | Host (uname -nr) | Python | glibc | Syscall | Flags |
| --- | --- | --- | --- | --- | --- |
| 2026-05-02 | srv1405293 / 6.8.0-111-generic | 3.12 (Ubuntu 24.04) | shipped with 24.04 (≥ 2.34) | `clone3` | `CLONE_VM\|CLONE_FS\|CLONE_FILES\|CLONE_SIGHAND\|CLONE_THREAD\|CLONE_SYSVSEM\|CLONE_SETTLS\|CLONE_PARENT_SETTID\|CLONE_CHILD_CLEARTID` |

> **Deploy-host re-capture pending.** The agent workstation uses the same
> Ubuntu 24.04 Python as the deploy target, so the result here is expected
> to match. This row should be re-run on the deploy host immediately before
> tagging a release and the result appended above.

---

## §6.4 ENOSYS-fallback validation experiment

The Option 5 mechanism in §2.1 rests on glibc's documented fallback from
`clone3 → ENOSYS` to `clone(2)`. Spec rev 3 mandates this be **measured**
on the deploy host's exact glibc, not asserted. The 3 steps below are the
implementation's evidence requirement; they must be attached to PLA-106
before the seccomp filter blob is locked.

### Step 1 — confirm `clone3` returns `ENOSYS` under the filter

Compile and run `worker/measure-clone-fallback.sh` step `s1`. The script
runs a tiny C program that issues `syscall(SYS_clone3, &args, sizeof(args))`
directly with `args.flags = SIGCHLD`, under the production seccomp filter.

**Expected:** return value `-1`, `errno == ENOSYS`. No `SIGSYS`, no child
created. If `errno != ENOSYS`, the mechanism is invalid for this host and
Option 5 is **rejected** — escalate per §6.4 escalation clause, do **not**
silently fall back to Option 4.

| Date | Host (uname -nr) | glibc | clone3 return | errno | Verdict |
| --- | --- | --- | --- | --- | --- |
| _pending deploy CI_ | _ldd --version_ | _uname -r_ | _-1_ | _ENOSYS_ | _Option 5 valid ✓ / rejected ✗_ |

### Step 2 — confirm `threading.Thread(...).start()` succeeds end-to-end

Run `worker/measure-clone-fallback.sh` step `s2`: under the same seccomp
filter, run `python3 -c "import threading; t=threading.Thread(target=lambda:
None); t.start(); t.join()"`.

**Expected:** clean exit, no `SIGSYS`, no `RuntimeError` from pthreads.

| Date | Host | Python | glibc | Exit code | Verdict |
| --- | --- | --- | --- | --- | --- |
| _pending deploy CI_ | _uname -nr_ | _python3 --version_ | _ldd --version_ | _0_ | _Mechanism functioning ✓_ |

### Step 3 — measure `(clone3_count, clone_count)` for N=4 sequential threads

Run `worker/measure-clone-fallback.sh` step `s3`: under the same filter,
spawn 4 threads sequentially (`t.start()` then `t.join()` then next),
tracing via `strace -f -c -e trace=clone,clone3 python3 prog.py` (or
`bpftrace` if `strace`-induced scheduling perturbation is a concern; record
which tool was used).

**The measured pair determines the outcome:**

- **`(1, 4)`** — glibc caches the `ENOSYS` result process-wide; subsequent
  thread-creates route straight to `clone(2)`. Steady-state cost ≈ free.
  Option 5 valid ✓.
- **`(4, 4)`** — glibc retries `clone3` per thread. Steady-state cost is
  4× syscall overhead per thread-create (microseconds; well within the
  spec §6.2 perf budget). Option 5 valid ✓.
- **`(4, 0)`** — the fallback is **not happening** on this glibc. NEW14
  also fails. **Halt and re-evaluate.** Per spec §6.4 rev 3:
  > "Fallback to Option 4 (allow `clone3` unconditionally with surrounding
  > controls) is *not* automatic — that becomes an Inv-3 risk-acceptance
  > question and routes to `request_board_approval` per CEO's escalation
  > contract `3f0d8a9d`. Coder must escalate, not silently switch options."

| Date | Host | glibc | Trace tool | clone3 count | clone count | Verdict |
| --- | --- | --- | --- | --- | --- | --- |
| _pending deploy CI_ | _uname -nr_ | _ldd --version_ | _strace / bpftrace_ | _N_ | _N_ | _(1,4)/(4,4)/(4,0)_ |

### Acceptance gate (binding)

§2.1 of spec rev 3 is conditionally accepted. The seccomp filter blob
cannot be locked for release until all three steps above have a row in the
table on the deploy-host glibc. NEW14 in `src/sandbox.bwrap.test.ts` is the
durable runtime canary; the §6.4 row is the one-time pre-release evidence.

### Local-host limitation (this workstation)

`worker/measure-clone-fallback.sh` cannot run end-to-end on the agent
workstation: `libseccomp-dev` and `bubblewrap` are not installed and the
heartbeat cannot install packages without password-gated `sudo`. The
script is committed in a runnable form for the deploy CI runner (which the
PLA-114 changes to `.github/workflows/sandbox.yml` and `.devcontainer/Dockerfile`
ensure has both packages). The §2.1 strace evidence above (which does
**not** require the filter loaded) was captured locally and is the input
to `PTHREAD_CLONE_FLAGS`.
