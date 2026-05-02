# Clone-flag evidence — PLA-114 / PLA-106 §2.1

This file records the exact `clone` / `clone3` flag set Python's `threading`
module issues for thread creation on the deploy host. It is the empirical
input to the BPF allow rule encoded in `worker/seccomp_filter.c`.

The spec (PLA-106 §2.1) **requires** that this evidence be re-captured on the
deploy host before the filter blob is locked in for a release, and the result
recorded here. The `pthread_create` glibc path may switch from `clone` to
`clone3` between glibc versions; that switch changes whether NEW14 (threading
positive control) passes against the spec's "kill `clone3` unconditionally"
rule.

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

## Implication for the seccomp filter

- The filter encodes `clone` allow-rule as documented (ANY-flag-mismatch →
  `SCMP_ACT_KILL_PROCESS`). This rule remains correct: nothing user-visible
  on this host issues plain `clone` for threading anymore, so the rule has
  no positive impact here, but it still kills `CLONE_NEW*` namespace-escape
  attempts via `clone(2)` (e.g. NEW2 PoC).
- The filter encodes `clone3` as **unconditional kill** per spec §2.1.
- On a host where glibc uses `clone3` for `pthread_create` (this host;
  likely also Ubuntu 22.04+ / Debian 12 deploy hosts running glibc ≥ 2.34),
  **NEW14 (threading positive control) will fail at the kernel layer
  with this filter as written.** The spec explicitly contemplates this:

  > "If a future glibc switches pthreads to clone3, the integration tests
  > in §4 will catch it (CadQuery threading test will fail loudly), and we
  > widen the allow rule then. Documented as a known follow-up."
  > — PLA-106 §2.1

  The spec author already accepted the contingency. The intended remediation
  is a **spec revision** (bumping `worker/seccomp_filter.c` to allow
  `clone3` either unconditionally or by `set_tid_size` heuristics), accepted
  by CTO on a fresh `request_confirmation`, then a follow-up implementation
  ticket for the SecurityEngineer to widen the rule. **Not** an in-place
  deviation by the implementer.

## Re-capture log

| Date | Host (uname -nr) | Python | glibc | Syscall | Flags |
| --- | --- | --- | --- | --- | --- |
| 2026-05-02 | srv1405293 / 6.8.0-111-generic | 3.12 (Ubuntu 24.04) | shipped with 24.04 (≥ 2.34) | `clone3` | `CLONE_VM\|CLONE_FS\|CLONE_FILES\|CLONE_SIGHAND\|CLONE_THREAD\|CLONE_SYSVSEM\|CLONE_SETTLS\|CLONE_PARENT_SETTID\|CLONE_CHILD_CLEARTID` |

> **Deploy-host re-capture pending.** The agent workstation uses the same
> Ubuntu 24.04 Python as the deploy target, so the result here is expected
> to match. This row should be re-run on the deploy host immediately before
> tagging a release and the result appended above.
