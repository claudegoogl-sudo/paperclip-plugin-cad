#!/usr/bin/env bash
#
# worker/measure-clone-fallback.sh — PLA-114 / PLA-106 §6.4
#
# Measures whether glibc's documented `clone3 -> ENOSYS -> clone(2)` fallback
# is functioning on the host's exact glibc, under the production seccomp
# filter. Produces three rows of evidence to be appended to
# `worker/seccomp-evidence.md` before the seccomp filter blob is locked for
# release.
#
# Prerequisites (run on deploy host or deploy CI runner — NOT the agent
# workstation, which lacks libseccomp-dev and bubblewrap):
#   apt-get install -y build-essential libseccomp-dev pkg-config bubblewrap
#                      strace python3
#   make -C worker seccomp_filter.bpf  # produces the flat BPF blob
#
# Usage:
#   worker/measure-clone-fallback.sh s1   # Step 1: clone3 -> ENOSYS
#   worker/measure-clone-fallback.sh s2   # Step 2: threading.Thread().start()
#   worker/measure-clone-fallback.sh s3   # Step 3: (clone3, clone2) count for N=4
#   worker/measure-clone-fallback.sh all  # all three; prints markdown rows
#
# Exit codes:
#   0  step succeeded; mechanism valid for that step
#   1  step failed; Option 5 invalidated for this host -> escalate per §6.4
#   2  prerequisite missing
#
# Spec reference: [PLA-106 spec doc](/PLA/issues/PLA-106#document-spec) rev 3
# (revision id 3ffe6af0-4ee7-4d82-b01a-fa08414d950b).

set -euo pipefail

WORKER_DIR="$(cd "$(dirname "$0")" && pwd)"
FILTER_BPF="${WORKER_DIR}/seccomp_filter.bpf"
LOADER_SHIM="${WORKER_DIR}/seccomp_load.py"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

require() {
  command -v "$1" >/dev/null 2>&1 || { echo "missing: $1" >&2; exit 2; }
}

require bwrap
require python3

if [[ ! -f "$FILTER_BPF" ]]; then
  echo "missing $FILTER_BPF — run: make -C worker seccomp_filter.bpf" >&2
  exit 2
fi
if [[ ! -f "$LOADER_SHIM" ]]; then
  echo "missing $LOADER_SHIM — required for python-side seccomp install" >&2
  exit 2
fi

host_uname="$(uname -nr)"
host_glibc="$(ldd --version 2>&1 | head -n1)"
host_python="$(python3 --version 2>&1)"
today="$(date -u +%Y-%m-%d)"

# bwrap argv mirrors the production sandbox spawn path (PLA-106 §1 rev 4).
# The seccomp filter blob and the python loader shim are mounted read-only
# under /sandbox/, and the python bootstrap installs the filter via prctl
# *after* trusted import-time setup completes. bwrap's `--seccomp <fd>`
# mechanism is NOT used: it would prctl-install the filter between fork and
# execve, killing the launcher's own execve into the target.
bwrap_argv=(
  bwrap
  --unshare-all
  --die-with-parent
  --clearenv
  --new-session
  --setenv PATH /usr/bin:/bin
  --setenv PYTHONDONTWRITEBYTECODE 1
  --setenv PYTHONUNBUFFERED 1
  --proc /proc
  --dev /dev
  --tmpfs /tmp
  --ro-bind /usr /usr
  --ro-bind /lib /lib
  --ro-bind /lib64 /lib64
  --ro-bind /bin /bin
  --ro-bind /etc/ld.so.cache /etc/ld.so.cache
  --ro-bind "$FILTER_BPF" /sandbox/seccomp_filter.bpf
  --ro-bind "$LOADER_SHIM" /sandbox/seccomp_load.py
)

# Run a python-c bootstrap inside the sandbox under the production seccomp
# filter. The bootstrap calls lock_down() before any user-influenced code
# runs, mirroring the §1.2 invariant. Caller passes the post-lock_down
# python expression as $1.
run_in_sandbox_py() {
  local post_lock_expr="$1"
  local bootstrap="import sys; sys.path.insert(0, '/sandbox'); from seccomp_load import lock_down; lock_down('/sandbox/seccomp_filter.bpf'); ${post_lock_expr}"
  "${bwrap_argv[@]}" -- /usr/bin/python3 -c "$bootstrap"
}

# ---------- Step 1: clone3 -> ENOSYS (probe via ctypes inside python) ----------
#
# Under the production seccomp filter, execve is on the killlist (covered by
# layer 1; the python bootstrap calls lock_down BEFORE invoking the probe so
# we cannot exec into a separate C binary post-lock). The clone3 syscall is
# trivially expressible in ctypes from inside the python process, so we
# inline the probe rather than launching a child.

step1() {
  if run_in_sandbox_py "$(cat <<'PY'
import ctypes, errno, sys
SYS_clone3 = 435
class CloneArgs(ctypes.Structure):
    _fields_ = [
        ('flags', ctypes.c_ulonglong),
        ('pidfd', ctypes.c_ulonglong),
        ('child_tid', ctypes.c_ulonglong),
        ('parent_tid', ctypes.c_ulonglong),
        ('exit_signal', ctypes.c_ulonglong),
        ('stack', ctypes.c_ulonglong),
        ('stack_size', ctypes.c_ulonglong),
        ('tls', ctypes.c_ulonglong),
    ]
libc = ctypes.CDLL('libc.so.6', use_errno=True)
args = CloneArgs()
args.exit_signal = 17  # SIGCHLD
rc = libc.syscall(SYS_clone3, ctypes.byref(args), ctypes.sizeof(args))
e = ctypes.get_errno()
sys.stdout.write(f'clone3_rc={rc} errno={e} ({"ENOSYS" if e == errno.ENOSYS else "OTHER"})\n')
sys.exit(0 if rc == -1 and e == errno.ENOSYS else 1)
PY
)"; then
    echo "| $today | $host_uname | $host_glibc | -1 | ENOSYS | Option 5 valid ✓ |"
    return 0
  else
    echo "| $today | $host_uname | $host_glibc | (see logs) | NOT ENOSYS | Option 5 REJECTED — escalate per §6.4 |" >&2
    return 1
  fi
}

# ---------- Step 2: threading.Thread().start() ----------

step2() {
  if run_in_sandbox_py "$(cat <<'PY'
import sys, threading
t = threading.Thread(target=lambda: None)
t.start()
t.join()
sys.stdout.write('threading_ok\n')
sys.exit(0)
PY
)"; then
    echo "| $today | $host_uname | $host_python | $host_glibc | 0 | Mechanism functioning ✓ |"
    return 0
  else
    echo "| $today | $host_uname | $host_python | $host_glibc | non-zero | Mechanism BROKEN — escalate per §6.4 |" >&2
    return 1
  fi
}

# ---------- Step 3: (clone3, clone2) count for N=4 sequential threads ----------

step3() {
  require strace
  local probe_expr
  probe_expr="$(cat <<'PY'
import threading
for _ in range(4):
    t = threading.Thread(target=lambda: None)
    t.start()
    t.join()
PY
)"
  # Step 3 measures glibc's nptl clone3->ENOSYS->clone(2) fallback under
  # the **production seccomp filter** (per file docstring line 4-7). The
  # filter is applied by `lock_down()` via prctl, which works identically
  # whether or not bwrap wraps the process — bwrap provides fs/namespace
  # isolation, which is orthogonal to the §6.4 measurement.
  #
  # Tracing INSIDE bwrap with `strace -f` forces strace to count bwrap's
  # own setup clones (`CLONE_NEWUSER`, `CLONE_NEWNS`, `CLONE_NEWPID`, etc.
  # plus the privileged-setup helper fork), which are non-load-bearing
  # for §6.4 but inflate `clone2_count` beyond the 4-per-thread
  # expectation. CI run 25259114651 produced (1,6) — clone3 attempted=1
  # (ENOSYS, glibc cached), clone2=6 (4 from threads + 2 from bwrap
  # setup) — semantically valid but rejected by strict (1,4) verdict.
  #
  # Fix: trace python directly with host-side paths to the filter blob
  # and the loader shim. The bwrap layer is verified by NEW16 and the
  # workflow smoke step; §6.4 specifically isolates the glibc fallback
  # behavior under the filter.
  local bootstrap="import sys; sys.path.insert(0, '${WORKER_DIR}'); from seccomp_load import lock_down; lock_down('${FILTER_BPF}'); ${probe_expr}"
  set +e
  strace -f -c -e trace=clone,clone3 -o "$TMPDIR/n4.trace" \
    /usr/bin/python3 -c "$bootstrap"
  local rc=$?
  set -e
  if [[ $rc -ne 0 ]]; then
    echo "n4_probe exited non-zero ($rc); cannot measure cleanly" >&2
    return 1
  fi
  # strace -c -o writes counts to file; parse the clone/clone3 rows.
  local clone3_count clone2_count
  clone3_count=$(awk '$NF=="clone3" {print $4}' "$TMPDIR/n4.trace" | head -n1)
  clone2_count=$(awk '$NF=="clone"  {print $4}' "$TMPDIR/n4.trace" | head -n1)
  : "${clone3_count:=0}"
  : "${clone2_count:=0}"
  local verdict
  if   [[ "$clone3_count" == "1" && "$clone2_count" == "4" ]]; then verdict="(1,4) — glibc caches ENOSYS; valid ✓"
  elif [[ "$clone3_count" == "4" && "$clone2_count" == "4" ]]; then verdict="(4,4) — glibc retries; valid ✓"
  elif [[ "$clone3_count" == "4" && "$clone2_count" == "0" ]]; then verdict="(4,0) — fallback BROKEN; HALT — escalate per §6.4"
  else verdict="($clone3_count,$clone2_count) — unexpected; investigate"
  fi
  echo "| $today | $host_uname | $host_glibc | strace | $clone3_count | $clone2_count | $verdict |"
  if [[ "$verdict" == *"BROKEN"* || "$verdict" == *"unexpected"* ]]; then
    return 1
  fi
}

case "${1:-}" in
  s1) step1 ;;
  s2) step2 ;;
  s3) step3 ;;
  all)
    # CTO 15:56 directive: NO `|| true` masks. Each step runs under
    # `set -euo pipefail`, and a failing step exits the script with the
    # step's return code so §6.4 evidence cannot silently regress. To
    # capture all three step outcomes in a single run (for diagnosis), the
    # caller can run s1/s2/s3 individually.
    echo "## §6.4 evidence — $(uname -nr) — $today"
    echo
    echo "### Step 1"
    echo "| Date | Host | glibc | clone3 return | errno | Verdict |"
    echo "| --- | --- | --- | --- | --- | --- |"
    step1
    echo
    echo "### Step 2"
    echo "| Date | Host | Python | glibc | Exit | Verdict |"
    echo "| --- | --- | --- | --- | --- | --- |"
    step2
    echo
    echo "### Step 3"
    echo "| Date | Host | glibc | Tool | clone3 | clone2 | Verdict |"
    echo "| --- | --- | --- | --- | --- | --- | --- |"
    step3
    ;;
  *)
    echo "usage: $0 {s1|s2|s3|all}" >&2
    exit 2
    ;;
esac
