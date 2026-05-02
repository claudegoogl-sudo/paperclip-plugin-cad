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

host_uname="$(uname -nr)"
host_glibc="$(ldd --version 2>&1 | head -n1)"
host_python="$(python3 --version 2>&1)"
today="$(date -u +%Y-%m-%d)"

# bwrap argv that mirrors the production sandbox spawn path (spec §1).
# Each step substitutes its own command at the end. FD 10 is the filter.
bwrap_argv=(
  bwrap
  --unshare-all
  --die-with-parent
  --clearenv
  --new-session
  --proc /proc
  --dev /dev
  --tmpfs /tmp
  --ro-bind /usr /usr
  --ro-bind /lib /lib
  --ro-bind /lib64 /lib64
  --ro-bind /bin /bin
  --ro-bind /etc/ld.so.cache /etc/ld.so.cache
  --seccomp 10
)

run_in_sandbox() {
  # shellcheck disable=SC2068  # intentional word-split of arg array
  exec 10<"$FILTER_BPF"
  "${bwrap_argv[@]}" -- "$@"
  local rc=$?
  exec 10<&-
  return $rc
}

# ---------- Step 1: clone3 -> ENOSYS ----------

step1() {
  cat >"$TMPDIR/clone3_probe.c" <<'C'
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/sched.h>

/* clone3 syscall number is not always in glibc headers; pin the value. */
#ifndef SYS_clone3
#define SYS_clone3 435
#endif

struct clone_args_v0 {
    unsigned long long flags;
    unsigned long long pidfd;
    unsigned long long child_tid;
    unsigned long long parent_tid;
    unsigned long long exit_signal;
    unsigned long long stack;
    unsigned long long stack_size;
    unsigned long long tls;
};

int main(void) {
    struct clone_args_v0 args = {0};
    args.flags = 0;
    args.exit_signal = SIGCHLD;
    long rc = syscall(SYS_clone3, &args, sizeof(args));
    int e = errno;
    printf("clone3_rc=%ld errno=%d (%s)\n", rc, e,
           e == ENOSYS ? "ENOSYS" : "OTHER");
    if (rc == -1 && e == ENOSYS) return 0;
    return 1;
}
C
  cc -O2 -Wall -o "$TMPDIR/clone3_probe" "$TMPDIR/clone3_probe.c"
  if run_in_sandbox "$TMPDIR/clone3_probe"; then
    echo "| $today | $host_uname | $host_glibc | -1 | ENOSYS | Option 5 valid ✓ |"
    return 0
  else
    echo "| $today | $host_uname | $host_glibc | (see logs) | NOT ENOSYS | Option 5 REJECTED — escalate per §6.4 |" >&2
    return 1
  fi
}

# ---------- Step 2: threading.Thread().start() ----------

step2() {
  cat >"$TMPDIR/thread_probe.py" <<'PY'
import sys, threading
t = threading.Thread(target=lambda: None)
t.start()
t.join()
print("threading_ok")
sys.exit(0)
PY
  if run_in_sandbox python3 "$TMPDIR/thread_probe.py"; then
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
  cat >"$TMPDIR/n4_probe.py" <<'PY'
import threading
def run():
    for _ in range(4):
        t = threading.Thread(target=lambda: None)
        t.start()
        t.join()
run()
PY
  # Use strace -c to aggregate counts; -f follows the python child created by
  # bwrap. We invoke strace OUTSIDE bwrap (tracing bwrap+python) because
  # ptrace(2) is denied by the filter; the trace is on the host side,
  # observing syscalls from the sandboxed task via the kernel's ptrace
  # accounting. strace -c emits an ascii table to stderr.
  exec 10<"$FILTER_BPF"
  strace -f -c -e trace=clone,clone3 -o "$TMPDIR/n4.trace" \
    "${bwrap_argv[@]}" -- python3 "$TMPDIR/n4_probe.py"
  local rc=$?
  exec 10<&-
  if [[ $rc -ne 0 ]]; then
    echo "n4_probe.py exited non-zero ($rc); cannot measure cleanly" >&2
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
    echo "## §6.4 evidence — $(uname -nr) — $today"
    echo
    echo "### Step 1"
    echo "| Date | Host | glibc | clone3 return | errno | Verdict |"
    echo "| --- | --- | --- | --- | --- | --- |"
    step1 || true
    echo
    echo "### Step 2"
    echo "| Date | Host | Python | glibc | Exit | Verdict |"
    echo "| --- | --- | --- | --- | --- | --- |"
    step2 || true
    echo
    echo "### Step 3"
    echo "| Date | Host | glibc | Tool | clone3 | clone2 | Verdict |"
    echo "| --- | --- | --- | --- | --- | --- | --- |"
    step3 || true
    ;;
  *)
    echo "usage: $0 {s1|s2|s3|all}" >&2
    exit 2
    ;;
esac
