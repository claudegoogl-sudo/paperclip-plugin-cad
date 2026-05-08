# worker/Makefile — PLA-114
#
# Builds the seccomp filter blob and a tiny preexec wrapper used as a fallback
# when the deploy host's bwrap is older than 0.6 (no --rlimit-* flags).
#
# Build prerequisites (deploy host + CI):
#   apt-get install -y build-essential libseccomp-dev pkg-config bubblewrap
#
# Outputs:
#   worker/seccomp_filter.bpf   - flat BPF blob, opened by the Node spawn
#                                  helper and passed to bwrap on FD 10.
#   worker/seccomp_filter.bpf.sha256
#                               - content hash recorded in the build manifest.
#   worker/cad_preexec          - small ELF that applies setrlimit() then
#                                  execve()s its argv[1..]; used between bwrap
#                                  and python on hosts where bwrap < 0.6.

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -Wpedantic
LDLIBS_SECCOMP := $(shell pkg-config --libs libseccomp 2>/dev/null || echo -lseccomp)
CFLAGS_SECCOMP := $(shell pkg-config --cflags libseccomp 2>/dev/null)

# PLA-216 Obs 1 — sock_filter instruction floor.
#
# Pins the lower bound on the number of `struct sock_filter` instructions in
# the compiled BPF blob. Each sock_filter is 8 bytes on Linux (__u16 code,
# __u8 jt, __u8 jf, __u32 k), so the count is `wc -c < seccomp_filter.bpf` / 8.
# A drop below this floor means a rule was silently dropped from
# seccomp_filter.c (editor accident, bad merge resolve, refactor) — the §5.2
# dual sha pin only catches *substitution*, not *attrition*. Bumping this
# value requires a deliberate change AND a security review note: the
# `SECCOMP_RULE_FLOOR=N` comment block in worker/seccomp_filter.c tracks
# the source-of-truth half of the pair so a rule-deletion PR diff surfaces
# both halves in one review pane.
MIN_SOCK_FILTER_COUNT ?= 99

ARTIFACTS := seccomp_filter.bpf seccomp_filter.bpf.sha256 cad_preexec

.PHONY: all clean
all: $(ARTIFACTS)

# ---------------------------------------------------------------------------
# Filter compiler — produces the flat BPF blob.
# ---------------------------------------------------------------------------

seccomp_filter_compile: seccomp_filter.c
	$(CC) $(CFLAGS) $(CFLAGS_SECCOMP) -o $@ $< $(LDLIBS_SECCOMP)

seccomp_filter.bpf: seccomp_filter_compile
	./seccomp_filter_compile > $@.tmp
	@actual=$$(( $$(wc -c < $@.tmp) / 8 )); \
	expected=$(MIN_SOCK_FILTER_COUNT); \
	if [ "$$actual" -lt "$$expected" ]; then \
	  echo "ERROR: $@ has $$actual sock_filter instructions, expected at least $$expected — did a rule get deleted?" >&2; \
	  echo "       (See SECCOMP_RULE_FLOOR comment in worker/seccomp_filter.c — PLA-216 Obs 1.)" >&2; \
	  rm -f $@.tmp; \
	  exit 1; \
	fi
	mv $@.tmp $@

seccomp_filter.bpf.sha256: seccomp_filter.bpf
	sha256sum seccomp_filter.bpf | awk '{print $$1}' > $@

# ---------------------------------------------------------------------------
# Tiny preexec wrapper (RLIMIT_* fallback for bwrap < 0.6). The wrapper is
# invoked between bwrap and python; it applies the rlimit table and then
# execve()s its argv[1..]. Inside the bwrap user namespace, RLIMIT_* are
# applied to the current task before exec, so the python child inherits them.
# ---------------------------------------------------------------------------

cad_preexec: cad_preexec.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f seccomp_filter_compile $(ARTIFACTS)
