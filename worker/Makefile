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
