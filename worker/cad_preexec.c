/*
 * worker/cad_preexec.c — PLA-114 / PLA-106 §3
 *
 * Small ELF used as a preexec wrapper between bwrap and python on deploy
 * hosts whose bwrap predates --rlimit-* (bwrap < 0.6, e.g. Debian 11).
 *
 * Usage (invoked by cad-worker-client.ts when needed):
 *
 *   bwrap [...] -- /worker/cad_preexec \
 *     <python> <worker.py> ...
 *
 * Behaviour:
 *   1. Reads the rlimit table from environment variables (set by the Node
 *      spawn helper). Each variable is a base-10 integer (bytes for AS/FSIZE,
 *      seconds for CPU, count for NPROC/NOFILE, 0 for CORE).
 *   2. Calls setrlimit(2) for each. setrlimit failures are fatal (exit 71)
 *      because a missing limit weakens the sandbox.
 *   3. execve()s argv[1..] with the inherited environment minus the
 *      CAD_PREEXEC_RLIMIT_* keys.
 *
 * Why a separate ELF: bwrap < 0.6 has no --rlimit-* flags. We need rlimits
 * applied AFTER the user-namespace setup (so the syscall succeeds without
 * CAP_SYS_RESOURCE) and BEFORE python starts (so the python interpreter and
 * its threads inherit them). A tiny static program between bwrap and python
 * is the simplest place to do that.
 *
 * Fail-closed: if any required variable is missing, exit 70 ("config
 * error"). The Node parent treats both 70 and 71 as worker_internal.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

struct rl_spec {
    const char *envvar;
    int resource;
    int required;
};

static int set_one(const char *envvar, int resource, int required)
{
    const char *raw = getenv(envvar);
    if (!raw || !*raw) {
        if (required) {
            fprintf(stderr, "[cad_preexec] missing required env: %s\n", envvar);
            return 70;
        }
        return 0;
    }
    char *end = NULL;
    errno = 0;
    unsigned long long v = strtoull(raw, &end, 10);
    if (errno != 0 || !end || *end != '\0') {
        fprintf(stderr, "[cad_preexec] %s not a valid base-10 integer: %s\n",
                envvar, raw);
        return 70;
    }
    struct rlimit rl = {(rlim_t)v, (rlim_t)v};
    if (setrlimit(resource, &rl) != 0) {
        fprintf(stderr, "[cad_preexec] setrlimit(%s=%llu): %s\n",
                envvar, v, strerror(errno));
        return 71;
    }
    /* Strip the var from the environment so python doesn't see them. */
    unsetenv(envvar);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: cad_preexec <command> [args...]\n");
        return 64;
    }

    static const struct rl_spec table[] = {
        {"CAD_PREEXEC_RLIMIT_AS",     RLIMIT_AS,     1},
        {"CAD_PREEXEC_RLIMIT_NPROC",  RLIMIT_NPROC,  1},
        {"CAD_PREEXEC_RLIMIT_NOFILE", RLIMIT_NOFILE, 1},
        {"CAD_PREEXEC_RLIMIT_FSIZE",  RLIMIT_FSIZE,  1},
        {"CAD_PREEXEC_RLIMIT_CPU",    RLIMIT_CPU,    1},
        {"CAD_PREEXEC_RLIMIT_CORE",   RLIMIT_CORE,   1},
    };

    for (size_t i = 0; i < sizeof(table) / sizeof(table[0]); i++) {
        int rc = set_one(table[i].envvar, table[i].resource, table[i].required);
        if (rc != 0) return rc;
    }

    execvp(argv[1], &argv[1]);
    fprintf(stderr, "[cad_preexec] execvp(%s): %s\n", argv[1], strerror(errno));
    return 72;
}
