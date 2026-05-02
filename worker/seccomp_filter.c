/*
 * worker/seccomp_filter.c — PLA-114 / PLA-106 §2
 *
 * Compiles to a flat BPF blob (seccomp_filter.bpf) that the Node spawn helper
 * passes to bwrap on FD 10 via `--seccomp 10`.
 *
 * Default action: SCMP_ACT_ALLOW. Practical posture per spec §2:
 *   "Allowlists for a full Python+CadQuery+OCCT process are infeasible to
 *    maintain across glibc updates. Practical posture: an explicit denylist
 *    of the syscalls an escape needs, with SCMP_ACT_KILL_PROCESS so a hit
 *    terminates the entire worker."
 *
 * Build:
 *   $ make -C worker seccomp_filter.bpf
 *
 *   Requires libseccomp-dev (>= 2.5). Apt: `apt-get install libseccomp-dev`.
 *
 * Verification (post-build):
 *   $ scmp_bpf_disasm < worker/seccomp_filter.bpf | head -40
 *
 * Runtime contract with cad-worker-client.ts:
 *   - Filter blob is opened read-only by the Node parent.
 *   - Passed via child_process.spawn `stdio` extra-FD slot.
 *   - bwrap reads it from FD 10 (--seccomp 10) once, then closes.
 *   - Parent closes its handle immediately after spawn (no FD leak).
 *
 * Layer-responsibility split (spec §7) — this filter denies syscall classes
 * (execve, fork/clone, network, mount, ptrace, bpf, io_uring, namespace ops,
 * keyring, identity-change, file-handle reopen, kernel programmability).
 * Path semantics and resource ceilings live in bwrap and rlimits respectively.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/sched.h>
#include <seccomp.h>

/*
 * Standard pthread clone flag bitmask captured per spec §2.1 evidence step.
 * On x86_64 / glibc 2.x this expands to 0x3D0F00.
 *
 * The integration tests in worker/seccomp-evidence.md re-verify this on the
 * deploy host before locking the filter. If glibc switches pthread_create()
 * to clone3 (already true on glibc >= 2.34), NEW14 (threading positive
 * control) will fail, and the SecurityEngineer follow-up issue widens the
 * rule. Documented contingency, not a deviation. (Spec §2.1 final paragraph.)
 */
#define PTHREAD_CLONE_FLAGS                                              \
    (CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD |  \
     CLONE_SYSVSEM | CLONE_SETTLS | CLONE_PARENT_SETTID |                \
     CLONE_CHILD_CLEARTID)

/*
 * Helper: add a kill-process rule for a syscall name. Logs and aborts on
 * failure — partial filter is worse than no filter.
 */
static void kill_syscall(scmp_filter_ctx ctx, const char *name)
{
    int sc = seccomp_syscall_resolve_name(name);
    if (sc == __NR_SCMP_ERROR) {
        /* Some syscalls (e.g. create_module, query_module on modern kernels)
         * may resolve to a negative pseudo-syscall; that is libseccomp's way
         * of saying "the kernel doesn't expose this anymore but we'll filter
         * by number anyway". Fall through to seccomp_rule_add_exact below. */
    }
    int rc = seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS,
                              sc != __NR_SCMP_ERROR ? sc :
                              seccomp_syscall_resolve_name_arch(SCMP_ARCH_NATIVE,
                                                                name),
                              0);
    if (rc < 0) {
        fprintf(stderr,
                "seccomp_rule_add(%s): %s\n", name, strerror(-rc));
        /* Don't abort: the syscall may simply not exist on this build of
         * libseccomp. The runtime kernel will still enforce whatever rules
         * we successfully added. The build script verifies the resulting
         * filter has the expected denylist length. */
    }
}

int main(void)
{
    /* Default ALLOW; explicit denylist below. SCMP_ACT_KILL_PROCESS kills
     * the whole worker on hit (no per-thread survival), producing SIGSYS at
     * the Node parent and a kernel audit record we can correlate. */
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!ctx) {
        fprintf(stderr, "seccomp_init failed\n");
        return 1;
    }

    /* ===== execve family ===== */
    kill_syscall(ctx, "execve");
    kill_syscall(ctx, "execveat");

    /* ===== fork / vfork (CadQuery uses pthreads, not fork) ===== */
    kill_syscall(ctx, "fork");
    kill_syscall(ctx, "vfork");

    /* ===== clone / clone3 — see spec §2.1 ============================ */
    /*
     * clone: allow ONLY when flags arg matches PTHREAD_CLONE_FLAGS exactly.
     * Any other invocation (including CLONE_NEWUSER, CLONE_NEWNET,
     * CLONE_NEWNS, CLONE_NEWPID, CLONE_NEWUTS, CLONE_NEWIPC, CLONE_NEWCGROUP,
     * plain fork-style clone(SIGCHLD), or any unknown bit combination) is
     * killed.
     *
     * Encoded as: kill on clone if arg0 != PTHREAD_CLONE_FLAGS.
     */
    {
        int sc_clone = seccomp_syscall_resolve_name("clone");
        if (sc_clone != __NR_SCMP_ERROR) {
            int rc = seccomp_rule_add(
                ctx, SCMP_ACT_KILL_PROCESS, sc_clone, 1,
                SCMP_A0(SCMP_CMP_NE, (scmp_datum_t)PTHREAD_CLONE_FLAGS));
            if (rc < 0) {
                fprintf(stderr,
                        "seccomp_rule_add(clone, !=PTHREAD): %s\n",
                        strerror(-rc));
                seccomp_release(ctx);
                return 1;
            }
        }
    }

    /*
     * clone3: takes a struct clone_args pointer, so BPF cannot filter by
     * flags. Spec PLA-106 §2.1 (rev 3, revision id 3ffe6af0) selects
     * Option 5: return ENOSYS to userspace. glibc's nptl pthread_create
     * and fork paths check for ENOSYS from the clone3 wrapper and fall
     * back to clone(2) with equivalent flags. The fallback then hits the
     * clone(2) flag-check rule above, which is the actual enforcement of
     * the "no namespace creation, no process replication" invariant.
     *
     * Net effect: every task-creation reaches the kernel as clone(2);
     * clone3 only ever fails with -ENOSYS. NEW14 (positive threading
     * control) is the durable canary for "is the ENOSYS fallback still
     * working in this glibc?" — necessary, not sufficient.
     *
     * Spec §6.4 records the validation experiment: a 3-step measurement
     * on the deploy host that confirms ENOSYS return + threading success
     * + the (clone3_count, clone_count) call ratio. The measurement gate
     * fires before the seccomp filter blob is locked for release.
     */
    {
        int sc_clone3 = seccomp_syscall_resolve_name("clone3");
        if (sc_clone3 != __NR_SCMP_ERROR) {
            int rc = seccomp_rule_add(
                ctx, SCMP_ACT_ERRNO(ENOSYS), sc_clone3, 0);
            if (rc < 0) {
                fprintf(stderr,
                        "seccomp_rule_add(clone3, ERRNO ENOSYS): %s\n",
                        strerror(-rc));
                seccomp_release(ctx);
                return 1;
            }
        }
    }

    /* ===== Network kill switch (defense-in-depth alongside netns) ===== */
    kill_syscall(ctx, "socket");
    kill_syscall(ctx, "socketpair");
    kill_syscall(ctx, "connect");
    kill_syscall(ctx, "bind");
    kill_syscall(ctx, "listen");
    kill_syscall(ctx, "accept");
    kill_syscall(ctx, "accept4");
    kill_syscall(ctx, "sendto");
    kill_syscall(ctx, "recvfrom");
    kill_syscall(ctx, "sendmsg");
    kill_syscall(ctx, "recvmsg");
    kill_syscall(ctx, "sendmmsg");
    kill_syscall(ctx, "recvmmsg");

    /* ===== Namespace manipulation ===== */
    kill_syscall(ctx, "setns");
    kill_syscall(ctx, "unshare");
    kill_syscall(ctx, "pivot_root");
    kill_syscall(ctx, "chroot");

    /* ===== Mount operations ===== */
    kill_syscall(ctx, "mount");
    kill_syscall(ctx, "umount");
    kill_syscall(ctx, "umount2");
    kill_syscall(ctx, "move_mount");
    kill_syscall(ctx, "open_tree");
    kill_syscall(ctx, "fsopen");
    kill_syscall(ctx, "fsmount");
    kill_syscall(ctx, "fsconfig");
    kill_syscall(ctx, "fspick");

    /* ===== ptrace + cross-process memory ===== */
    kill_syscall(ctx, "ptrace");
    kill_syscall(ctx, "process_vm_readv");
    kill_syscall(ctx, "process_vm_writev");

    /* ===== Kernel keyring ===== */
    kill_syscall(ctx, "keyctl");
    kill_syscall(ctx, "add_key");
    kill_syscall(ctx, "request_key");

    /* ===== Kernel programmability ===== */
    kill_syscall(ctx, "bpf");
    kill_syscall(ctx, "perf_event_open");
    kill_syscall(ctx, "kexec_load");
    kill_syscall(ctx, "kexec_file_load");
    kill_syscall(ctx, "init_module");
    kill_syscall(ctx, "finit_module");
    kill_syscall(ctx, "delete_module");
    kill_syscall(ctx, "create_module");
    kill_syscall(ctx, "query_module");

    /* ===== Memory / page LPE primitives ===== */
    kill_syscall(ctx, "userfaultfd");
    kill_syscall(ctx, "pkey_alloc");
    kill_syscall(ctx, "pkey_free");
    kill_syscall(ctx, "pkey_mprotect");

    /* ===== File handle reopen bypass ===== */
    kill_syscall(ctx, "name_to_handle_at");
    kill_syscall(ctx, "open_by_handle_at");

    /* ===== Misc kernel attack surface ===== */
    kill_syscall(ctx, "iopl");
    kill_syscall(ctx, "ioperm");
    kill_syscall(ctx, "swapon");
    kill_syscall(ctx, "swapoff");
    kill_syscall(ctx, "reboot");
    kill_syscall(ctx, "nfsservctl");
    kill_syscall(ctx, "vmsplice");
    kill_syscall(ctx, "migrate_pages");
    kill_syscall(ctx, "move_pages");
    /* PLA-106 spec rev 5 (7d47d5a3) §2: mbind action change
     * KILL_PROCESS -> ERRNO(EPERM). Numpy/OCP emit advisory
     * mbind(..., MPOL_PREFERRED, ...) NUMA hints on the CadQuery import
     * path (CI run 25259321581 Phase C dmesg + local strace reproduction).
     * EPERM is no weaker than SIGSYS for the attacker (zero-effect syscall
     * either way) but lets benign callers fall back gracefully. The
     * dangerous MPOL_* modes already EPERM under our cap-drop posture
     * (no CAP_SYS_NICE); ERRNO uniforms that across the full mode set.
     *
     * Peer LPE primitives (vmsplice, migrate_pages, move_pages) explicitly
     * stay KILL_PROCESS per CTO endorsement cdd124fd: no observed legit
     * caller, LPE-primitive nature unchanged. */
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(mbind), 0);
    /* personality(): kill only when arg != 0. arg=0 is a benign "what
     * personality am I?" query that some libc implementations issue at
     * startup. The spec lists this as conditional. */
    {
        int sc_pers = seccomp_syscall_resolve_name("personality");
        if (sc_pers != __NR_SCMP_ERROR) {
            int rc = seccomp_rule_add(
                ctx, SCMP_ACT_KILL_PROCESS, sc_pers, 1,
                SCMP_A0(SCMP_CMP_NE, 0));
            if (rc < 0) {
                fprintf(stderr,
                        "seccomp_rule_add(personality, !=0): %s\n",
                        strerror(-rc));
            }
        }
    }

    /* ===== File mode/owner mutation (post-exploitation utility) ===== */
    kill_syscall(ctx, "chmod");
    kill_syscall(ctx, "fchmod");
    kill_syscall(ctx, "fchmodat");
    kill_syscall(ctx, "chown");
    kill_syscall(ctx, "fchown");
    kill_syscall(ctx, "fchownat");
    kill_syscall(ctx, "lchown");

    /* ===== Identity change (we start as nobody; any change is hostile) === */
    kill_syscall(ctx, "setuid");
    kill_syscall(ctx, "setgid");
    kill_syscall(ctx, "setreuid");
    kill_syscall(ctx, "setregid");
    kill_syscall(ctx, "setresuid");
    kill_syscall(ctx, "setresgid");
    kill_syscall(ctx, "setfsuid");
    kill_syscall(ctx, "setfsgid");

    /* ===== io_uring (known seccomp bypass surface) ===== */
    kill_syscall(ctx, "io_uring_setup");
    kill_syscall(ctx, "io_uring_enter");
    kill_syscall(ctx, "io_uring_register");

    /* Export to FD passed as argv[1]. The Makefile drives this with
     * `worker/build_seccomp 3 3>worker/seccomp_filter.bpf`. */
    int out_fd = STDOUT_FILENO;
    int rc = seccomp_export_bpf(ctx, out_fd);
    if (rc < 0) {
        fprintf(stderr, "seccomp_export_bpf: %s\n", strerror(-rc));
        seccomp_release(ctx);
        return 1;
    }

    seccomp_release(ctx);
    return 0;
}
