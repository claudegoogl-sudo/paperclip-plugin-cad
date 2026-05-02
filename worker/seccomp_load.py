"""
worker/seccomp_load.py — PLA-114 / PLA-106 §1 (rev 4)

Python-side seccomp filter installer. Replaces bubblewrap's `--seccomp <fd>`
mechanism, which is incompatible with a filter that denylists `execve` /
`execveat` (the launcher's own exec into the target gets killed before any
target code runs).

Why python-side:
    bubblewrap's `--seccomp` does prctl(PR_SET_SECCOMP, ...) between fork()
    and execve(). Seccomp filters are inherited across execve by design and
    apply to the calling thread immediately — including the very execve
    that follows the prctl. With execve in the kill list, no target ever
    runs. The canonical pattern (Chromium renderer, Firefox content
    process, Google sandbox2, gVisor's launcher) is to install the filter
    from inside the target process *after* trusted bootstrap completes,
    which is what this module does.

Usage:
    The bootstrap (passed via `python -c "..."` on the bwrap command line)
    runs exactly:

        import sys; sys.path.insert(0, '/sandbox')
        from seccomp_load import lock_down
        lock_down('/sandbox/seccomp_filter.bpf')
        import cad_worker; cad_worker.main()

    `lock_down(blob_path)` is the **last** statement before any
    user-influenced import or eval. The contract is: no untrusted code
    reaches the import system before lock_down returns.

Filter blob format:
    libseccomp's `seccomp_export_bpf()` writes a flat sequence of
    `struct sock_filter` entries (8 bytes each on Linux: u16 code, u8 jt,
    u8 jf, u32 k). We mmap the blob, build a `struct sock_fprog`
    { len: number-of-entries, filter: pointer-to-mmap }, and hand it to
    prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &fprog).

Failure modes:
    Any failure (open, mmap, prctl) raises SeccompLoadError with the
    underlying errno string. The Node parent treats a non-zero exit before
    any stdout output as worker_internal. The caller MUST NOT proceed to
    user code if lock_down() raises.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import errno
import os
from ctypes import c_char_p, c_int, c_size_t, c_uint32, c_ulong, c_ushort, c_void_p

# Linux prctl options (linux/prctl.h)
_PR_SET_NO_NEW_PRIVS = 38
_PR_SET_SECCOMP = 22

# Linux seccomp modes (linux/seccomp.h)
_SECCOMP_MODE_FILTER = 2

# struct sock_filter (linux/filter.h):
#   u16 code; u8 jt; u8 jf; u32 k;
_SOCK_FILTER_SIZE = 8


class SeccompLoadError(RuntimeError):
    """Raised when seccomp filter installation fails. Worker MUST NOT proceed."""


class _SockFprog(ctypes.Structure):
    """struct sock_fprog from linux/filter.h."""

    _fields_ = (
        ("len", c_ushort),
        ("filter", c_void_p),
    )


def _libc() -> ctypes.CDLL:
    name = ctypes.util.find_library("c") or "libc.so.6"
    return ctypes.CDLL(name, use_errno=True)


def lock_down(blob_path: str) -> None:
    """
    Install the seccomp BPF filter at `blob_path` on the current thread.

    Sequence (each step fails closed):
      1. prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) — required before
         PR_SET_SECCOMP on an unprivileged process.
      2. open + read the blob into a heap buffer (avoids mmap lifetime
         confusion across the prctl call).
      3. Build sock_fprog { len, filter -> &buffer[0] }.
      4. prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &fprog, 0, 0).

    On success, returns None and the filter is in force. Any subsequent
    syscall on the denylist kills the calling process with SIGSYS.
    """
    libc = _libc()
    prctl = libc.prctl
    prctl.argtypes = (c_int, c_ulong, c_ulong, c_ulong, c_ulong)
    prctl.restype = c_int

    # (1) PR_SET_NO_NEW_PRIVS — required for unprivileged seccomp install.
    rc = prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
    if rc != 0:
        e = ctypes.get_errno()
        raise SeccompLoadError(
            f"prctl(PR_SET_NO_NEW_PRIVS, 1) failed: {os.strerror(e)} (errno={e})"
        )

    # (2) Read the entire blob. The kernel copies it during PR_SET_SECCOMP,
    # so a heap buffer is sufficient — no mmap needed.
    try:
        with open(blob_path, "rb") as f:
            blob = f.read()
    except OSError as exc:
        raise SeccompLoadError(
            f"failed to read seccomp filter blob {blob_path!r}: {exc}"
        ) from exc

    if not blob:
        raise SeccompLoadError(
            f"seccomp filter blob {blob_path!r} is empty"
        )
    if len(blob) % _SOCK_FILTER_SIZE != 0:
        raise SeccompLoadError(
            f"seccomp filter blob {blob_path!r} size {len(blob)} is not a "
            f"multiple of sock_filter size ({_SOCK_FILTER_SIZE})"
        )
    nfilters = len(blob) // _SOCK_FILTER_SIZE
    # BPF programs have a hard kernel limit of BPF_MAXINSNS = 4096.
    if nfilters == 0 or nfilters > 4096:
        raise SeccompLoadError(
            f"seccomp filter blob {blob_path!r} has {nfilters} entries "
            f"(must be 1..4096)"
        )

    buf = (ctypes.c_ubyte * len(blob)).from_buffer_copy(blob)
    fprog = _SockFprog(
        len=c_ushort(nfilters),
        filter=ctypes.cast(buf, c_void_p),
    )

    # (3+4) PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &fprog
    rc = prctl(
        _PR_SET_SECCOMP,
        _SECCOMP_MODE_FILTER,
        ctypes.cast(ctypes.byref(fprog), c_void_p).value or 0,
        0,
        0,
    )
    if rc != 0:
        e = ctypes.get_errno()
        # Common errno values worth surfacing literally:
        #   EACCES  — NO_NEW_PRIVS not set (shouldn't happen, see step 1)
        #   EFAULT  — bad pointer (programming error in this shim)
        #   EINVAL  — malformed BPF or unsupported mode
        raise SeccompLoadError(
            f"prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER) failed: "
            f"{os.strerror(e)} (errno={e})"
        )

    # Keep a reference so the buffer outlives this stack frame for the
    # remainder of the process. The kernel has copied the program, so this
    # is paranoia, but BPF program lifetime around prctl is famously subtle
    # on some kernels and a stray free can never be debugged from python.
    global _RETAINED_BUFFER  # noqa: PLW0603
    _RETAINED_BUFFER = buf

    # Suppress unused-import lint for c_char_p / c_size_t / c_uint32 / errno.
    # They're kept for readers who copy this shim into adjacent contexts.
    _ = (c_char_p, c_size_t, c_uint32, errno)


_RETAINED_BUFFER: object | None = None


__all__ = ("SeccompLoadError", "lock_down")
