#!/usr/bin/env python3
"""
CadQuery worker subprocess — PLA-54.

Reads ONE JSON job from stdin, executes the CadQuery script in an isolated
environment, writes ONE JSON result to stdout, then exits.

Process model choice (PLA-54 design):
  stdin/stdout pipe (variant of option (a): named pipe / length-prefixed protocol).
  - Job delivered as a single JSON document on stdin; result on stdout.
  - No TCP listener; no Unix socket file; satisfies AC2 trivially.
  - No port allocation surface at all.
  - Simpler than length-prefixed framing because stdin EOF signals end-of-input.

Job schema (stdin, single JSON document):
    {
        "script":  "<python source string>",
        "format":  "step" | "stl",
        "workdir": "<absolute tmpdir path for this invocation>"
    }

Result schema (stdout, single JSON line):
    Success:
        { "ok": true, "artifactPath": "<absolute path to exported file>" }
    Error:
        { "ok": false, "error": "<error_code>", "message": "<detail>" }

Error codes:
    "script_error"     — user script raised an exception or did not set `result`
    "worker_internal"  — export or I/O failure inside the worker itself
    "worker_oom"       — script consumed too much memory (MemoryError)

Timeout (AC3):
    Enforced by the Node.js parent process via SIGKILL after (timeout + 5s).
    The worker does NOT install its own timer; clean kill + process reap is the
    responsibility of the parent (cad-worker-client.ts).

Network restriction (AC6 — library-restriction-based approach):
    Before exec()ing user code, socket / urllib / http.client (and related
    modules) are replaced with _NetworkBlockedModule stubs that raise OSError
    on any attribute access or call.  This prevents accidental or deliberate
    outbound HTTP/DNS from within the script.

    Rationale for library-restriction over namespace-based (unshare/seccomp):
      - Works portably without root or Linux-capability requirements.
      - Sufficient for the stated threat model (agent-authored scripts that
        should not make network calls, not a hostile adversary bypassing the
        Python interpreter).
      - Acceptable per PLA-54 scope ("call the choice in the design comment").

Dependency pinning (AC5):
    CadQuery and its transitive dependencies are pinned via
    worker/requirements-cad.txt in this repository.
    Key pins (from pip freeze on the deployment host):
        cadquery==2.7.0
        cadquery-ocp==7.8.1.1.post1
    Full exact pin list lives in worker/requirements-cad.txt.
"""

import builtins as _builtins
import json
import os
import sys
import tempfile
import traceback
from types import ModuleType
from typing import Any

# Capture the real __import__ and the real `os` module at module-load time,
# before any restrictions or proxy swaps.  These references back the
# _restricted_import / _RestrictedOs implementations and the worker's own
# os.* operations (chdir / path.join / path.realpath / etc.).
#
# IMPORTANT: these references persist as cad_worker module globals; any code
# path that can reach `sys.modules['__main__']._REAL_IMPORT` /
# `sys.modules['__main__']._REAL_OS` would defeat the proxy.  Closing the
# in-process Python escape surface for that gadget requires OS-level isolation
# (Option B); see PLA-73 strategic note (2026-05-01).  This is a documented
# residual risk in the Option A threat model.
_REAL_IMPORT = _builtins.__import__
_REAL_OS = os

# Capture real compile / exec at module load.  These are used by the worker
# to compile + run the user script once.  Captured here (rather than relying
# on lookup at call time) for defensive reasons — if a future iteration of
# _harden_builtins() reintroduces deniers on builtins.compile / builtins.exec,
# the worker's own compile/exec call must still succeed.  The user's exec
# namespace pops these names from its `__builtins__` dict so they remain
# unreachable to user code.
_REAL_COMPILE = _builtins.compile
_REAL_EXEC = _builtins.exec

# ---------------------------------------------------------------------------
# Network restriction — library-restriction-based (PLA-54 AC6)
# ---------------------------------------------------------------------------

_BLOCKED_MODULES: list[str] = [
    # ---- Network primitive root (primary enforcement layer) ----
    #
    # Blocking `socket` is the single most effective control: every Python
    # network client (urllib.request, http.client, requests, httpx, aiohttp,
    # ftplib, smtplib, …) ultimately calls socket.create_connection() or
    # socket.socket().  Blocking this single module cuts off all outbound
    # TCP/UDP without needing to enumerate higher-level packages.
    #
    # NOTE: We do NOT block urllib.parse / urllib.robotparser / http.cookies /
    # http.cookiejar because those are URL-string utilities used by pathlib,
    # importlib.metadata, and other stdlib internals — they make no network
    # calls.  Only blocking socket is needed.
    "socket",          # root of all TCP/UDP access
    "ssl",             # TLS layer over socket
    "_ssl",            # C extension backing ssl

    # ---- Belt-and-suspenders: block the primary HTTP request modules ----
    # These are only blocked here as a second layer; socket blocking alone
    # is sufficient.  They are replaced AFTER CadQuery is imported (so
    # stdlib stdlib internals that import these during CadQuery init can do
    # so freely — CadQuery does not make network calls during import).
    # Note: pre-installing these in sys.modules before the user script runs
    # means `import requests` or `import httpx` will return our stub, but
    # `import urllib.request` followed by `urllib.request.urlopen(...)` is
    # handled by socket blocking (see below — socket is the root guard).
    "http.client",     # raw HTTP/HTTPS over TCP
    "http.server",     # TCP server
    "ftplib",          # FTP client
    "smtplib",         # SMTP client
    "imaplib",         # IMAP client
    "poplib",          # POP3 client
    "telnetlib",       # Telnet client
    "xmlrpc.client",   # XML-RPC HTTP client
    "xmlrpc.server",   # XML-RPC TCP server
    "requests",        # third-party HTTP library
    "httpx",           # third-party async HTTP client
    "aiohttp",         # third-party async HTTP client

    # ---- Process / OS escape vectors (PLA-76 CRITICAL-1, CRITICAL-2, HIGH-1) ----
    "subprocess",           # CRITICAL-1: arbitrary command execution
    "ctypes",               # CRITICAL-2: native library / raw syscall access
    "ctypes.util",          # CRITICAL-2: ctypes helper
    "importlib",            # HIGH-1: dynamic module loading bypass
    "importlib.util",       # HIGH-1
    "importlib.machinery",  # HIGH-1
    "multiprocessing",      # process spawning (belt-and-suspenders with subprocess)
    "threading",            # long-running thread escape from sandbox lifetime

    # ---- Platform OS modules (PLA-75 R4) ----
    # The C-level OS modules backing `os`.  `os` re-exports `system`, `popen`,
    # `exec*`, `fork`, etc. from these modules.  Once `os` is loaded the
    # bindings inside the `os` module's namespace are sufficient — no other
    # code needs fresh access.  Blocking these here means user-script
    # `import posix; posix.system(...)` is rejected by `_restricted_import`.
    # _harden_post_init_imports() additionally pops them from sys.modules and
    # adds them to _META_PATH_BLOCKED, so dict-read and re-import bypasses
    # are also closed.
    "posix",                # Linux / POSIX C extension exposing system/exec*/fork
    "nt",                   # Windows equivalent
    "_posixsubprocess",     # exposes fork_exec directly
    "pty",                  # Pseudo-terminal: leaks fork() via openpty/fork
]

# Modules that are blocked AFTER CadQuery init (rather than before), via
# _harden_post_init_imports().  These are needed by Python / CadQuery during
# their own startup, so we let them load through the normal import system,
# then revoke access right before user code runs.
_PLATFORM_OS_MODULES: tuple = ("posix", "nt", "_posixsubprocess", "pty")

# Frozenset for O(1) lookup in _restricted_import and _BlockingMetaPathFinder.
_BLOCKED_MODULES_SET: frozenset[str] = frozenset(_BLOCKED_MODULES)

# Subset that is safe to replace with stubs in sys.modules without breaking
# Python or CadQuery internals.
#
# ctypes / ctypes.util are EXCLUDED: CadQuery loads OpenCASCADE C extensions via
# ctypes.  Replacing sys.modules['ctypes'] before exec() would hand CadQuery a
# stub instead of the real ctypes, breaking shape creation and export.
# _restricted_import (exec-namespace only) still blocks user-script `import ctypes`.
#
# importlib.* are EXCLUDED: CadQuery's __init__.py does
# `from importlib.metadata import version` on first import, and transitively
# pulls in importlib.abc / importlib.resources.  Stubbing any of these breaks the
# import chain.  User-script imports are still blocked by _restricted_import.
#
# threading is EXCLUDED: Python's runtime needs sys.modules['threading'] for
# __del__ / atexit cleanup.  User-script imports are blocked by _restricted_import.
#
# _PLATFORM_OS_MODULES (posix/nt/_posixsubprocess/pty) are EXCLUDED: they are
# already loaded at Python startup and the `os` module re-exports the bindings
# it needs from them; CadQuery / OpenCASCADE may also lazily reach posix
# during their own init.  _harden_post_init_imports() pops + meta-path-blocks
# them after CadQuery is fully imported (PLA-75 R4).
_SYS_MODULES_STUBS: list[str] = [
    m for m in _BLOCKED_MODULES
    if not (
        m == "threading"
        or m.startswith(("ctypes", "importlib"))
        or m in _PLATFORM_OS_MODULES
    )
]

# Modules safe to intercept globally via sys.meta_path.
# Meta-path hooks fire for ALL imports (including CadQuery internals), so during
# CadQuery's transitive import we must NOT block anything CadQuery needs:
#   ctypes / ctypes.*  — OCC loads C extensions via ctypes
#   importlib.*        — CadQuery uses importlib.metadata, .abc, .resources
#
# After CadQuery has been pre-imported in _run_script (PLA-75 R2), we expand the
# block list to include ctypes/_ctypes via _harden_post_init_imports().  The set
# is mutable for that reason — _BlockingMetaPathFinder reads the live set on
# every find_spec call, so additions take effect for subsequent imports.
_META_PATH_BLOCKED: set[str] = set(
    m for m in _BLOCKED_MODULES
    if not (
        m.startswith(("ctypes", "importlib"))
        or m in _PLATFORM_OS_MODULES
    )
)


class _NetworkBlockedModule(ModuleType):
    """
    Replacement for a blocked network module.

    Any attribute access raises OSError so that code such as::

        import socket
        socket.create_connection(...)

    or::

        from urllib.request import urlopen

    raises before any network activity can begin.
    """

    def __init__(self, name: str) -> None:
        super().__init__(name)
        object.__setattr__(self, "__blocked__", True)

    def __getattr__(self, attr: str) -> Any:
        raise OSError(
            f"[cad-worker] Network access blocked: "
            f"'{object.__getattribute__(self, '__name__')}.{attr}' "
            f"is not available inside the CadQuery sandbox. "
            f"Scripts must not make outbound network calls."
        )

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        raise OSError(
            "[cad-worker] Network access blocked: "
            "this module is not available inside the CadQuery sandbox."
        )


def _install_network_block() -> None:
    """
    Replace all blocked modules in sys.modules with stubs.

    Called once, immediately before exec()ing user code.
    Already-imported native extension modules (e.g. _ssl) are replaced too
    so that code that cached a reference to the real module at import time
    cannot bypass the block via that reference — they would need to have
    imported the module before this function ran, which we prevent by calling
    this before exec().
    """
    for mod_name in _SYS_MODULES_STUBS:
        sys.modules[mod_name] = _NetworkBlockedModule(mod_name)


# ---------------------------------------------------------------------------
# Restricted `os` proxy (PLA-75 R1 — block os.system / os.exec* / os.fork RCE)
# ---------------------------------------------------------------------------

# Attributes of `os` that grant process / shell / privilege escalation surface.
# Access from inside the user script raises PermissionError.
#
# CadQuery does not call any of these from its internals; it uses os.path.*,
# os.sep, os.getcwd, os.environ (read), os.fspath, etc. — all of which are
# allowed and delegated to the real os module via the proxy's __getattr__.
#
# The proxy is ONLY visible to the user-script exec namespace (returned by
# _restricted_import for `import os` / `from os import …`).  The worker itself
# and CadQuery's internals continue to use the real `os` module (imported via
# Python's normal __import__, which is not replaced at the process level).
_OS_BLOCKED_ATTRS: frozenset[str] = frozenset({
    # Shell / arbitrary command execution
    "system", "popen",
    # exec* family (replace current process image)
    "execl", "execle", "execlp", "execlpe",
    "execv", "execve", "execvp", "execvpe",
    "_exit",
    # spawn* / posix_spawn family
    "spawnl", "spawnle", "spawnlp", "spawnlpe",
    "spawnv", "spawnve", "spawnvp", "spawnvpe",
    "posix_spawn", "posix_spawnp",
    # fork / pty
    "fork", "forkpty", "pipe", "pipe2",
    # signals to other processes
    "kill", "killpg",
    # privilege manipulation
    "setuid", "setgid", "seteuid", "setegid", "setreuid", "setregid",
    "setresuid", "setresgid", "setgroups", "initgroups",
    # filesystem mutation outside _restricted_open's purview
    "chmod", "fchmod", "lchmod",
    "chown", "fchown", "lchown",
    "unlink", "remove", "removedirs", "rmdir",
    "rename", "renames", "replace",
    "symlink", "link",
    "mkfifo", "mknod",
    "truncate",
    # environment mutation (env vars are inherited by any future subprocess)
    "putenv", "unsetenv",
    # raw fd / device ops
    "open", "openpty", "device_encoding",
    "dup", "dup2", "close", "closerange",
    "ftruncate", "fchdir",
    "chroot",
    # process group / session manipulation
    "setpgid", "setpgrp", "setsid",
})


class _RestrictedOs(ModuleType):
    """
    Proxy for the real `os` module visible to user scripts.

    Reads of non-blocked names delegate to the real `os` module via the
    module-level ``_REAL_OS`` reference (captured at module load).  Reads of
    blocked names raise PermissionError so the offending line raises BEFORE
    any side effect.

    PLA-75 R5/R6 — the real os reference is NOT stored on the proxy instance.
    A previous implementation used ``object.__setattr__(self, "_real_os", os)``,
    which placed the real module in the proxy's ``__dict__`` and was reachable
    via ``os._real_os`` (bypasses __getattr__) and ``vars(os)['_real_os']``.
    The current design keeps the reference in module-level ``_REAL_OS`` and
    routes attribute access through the class's __getattr__, so neither
    direct attribute access nor dict introspection of the proxy can leak the
    real module.

    Why a proxy and not a sys.modules swap: kept for symmetry with the original
    design, but PLA-75 R3 additionally swaps ``sys.modules['os']`` to point at
    this same proxy (see _harden_post_init_imports).  The worker's own
    ``import os`` global is captured at module load (``_REAL_OS``) and is not
    affected by the swap.
    """

    __slots__ = ()

    def __init__(self) -> None:
        super().__init__("os")
        # NOTE: deliberately no instance attributes.  See class docstring (R5/R6).

    def __getattr__(self, attr: str) -> Any:
        if attr in _OS_BLOCKED_ATTRS:
            raise PermissionError(
                f"[cad-worker] os.{attr} is not allowed inside the CadQuery "
                f"sandbox (blocks shell/process escape — PLA-75 R1)."
            )
        # Fall through to the real os module via the module-level reference.
        # AttributeError from getattr is propagated naturally (e.g. os._real_os
        # raises AttributeError post-fix, which is the regression-test signal).
        return getattr(_REAL_OS, attr)

    def __setattr__(self, attr: str, value: Any) -> None:
        # Prevent user scripts from rebinding os.system etc. on the proxy and
        # from re-introducing a leaked _real_os attribute.
        raise PermissionError(
            f"[cad-worker] Cannot mutate os.{attr} inside the CadQuery sandbox."
        )

    def __delattr__(self, attr: str) -> None:
        raise PermissionError(
            f"[cad-worker] Cannot delete os.{attr} inside the CadQuery sandbox."
        )


# Singleton — built lazily once the module finishes loading the real os.
_RESTRICTED_OS: _RestrictedOs = _RestrictedOs()


# ---------------------------------------------------------------------------
# Restricted import / open helpers (PLA-76 CRITICAL-3, HIGH-1, HIGH-2;
#                                    PLA-75 R1 os proxy routing)
# ---------------------------------------------------------------------------

def _restricted_import(
    name: str,
    globals: Any = None,  # noqa: A002
    locals: Any = None,   # noqa: A002
    fromlist: tuple = (),
    level: int = 0,
) -> Any:
    """
    Drop-in replacement for ``__import__`` injected into the exec namespace.

    Raises ImportError for any module in _BLOCKED_MODULES_SET, including
    sub-module paths whose root is blocked (e.g. "ctypes.util" -> "ctypes").

    For `os` (PLA-75 R1) the user-visible binding is the _RESTRICTED_OS proxy,
    which transparently delegates safe attributes to the real os module while
    raising PermissionError for shell/process/privilege escalation surface.
    `from os.path import X` (where the requested module IS os.path) returns
    the real os.path because os.path is a safe-attribute namespace.

    Falls through to the real ``__import__`` for everything else.
    """
    top = name.split(".")[0]
    if name in _BLOCKED_MODULES_SET or top in _BLOCKED_MODULES_SET:
        raise ImportError(
            f"[cad-worker] Import blocked: '{name}' is not allowed "
            f"inside the CadQuery sandbox."
        )

    if top == "os":
        # `from os.path import X`  → caller wants the real os.path submodule
        # (Python returns the leaf module when fromlist is non-empty).  os.path
        # is safe (no shell/process surface) and forcing the proxy here would
        # break `from os.path import join, dirname, …`.
        if name == "os.path" and fromlist:
            return _REAL_IMPORT(name, globals, locals, fromlist, level)
        # All other `import os` / `import os.path` / `from os import X` paths
        # resolve through the proxy.  When fromlist is non-empty (e.g.
        # `from os import path, sep, getcwd`) the import statement does
        # getattr(returned_module, name) for each fromlist entry — the proxy's
        # __getattr__ raises for blocked names and delegates for safe ones.
        return _RESTRICTED_OS

    return _REAL_IMPORT(name, globals, locals, fromlist, level)


def _restricted_open(workdir: str):
    """
    Return a restricted ``open`` callable that only permits access inside
    *workdir*.  Resolves symlinks before comparing paths.

    File-descriptor integers are passed through unchanged (needed by Python
    internals).  Paths outside the sandbox raise PermissionError.
    """
    _real_open = _builtins.open
    _realpath_workdir = os.path.realpath(workdir)

    def _open(file: Any, *args: Any, **kwargs: Any) -> Any:
        if not isinstance(file, int):
            realpath = os.path.realpath(str(file))
            inside = (
                realpath == _realpath_workdir
                or realpath.startswith(_realpath_workdir + os.sep)
            )
            if not inside:
                raise PermissionError(
                    f"[cad-worker] File access blocked: '{file}' resolves to "
                    f"'{realpath}' which is outside the sandbox workdir "
                    f"'{_realpath_workdir}'."
                )
        return _real_open(file, *args, **kwargs)

    return _open


# ---------------------------------------------------------------------------
# sys.meta_path blocker (PLA-76 CRITICAL-3 — del sys.modules bypass)
# ---------------------------------------------------------------------------

class _BlockingMetaPathFinder:
    """
    sys.meta_path hook installed before exec() to intercept find_spec calls.

    Raises ImportError for any blocked module even if the caller has
    deleted the sys.modules stub and is using the real ``__import__``
    (e.g. via ``builtins.__import__``).  This closes the
    ``del sys.modules[name]; import name`` reimport bypass (CRITICAL-3).
    """

    def find_spec(self, fullname: str, path: Any, target: Any = None) -> None:  # type: ignore[return]
        # Uses _META_PATH_BLOCKED (not the full _BLOCKED_MODULES_SET) because
        # meta_path hooks fire for ALL imports in the process — including CadQuery
        # internals that legitimately need ctypes / importlib.* during cq init.
        # _harden_post_init_imports() expands this set with ctypes/_ctypes after
        # CadQuery has finished its transitive imports, so user-script bypasses
        # via __import__ also fail (PLA-75 R2).
        if fullname in _META_PATH_BLOCKED:
            raise ImportError(
                f"[cad-worker] Import blocked: '{fullname}' is not allowed "
                f"inside the CadQuery sandbox."
            )
        return None  # not handled here; let other finders proceed


def _install_meta_path_blocker() -> None:
    """Insert _BlockingMetaPathFinder at the front of sys.meta_path (idempotent)."""
    if not any(isinstance(f, _BlockingMetaPathFinder) for f in sys.meta_path):
        sys.meta_path.insert(0, _BlockingMetaPathFinder())


def _harden_post_init_imports() -> None:
    """
    Lock down ctypes / posix / nt / _posixsubprocess / pty + redirect
    sys.modules['os'] to the proxy after CadQuery's transitive imports resolve.

    CadQuery's OpenCASCADE bindings load via ctypes during cq init.  Once
    init is done, cq.* references hold direct callable bindings to the
    loaded C functions — they do NOT re-look-up via sys.modules['ctypes'],
    so popping ctypes here is safe for subsequent CadQuery operations.  The
    same holds for posix / nt / _posixsubprocess / pty: `os` re-exports
    `system`/`popen`/`exec*`/`fork`/etc. into its own namespace at import
    time, so popping the C-level OS modules afterwards does not break the
    proxy's delegation path.

    Three layers, all required to fully close the bypass classes:

      1. Pop the cached modules from sys.modules (closes direct dict-read,
         e.g. `sys.modules['ctypes'].CDLL(…)` and `sys.modules['posix'].system(…)`).

      2. Replace `sys.modules['os']` with the _RestrictedOs proxy
         (PLA-75 R3 — closes `sys.modules['os'].system(…)`).  The worker's own
         `os` global (captured at module load as _REAL_OS) is unaffected.

      3. Add the popped names to _META_PATH_BLOCKED so any re-import attempt
         (via the real __import__, importlib machinery, or any other code
         path that goes through the import system) is intercepted by
         _BlockingMetaPathFinder and raises ImportError.  Closes the
         "pop and re-import" follow-up bypass.

    Residual risks (tracked, not blocked by this round):
      RR1: `sys.meta_path.clear()` from user code disables the blocker.
      RR2: Any unblocked C extension exposing dlopen-equivalent behavior.
      RR3: cad_worker module globals (_REAL_IMPORT, _REAL_OS) are reachable
           via `sys.modules['__main__'].__dict__` / frame walking.  Closing
           this requires either a refactor that puts these references in
           closures OR OS-level isolation (Option B, see PLA-73 strategic
           note).
    """
    # Layer 1 — direct dict access: drop the cached ctypes / platform-os
    # modules so sys.modules['<name>'] raises KeyError on read.
    _post_init_pops = ("ctypes", "ctypes.util", "_ctypes", *_PLATFORM_OS_MODULES)
    for _name in _post_init_pops:
        sys.modules.pop(_name, None)

    # PLA-75 R3 — `sys.modules['os'].system(…)` bypass.  Replace the cached
    # real `os` module in sys.modules with the proxy.  The worker's
    # internal references (the module-level `os` import, captured as
    # _REAL_OS) are untouched; CadQuery / OCP / tempfile / json / traceback
    # all captured `os` at their own module load and are similarly unaffected.
    sys.modules["os"] = _RESTRICTED_OS

    # Layer 2 — re-import path: extend the meta-path block list to cover
    # ctypes (PLA-75 R2) and the C-level OS modules (PLA-75 R4).
    _META_PATH_BLOCKED.update({
        "ctypes", "ctypes.util", "_ctypes",
        *_PLATFORM_OS_MODULES,
    })


def _harden_builtins() -> None:
    """
    PLA-75 R7 — patch the real `builtins` module to neutralise the
    "__builtins__ leak" attack surface.

    Background.  Every pre-imported Python module has its `__builtins__`
    attribute pointing at the real `builtins` module.  A user script can
    therefore reach the real `__import__`, `eval`, `exec`, `compile`, etc.
    via any other module:

        import sys
        real_imp = sys.modules['cadquery'].__builtins__.__import__
        real_imp('os').system(...)            # → real os, real shell

        json.__builtins__.eval(
            "__import__('os').system(...)",
            {},                                # auto-injects real builtins
        )

    The exec-namespace `__builtins__` dict (set up by `_run_script`) does NOT
    block these paths because they go through the *real* builtins module, not
    the user-frame's restricted dict.

    Defence.  Replace `_builtins.__import__` with `_restricted_import` so
    that EVERY path to the real `__import__` (cross-module __builtins__,
    eval-with-empty-globals, frame-walking, …) enforces the same blocklist
    + os proxy logic.  After this patch:

      - `eval(code, {})` auto-injects real builtins; the `__import__` lookup
        inside the compiled bytecode resolves to `_restricted_import`, so
        `__import__('os')` returns the `_RestrictedOs` proxy.
      - `exec("...", explicit_globals)` similarly uses `_restricted_import`
        whether or not the caller supplies a `__builtins__` key.
      - `sys.modules['<any module>'].__builtins__.__import__('os')` → proxy.

    eval / exec / compile / breakpoint / input themselves are LEFT IN PLACE
    on the real builtins module because:

      - CadQuery's `multimethod` dependency calls `typing.get_type_hints()`
        which calls `compile()` on forward-reference strings during
        operations like `cq.Workplane('XY').box(...)`; replacing compile
        breaks all CadQuery geometry.
      - `eval` / `exec` are reached lazily by various stdlib code paths
        (typing, dataclasses, …).
      - With `__import__` restricted, eval/exec/compile cannot reach the
        real `os` module, so they no longer enable shell escape — they
        only enable arbitrary in-sandbox Python (which the user already has
        via the exec'd script).

    Ordering.  Must run AFTER CadQuery's transitive imports complete (so
    `import` statements during cq init use the real, unrestricted import
    machinery) and BEFORE the user script is exec()'d.

    Residual risks (still open):

      - sys.meta_path.clear() (RR1) — independent of builtins.
      - cad_worker module globals (_REAL_IMPORT, _REAL_OS, _REAL_COMPILE,
        _REAL_EXEC) are reachable via `sys.modules['__main__'].__dict__` /
        frame walking.  Closing this requires either a closure refactor or
        OS-level isolation (Option B, see PLA-73 strategic note).
      - R8 (subclass-walk gadget) — out of scope for this round per the
        SecurityEngineer's review.
    """
    # Replace the real __import__ so any code path that reaches it (via
    # real builtins module, via sys.modules['cadquery'].__builtins__, via
    # `eval(code, {})`, etc.) goes through the same blocklist + os proxy
    # logic the user-frame's _restricted_builtins already uses.
    _builtins.__import__ = _restricted_import


# ---------------------------------------------------------------------------
# Script execution
# ---------------------------------------------------------------------------

def _run_script(script: str, fmt: str, workdir: str) -> dict:
    """
    Execute a CadQuery script and export the result to *workdir*.

    The user script must assign a CadQuery object to the name ``result``.
    The worker exports it to ``<workdir>/artifact.<fmt>``.

    Returns a dict suitable for JSON serialisation (see module docstring).
    """
    # Change into the isolated working directory for this invocation.
    # (Parent creates a fresh mkdtemp; nothing from prior invocations is here.)
    try:
        os.chdir(workdir)
    except OSError as exc:
        return {
            "ok": False,
            "error": "worker_internal",
            "message": f"Could not chdir to workdir {workdir!r}: {exc}",
        }

    # Set virtual-address-space ceiling before user code runs (PLA-76 MEDIUM-1).
    # Note: RLIMIT_AS caps total virtual memory of this process.  CadQuery with
    # OpenCASCADE can map significant virtual address space; if this limit is too
    # tight for a given deployment, raise it here.
    try:
        import resource  # noqa: PLC0415
        _MEM_LIMIT = 2 * 1024 ** 3  # 2 GiB virtual address space
        resource.setrlimit(resource.RLIMIT_AS, (_MEM_LIMIT, _MEM_LIMIT))
    except Exception:  # noqa: BLE001
        pass  # RLIMIT_AS not available on this platform (e.g. macOS)

    # PLA-75 R2: pre-import CadQuery here, BEFORE installing the meta-path
    # blocker and network stubs.  This lets cq's transitive imports of ctypes
    # / importlib.metadata / _ctypes resolve through the normal import system.
    # Once cq is loaded, _harden_post_init_imports() drops the cached ctypes
    # modules and adds them to the meta-path block list, closing the
    # `sys.modules['ctypes']` direct-dict-read bypass identified in PLA-75.
    try:
        import cadquery as cq  # noqa: PLC0415
    except Exception:  # noqa: BLE001
        return {
            "ok": False,
            "error": "worker_internal",
            "message": (
                "CadQuery import failed during sandbox init:\n"
                + traceback.format_exc()
            ),
        }

    # PLA-75 R2: harden ctypes (pop sys.modules + extend meta-path block).
    # MUST run AFTER CadQuery is imported (so cq's bindings are resolved) and
    # BEFORE the meta-path blocker is installed (so the new entries are honored).
    _harden_post_init_imports()

    # Install meta_path blocker BEFORE network block so all subsequent import
    # attempts (including bypass via real __import__) are intercepted.
    _install_meta_path_blocker()

    # Install module stubs in sys.modules (network + process-escape modules).
    _install_network_block()

    # PLA-75 R7: patch the real `builtins` module so cross-module __builtins__
    # access cannot reach the unrestricted `__import__` / `eval` / `exec` /
    # `compile` / `breakpoint` / `input`.  MUST run AFTER CadQuery init (so
    # cq's init can use the real eval/compile if it needs them) and AFTER
    # _install_network_block / _install_meta_path_blocker (so any builtin
    # invocation that triggers an import sees the restricted state).
    _harden_builtins()

    # Build restricted __builtins__ for the exec namespace (PLA-76 CRITICAL-3).
    # Removes eval/exec/compile/breakpoint/input, replaces __import__ with
    # _restricted_import (enforces _BLOCKED_MODULES_SET) and open with
    # _restricted_open (enforces workdir confinement).
    _restricted_builtins: dict = dict(vars(_builtins))
    for _dangerous_name in ("eval", "exec", "compile", "breakpoint", "input"):
        _restricted_builtins.pop(_dangerous_name, None)
    _restricted_builtins["__import__"] = _restricted_import
    _restricted_builtins["open"] = _restricted_open(os.path.realpath(workdir))

    # Execute the user script in a namespace with restricted builtins.
    # Use the module-level _REAL_COMPILE / _REAL_EXEC captured at module
    # load — defensive pattern matching _REAL_IMPORT / _REAL_OS so that any
    # future _harden_builtins() variant which deniers compile/exec doesn't
    # break the worker's own one-shot compile/exec call.
    ns: dict = {"__builtins__": _restricted_builtins}
    try:
        _REAL_EXEC(_REAL_COMPILE(script, "<cad_script>", "exec"), ns)  # noqa: S102
    except MemoryError:
        return {
            "ok": False,
            "error": "worker_oom",
            "message": "Script consumed too much memory (MemoryError).",
        }
    except SystemExit as exc:
        return {
            "ok": False,
            "error": "script_error",
            "message": f"Script called sys.exit({exc.code}).",
        }
    except Exception:  # noqa: BLE001
        return {
            "ok": False,
            "error": "script_error",
            "message": traceback.format_exc(),
        }

    # Script must assign its CadQuery result to the name `result`.
    cq_result = ns.get("result")
    if cq_result is None:
        return {
            "ok": False,
            "error": "script_error",
            "message": (
                "Script did not assign a CadQuery object to `result`. "
                "The last expression must be `result = <your cq object>`."
            ),
        }

    # Map format to canonical file extension.
    ext_map = {"step": "step", "stl": "stl", "3mf": "3mf"}
    ext = ext_map.get(fmt, "step")
    artifact_path = os.path.join(workdir, f"artifact.{ext}")

    try:
        # cq is already imported at the top of _run_script (PLA-75 R2 pre-import).
        export_type_map = {
            "stl":   cq.exporters.ExportTypes.STL,
            "3mf":   cq.exporters.ExportTypes.THREEMF,
            "step":  cq.exporters.ExportTypes.STEP,
        }
        export_type = export_type_map.get(fmt, cq.exporters.ExportTypes.STEP)
        cq.exporters.export(cq_result, artifact_path, export_type)
    except Exception:  # noqa: BLE001
        return {
            "ok": False,
            "error": "worker_internal",
            "message": f"Export failed:\n{traceback.format_exc()}",
        }

    return {"ok": True, "artifactPath": artifact_path}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    # Read the entire stdin as a JSON document.
    try:
        raw = sys.stdin.read()
        job: dict = json.loads(raw)
    except json.JSONDecodeError as exc:
        _write_result({
            "ok": False,
            "error": "worker_internal",
            "message": f"Invalid JSON on stdin: {exc}",
        })
        sys.exit(1)
    except Exception as exc:  # noqa: BLE001
        _write_result({
            "ok": False,
            "error": "worker_internal",
            "message": f"Failed to read stdin: {exc}",
        })
        sys.exit(1)

    script: str = job.get("script", "")
    fmt: str = job.get("format", "step")
    workdir: str = job.get("workdir") or tempfile.mkdtemp(
        prefix="cad-worker-", dir=tempfile.gettempdir()
    )

    result = _run_script(script, fmt, workdir)
    _write_result(result)


def _write_result(result: dict) -> None:
    """Write the result dict as a single JSON line to stdout."""
    sys.stdout.write(json.dumps(result) + "\n")
    sys.stdout.flush()


if __name__ == "__main__":
    main()
