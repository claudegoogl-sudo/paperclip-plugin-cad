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

# Capture the real __import__ at module-load time, before any restrictions.
_REAL_IMPORT = _builtins.__import__

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
]

# Frozenset for O(1) lookup in _restricted_import and _BlockingMetaPathFinder.
_BLOCKED_MODULES_SET: frozenset[str] = frozenset(_BLOCKED_MODULES)

# Subset that is safe to replace with stubs in sys.modules without breaking
# Python or CadQuery internals.
#
# importlib / importlib.util / importlib.machinery are EXCLUDED from sys.modules
# stubs because CadQuery's __init__.py does `from importlib.metadata import …`
# lazily during user-script execution; stubbing importlib breaks that import.
# _restricted_import and _BlockingMetaPathFinder still block user-script imports.
#
# threading is EXCLUDED because Python's runtime needs sys.modules['threading']
# for cleanup (__del__, atexit hooks).  User-script imports are still blocked by
# _restricted_import.
_SYS_MODULES_STUBS: list[str] = [
    m for m in _BLOCKED_MODULES
    if not (m == "threading" or m.startswith("importlib"))
]


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
# Restricted import / open helpers (PLA-76 CRITICAL-3, HIGH-1, HIGH-2)
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
    Falls through to the real ``__import__`` for everything else.
    """
    top = name.split(".")[0]
    if name in _BLOCKED_MODULES_SET or top in _BLOCKED_MODULES_SET:
        raise ImportError(
            f"[cad-worker] Import blocked: '{name}' is not allowed "
            f"inside the CadQuery sandbox."
        )
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
        # Use EXACT matching only (not root-prefix).  Root-prefix matching would
        # also block importlib.metadata, importlib.resources, etc. which are
        # legitimate stdlib modules needed by CadQuery internals.  The precise
        # entries in _BLOCKED_MODULES_SET (importlib.util, importlib.machinery)
        # are the dangerous ones; importlib.metadata is intentionally not listed.
        if fullname in _BLOCKED_MODULES_SET:
            raise ImportError(
                f"[cad-worker] Import blocked: '{fullname}' is not allowed "
                f"inside the CadQuery sandbox."
            )
        return None  # not handled here; let other finders proceed


def _install_meta_path_blocker() -> None:
    """Insert _BlockingMetaPathFinder at the front of sys.meta_path (idempotent)."""
    if not any(isinstance(f, _BlockingMetaPathFinder) for f in sys.meta_path):
        sys.meta_path.insert(0, _BlockingMetaPathFinder())


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

    # Install meta_path blocker BEFORE network block so all subsequent import
    # attempts (including bypass via real __import__) are intercepted.
    _install_meta_path_blocker()

    # Install module stubs in sys.modules (network + process-escape modules).
    _install_network_block()

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
    ns: dict = {"__builtins__": _restricted_builtins}
    try:
        exec(compile(script, "<cad_script>", "exec"), ns)  # noqa: S102
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
        import cadquery as cq  # noqa: PLC0415

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
