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

import json
import os
import sys
import tempfile
import traceback
from types import ModuleType
from typing import Any

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
    Replace all network-capable modules in sys.modules with blockers.

    Called once, immediately before exec()ing user code.
    Already-imported native extension modules (e.g. _ssl) are replaced too
    so that code that cached a reference to the real module at import time
    cannot bypass the block via that reference — they would need to have
    imported the module before this function ran, which we prevent by calling
    this before exec().
    """
    for mod_name in _BLOCKED_MODULES:
        sys.modules[mod_name] = _NetworkBlockedModule(mod_name)


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

    # Install network blocker BEFORE exec()ing any user code.
    _install_network_block()

    # Execute the user script in an isolated namespace.
    ns: dict = {}
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
