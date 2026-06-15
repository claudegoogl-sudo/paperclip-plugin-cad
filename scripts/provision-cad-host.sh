#!/usr/bin/env bash
# provision-cad-host.sh
#
# Provision the CAD worker's Python mesh tooling into the SANDBOX-VISIBLE system
# site so cad.run_script's bwrap sandbox (ro-binds /usr only, HOME=/tmp,
# --tmpfs /tmp) can import them at runtime.
#
# The sandbox sees ONLY paths under /usr. The Ubuntu root-pip "local" site
# /usr/local/lib/python3.12/dist-packages is where cadquery/scipy/numpy already
# live and import OK. trimesh/manifold3d were missing there (trimesh was a
# --user install at ~/.local = /tmp/.local in-sandbox = invisible; manifold3d
# was not installed at all) -> PLA-1124.
#
# DURABILITY (PLA-1127): run this on every host rebuild/redeploy so the mesh
# deps survive. It reads the pins straight from worker/requirements-cad.txt
# (single source of truth — no drift) and installs them into the sandbox site.
#
# Idempotent: re-running converges (pip --target reinstalls the pinned versions).
# Shared-infra mutation -> run ONLY via the board/operator gate. Requires root.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REQ_FILE="${REQ_FILE:-$REPO_ROOT/worker/requirements-cad.txt}"

PYBIN="${PYBIN:-/usr/bin/python3}"
PYVER="$("$PYBIN" -c 'import sys;print("%d.%d"%sys.version_info[:2])')"
TARGET="/usr/local/lib/python${PYVER}/dist-packages"

# Pins come from worker/requirements-cad.txt so this script can never drift from
# the committed manifest. Only numpy is an import-time dep of trimesh+manifold3d
# and it is already present in $TARGET, so --no-deps is safe (verified PLA-1124:
# import succeeds with only these two added on PYTHONPATH).
test -f "$REQ_FILE" || { echo "[provision] ERROR: requirements file not found: $REQ_FILE"; exit 1; }
extract_pin() {
  # $1 = package name; print the exact "name==version" line, ignore comments.
  grep -E "^${1}==" "$REQ_FILE" | head -n1
}
TRIMESH_PIN="$(extract_pin trimesh)"
MANIFOLD_PIN="$(extract_pin manifold3d)"
[ -n "$TRIMESH_PIN" ]  || { echo "[provision] ERROR: trimesh pin missing in $REQ_FILE"; exit 1; }
[ -n "$MANIFOLD_PIN" ] || { echo "[provision] ERROR: manifold3d pin missing in $REQ_FILE"; exit 1; }

ROLLBACK="sudo rm -rf ${TARGET}/trimesh ${TARGET}/trimesh-*.dist-info ${TARGET}/manifold3d*.so ${TARGET}/manifold3d.pyi ${TARGET}/manifold3d-*.dist-info"

fail() { echo "RESULT: FAILURE"; echo "[provision] rollback: ${ROLLBACK}"; }
trap fail ERR

# Root guard.
if [ "$(id -u)" -ne 0 ]; then
  echo "[provision] ERROR: must run as root (use: sudo bash $0)"; exit 1
fi

echo "[provision] requirements: $REQ_FILE"
echo "[provision] pins: $TRIMESH_PIN $MANIFOLD_PIN"
echo "[provision] target site: $TARGET (python $PYVER)"
test -d "$TARGET" || { echo "[provision] ERROR: $TARGET missing"; exit 1; }

"$PYBIN" -m pip install --no-deps --upgrade --target "$TARGET" \
    "$TRIMESH_PIN" "$MANIFOLD_PIN"

echo "[provision] installed:"
ls "$TARGET" | grep -iE '^trimesh|^manifold' || { echo "[provision] ERROR: not present after install"; exit 1; }

# Post-install gate: import under the REAL sandbox shape (uid nobody, /usr-only,
# HOME=/tmp, --tmpfs /tmp, --unshare-all). Must print SANDBOX_IMPORT_OK.
echo "[provision] sandbox import verification:"
bwrap --unshare-all --die-with-parent --new-session --clearenv \
  --setenv PATH /usr/bin:/bin --setenv HOME /tmp --setenv LANG C.UTF-8 \
  --uid 65534 --gid 65534 --hostname cad-worker --proc /proc --dev /dev \
  --ro-bind /usr /usr --ro-bind /lib /lib --ro-bind /lib64 /lib64 \
  --ro-bind /bin /bin --ro-bind /etc/ld.so.cache /etc/ld.so.cache --tmpfs /tmp \
  -- "$PYBIN" -c \
  'import scipy,trimesh,manifold3d,numpy;print("SANDBOX_IMPORT_OK",scipy.__version__,trimesh.__version__,numpy.__version__)'

trap - ERR
echo "RESULT: SUCCESS"
echo "[provision] done."
