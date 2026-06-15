/**
 * PLA-1089 Ask 2 — mesh-boolean tooling under the REAL bwrap+seccomp sandbox.
 *
 * Proves acceptance criterion 3:
 *   - `import trimesh, manifold3d, scipy` succeeds inside the live kernel
 *     sandbox (no SIGSYS, no in-process ImportError),
 *   - a watertight-repair + ~0.4 mm clearance offset + boolean-subtract
 *     round-trip on a faceted mesh yields a watertight solid with vol > 0,
 *   - the manifold3d engine (in-process) is what trimesh selects — no
 *     subprocess shell-out, and
 *   - the subprocess-leak that pre-importing trimesh would otherwise open
 *     (`trimesh.interfaces.generic.subprocess`) is neutralised.
 *
 * Gating: the suite needs (a) bubblewrap + the compiled seccomp filter, and
 * (b) the mesh stack installed where the sandbox can see it (i.e. under /usr,
 * which `worker/requirements-cad.txt` lands in CI — see sandbox.yml). On a dev
 * box where trimesh/manifold3d live only in a user site-packages dir the
 * sandbox does not bind, the availability probe fails and every test self-skips
 * with a clear reason rather than producing a false red. In CI (env `CI`), by
 * contrast, a bwrap-capable runner that cannot import the mesh stack is a hard
 * FAILURE — the gate cannot be satisfied by a silent skip (PLA-1089 SE-3).
 */

import { describe, it, expect, beforeAll } from "vitest";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { mkdtemp } from "node:fs/promises";
import { execSync } from "node:child_process";
import { existsSync } from "node:fs";

import {
  invokeWorker,
  selectSpawnMode,
  DEFAULT_TIMEOUT_SECONDS,
  type SpawnModeDecision,
  type WorkerResult,
} from "./cad-worker-client.js";

function bwrapAvailable(): boolean {
  if (process.platform !== "linux") return false;
  try {
    execSync("command -v bwrap", { stdio: "ignore" });
  } catch {
    return false;
  }
  return existsSync("worker/seccomp_filter.bpf");
}

const HAS_BWRAP = bwrapAvailable();
// PLA-1089 SE-3: a BLOCKING "native code is sandbox-safe / no SIGSYS" sign-off is
// worthless if the proving test silently skips. In CI, a bwrap-capable runner
// that cannot import the mesh stack is a hard FAILURE (not a skip) — CI must
// install trimesh/manifold3d/scipy into the sandbox-visible path (/usr, see
// sandbox.yml) so the probe succeeds and the two cases below actually execute.
// On dev boxes (no CI) the suite still self-skips with a clear reason.
const IS_CI = !!process.env.CI;
const T = 30_000;

let DECISION: SpawnModeDecision;
let MESH_OK = false;
let MESH_SKIP_REASON = "";

async function freshWorkdir(): Promise<string> {
  return mkdtemp(join(tmpdir(), "cad-mesh-test-"));
}

async function run(script: string): Promise<WorkerResult> {
  const workdir = await freshWorkdir();
  return invokeWorker({ script, format: "stl", workdir }, DEFAULT_TIMEOUT_SECONDS, DECISION);
}

// Importing all three + emitting a trivial CadQuery result proves the stack is
// importable in the sandbox. If it is not, the message tells us whether it was
// an ImportError (deps absent from the bound mount) vs a kernel kill.
const PROBE_SCRIPT = [
  "import trimesh, manifold3d, scipy",
  "import cadquery as cq",
  'result = cq.Workplane("XY").box(1, 1, 1)',
].join("\n");

beforeAll(async () => {
  if (!HAS_BWRAP) {
    MESH_SKIP_REASON = "bubblewrap or worker/seccomp_filter.bpf not present";
    return;
  }
  // vitest.config.ts defaults CAD_WORKER_UNSAFE_DEV=1; the kernel-sandbox path
  // requires it cleared (matches sandbox.bwrap.test.ts).
  delete process.env.CAD_WORKER_UNSAFE_DEV;
  DECISION = selectSpawnMode();
  expect(DECISION.mode).toBe("bwrap+seccomp");

  const r = await run(PROBE_SCRIPT);
  MESH_OK = r.ok;
  if (!r.ok) {
    MESH_SKIP_REASON =
      `mesh stack not importable in sandbox: ${r.error ?? "?"} — ` +
      `${(r.message ?? "").slice(0, 200)}`;
  }

  // PLA-1089 SE-3: in CI, a bwrap-capable runner that cannot prove the mesh
  // stack is sandbox-importable must FAIL the gate, not skip past it.
  if (IS_CI && HAS_BWRAP && !MESH_OK) {
    throw new Error(
      "PLA-1089 SE-3: mesh-boolean sandbox proof did not execute in CI. " +
        "bwrap is present but the trimesh/manifold3d/scipy probe failed — CI must " +
        "install worker/requirements-cad.txt into the sandbox-visible path (/usr). " +
        `Probe result: ${MESH_SKIP_REASON}`,
    );
  }
}, T);

describe.skipIf(!HAS_BWRAP)("PLA-1089 Ask 2 — mesh-boolean under bwrap+seccomp", () => {
  it("imports trimesh+manifold3d+scipy and runs repair+offset+boolean (vol>0)", async (ctx) => {
    if (!MESH_OK) return ctx.skip(MESH_SKIP_REASON);

    const r = await run(
      [
        "import trimesh, numpy as np",
        "import cadquery as cq",
        // Faceted scan stand-in: a subdivided icosphere (watertight already,
        // but exercise the repair entrypoints used on real scans).
        "scan = trimesh.creation.icosphere(subdivisions=3, radius=10.0)",
        "trimesh.repair.fill_holes(scan); trimesh.repair.fix_normals(scan)",
        'assert scan.is_watertight, "repair failed"',
        // ~0.4 mm clearance offset: displace verts along vertex normals.
        "cl = scan.copy()",
        "cl.vertices = scan.vertices + scan.vertex_normals * 0.4",
        "cl.fix_normals()",
        'assert cl.is_watertight, "offset not watertight"',
        // Socket = block minus clearance-dilated scan, exact in-process engine.
        "block = trimesh.creation.box(extents=(30, 30, 30))",
        'socket = block.difference(cl, engine="manifold")',
        'assert socket.is_watertight and socket.volume > 0, "boolean subtract failed"',
        'assert socket.volume < block.volume, "subtract removed nothing"',
        // Export needs a CadQuery shape; the mesh asserts above are the gate.
        'result = cq.Workplane("XY").box(1, 1, 1)',
      ].join("\n"),
    );

    expect(r.ok, JSON.stringify(r)).toBe(true);
    if (r.ok) expect(r.artifactPath).toBeTruthy();
  }, T);

  it("neutralises the trimesh subprocess + os shell-out gadgets (no sandbox escape)", async (ctx) => {
    if (!MESH_OK) return ctx.skip(MESH_SKIP_REASON);

    const r = await run(
      [
        "import trimesh",
        "import cadquery as cq",
        // The pre-import scrub replaces the subprocess shell-out global on
        // EVERY trimesh submodule that holds one (generic / ply / binvox).
        // Reaching .run(...) on any of them must raise, not spawn a process.
        "holders = [",
        "    trimesh.interfaces.generic,",
        "    trimesh.exchange.ply,",
        "    trimesh.exchange.binvox,",
        "]",
        "for h in holders:",
        "    escaped = False",
        "    try:",
        '        h.subprocess.run(["id"])',
        "        escaped = True",
        "    except PermissionError:",
        "        pass",
        '    assert not escaped, "subprocess leak OPEN via " + h.__name__',
        // PLA-1091: the `os` global is scrubbed with the same predicate, so a
        // captured real-os reference (e.g. trimesh.exchange.binvox.os.system)
        // cannot be reached. A submodule that bound no real os (h.os is None on
        // this trimesh build, e.g. exchange.ply) has nothing to scrub — skip it.
        "for h in holders:",
        '    og = getattr(h, "os", None)',
        "    if og is None:",
        "        continue",
        "    os_escaped = False",
        "    try:",
        "        og.system",
        "        os_escaped = True",
        "    except PermissionError:",
        "        pass",
        '    assert not os_escaped, "os leak OPEN via " + h.__name__',
        'result = cq.Workplane("XY").box(1, 1, 1)',
      ].join("\n"),
    );

    // ok === true means both asserts held (leaks closed) and export succeeded.
    expect(r.ok, JSON.stringify(r)).toBe(true);
  }, T);
});
