# Devcontainer for paperclip-plugin-cad — PLA-114
#
# Provisions Node 20, Python 3.12, CadQuery deps, AND the kernel-sandbox
# tooling (bubblewrap + libseccomp-dev) so the bwrap integration matrix
# can run inside the container the same way it runs in CI and on the
# deploy host. Without these, `npm test` on `src/sandbox.bwrap.test.ts`
# falls back to the dev_direct path (in-process layer only) and the
# kernel-discriminator assertions cannot fire.

FROM mcr.microsoft.com/devcontainers/javascript-node:20-bookworm

# --- System deps -----------------------------------------------------------
# bubblewrap          — kernel-sandbox runtime (PLA-106 §1)
# libseccomp-dev      — needed to build worker/seccomp_filter.c
# build-essential     — gcc + make for the filter blob and cad_preexec
# pkg-config          — libseccomp.pc lookup
# strace              — clone-flag evidence capture (PLA-106 §2.1)
# python3.12 + pip    — CadQuery worker
# ca-certificates     — pip TLS root anchors
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       bubblewrap \
       libseccomp-dev \
       libseccomp2 \
       build-essential \
       pkg-config \
       strace \
       python3.12 \
       python3-pip \
       ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Verify the toolchain is wired up correctly. Build will fail loud if
# either is missing.
RUN bwrap --version \
    && pkg-config --modversion libseccomp

WORKDIR /workspaces/paperclip-plugin-cad
