# SaltyOS Build Commands
# SPDX-License-Identifier: GPL-2.0-only

# Show available recipes
help:
    @echo "SaltyOS Build System"
    @echo ""
    @echo "== Quick Start (daily development) =="
    @echo "  just setup          Configure the build (once)"
    @echo "  just build          Build kernel + userland"
    @echo "  just run            Build + run in QEMU"
    @echo "  just rr             Quick rebuild + run"
    @echo ""
    @echo "== QEMU Options =="
    @echo "  just run --smp 2    Run with 2 CPUs"
    @echo "  just run --smp 4    Run with 4 CPUs"
    @echo "  just run --uefi     Run with UEFI firmware"
    @echo "  just run --debug    Run with interrupt logging"
    @echo "  just run --gdb      Run with GDB server"
    @echo "  just run --headless Run without GUI"
    @echo ""
    @echo "== Toolchain Bootstrap (one-time, in order) =="
    @echo "  1. just toolchain-setup          Create directories"
    @echo "  2. just toolchain-build-llvm     Build host Clang/LLD"
    @echo "  3. just toolchain-build-rust     Build host rustc"
    @echo "  just toolchain-doctor            Validate toolchain"
    @echo ""
    @echo "== Ports =="
    @echo "  just port <name>    Build a port (bash, coreutils, ...)"
    @echo ""
    @echo "== Images =="
    @echo "  just mkrootfs       Build rootfs.img from manifest"
    @echo "  just mksaltyfs      Create test_data.img (manual)"

# Default target architecture
arch := "x86_64"

# Build directory
builddir := "build"

# =============================================================================
# Setup & Configuration
# =============================================================================

# Internal: shared setup implementation
[private]
_setup-impl suffix arch:
    #!/usr/bin/env bash
    set -euo pipefail
    dir="{{builddir}}{{suffix}}"
    source tools/toolchain/env.sh
    if [ -z "${CC:-}" ]; then
      cc_path="$SALTYOS_TOOLCHAIN_PREFIX/bin/clang"
      if [ -x "$cc_path" ]; then
        CC="$cc_path"
      else
        echo "No clang found." >&2
        echo "Checked prefix: $cc_path" >&2
        echo "Run 'just toolchain-build-llvm', set SALTYOS_TOOLCHAIN_PREFIX, or override CC=/path/to/clang." >&2
        exit 1
      fi
    fi
    if [ -z "${RUSTC:-}" ]; then
      rustc_path="$SALTYOS_TOOLCHAIN_PREFIX/bin/rustc"
      if [ -x "$rustc_path" ]; then
        RUSTC="$rustc_path"
      else
        echo "No rustc found." >&2
        echo "Checked prefix: $rustc_path" >&2
        echo "Checked stage1: $SALTYOS_RUST_STAGE1_RUSTC" >&2
        echo "Run 'just toolchain-build-rust', set SALTYOS_TOOLCHAIN_PREFIX, or override RUSTC=/path/to/rustc." >&2
        exit 1
      fi
    fi
    mkdir -p "$dir"
    {
      printf '[binaries]\n'
      printf 'c     = %s\n' "'${CC}'"
      printf 'rustc = %s\n' "'${RUSTC}'"
      prefix="${SALTYOS_TOOLCHAIN_PREFIX}/bin"
      for tool in llvm-objcopy lld-link llvm-strip llvm-ar; do
        [ -x "${prefix}/${tool}" ] && printf '%s = %s\n' "${tool}" "'${prefix}/${tool}'"
      done
    } > "$dir/toolchain.ini"
    meson setup "$dir" \
      --native-file="$dir/toolchain.ini" \
      -Darch={{arch}} \
      -Dbuild_boot=true \
      -Dbuild_kernel=true \
      -Dbuild_userland=true

# Configure the build (run once)
setup: (_setup-impl "" arch)

# Configure for x86_64
setup-x86_64: (_setup-impl "-x86_64" "x86_64")

# Configure for aarch64
setup-aarch64: (_setup-impl "-aarch64" "aarch64")

# Reconfigure with new options
reconfigure *ARGS:
    meson configure {{builddir}} {{ARGS}}

# =============================================================================
# Build Commands
# =============================================================================

# Build all components
build:
    meson compile -C {{builddir}}

# Build with verbose output
build-verbose:
    meson compile -C {{builddir}} -v

# Clean build artifacts
clean:
    meson compile -C {{builddir}} --clean

# Full clean (remove build directory)
distclean:
    rm -rf {{builddir}} {{builddir}}-x86_64 {{builddir}}-aarch64

# =============================================================================
# Run & Debug
# =============================================================================

# Run in QEMU (flags: --smp N, --mem SIZE, --debug, --headless, --gdb, --uefi)
run *ARGS: build
    bash tools/run-qemu.sh {{builddir}} {{ARGS}}

# Connect GDB to running QEMU
gdb:
    gdb -ex "target remote localhost:1234" \
        -ex "symbol-file {{builddir}}/kernel/kernel.elf"

# =============================================================================
# Utilities
# =============================================================================

# Create disk image (BIOS)
image: build
    meson compile -C {{builddir}} disk_image

# Create disk image (UEFI)
image-uefi: build
    meson compile -C {{builddir}} uefi_image

# Show build configuration
info:
    meson configure {{builddir}}

# Print shell exports for the workspace-local toolchain layout
# Usage: eval "$(just toolchain-env)"
toolchain-env:
    bash tools/toolchain/env.sh --print

# Validate that the active clang/rustc/llvm-config match the SaltyOS target setup
toolchain-doctor:
    bash tools/toolchain/doctor.sh

# Create the recommended workspace-local toolchain layout directories
toolchain-setup:
    #!/usr/bin/env bash
    set -euo pipefail
    source tools/toolchain/env.sh
    mkdir -p "$SALTYOS_LLVM_BUILD_DIR" "$SALTYOS_RUST_BUILD_DIR" "$SALTYOS_TOOLCHAIN_PREFIX/bin"
    echo "Initialized toolchain directories:"
    echo "  LLVM build : $SALTYOS_LLVM_BUILD_DIR"
    echo "  Rust build : $SALTYOS_RUST_BUILD_DIR"
    echo "  Prefix     : $SALTYOS_TOOLCHAIN_PREFIX"
    echo
    echo "Next:"
    echo "  just toolchain-build-llvm"
    echo "  just toolchain-build-rust"

# Configure, build, and install the patched LLVM/Clang/LLD into the local prefix
toolchain-build-llvm:
    #!/usr/bin/env bash
    set -euo pipefail
    source tools/toolchain/env.sh
    mkdir -p "$SALTYOS_LLVM_BUILD_DIR" "$SALTYOS_TOOLCHAIN_PREFIX"
    cmake -S "$SALTYOS_LLVM_SRC_DIR/llvm" -B "$SALTYOS_LLVM_BUILD_DIR" -G Ninja \
      -DCMAKE_BUILD_TYPE=Release \
      -DLLVM_ENABLE_PROJECTS="clang;lld" \
      -DLLVM_TARGETS_TO_BUILD="X86" \
      -DLLVM_INSTALL_UTILS=ON \
      -DLLVM_ENABLE_RUNTIMES=compiler-rt \
      -DLLVM_RUNTIME_TARGETS="default;x86_64-unknown-saltyos" \
      -DRUNTIMES_x86_64-unknown-saltyos_CMAKE_C_FLAGS="-ffreestanding" \
      -DRUNTIMES_x86_64-unknown-saltyos_CMAKE_CXX_FLAGS="-ffreestanding" \
      -DRUNTIMES_x86_64-unknown-saltyos_CMAKE_C_COMPILER_FORCED=ON \
      -DRUNTIMES_x86_64-unknown-saltyos_CMAKE_CXX_COMPILER_FORCED=ON \
      -DRUNTIMES_x86_64-unknown-saltyos_COMPILER_RT_BUILD_BUILTINS=ON \
      -DRUNTIMES_x86_64-unknown-saltyos_COMPILER_RT_BUILD_SANITIZERS=OFF \
      -DRUNTIMES_x86_64-unknown-saltyos_COMPILER_RT_BUILD_XRAY=OFF \
      -DRUNTIMES_x86_64-unknown-saltyos_COMPILER_RT_BUILD_LIBFUZZER=OFF \
      -DRUNTIMES_x86_64-unknown-saltyos_COMPILER_RT_BUILD_PROFILE=OFF \
      -DRUNTIMES_x86_64-unknown-saltyos_COMPILER_RT_BUILD_MEMPROF=OFF \
      -DRUNTIMES_x86_64-unknown-saltyos_COMPILER_RT_BUILD_ORC=OFF \
      -DRUNTIMES_x86_64-unknown-saltyos_COMPILER_RT_BUILD_GWP_ASAN=OFF \
      -DRUNTIMES_x86_64-unknown-saltyos_COMPILER_RT_BUILD_CTX_PROFILE=OFF \
      -DRUNTIMES_x86_64-unknown-saltyos_COMPILER_RT_BUILTINS_ENABLE_PIC=ON \
      -DRUNTIMES_x86_64-unknown-saltyos_COMPILER_RT_BAREMETAL_BUILD=ON \
      -DCMAKE_INSTALL_PREFIX="$SALTYOS_TOOLCHAIN_PREFIX"
    ninja -C "$SALTYOS_LLVM_BUILD_DIR" -j"$(nproc)"
    ninja -C "$SALTYOS_LLVM_BUILD_DIR" install

# Build the patched Rust stage1 libraries/compiler using the local LLVM prefix
toolchain-build-rust:
    #!/usr/bin/env bash
    set -euo pipefail
    source tools/toolchain/env.sh
    mkdir -p "$SALTYOS_RUST_BUILD_DIR" "$SALTYOS_TOOLCHAIN_BUILD_ROOT" "$SALTYOS_TOOLCHAIN_PREFIX/bin"
    llvm_config_path="$SALTYOS_TOOLCHAIN_PREFIX/bin/llvm-config"
    if [ ! -x "$llvm_config_path" ]; then
      echo "Missing llvm-config in prefix: $llvm_config_path" >&2
      echo "Run 'just toolchain-build-llvm' first (or set SALTYOS_TOOLCHAIN_PREFIX to an existing install)." >&2
      exit 1
    fi
    filecheck_path="$SALTYOS_TOOLCHAIN_PREFIX/bin/FileCheck"
    if [ ! -x "$filecheck_path" ]; then
      echo "Missing FileCheck in prefix: $filecheck_path" >&2
      echo "Run 'just toolchain-build-llvm' first (it installs/links FileCheck into the prefix)." >&2
      exit 1
    fi
    config_path="$SALTYOS_TOOLCHAIN_BUILD_ROOT/rust-bootstrap.toml"
    {
      echo '[build]'
      echo 'target = ["x86_64-unknown-linux-gnu"]'
      echo ''
      echo '[install]'
      echo "prefix = \"$SALTYOS_TOOLCHAIN_PREFIX\""
      echo 'sysconfdir = "etc"'
      echo ''
      echo '[llvm]'
      echo 'download-ci-llvm = false'
      echo ''
      echo '[rust]'
      echo 'use-lld = true'
      echo ''
      echo '[target.x86_64-unknown-linux-gnu]'
      echo "llvm-config = \"$llvm_config_path\""
      echo "llvm-filecheck = \"$filecheck_path\""
    } > "$config_path"
    python3 "$SALTYOS_RUST_SRC_DIR/x.py" install \
      --src "$SALTYOS_RUST_SRC_DIR" \
      --build-dir "$SALTYOS_RUST_BUILD_DIR" \
      --config "$config_path" \
      --stage 1 \
      compiler/rustc library/std src
    echo "Installed stage1 rustc into prefix: $SALTYOS_TOOLCHAIN_PREFIX"

# Format all source code
fmt:
    find kernel -name "*.rs" -exec rustfmt {} \;
    find boot -name "*.c" -o -name "*.h" | xargs clang-format -i

# Check formatting without modifying
fmt-check:
    find kernel -name "*.rs" -exec rustfmt --check {} \;

# Run clippy on kernel
clippy:
    @echo "Clippy check not yet implemented for freestanding build"

# Generate documentation
docs:
    @echo "Documentation generation not yet implemented"

# Show line counts
loc:
    @echo "=== Source Lines of Code ==="
    @find kernel boot userland lib -name "*.rs" -o -name "*.c" -o -name "*.h" -o -name "*.asm" 2>/dev/null | xargs wc -l | tail -1

# =============================================================================
# Ports
# =============================================================================

# Build a specific port
port NAME: build
    #!/usr/bin/env bash
    set -euo pipefail
    source tools/toolchain/env.sh
    {{builddir}}/tools/portbuild/portbuild build ports/{{NAME}} -o {{builddir}}/ports -b {{builddir}} -v

# Fetch all port sources
fetch-ports:
    {{builddir}}/tools/portbuild/portbuild fetch ports/bash -b {{builddir}}
    {{builddir}}/tools/portbuild/portbuild fetch ports/coreutils -b {{builddir}}

# Clean port build artifacts
clean-ports:
    {{builddir}}/tools/portbuild/portbuild clean ports/bash
    {{builddir}}/tools/portbuild/portbuild clean ports/coreutils

# Show port info
port-info NAME:
    {{builddir}}/tools/portbuild/portbuild info ports/{{NAME}}

# =============================================================================
# Development Helpers
# =============================================================================

# Watch for changes and rebuild
watch:
    watchexec -e rs,c,h,asm just build

# Quick rebuild and run
rr: build run

# Generate SaltyFS test image
mksaltyfs:
    python3 tools/mksaltyfs.py -o test_data.img -s 64M

# Build rootfs image from manifest
mkrootfs: build
    tools/mkrootfs --output {{builddir}}/rootfs.img --size 256M \
        --manifest images/rootfs.manifest -v

# Create a new component skeleton
new-component NAME:
    @echo "Creating component: {{NAME}}"
    mkdir -p userland/{{NAME}}/src
    @echo "Component {{NAME}} created in userland/{{NAME}}"
