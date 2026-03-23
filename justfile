# SaltyOS Build Commands
# SPDX-License-Identifier: GPL-2.0-only

# Show available recipes
help:
    @echo "SaltyOS Build System"
    @echo ""
    @echo "== Quick Start (daily development) =="
    @echo "  just setup              Configure the build (once, default: x86_64)"
    @echo "  just build              Build kernel + userland"
    @echo "  just run                Build + run in QEMU"
    @echo "  just rr                 Quick rebuild + run"
    @echo ""
    @echo "== Multi-Architecture (arch= prefix works with any recipe) =="
    @echo "  just arch=aarch64 setup   Configure aarch64 build"
    @echo "  just arch=aarch64 build   Build for aarch64"
    @echo "  just arch=aarch64 run     Run aarch64 in QEMU (UEFI only)"
    @echo ""
    @echo "== QEMU Options (combinable) =="
    @echo "  just run --smp 2        Run with 2 CPUs"
    @echo "  just run --smp 4        Run with 4 CPUs"
    @echo "  just run --uefi         Run with UEFI firmware"
    @echo "  just run --debug        Run with interrupt logging (qemu.log)"
    @echo "  just run --gdb          Run with GDB server (-s -S)"
    @echo "  just run --headless     Run without GUI (serial only)"
    @echo "  just run --mem 1G       Set memory size"
    @echo "  just run --extra-disk F Attach additional virtio-blk disk"
    @echo ""
    @echo "== Debugging =="
    @echo "  just gdb                Connect GDB to running QEMU"
    @echo "  just reconfigure -Dkernel_log_level=debug"
    @echo ""
    @echo "== Code Quality =="
    @echo "  just fmt                Format Rust + C source"
    @echo "  just fmt-check          Check Rust formatting"
    @echo ""
    @echo "== Toolchain (use arch= to target aarch64, e.g. just arch=aarch64 tc all) =="
    @echo "  just tc setup                    Create directories"
    @echo "  just tc build host llvm          Build host Clang/LLD (~30 min)"
    @echo "  just tc build host rust          Build host rustc (~20 min)"
    @echo "  just tc doctor                   Validate toolchain"
    @echo "  just tc all                      Run all host steps in order"
    @echo ""
    @echo "== Cross-Compilation (use arch= to target aarch64) =="
    @echo "  just sysroot                     Generate cross-compilation sysroot (includes libc++)"
    @echo "  just cross-hello                 C smoke test"
    @echo "  just cross-hello-cpp             C++ smoke test"
    @echo ""
    @echo "== Self-Hosting (use arch= to target aarch64) =="
    @echo "  just tc build cross llvm         Cross-compile Clang/LLD for SaltyOS"
    @echo "  just tc build cross rust         Cross-compile rustc for SaltyOS"
    @echo "  just self-host                   Full cross-compile pipeline"
    @echo "  just tc package                  Package cross-compiled toolchain for rootfs"
    @echo "  just tc self-host                Same (without OS build dependency)"
    @echo ""
    @echo "== Ports =="
    @echo "  just port <name>        Build a port (bash, coreutils, ...)"
    @echo "  just fetch-ports        Download all port sources"
    @echo "  just port-info <name>   Show port configuration"
    @echo "  just clean-ports        Remove port build artifacts"
    @echo ""
    @echo "== Images =="
    @echo "  just image              Create BIOS disk image"
    @echo "  just image-uefi         Create UEFI disk image"
    @echo "  just mkrootfs           Build rootfs.img (binaries + optional LLVM/ports)"
    @echo "  just mksaltyfs          Create test_data.img (manual)"
    @echo ""
    @echo "== Misc =="
    @echo "  just info               Show build configuration"
    @echo "  just loc                Show source line counts"
    @echo "  just watch              Watch for changes + rebuild"
    @echo "  just distclean          Remove all build dirs"

# Default target architecture
arch := "x86_64"

# Build directory (arch-qualified)
builddir := "build-" + arch

# =============================================================================
# Setup & Configuration
# =============================================================================

# Internal: shared setup implementation
[private]
_setup-impl arch:
    #!/usr/bin/env bash
    set -euo pipefail
    dir="build-{{arch}}"
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
    # Custom-built clang needs the macOS SDK path to pass Meson's sanity check
    if [[ "$(uname -s)" == "Darwin" ]]; then
      export SDKROOT="${SDKROOT:-$(xcrun --show-sdk-path)}"
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
      -Dbuild_userland=true \
      -Dbuild_ports=true

# Configure the build (run once)
setup: (_setup-impl arch)

# Reconfigure with new options
reconfigure *ARGS:
    meson configure {{builddir}} {{ARGS}}

# =============================================================================
# Build Commands
# =============================================================================

# Build all components
build:
    #!/usr/bin/env bash
    source tools/toolchain/env.sh
    meson compile -C {{builddir}}

# Build with verbose output
build-verbose:
    meson compile -C {{builddir}} -v

# Clean build artifacts
clean:
    meson compile -C {{builddir}} --clean

# Full clean (remove meson build directories, preserve build-toolchain)
distclean:
    rm -rf build-x86_64 build-aarch64

# =============================================================================
# Run & Debug
# =============================================================================

# Run in QEMU (flags: --smp N, --mem SIZE, --debug, --headless, --gdb, --uefi)
run *ARGS: build
    bash tools/run-qemu.sh {{builddir}} --arch {{arch}} {{ARGS}}

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

# Unified toolchain entry point
# Usage: just tc <command> [args...]
#   just tc setup                     Create directories
#   just tc build host llvm           Build host Clang/LLD
#   just tc build host rust           Build host rustc
#   just tc build cross llvm          Cross-compile Clang/LLD for SaltyOS
#   just tc build cross rust          Cross-compile rustc for SaltyOS
#   just tc sysroot                   Generate sysroot (includes libc++ when available)
#   just tc doctor                    Validate toolchain
#   just tc all                       setup → host llvm → host rust → doctor
#   just tc self-host                 sysroot → cross llvm → cross rust
tc CMD *ARGS:
    SALTYOS_MESON_BUILDDIR={{builddir}} SALTYOS_ARCH={{arch}} bash tools/toolchain/build.sh {{CMD}} {{ARGS}}

# Generate cross-compilation sysroot (requires: just build)
sysroot: build
    @just tc sysroot

# Full cross-compile pipeline (requires: just sysroot)
# libc++ is built by 'just build' when build_libcxx=auto|true and
# toolchain/llvm-project is present, then installed into sysroot by 'just sysroot'.
self-host: sysroot
    @just tc build cross llvm
    @just tc build cross rust
    @just tc package

# Cross-compile C smoke test against sysroot
cross-hello: sysroot
    bash tests/cross/build.sh {{builddir}}/sysroot

# Cross-compile C++ smoke test against sysroot + libc++
cross-hello-cpp: sysroot
    bash tests/cross/build_cpp.sh {{builddir}}/sysroot

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
    SALTYOS_ARCH={{arch}} {{builddir}}/tools/port/port build ports/{{NAME}} -o {{builddir}}/ports -b {{builddir}} -v

# Fetch all port sources
fetch-ports:
    {{builddir}}/tools/port/port fetch ports/bash -b {{builddir}}
    {{builddir}}/tools/port/port fetch ports/coreutils -b {{builddir}}

# Clean port build artifacts (all ports, all architectures)
clean-ports:
    #!/usr/bin/env bash
    set -euo pipefail
    for d in ports/*/; do
        [ -f "$d/$(basename "$d").port" ] || continue
        for w in "$d"work-*/; do
            [ -d "$w" ] && rm -rf "$w" && echo "Removed $w"
        done
        [ -d "${d}stage" ] && rm -rf "${d}stage" && echo "Removed ${d}stage"
    done
    echo "All port work directories cleaned."

# Show port info
port-info NAME:
    {{builddir}}/tools/port/port info ports/{{NAME}}

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

# Build rootfs image (binaries always; LLVM after `just tc package`; ports if build_ports=true)
mkrootfs: build
    #!/usr/bin/env bash
    source tools/toolchain/env.sh
    meson compile -C {{builddir}} rootfs_image

# Create a new component skeleton
new-component NAME:
    @echo "Creating component: {{NAME}}"
    mkdir -p userland/{{NAME}}/src
    @echo "Component {{NAME}} created in userland/{{NAME}}"
