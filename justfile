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
    @echo "== Toolchain =="
    @echo "  just tc setup                    Create directories"
    @echo "  just tc build host llvm          Build host Clang/LLD (~30 min)"
    @echo "  just tc build host rust          Build host rustc (~20 min)"
    @echo "  just tc doctor                   Validate toolchain"
    @echo "  just tc all                      Run all host steps in order"
    @echo ""
    @echo "== Cross-Compilation =="
    @echo "  just sysroot                     Generate cross-compilation sysroot (includes libc++)"
    @echo "  just cross-hello                 C smoke test"
    @echo "  just cross-hello-cpp             C++ smoke test"
    @echo ""
    @echo "== Self-Hosting =="
    @echo "  just tc build cross llvm         Cross-compile Clang/LLD for SaltyOS"
    @echo "  just tc build cross rust         Cross-compile rustc for SaltyOS"
    @echo "  just self-host                   Full cross-compile pipeline"
    @echo "  just tc self-host                Same (without OS build dependency)"
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
    SALTYOS_MESON_BUILDDIR={{builddir}} bash tools/toolchain/build.sh {{CMD}} {{ARGS}}

# Generate cross-compilation sysroot (requires: just build)
sysroot: build
    @just tc sysroot

# Full cross-compile pipeline (requires: just sysroot)
# libc++ is built by 'just build' when build_libcxx=auto|true and
# toolchain/llvm-project is present, then installed into sysroot by 'just sysroot'.
self-host: sysroot
    @just tc build cross llvm
    @just tc build cross rust

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

# Strip cross-compiled LLVM binaries for rootfs inclusion.
# Run this once after a cross LLVM build, before `just build`.
strip-llvm:
    #!/usr/bin/env bash
    set -euo pipefail
    STRIP=build-toolchain/prefix/bin/llvm-strip
    SRC=build-toolchain/llvm-saltyos/bin
    DST=build-toolchain/llvm-saltyos-stripped
    mkdir -p "$DST/bin" "$DST/lib"
    clang_bin="$(cd "$SRC" && ls clang-* 2>/dev/null | head -1)"
    if [ -z "$clang_bin" ]; then
        echo "Error: no clang-* binary found in $SRC" >&2
        exit 1
    fi
    for f in "$clang_bin" lld llvm-ar llvm-nm llvm-objcopy; do
        echo "Stripping $f..."
        cp "$SRC/$f" "$DST/bin/$f"
        "$STRIP" "$DST/bin/$f"
    done
    cp build/lib/besalt/cpp/libc++.so "$DST/lib/libc++.so"
    # Clang resource directory and SaltyOS compiler-rt builtins
    echo "Copying clang resource directory..."
    rm -rf "$DST/lib/clang"
    cp -r build-toolchain/llvm-saltyos/lib/clang "$DST/lib/clang"
    RT_DIR="$(find build-toolchain/llvm/lib/clang -type d -path '*/lib/x86_64-unknown-saltyos' -print -quit)"
    if [ -z "$RT_DIR" ]; then
        echo "Missing SaltyOS compiler-rt runtime directory in build-toolchain/llvm/lib/clang" >&2
        exit 1
    fi
    RT_REL="${RT_DIR#build-toolchain/llvm/lib/clang/}"
    rm -rf "$DST/lib/clang/$RT_REL"
    mkdir -p "$(dirname "$DST/lib/clang/$RT_REL")"
    cp -r "$RT_DIR" "$(dirname "$DST/lib/clang/$RT_REL")"
    # CRT objects and linker script
    echo "Copying development files..."
    cp build/lib/besalt/c/crt_start.o "$DST/lib/crt_start.o"
    cp build/rust/core.o "$DST/lib/core.o"
    cp build/rust/compiler_builtins.o "$DST/lib/compiler_builtins.o"
    cp lib/besalt/saltyos-pie.ld "$DST/lib/saltyos-pie.ld"
    # Link-time libraries
    cp build/lib/besalt/c/libc.so "$DST/lib/libc.so"
    cp build/lib/besalt/lib/libbesalt.so "$DST/lib/libbesalt.so"
    # Stub archives (-lm, -lpthread, etc.)
    for stub in libm.a libpthread.a librt.a libdl.a libutil.a; do
        printf '!<arch>\n' > "$DST/lib/$stub"
    done
    echo "Done. Stripped sizes:"
    du -sh "$DST/bin/"* "$DST/lib/"*

# Build rootfs image from manifest (strip-llvm must run before build).
mkrootfs: strip-llvm build
    tools/mkrootfs --output {{builddir}}/rootfs.img --size 512M \
        --manifest images/rootfs.manifest -v

# Create a new component skeleton
new-component NAME:
    @echo "Creating component: {{NAME}}"
    mkdir -p userland/{{NAME}}/src
    @echo "Component {{NAME}} created in userland/{{NAME}}"
