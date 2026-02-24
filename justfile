# SaltyOS Build Commands
# SPDX-License-Identifier: GPL-2.0-only

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

# Run in QEMU (x86_64)
run: build
    qemu-system-x86_64 \
        -machine q35 \
        -cpu qemu64 \
        -m 512M \
        -serial stdio \
        -drive file={{builddir}}/saltyos.img,format=raw,if=none,id=disk \
        -device ahci,id=ahci \
        -device ide-hd,drive=disk,bus=ahci.0 \
        -no-reboot \
        -no-shutdown

# Run in QEMU with extreme lowmem (4MB)
run-4m: build
    qemu-system-x86_64 \
        -machine q35 \
        -cpu qemu64 \
        -m 4M \
        -serial stdio \
        -drive file={{builddir}}/saltyos.img,format=raw,if=none,id=disk \
        -device ahci,id=ahci \
        -device ide-hd,drive=disk,bus=ahci.0 \
        -no-reboot \
        -no-shutdown

# Run in QEMU with lowmem (8MB)
run-8m: build
    qemu-system-x86_64 \
        -machine q35 \
        -cpu qemu64 \
        -m 8M \
        -serial stdio \
        -drive file={{builddir}}/saltyos.img,format=raw,if=none,id=disk \
        -device ahci,id=ahci \
        -device ide-hd,drive=disk,bus=ahci.0 \
        -no-reboot \
        -no-shutdown

# Run in QEMU with lowmem (16MB)
run-16m: build
    qemu-system-x86_64 \
        -machine q35 \
        -cpu qemu64 \
        -m 16M \
        -serial stdio \
        -drive file={{builddir}}/saltyos.img,format=raw,if=none,id=disk \
        -device ahci,id=ahci \
        -device ide-hd,drive=disk,bus=ahci.0 \
        -no-reboot \
        -no-shutdown

# Run in QEMU with SMP (2 CPUs)
run-smp: build
    qemu-system-x86_64 \
        -machine q35 \
        -cpu qemu64 \
        -smp 2 \
        -m 512M \
        -serial stdio \
        -drive file={{builddir}}/saltyos.img,format=raw,if=none,id=disk \
        -device ahci,id=ahci \
        -device ide-hd,drive=disk,bus=ahci.0 \
        -no-reboot \
        -no-shutdown

# Run SMP headless with debug output
run-smp-debug: build
    qemu-system-x86_64 \
        -machine q35 \
        -cpu qemu64 \
        -smp 2 \
        -m 512M \
        -serial stdio \
        -display none \
        -drive file={{builddir}}/saltyos.img,format=raw,if=none,id=disk \
        -device ahci,id=ahci \
        -device ide-hd,drive=disk,bus=ahci.0 \
        -no-reboot \
        -no-shutdown \
        -d int,cpu_reset \
        -D qemu.log

# Run SMP with 4 CPUs
run-smp4: build
    qemu-system-x86_64 \
        -machine q35 \
        -cpu qemu64 \
        -smp 4 \
        -m 512M \
        -serial stdio \
        -drive file={{builddir}}/saltyos.img,format=raw,if=none,id=disk \
        -device ahci,id=ahci \
        -device ide-hd,drive=disk,bus=ahci.0 \
        -no-reboot \
        -no-shutdown

# Run with debug output
run-debug: build
    qemu-system-x86_64 \
        -machine q35 \
        -cpu qemu64 \
        -m 512M \
        -serial stdio \
        -drive file={{builddir}}/saltyos.img,format=raw,if=none,id=disk \
        -device ahci,id=ahci \
        -device ide-hd,drive=disk,bus=ahci.0 \
        -no-reboot \
        -no-shutdown \
        -d int,cpu_reset \
        -D qemu.log

# Run with GDB server (wait for connection)
run-gdb: build
    qemu-system-x86_64 \
        -machine q35 \
        -cpu qemu64 \
        -m 512M \
        -serial stdio \
        -drive file={{builddir}}/saltyos.img,format=raw,if=none,id=disk \
        -device ahci,id=ahci \
        -device ide-hd,drive=disk,bus=ahci.0 \
        -no-reboot \
        -no-shutdown \
        -s -S

# Connect GDB to running QEMU
gdb:
    gdb -ex "target remote localhost:1234" \
        -ex "symbol-file {{builddir}}/kernel/kernel.elf"

# Run with UEFI firmware
run-uefi: image-uefi
    bash -eu -c '\
        ovmf_code="${OVMF_CODE:-}"; \
        ovmf_vars="${OVMF_VARS:-}"; \
        if [ -z "$ovmf_code" ]; then \
            for cand in /usr/share/edk2-ovmf/OVMF_CODE.fd /usr/share/OVMF/OVMF_CODE_4M.fd /usr/share/ovmf/OVMF.fd /usr/share/qemu/OVMF.fd; do \
                if [ -f "$cand" ]; then ovmf_code="$cand"; break; fi; \
            done; \
        fi; \
        if [ -z "$ovmf_vars" ]; then \
            for cand in /usr/share/edk2-ovmf/OVMF_VARS.fd /usr/share/OVMF/OVMF_VARS_4M.fd /usr/share/OVMF/OVMF_VARS.fd; do \
                if [ -f "$cand" ]; then ovmf_vars="$cand"; break; fi; \
            done; \
        fi; \
        if [ -z "$ovmf_code" ]; then \
            echo "OVMF firmware not found. Set OVMF_CODE (and optionally OVMF_VARS)." >&2; \
            exit 1; \
        fi; \
        if [ -n "$ovmf_vars" ] && [ -f "$ovmf_vars" ]; then \
            ovmf_vars_runtime="{{builddir}}/OVMF_VARS.fd"; \
            if [ ! -f "$ovmf_vars_runtime" ]; then cp "$ovmf_vars" "$ovmf_vars_runtime"; fi; \
            qemu-system-x86_64 \
                -machine q35 \
                -cpu qemu64 \
                -m 512M \
                -serial stdio \
                -drive if=pflash,format=raw,readonly=on,file="$ovmf_code" \
                -drive if=pflash,format=raw,file="$ovmf_vars_runtime" \
                -drive file={{builddir}}/saltyos-uefi.img,format=raw \
                -no-reboot \
                -no-shutdown; \
        else \
            qemu-system-x86_64 \
                -machine q35 \
                -cpu qemu64 \
                -m 512M \
                -serial stdio \
                -bios "$ovmf_code" \
                -drive file={{builddir}}/saltyos-uefi.img,format=raw \
                -no-reboot \
                -no-shutdown; \
        fi'

# Run UEFI with debug output
run-uefi-debug: image-uefi
    bash -eu -c '\
        ovmf_code="${OVMF_CODE:-}"; \
        ovmf_vars="${OVMF_VARS:-}"; \
        if [ -z "$ovmf_code" ]; then \
            for cand in /usr/share/edk2-ovmf/OVMF_CODE.fd /usr/share/OVMF/OVMF_CODE_4M.fd /usr/share/ovmf/OVMF.fd /usr/share/qemu/OVMF.fd; do \
                if [ -f "$cand" ]; then ovmf_code="$cand"; break; fi; \
            done; \
        fi; \
        if [ -z "$ovmf_vars" ]; then \
            for cand in /usr/share/edk2-ovmf/OVMF_VARS.fd /usr/share/OVMF/OVMF_VARS_4M.fd /usr/share/OVMF/OVMF_VARS.fd; do \
                if [ -f "$cand" ]; then ovmf_vars="$cand"; break; fi; \
            done; \
        fi; \
        if [ -z "$ovmf_code" ]; then \
            echo "OVMF firmware not found. Set OVMF_CODE (and optionally OVMF_VARS)." >&2; \
            exit 1; \
        fi; \
        if [ -n "$ovmf_vars" ] && [ -f "$ovmf_vars" ]; then \
            ovmf_vars_runtime="{{builddir}}/OVMF_VARS.fd"; \
            if [ ! -f "$ovmf_vars_runtime" ]; then cp "$ovmf_vars" "$ovmf_vars_runtime"; fi; \
            qemu-system-x86_64 \
                -machine q35 \
                -cpu qemu64 \
                -m 512M \
                -serial stdio \
                -drive if=pflash,format=raw,readonly=on,file="$ovmf_code" \
                -drive if=pflash,format=raw,file="$ovmf_vars_runtime" \
                -drive file={{builddir}}/saltyos-uefi.img,format=raw \
                -no-reboot \
                -no-shutdown \
                -d int,cpu_reset \
                -D qemu.log; \
        else \
            qemu-system-x86_64 \
                -machine q35 \
                -cpu qemu64 \
                -m 512M \
                -serial stdio \
                -bios "$ovmf_code" \
                -drive file={{builddir}}/saltyos-uefi.img,format=raw \
                -no-reboot \
                -no-shutdown \
                -d int,cpu_reset \
                -D qemu.log; \
        fi'

# Run with debug output (headless, no GUI window)
run-debug-headless: build
    qemu-system-x86_64 \
        -machine q35 \
        -cpu qemu64 \
        -m 512M \
        -serial stdio \
        -display none \
        -drive file={{builddir}}/saltyos.img,format=raw,if=none,id=disk \
        -device ahci,id=ahci \
        -device ide-hd,drive=disk,bus=ahci.0 \
        -no-reboot \
        -no-shutdown \
        -d int,cpu_reset \
        -D qemu.log

# Run UEFI with debug output (headless, no GUI window)
run-uefi-debug-headless: image-uefi
    bash -eu -c '\
        ovmf_code="${OVMF_CODE:-}"; \
        ovmf_vars="${OVMF_VARS:-}"; \
        if [ -z "$ovmf_code" ]; then \
            for cand in /usr/share/edk2-ovmf/OVMF_CODE.fd /usr/share/OVMF/OVMF_CODE_4M.fd /usr/share/ovmf/OVMF.fd /usr/share/qemu/OVMF.fd; do \
                if [ -f "$cand" ]; then ovmf_code="$cand"; break; fi; \
            done; \
        fi; \
        if [ -z "$ovmf_vars" ]; then \
            for cand in /usr/share/edk2-ovmf/OVMF_VARS.fd /usr/share/OVMF/OVMF_VARS_4M.fd /usr/share/OVMF/OVMF_VARS.fd; do \
                if [ -f "$cand" ]; then ovmf_vars="$cand"; break; fi; \
            done; \
        fi; \
        if [ -z "$ovmf_code" ]; then \
            echo "OVMF firmware not found. Set OVMF_CODE (and optionally OVMF_VARS)." >&2; \
            exit 1; \
        fi; \
        if [ -n "$ovmf_vars" ] && [ -f "$ovmf_vars" ]; then \
            ovmf_vars_runtime="{{builddir}}/OVMF_VARS.fd"; \
            if [ ! -f "$ovmf_vars_runtime" ]; then cp "$ovmf_vars" "$ovmf_vars_runtime"; fi; \
            qemu-system-x86_64 \
                -machine q35 \
                -cpu qemu64 \
                -m 512M \
                -serial stdio \
                -display none \
                -drive if=pflash,format=raw,readonly=on,file="$ovmf_code" \
                -drive if=pflash,format=raw,file="$ovmf_vars_runtime" \
                -drive file={{builddir}}/saltyos-uefi.img,format=raw \
                -no-reboot \
                -no-shutdown \
                -d int,cpu_reset \
                -D qemu.log; \
        else \
            qemu-system-x86_64 \
                -machine q35 \
                -cpu qemu64 \
                -m 512M \
                -serial stdio \
                -display none \
                -bios "$ovmf_code" \
                -drive file={{builddir}}/saltyos-uefi.img,format=raw \
                -no-reboot \
                -no-shutdown \
                -d int,cpu_reset \
                -D qemu.log; \
        fi'

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
      -DCMAKE_INSTALL_PREFIX="$SALTYOS_TOOLCHAIN_PREFIX"
    ninja -C "$SALTYOS_LLVM_BUILD_DIR" -j"$(nproc)"
    ninja -C "$SALTYOS_LLVM_BUILD_DIR" install
    if [ ! -x "$SALTYOS_TOOLCHAIN_PREFIX/bin/FileCheck" ] && [ -x "$SALTYOS_LLVM_BUILD_DIR/bin/FileCheck" ]; then
      ln -sf "$SALTYOS_LLVM_BUILD_DIR/bin/FileCheck" "$SALTYOS_TOOLCHAIN_PREFIX/bin/FileCheck"
      echo "Linked FileCheck into prefix:"
      echo "  $SALTYOS_TOOLCHAIN_PREFIX/bin/FileCheck -> $SALTYOS_LLVM_BUILD_DIR/bin/FileCheck"
    fi

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
    python3 "$SALTYOS_RUST_SRC_DIR/x.py" build \
      --src "$SALTYOS_RUST_SRC_DIR" \
      --build-dir "$SALTYOS_RUST_BUILD_DIR" \
      --config "$config_path" \
      --stage 1 \
      library
    ln -sf "$SALTYOS_RUST_BUILD_DIR/x86_64-unknown-linux-gnu/stage1/bin/rustc" \
           "$SALTYOS_TOOLCHAIN_PREFIX/bin/rustc"
    echo "Linked stage1 rustc into prefix:"
    echo "  $SALTYOS_TOOLCHAIN_PREFIX/bin/rustc -> $SALTYOS_RUST_BUILD_DIR/x86_64-unknown-linux-gnu/stage1/bin/rustc"

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

# Run with virtio-blk data disk (requires test_data.img — run `just mksaltyfs` first)
run-blk: build
    qemu-system-x86_64 \
        -machine q35 \
        -cpu qemu64 \
        -m 512M \
        -serial stdio \
        -drive file={{builddir}}/saltyos.img,format=raw,if=none,id=disk \
        -device ahci,id=ahci \
        -device ide-hd,drive=disk,bus=ahci.0 \
        -drive file=test_data.img,format=raw,if=none,id=datadisk \
        -device virtio-blk-pci,drive=datadisk \
        -no-reboot \
        -no-shutdown

# Run with virtio-blk and SMP
run-blk-smp: build
    qemu-system-x86_64 \
        -machine q35 \
        -cpu qemu64 \
        -smp 2 \
        -m 512M \
        -serial stdio \
        -drive file={{builddir}}/saltyos.img,format=raw,if=none,id=disk \
        -device ahci,id=ahci \
        -device ide-hd,drive=disk,bus=ahci.0 \
        -drive file=test_data.img,format=raw,if=none,id=datadisk \
        -device virtio-blk-pci,drive=datadisk \
        -no-reboot \
        -no-shutdown

# Run with virtio-net NIC
run-net: build
    qemu-system-x86_64 \
        -machine q35 \
        -cpu qemu64 \
        -m 512M \
        -serial stdio \
        -drive file={{builddir}}/saltyos.img,format=raw,if=none,id=disk \
        -device ahci,id=ahci \
        -device ide-hd,drive=disk,bus=ahci.0 \
        -netdev user,id=net0 \
        -device virtio-net-pci,netdev=net0 \
        -no-reboot \
        -no-shutdown

# Create a new component skeleton
new-component NAME:
    @echo "Creating component: {{NAME}}"
    mkdir -p userland/{{NAME}}/src
    @echo "Component {{NAME}} created in userland/{{NAME}}"
