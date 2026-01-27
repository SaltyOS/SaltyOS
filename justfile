# SaltyOS Build Commands
# SPDX-License-Identifier: GPL-2.0-only

# Default target architecture
arch := "x86_64"

# Build directory
builddir := "build"

# =============================================================================
# Setup & Configuration
# =============================================================================

# Configure the build (run once)
setup:
    meson setup {{builddir}} \
        -Darch={{arch}} \
        -Dbuild_boot=true \
        -Dbuild_kernel=true \
        -Dbuild_userland=false

# Configure for x86_64
setup-x86_64:
    meson setup {{builddir}}-x86_64 \
        -Darch=x86_64 \
        -Dbuild_boot=true \
        -Dbuild_kernel=true

# Configure for aarch64
setup-aarch64:
    meson setup {{builddir}}-aarch64 \
        -Darch=aarch64 \
        -Dbuild_boot=true \
        -Dbuild_kernel=true

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
run-uefi: build
    qemu-system-x86_64 \
        -machine q35 \
        -cpu qemu64 \
        -m 512M \
        -serial stdio \
        -bios /usr/share/OVMF/OVMF_CODE.fd \
        -drive file={{builddir}}/saltyos.img,format=raw \
        -no-reboot \
        -no-shutdown

# =============================================================================
# Testing
# =============================================================================

# Run unit tests (host)
test:
    meson test -C {{builddir}}

# Run integration tests in QEMU
test-integration: build
    @echo "Integration tests not yet implemented"

# =============================================================================
# Utilities
# =============================================================================

# Create disk image
image: build
    meson compile -C {{builddir}} disk_image

# Show build configuration
info:
    meson configure {{builddir}}

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
# Development Helpers
# =============================================================================

# Watch for changes and rebuild
watch:
    watchexec -e rs,c,h,asm just build

# Quick rebuild and run
rr: build run

# Create a new component skeleton
new-component NAME:
    @echo "Creating component: {{NAME}}"
    mkdir -p userland/{{NAME}}/src
    @echo "Component {{NAME}} created in userland/{{NAME}}"
