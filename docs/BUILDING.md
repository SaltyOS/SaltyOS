# Building SaltyOS

This document provides detailed instructions for building SaltyOS from source.

## Prerequisites

### Required Tools

| Tool | Version | Purpose |
|------|---------|---------|
| Meson | >= 1.1 | Build system |
| Ninja | >= 1.10 | Build backend |
| Rust | nightly | Kernel development (edition 2024, with `rust-src` component) |
| NASM | >= 2.15 | x86 assembly |
| Clang | >= 11 | C compiler (required; GCC is not supported) |
| GNU ld / LLD | latest | Linker |

> **Note:** If `clang` is not your default C compiler, set `CC=clang` before
> running `just setup` or `meson setup`, e.g. `CC=clang just setup`.

### Optional Tools

| Tool | Purpose |
|------|---------|
| QEMU | Running and testing (qemu-system-x86_64, qemu-system-aarch64) |
| GDB | Debugging |
| just | Task runner (convenience) |
| OVMF / AAVMF | UEFI testing (x86_64 / aarch64) |
| xorriso | ISO image creation |
| mtools | FAT image manipulation |

## Installation

### Arch Linux

```bash
# Core tools
sudo pacman -S meson ninja nasm clang lld

# Rust (use rustup for nightly)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup default nightly
rustup component add rust-src llvm-tools-preview

# Testing/debugging
sudo pacman -S qemu-system-x86 qemu-system-aarch64 gdb ovmf

# Optional
sudo pacman -S just xorriso mtools
```

### Ubuntu/Debian

```bash
# Core tools
sudo apt update
sudo apt install meson ninja-build nasm clang lld

# Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup default nightly
rustup component add rust-src llvm-tools-preview

# Testing/debugging
sudo apt install qemu-system-x86 qemu-system-arm gdb ovmf

# Optional (just is not in default repos)
cargo install just
sudo apt install xorriso mtools
```

### Fedora

```bash
# Core tools
sudo dnf install meson ninja-build nasm clang lld

# Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup default nightly
rustup component add rust-src llvm-tools-preview

# Testing/debugging
sudo dnf install qemu-system-x86 qemu-system-aarch64 gdb edk2-ovmf edk2-aarch64

# Optional
cargo install just
sudo dnf install xorriso mtools
```

### macOS

```bash
# Homebrew
brew install meson ninja nasm llvm

# Clang from Homebrew includes cross-compilation support.
# Add LLVM to PATH (Homebrew's clang):
export PATH="$(brew --prefix llvm)/bin:$PATH"

# Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup default nightly
rustup component add rust-src llvm-tools-preview

# QEMU
brew install qemu

# Optional
brew install just xorriso mtools
```

## Building

### Quick Start

Using `just` (recommended):

```bash
# Configure and build (defaults to x86_64)
just setup
just build

# Run in QEMU
just run
```

Using Meson directly:

```bash
# Configure
meson setup build-x86_64

# Build
meson compile -C build-x86_64

# Or using ninja directly
ninja -C build-x86_64
```

### Multi-Architecture Builds

The `arch` variable (default: `x86_64`) controls the target for all just recipes. Build directories are arch-qualified (`build-x86_64`, `build-aarch64`).

```bash
# aarch64 build
just arch=aarch64 setup
just arch=aarch64 build
just arch=aarch64 run          # aarch64 forces UEFI

# The arch= prefix works with any recipe
just arch=aarch64 reconfigure -Dkernel_log_level=debug
just arch=aarch64 port bash
just arch=aarch64 tc build host llvm
```

aarch64 is **UEFI-only** (no BIOS bootloader). QEMU uses `virt,gic-version=3` machine with Cortex-A72 CPU.

### Configuration Options

View all options:

```bash
meson configure build-x86_64
```

Available options:

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `arch` | combo | x86_64 | Target architecture (`x86_64`, `aarch64`) |
| `build_boot` | bool | true | Build the bootloader |
| `build_kernel` | bool | true | Build the microkernel |
| `build_userland` | bool | false | Build userland components |
| `build_ports` | bool | false | Build port packages (requires `build_userland=true`) |
| `build_libcxx` | combo | auto | Build libc++.so (`auto`=detect llvm-project, `true`=require, `false`=skip) |
| `debug_serial` | bool | true | Enable serial debugging |
| `debug_symbols` | bool | true | Include debug symbols |
| `kernel_log_level` | combo | info | Kernel log verbosity (`error`, `warn`, `info`, `debug`, `trace`) |
| `userland_log_level` | combo | info | Userland log verbosity (`error`, `warn`, `info`, `debug`, `trace`) |
| `kernel_debug_modules` | string | (empty) | Comma-separated kernel modules for debug logging (e.g., `mm,ipc,syscall,arch,cap,sched,console`) |
| `userland_debug_programs` | string | (empty) | Comma-separated userland programs for debug logging (e.g., `procmgr,mmsrv,vfs,netsrv`) |
| `max_cpus` | int | 16 | Maximum supported CPUs (1-256) |
| `kernel_stack_size` | int | 16384 | Kernel stack size per thread (4096-65536) |

Reconfigure:

```bash
# Enable userland build
just reconfigure -Dbuild_userland=true

# Set kernel debug level and per-module debug logging
just reconfigure -Dkernel_log_level=debug -Dkernel_debug_modules=mm,ipc,syscall

# Set userland debug level with per-program granularity
just reconfigure -Duserland_log_level=debug -Duserland_debug_programs=procmgr,mmsrv,vfs

# Combined example for aarch64
just arch=aarch64 reconfigure -Dkernel_log_level=debug -Duserland_log_level=debug
```

### Build Targets

```bash
# Build everything
just build

# Verbose build
just build-verbose

# Create disk images
just image              # BIOS disk image
just image-uefi         # UEFI disk image
just mkrootfs           # Rootfs image (binaries + optional LLVM/ports)
just mksaltyfs          # SaltyFS test image
```

## Running

### QEMU Options

All QEMU options are passed as flags to `just run` and can be combined:

```bash
just run                           # Default: BIOS, single CPU, 512M
just run --smp 2                   # Run with 2 CPUs
just run --smp 4                   # Run with 4 CPUs
just run --uefi                    # Boot with UEFI firmware
just run --gdb                     # Start GDB server (-s -S)
just run --debug                   # Interrupt/reset logging (qemu.log)
just run --headless                # Serial only, no GUI
just run --mem 1G                  # Custom memory size
just run --extra-disk FILE         # Attach additional virtio-blk disk

# Combining flags
just run --smp 4 --uefi --headless --debug

# aarch64 (always UEFI)
just arch=aarch64 run --smp 2
```

### QEMU Network Options

```bash
just run --no-net                  # Skip virtio-net attachment
just run --net-mode user           # User-mode networking (default)
just run --net-mode tap            # TAP device
just run --net-mode vmnet-bridged  # macOS vmnet bridged
just run --tap-ifname tap0         # Custom TAP interface name
just run --vmnet-ifname en0        # Host interface for vmnet-bridged
```

### UTM (macOS)

```bash
just run --utm                     # Build + run via UTM on macOS
just run --utm --no-hvf            # Disable Hypervisor.framework (use TCG)
just run --utm --utm-name MyVM     # Custom UTM VM name
```

### Manual QEMU (x86_64 BIOS)

```bash
qemu-system-x86_64 \
    -machine q35 \
    -cpu qemu64 \
    -m 512M \
    -serial stdio \
    -drive file=build-x86_64/saltyos.img,format=raw,if=none,id=disk \
    -device ahci,id=ahci \
    -device ide-hd,drive=disk,bus=ahci.0 \
    -no-reboot
```

### Manual QEMU (x86_64 UEFI)

```bash
qemu-system-x86_64 \
    -machine q35 \
    -cpu qemu64 \
    -m 512M \
    -serial stdio \
    -bios /usr/share/edk2-ovmf/OVMF_CODE.fd \
    -drive file=build-x86_64/saltyos-uefi.img,format=raw \
    -no-reboot
```

## Debugging

### GDB Debugging

Terminal 1 - Start QEMU with GDB server:

```bash
just run --gdb
```

Terminal 2 - Connect GDB:

```bash
just gdb

# Or manually:
gdb -ex "target remote localhost:1234" \
    -ex "symbol-file build-x86_64/kernite/kernite.elf"
```

### GDB Commands

```gdb
# Set breakpoint at kernel entry
break kmain

# Continue execution
continue

# Step through instructions
stepi

# Examine registers
info registers

# Examine memory
x/16x 0xFFFFFFFF80000000

# Backtrace
bt
```

### QEMU Debug Logging

```bash
just run --debug

# Creates qemu.log with interrupt and CPU reset traces
```

### Serial Output

The kernel outputs debug messages to COM1 (serial port). QEMU redirects this to stdio by default with `-serial stdio`.

## Directory Structure

After building:

```
build-x86_64/                    # (or build-aarch64/)
├── boot/
│   ├── stage1/
│   │   ├── mbr.bin              # BIOS MBR (512 bytes)
│   │   └── uefi.efi            # UEFI application
│   ├── stage2/
│   │   └── stage2.bin           # Mode switch + loader
│   └── stage3/
│       └── stage3.bin           # Kernel loader
├── kernite/
│   └── kernite.elf              # Microkernel binary
├── userland/                    # (if build_userland=true)
│   ├── init
│   └── ...
├── ports/                       # (if build_ports=true)
│   └── ...
└── saltyos.img                  # Bootable disk image
```

## Ports

Third-party software is built via declarative `.port` files in `ports/`. The port build tool (`tools/port/`) handles fetching, configuring, building, and installing.

Currently available ports (16): bash, bzip2, curl, freebsd-utils, make, nano, nasm, ncurses, ninja, openssl, perl, python, wget, xz, zlib, zstd.

```bash
just port bash                   # Build a specific port
just fetch-ports                 # Download all port sources
just port-info bash              # Show port configuration
just clean-ports                 # Remove port build artifacts

# aarch64 ports
just arch=aarch64 port bash
```

See [Ports Build System](design/ports.md) for the full `.port` format specification, how to add new ports, and C standard library details.

## Troubleshooting

### Rust Errors

**"can't find crate for `core`"**

```bash
rustup component add rust-src
```

**"error: linker `rust-lld` not found"**

```bash
rustup component add llvm-tools-preview
```

### Meson Errors

**"Program 'rustc' not found"**

Ensure Rust is in your PATH:

```bash
source ~/.cargo/env
```

**"Program 'nasm' not found"**

Install NASM for your platform (see Prerequisites).

### QEMU Errors

**"Could not access KVM kernel module"**

Run without KVM acceleration:

```bash
qemu-system-x86_64 ... -accel tcg
```

Or enable KVM:

```bash
sudo modprobe kvm
sudo modprobe kvm_intel  # or kvm_amd
```

**"Could not find OVMF firmware"**

Install OVMF and check path:

```bash
# Arch
ls /usr/share/OVMF/

# Ubuntu
ls /usr/share/OVMF/

# Fedora
ls /usr/share/edk2/ovmf/
```

### Build Hangs

If the build seems stuck, try verbose mode:

```bash
just build-verbose
```

This shows each command being executed.

## Development Workflow

### Recommended Workflow

1. Make changes to source files
2. Build: `just build`
3. Test: `just run`
4. Debug (if needed): `just run --gdb` + `just gdb`
5. Repeat

### Watch Mode

For continuous rebuilding on file changes:

```bash
just watch
```

Requires `watchexec`:

```bash
cargo install watchexec-cli
```

### Quick Rebuild and Run

```bash
just rr
```

This is equivalent to `just build && just run`.

## CI/CD Notes

For CI environments:

```bash
# Install dependencies (example for Ubuntu)
sudo apt-get update
sudo apt-get install -y meson ninja-build nasm clang lld

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source ~/.cargo/env
rustup default nightly
rustup component add rust-src llvm-tools-preview

# Build
just setup
just build

# Headless test
just run --headless --debug
```

## See Also

- [README.md](../README.md) - Project overview
- [ARCHITECTURE.md](ARCHITECTURE.md) - System architecture
- [TOOLCHAIN.md](TOOLCHAIN.md) - Building the patched LLVM/Clang and Rust toolchain
- [design/](design/) - Design documents
- [spec/](spec/) - Technical specifications
