# Building SaltyOS

This document provides detailed instructions for building SaltyOS from source.

## Prerequisites

### Required Tools

| Tool | Version | Purpose |
|------|---------|---------|
| Meson | >= 1.1 | Build system |
| Ninja | >= 1.10 | Build backend |
| Rust | nightly | Kernel development |
| NASM | >= 2.15 | x86 assembly |
| Clang | >= 11 | C compiler (required; GCC is not supported) |
| GNU ld / LLD | latest | Linker |

> **Note:** If `clang` is not your default C compiler, set `CC=clang` before
> running `just setup` or `meson setup`, e.g. `CC=clang just setup`.

### Optional Tools

| Tool | Purpose |
|------|---------|
| QEMU | Running and testing |
| GDB | Debugging |
| just | Task runner (convenience) |
| OVMF | UEFI testing |
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
sudo pacman -S qemu-system-x86 gdb ovmf

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
sudo apt install qemu-system-x86 gdb ovmf

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
sudo dnf install qemu-system-x86 gdb edk2-ovmf

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
# Configure and build
just setup
just build

# Run in QEMU
just run
```

Using Meson directly:

```bash
# Configure
meson setup build

# Build
meson compile -C build

# Or using ninja directly
ninja -C build
```

### Configuration Options

View all options:

```bash
meson configure build
```

Available options:

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `arch` | combo | x86_64 | Target architecture (x86_64) |
| `build_boot` | bool | true | Build the bootloader |
| `build_kernel` | bool | true | Build the microkernel |
| `build_userland` | bool | false | Build userland components |
| `debug_serial` | bool | true | Enable serial debugging |
| `debug_symbols` | bool | true | Include debug symbols |
| `kernel_log_level` | combo | info | Log verbosity (error, warn, info, debug, trace) |
| `max_cpus` | int | 16 | Maximum supported CPUs |
| `kernel_stack_size` | int | 16384 | Kernel stack size per thread |

Reconfigure:

```bash
# Enable userland build
meson configure build -Dbuild_userland=true

# Set debug level
meson configure build -Dkernel_log_level=debug
```

### Cross-Compilation

For cross-compiling (e.g., building on a different host architecture):

```bash
meson setup build --cross-file tools/cross/x86_64.txt
```

### Build Targets

```bash
# Build everything
meson compile -C build

# Build specific component
meson compile -C build kernel
meson compile -C build boot

# Create disk image
meson compile -C build disk_image

# Verbose build
meson compile -C build -v
```

## Running

### QEMU (BIOS)

```bash
just run

# Or manually:
qemu-system-x86_64 \
    -machine q35 \
    -cpu qemu64 \
    -m 512M \
    -serial stdio \
    -drive file=build/saltyos.img,format=raw,if=none,id=disk \
    -device ahci,id=ahci \
    -device ide-hd,drive=disk,bus=ahci.0 \
    -no-reboot
```

### QEMU (UEFI)

```bash
just run-uefi

# Or manually:
qemu-system-x86_64 \
    -machine q35 \
    -cpu qemu64 \
    -m 512M \
    -serial stdio \
    -bios /usr/share/edk2-ovmf/OVMF_CODE.fd \
    -drive file=build/saltyos-uefi.img,format=raw \
    -no-reboot
```

## Debugging

### GDB Debugging

Terminal 1 - Start QEMU with GDB server:

```bash
just run-gdb
```

Terminal 2 - Connect GDB:

```bash
just gdb

# Or manually:
gdb -ex "target remote localhost:1234" \
    -ex "symbol-file build/kernel/kernel.elf"
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
just run-debug

# Creates qemu.log with interrupt and CPU reset traces
```

### Serial Output

The kernel outputs debug messages to COM1 (serial port). QEMU redirects this to stdio by default with `-serial stdio`.

## Directory Structure

After building:

```
build/
├── boot/
│   ├── stage1/
│   │   ├── mbr.bin          # BIOS MBR (512 bytes)
│   │   └── uefi.efi         # UEFI application
│   ├── stage2/
│   │   └── stage2.bin       # Mode switch + loader
│   └── stage3/
│       └── stage3.bin       # Kernel loader
├── kernel/
│   └── kernel.elf           # Microkernel binary
├── userland/                 # (if build_userland=true)
│   ├── init
│   └── ...
└── saltyos.img              # Bootable disk image
```

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
meson compile -C build -v
```

This shows each command being executed.

## Ports

When `build_userland=true`, the build system automatically discovers and cross-compiles third-party C software from `ports/`. Each port is defined by a declarative `.port` file and built by the `portbuild` host tool.

Currently available ports: GNU Bash 5.2.32, FreeBSD utilities (22 programs: echo, cat, ls, cp, mv, rm, etc.).

See [Ports Build System](design/ports.md) for the full `.port` format specification, how to add new ports, and C standard library details.

## Development Workflow

### Recommended Workflow

1. Make changes to source files
2. Build: `just build`
3. Test: `just run`
4. Debug (if needed): `just run-gdb` + `just gdb`
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

This is equivalent to `just build run`.

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
meson setup build
meson compile -C build

# Run tests (when available)
meson test -C build
```

## See Also

- [README.md](../README.md) - Project overview
- [ARCHITECTURE.md](ARCHITECTURE.md) - System architecture
- [design/](design/) - Design documents
- [spec/](spec/) - Technical specifications
