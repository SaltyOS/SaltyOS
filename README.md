# SaltyOS

A Unix-like microkernel operating system written in Rust, targeting x86_64 architecture with multi-architecture extensibility.

## Overview

SaltyOS is designed with a clean separation between kernel primitives and userspace services, following a capability-based security model. The project aims to create a secure, modular operating system with innovative features like external paging and a clean userspace driver architecture.

## Features

- **Microkernel Architecture**: Minimal kernel with userspace services
- **Capability-Based Security**: Fine-grained access control via capabilities
- **External Pager Model**: Userspace-controlled memory management
- **Multi-ABI Design**: SKA, SSABI, SSIP protocols for layered communication
- **UEFI & BIOS Support**: Boot on both firmware types

## Project Structure

```
SaltyOS/
├── abi/             # Application Binary Interfaces (SKA, SSABI, SSIP)
├── bootloader/      # UEFI and BIOS bootloaders
├── kernel/          # Microkernel core
├── scripts/         # Build and run scripts
├── target-specs/    # Custom Rust target specifications
└── docs/            # Design documentation
```

## Quick Start

### Prerequisites

```bash
# Rust toolchain
rustup install stable
rustup component add rust-src
cargo install cargo-build-std

# Build tools
nasm              # For BIOS bootloader
qemu-system-x86_64  # For testing
```

### Building

```bash
./scripts/build.sh
```

This generates disk images in the `build/` directory:
- `saltyos-uefi.img` - UEFI bootable image
- `saltyos-bios.img` - BIOS bootable image

### Running in QEMU

```bash
# UEFI mode
./scripts/run-qemu-uefi.sh

# BIOS mode
./scripts/run-qemu-bios.sh
```

## Architecture

### Layered Design

```
┌─────────────────────────────────────┐
│         Userspace Applications       │
├─────────────────────────────────────┤
│         POSIX Emulation (libc)       │
├─────────────────────────────────────┤
│       Userspace Servers              │
│  (FS, Graphics, Device Drivers)      │
├─────────────────────────────────────┤
│         SSIP (IPC Protocol)          │
├─────────────────────────────────────┤
│      SSABI (Syscall Interface)       │
├─────────────────────────────────────┤
│         Microkernel                  │
│  (Threads, IPC, Capabilities)        │
├─────────────────────────────────────┤
│         Hardware Abstraction         │
└─────────────────────────────────────┘
```

### Custom ABIs

- **SKA** (SaltyKernel ABI): Bootloader to kernel contract
- **SSABI** (SaltySys ABI): Minimal syscall interface
- **SSIP** (SaltySys IPC): Userspace service protocol

## Development Phases

| Phase | Status | Description |
|-------|--------|-------------|
| 1 | ✅ Complete | Boot, SKA BootInfo, basic SSABI |
| 2 | ✅ Complete | Timer, interrupts, PCI |
| 3 | Planned | External pager, thread management |
| 4 | Planned | SSIP protocol, device manager |
| 5-7 | Planned | Userspace servers, SaltyFS |
| 8+ | Planned | Multi-arch, security hardening |

## Documentation

See `docs/implementation.md` for detailed design documentation.

## Contributing

This project follows:
- Rust Edition 2024
- `#![no_std]` for kernel code
- Capability-based security principles
- Phase-driven development

## License

Copyright (c) 2026 Hamin Sung a.k.a saltyming

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

See [LICENSE.md](LICENSE.md) for the full text.
