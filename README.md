# SaltyOS

A Unix-like microkernel operating system written in Rust, with a custom 3-stage bootloader in Assembly and C.

## Overview

SaltyOS is a capability-based microkernel designed with security and modularity as primary goals. It draws inspiration from seL4, L4, and Minix3, implementing a minimal trusted computing base with most system services running in userspace.

### Key Features

- **Microkernel Architecture**: Only essential services (scheduling, IPC, memory management, capabilities) run in kernel space
- **Capability-Based Security**: All resource access is mediated through unforgeable capability tokens
- **Fat Capabilities**: Extended capability format with rich metadata for fine-grained access control
- **Synchronous IPC + Notifications**: Fast rendezvous-style IPC with lightweight async signaling
- **EDF Scheduler**: Earliest Deadline First scheduling for real-time workload support
- **Multi-Architecture**: Designed for x86_64 with aarch64 support planned
- **Custom Bootloader**: 3-stage bootloader supporting both BIOS and UEFI
- **SaltyFS**: Copy-on-write filesystem with snapshot support (userspace driver)

## Project Status

🚧 **Early Development** - Not yet bootable

Current focus:
- [ ] Stage 1/2 bootloader (BIOS + UEFI)
- [ ] Basic kernel entry and serial output
- [ ] Memory management (physical + virtual)
- [ ] Capability system foundation

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Userspace                               │
├─────────────┬─────────────┬─────────────┬─────────────┬────────┤
│    init     │   procmgr   │     vfs     │   drivers   │  apps  │
│             │             │   saltyfs   │  (pci,nvme) │        │
└──────┬──────┴──────┬──────┴──────┬──────┴──────┬──────┴────────┘
       │             │             │             │
       │         IPC (Endpoints + Notifications) │
       │             │             │             │
┌──────┴─────────────┴─────────────┴─────────────┴───────────────┐
│                     SaltyOS Microkernel                        │
├────────────┬────────────┬────────────┬────────────┬────────────┤
│ Capability │    IPC     │  Scheduler │   Memory   │    Arch    │
│   System   │ Endpoints  │    (EDF)   │ Management │  (x86_64)  │
└────────────┴────────────┴────────────┴────────────┴────────────┘
```

## Building

### Prerequisites

- Rust toolchain (nightly)
- Meson build system (>= 1.1)
- Ninja
- NASM assembler
- GCC or Clang (cross-compiler for target arch)
- QEMU (for testing)

### Quick Start

```bash
# Install Rust nightly
rustup install nightly
rustup default nightly
rustup component add rust-src

# Configure build
just setup

# Build
just build

# Run in QEMU
just run
```

### Build Options

```bash
# Configure for different architecture
just setup-aarch64

# Enable debug symbols
just reconfigure -Ddebug_symbols=true

# Change log level
just reconfigure -Dkernel_log_level=debug
```

## Documentation

- [Architecture Overview](docs/ARCHITECTURE.md)
- [Building Guide](docs/BUILDING.md)
- [Design Documents](docs/design/)
  - [Design Overview](docs/design/overview.md)
  - [Bootloader](docs/design/bootloader.md)
  - [Kernel](docs/design/kernel.md)
  - [Capability System](docs/design/capability.md)
  - [IPC](docs/design/ipc.md)
  - [Scheduling](docs/design/scheduling.md)
  - [Memory Management](docs/design/memory.md)
  - [SaltyFS](docs/design/saltyfs.md)
- [Specifications](docs/spec/)
  - [System Calls](docs/spec/syscalls.md)
  - [Boot Protocol](docs/spec/boot_protocol.md)
  - [ABI](docs/spec/abi.md)

## Project Structure

```
SaltyOS/
├── boot/                   # 3-stage bootloader
│   ├── stage1/             # MBR/UEFI entry (ASM)
│   ├── stage2/             # Protected/Long mode setup (C)
│   ├── stage3/             # Filesystem + kernel loader (C)
│   └── common/             # Shared utilities
├── kernel/                 # Rust microkernel
│   └── src/
│       ├── arch/           # Architecture-specific code
│       ├── cap/            # Capability system
│       ├── ipc/            # IPC subsystem
│       ├── mm/             # Memory management
│       ├── sched/          # Scheduler
│       └── syscall/        # System call handlers
├── userland/               # Userspace servers
│   ├── init/               # First process
│   ├── procmgr/            # Process manager
│   ├── vfs/                # VFS server
│   └── drivers/            # Userspace drivers
├── lib/                    # Shared libraries
│   ├── libsalty/           # System call wrappers
│   └── libc/               # Minimal C library
├── tools/                  # Build utilities
│   └── cross/              # Cross-compilation configs
└── docs/                   # Documentation
```

## Design Philosophy

### What the Kernel Does

- Thread management and scheduling (EDF)
- Synchronous IPC (endpoints) and async notifications
- Virtual address space management (VSpace)
- Physical memory allocation and mapping
- Capability-based access control
- IRQ routing to userspace
- Kernel object lifecycle management

### What the Kernel Does NOT Do

- Filesystem (VFS is a userspace server)
- Network stack
- Device drivers (userspace, with mapped MMIO)
- Process management policy (userspace procmgr)
- Access control policy (enforced via capabilities)

## Contributing

Contributions are welcome! Please read the design documents first to understand the architecture.

## License

This project is licensed under the GNU General Public License v2.0 only (GPL-2.0-only).

See [LICENSE.md](LICENSE.md) for the full license text.

## Acknowledgments

SaltyOS draws inspiration from:

- [seL4](https://sel4.systems/) - Capability system, IPC design
- [L4 family](https://en.wikipedia.org/wiki/L4_microkernel_family) - Microkernel principles
- [Minix3](https://www.minix3.org/) - Userspace drivers
- [Redox OS](https://www.redox-os.org/) - Rust OS development
