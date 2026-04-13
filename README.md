# SaltyOS

A capability-based microkernel operating system written in Rust, with a custom bootloader in Assembly and C. Dual-architecture (x86_64 + aarch64) with multi-personality subsystem support (POSIX and Win32).

## Overview

SaltyOS is a microkernel designed with security and modularity as primary goals. It draws inspiration from seL4, L4, Minix3, and Fuchsia, implementing a minimal trusted computing base with most system services running in userspace.

### Key Features

- **Microkernel Architecture**: Only essential services (scheduling, IPC, memory management, capabilities) run in kernel space
- **Capability-Based Security**: All resource access is mediated through unforgeable fat capability tokens (32 bytes with inline metadata)
- **Synchronous IPC + Notifications**: Fast rendezvous-style IPC with lightweight async signaling and assembly fastpath for Call/ReplyRecv
- **Multi-Architecture**: Full support for x86_64 (BIOS + UEFI) and aarch64 (UEFI)
- **SMP Support**: Multi-core boot (ACPI MADT on x86_64, PSCI on aarch64), per-CPU scheduling with IPI-driven reschedule (up to 256 CPUs)
- **EDF Scheduler**: Earliest Deadline First scheduling with budget enforcement and CPU affinity
- **Multi-Personality Subsystem**: POSIX and Win32 subsystems running side-by-side, with personality-specific servers
- **POSIX Compatibility**: Signals, pipes, Unix domain sockets, TCP/UDP inet sockets, poll/epoll, shared memory, fork/exec, PTY
- **Win32 Compatibility**: PE/COFF loader, kernel32.dll shim, Win32 console subsystem (csrss)
- **Network Stack**: TCP/UDP/ICMP via smoltcp, DNS resolver, DHCP, virtio-net driver
- **MemoryObject-Based MM**: Fuchsia-inspired MemoryObject abstraction for mmap, file-backed pages, COW fork
- **Custom Bootloader**: 3-stage bootloader supporting both BIOS and UEFI
- **SaltyFS**: Copy-on-write filesystem with B-tree directory indexing and snapshot support
- **C/C++ Standard Library**: basalt libc (stdio, stdlib, string, malloc, termios, regex) and optional libc++
- **Self-Hosting Toolchain**: Patched LLVM/Clang/LLD and rustc cross-compiled for SaltyOS targets
- **Ports System**: 16+ third-party packages buildable for SaltyOS (bash, curl, python, perl, make, etc.)

## Architecture

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                              Userspace                                       │
├──────────────────────────────────────────────────────────────────────────────┤
│  POSIX Personality               │  Win32 Personality                        │
│  ┌────────────────────────────┐  │  ┌─────────────────────────────────────┐  │
│  │ posix_ttysrv  posix_getty  │  │  │ win32_csrss (console + imports)     │  │
│  │ netsrv  dnssrv             │  │  │ kernel32.dll shim                   │  │
│  └────────────────────────────┘  │  └─────────────────────────────────────┘  │
├──────────────────────────────────┴──────────────────────────────────────────┤
│  Core Services                                                               │
│  ┌───────┬─────────┬────────┬─────────┬──────────┬──────────┬─────────────┐  │
│  │ init  │  mmsrv  │procmgr │   vfs   │ nameserv │ console  │    apps     │  │
│  └──┬────┴────┬────┴───┬────┴────┬────┴─────┬────┴─────┬────┴─────────────┘  │
│     │         │        │         │          │          │                      │
│  Drivers: pcidrv, blkdrv, netdrv, dispdrv  │  FS: saltyfs                    │
├──────────────────────────────────┬──────────┴────────────────────────────────┤
│     IPC (Endpoints + Notifications + Fastpath)                               │
├──────────────────────────────────────────────────────────────────────────────┤
│                          SaltyOS Microkernel (kernite)                        │
├──────────┬──────────┬──────────┬──────────┬──────────┬───────────────────────┤
│Capability│   IPC    │Scheduler │  Memory  │   SMP    │ Arch (x86_64/aarch64) │
│  System  │Endpoints │  (EDF)   │ (VSpace, │ (APIC/   │ GDT/IDT/APIC (x86)   │
│ (fat cap)│ + Notif  │          │  MO,COW) │ GIC/IPI) │ GICv3/PSCI (arm)     │
└──────────┴──────────┴──────────┴──────────┴──────────┴───────────────────────┘
```

## Building

### Prerequisites

- Rust nightly with `rust-src` component (edition 2024)
- Clang (required; gcc is not supported)
- NASM assembler
- Meson (>= 1.1) + Ninja
- QEMU (for testing)
- OVMF / AAVMF (for UEFI testing)

### Quick Start

```bash
# Install Rust nightly
rustup install nightly
rustup default nightly
rustup component add rust-src

# Configure and build (defaults to x86_64)
just setup
just build

# Run in QEMU
just run
```

### Build Commands

```bash
just setup                  # Configure build (run once, defaults to x86_64)
just build                  # Build all components
just run                    # Build + run in QEMU (BIOS, single CPU)
just run --smp 2            # Run with 2 CPUs
just run --smp 4            # Run with 4 CPUs
just run --uefi             # Run with UEFI firmware
just run --gdb              # QEMU with GDB server (-s -S)
just run --debug            # Run with interrupt/reset logging (qemu.log)
just run --headless         # Headless (serial only, no GUI)
just rr                     # Quick rebuild + run
just distclean              # Remove all build dirs (needed before re-setup)

# Code quality
just fmt                    # Format Rust (rustfmt) and C (clang-format)
just fmt-check              # Check Rust formatting

# Configuration
just reconfigure -Dkernel_log_level=debug
just reconfigure -Ddebug_symbols=true
```

Flags can be combined: `just run --smp 4 --uefi --headless --debug`.

### Multi-Architecture

```bash
# aarch64 (UEFI-only)
just arch=aarch64 setup
just arch=aarch64 build
just arch=aarch64 run
```

Build directories are arch-qualified (`build-x86_64`, `build-aarch64`). The `arch=` prefix applies to any recipe.

### Custom Toolchain

```bash
just tc all                 # Build host Clang/LLD + rustc
just self-host              # Cross-compile toolchain for SaltyOS
```

See [Toolchain Guide](docs/TOOLCHAIN.md) for details.

### Ports

Third-party software built via declarative `.port` files:

```bash
just port bash              # Build a port
just fetch-ports            # Download all sources
```

Available ports: bash, bzip2, curl, freebsd-utils, make, nano, nasm, ncurses, ninja, openssl, perl, python, wget, xz, zlib, zstd.

## Project Structure

```
SaltyOS/
├── boot/                          # 3-stage bootloader (BIOS + UEFI)
│   ├── stage1/                    # MBR / UEFI PE/COFF entry
│   ├── stage2/                    # Mode setup (protected/long mode, identity map)
│   ├── stage3/                    # FS mount, kernel + initrd loading
│   └── common/                    # Shared utilities
├── kernite/                       # Microkernel (Rust)
│   └── src/
│       ├── arch/{x86_64,aarch64}/ # Architecture-specific code
│       ├── cap/                   # Capability system (CNode, CDT, Untyped, IoPort)
│       ├── ipc/                   # Endpoints, Notifications, Futex, IRQ routing
│       ├── mm/                    # VSpace, MemoryObject, COW, Bitmap PMM
│       ├── sched/                 # EDF scheduler, TCB, PIP, sleep queue
│       └── syscall/               # 28 syscalls, invoke dispatch, IPC fastpath
├── userland/                      # Userspace programs (domain-based layout)
│   ├── core/                      # Core infrastructure
│   │   ├── init/                  # First process (service-based bootstrap)
│   │   ├── mmsrv/                 # Memory manager server
│   │   ├── procmgr/              # Process manager (spawn/exit/waitpid)
│   │   ├── namesrv/              # Name service (endpoint lookup)
│   │   └── vfs/                   # Virtual filesystem server
│   ├── servers/                   # Service daemons
│   │   ├── console/               # Serial console server
│   │   ├── netsrv/                # TCP/UDP network stack (smoltcp)
│   │   ├── dnssrv/                # DNS resolver
│   │   ├── posix/                 # POSIX personality servers
│   │   │   ├── posix_ttysrv/      # TTY/PTY daemon
│   │   │   └── posix_getty/       # Login prompt
│   │   └── win32/                 # Win32 personality servers
│   │       └── win32_csrss/       # Win32 console + import resolver
│   ├── drivers/                   # Device drivers
│   │   ├── pcidrv/                # PCI enumeration server
│   │   ├── blkdrv/                # Block device driver (virtio-blk)
│   │   ├── netdrv/                # Network driver (virtio-net)
│   │   ├── dispdrv/               # Display driver (framebuffer)
│   │   └── filesystems/saltyfs/   # SaltyFS filesystem server
│   ├── tests/                     # Test programs
│   │   ├── test_runner/           # Automated test suite (16 modules)
│   │   └── hello_pe/              # Win32 PE test program
│   └── services/                  # Service descriptor files (.service)
├── lib/                           # Shared libraries
│   ├── trona/                     # System library (Rust)
│   │   ├── substrate/             # Core kernel ABI (syscalls, IPC, invoke, types)
│   │   ├── uapi/                  # Shared UAPI constants and protocol labels
│   │   ├── posix/                 # POSIX compatibility layer
│   │   ├── win32/                 # Win32 shim (kernel32.dll, console)
│   │   ├── loader/                # ELF/PE/CPIO loaders
│   │   └── rtld/{elf,pe}/         # Runtime dynamic linkers (ELF + PE)
│   └── basalt/                    # C/C++ standard library
│       ├── c/                     # libc.so (basaltc)
│       └── cpp/                   # libc++.so (optional, from LLVM)
├── ports/                         # Third-party software ports
├── toolchain/                     # Custom LLVM + rustc (git submodules)
├── tools/                         # Build utilities (mkcpio, mkimage, port builder)
└── docs/                          # Documentation
```

## Design Philosophy

### What the Kernel Does

- SMP multi-core support (ACPI/PSCI discovery, per-CPU state, IPI reschedule/teardown)
- Thread management and EDF scheduling with budget enforcement and CPU affinity
- Synchronous IPC (endpoints) and async notifications with bound notification support
- Virtual address space management (VSpace) with MemoryObject-based page mapping
- Physical memory allocation (frame allocator, untyped retype, MemoryObject commit/decommit)
- Capability-based access control (fat capabilities, CDT, CNode guard/radix tree)
- Context switching, FPU lazy save/restore, and interrupt handling
- IRQ routing to userspace via notification capabilities
- I/O port access control via IoPort capabilities
- Fault delivery to userspace fault handlers (page fault, cap fault)
- Futex for userspace synchronization primitives

### What the Kernel Does NOT Do

- Filesystem (VFS + SaltyFS are userspace servers)
- Memory allocation policy (mmsrv handles brk/mmap/fork/file-backed pages)
- Network stack (netsrv handles TCP/UDP/ICMP via smoltcp)
- Device drivers (userspace, with mapped MMIO or IoPort caps)
- Process management policy (procmgr handles spawn/exit/signals)
- DNS resolution (dnssrv handles recursive DNS)
- Display management (dispdrv handles framebuffer)
- Terminal/PTY management (posix_ttysrv handles line discipline)

## Testing

```bash
just build                      # Must succeed before any commit
just run                        # Quick smoke test — watch serial for KERNEL PANIC
just run --smp 2                # SMP test — race conditions only show with >1 CPU
just run --smp 4                # Stress test with 4 CPUs
just run --headless --debug     # CI-like testing (serial only, logs to qemu.log)
just fmt-check                  # Check Rust formatting
```

The `test_runner` runs 16 automated test modules (hello, fs, mmap, fork, signal, socket, pipe, time, terminal, epoll, dns, saltyfs, pthread, sse, neon, pe) and prints `PASS`/`FAIL` via serial output.

## Documentation

- [Architecture Overview](docs/ARCHITECTURE.md)
- [Building Guide](docs/BUILDING.md)
- [Toolchain Guide](docs/TOOLCHAIN.md)
- [Design Documents](docs/design/)
  - [Design Overview](docs/design/overview.md)
  - [Bootloader](docs/design/bootloader.md)
  - [Kernel](docs/design/kernel.md)
  - [Capability System](docs/design/capability.md)
  - [IPC](docs/design/ipc.md)
  - [Scheduling](docs/design/scheduling.md)
  - [Memory Management](docs/design/memory.md)
  - [SaltyFS](docs/design/saltyfs.md)
  - [POSIX Compatibility](docs/design/posix.md)
  - [trona System Library](docs/design/trona.md)
  - [basalt C Library](docs/design/basaltc.md)
  - [Memory Manager Server](docs/design/mmsrv.md)
  - [Ports System](docs/design/ports.md)
- [Specifications](docs/spec/)
  - [System Calls](docs/spec/syscalls.md)
  - [ABI](docs/spec/abi.md)
  - [Boot Protocol](docs/spec/boot_protocol.md)

## Contributing

Contributions are welcome! Please read the design documents first to understand the architecture.

## License

Copyright (c) 2026 Hamin Sung a.k.a saltyming

This project is licensed under the GNU General Public License v2.0 only (GPL-2.0-only).

See [LICENSE.md](LICENSE.md) for the full license text.

## Acknowledgments

SaltyOS draws inspiration from:

- [seL4](https://sel4.systems/) - Capability system, IPC design
- [Fuchsia](https://fuchsia.dev/) - MemoryObject design
- [L4 family](https://en.wikipedia.org/wiki/L4_microkernel_family) - Microkernel principles
- [Minix3](https://www.minix3.org/) - Userspace drivers
- [Redox OS](https://www.redox-os.org/) - Rust OS development
- [smoltcp](https://github.com/smoltcp-rs/smoltcp) - TCP/IP stack
