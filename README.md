# SaltyOS

A Unix-like microkernel operating system written in Rust, with a custom 3-stage bootloader in Assembly and C.

## Overview

SaltyOS is a capability-based microkernel designed with security and modularity as primary goals. It draws inspiration from seL4, L4, and Minix3, implementing a minimal trusted computing base with most system services running in userspace.

### Key Features

- **Microkernel Architecture**: Only essential services (scheduling, IPC, memory management, capabilities) run in kernel space
- **Capability-Based Security**: All resource access is mediated through unforgeable capability tokens
- **Fat Capabilities**: Extended capability format with rich metadata for fine-grained access control
- **Synchronous IPC + Notifications**: Fast rendezvous-style IPC with lightweight async signaling
- **SMP Support**: Multi-core boot via ACPI MADT, per-CPU scheduling with IPI-driven reschedule (up to 16 CPUs)
- **EDF Scheduler**: Earliest Deadline First scheduling for real-time workload support
- **Multi-Architecture**: Designed for x86_64 with aarch64 support planned
- **Custom Bootloader**: 3-stage bootloader supporting both BIOS and UEFI
- **POSIX Compatibility Layer**: Signals, pipes, sockets, poll/epoll, shared memory, fork/exec
- **C Standard Library (saltyc)**: Full stdio/stdlib/string/unistd for C program support
- **Terminal Support**: Line discipline with canonical/raw mode, signal generation

## Project Status

### Completed Components

- [x] **3-stage bootloader** (BIOS + UEFI support)
- [x] **Kernel entry** with serial debug output
- [x] **Memory management** (frame allocator, page tables, VSpace)
- [x] **Capability system** (fat caps, CDT, CNode operations: copy/mint/move/mutate/revoke/delete/save_caller)
- [x] **Synchronous IPC** (endpoints with send/recv/call/reply_recv/nbsend)
- [x] **Async notifications** (signal/wait/poll, combined endpoint wait)
- [x] **EDF scheduler** (budget enforcement, deadline-based)
- [x] **Context switching** (full save/restore, per-thread user RSP)
- [x] **Interrupt handling** (IDT, IRQ routing via notifications)
- [x] **System call dispatch** (16 syscalls, capability invocations)
- [x] **ELF loader** (loads userspace from CPIO initrd)
- [x] **Init process** (service-based multi-phase bootstrap)
- [x] **Console server** (serial I/O, line discipline, signal generation)
- [x] **Runtime dynamic linker** (shared library loading)
- [x] **Fault handling** (page fault delivery via fault endpoints, reply-to-resume)
- [x] **IPC buffer** (message overflow MR4-MR19, capability transfer)
- [x] **I/O port capabilities** (IoPort_In8/Out8/In16/Out16)
- [x] **Debug syscalls** (DebugPutChar, DebugDumpState, DebugPutStr, DebugPutBuf)
- [x] **Userspace servers** (procmgr, vfs, nameserv)
- [x] **SMP** (ACPI MADT discovery, AP trampoline, per-CPU GDT/TSS, APIC timer, IPI reschedule/VSpace teardown, CPU affinity)
- [x] **IPC assembly fastpath** (hybrid asm/Rust for Call + ReplyRecv, short messages, no cap transfer)
- [x] **POSIX compatibility** (signals, Unix domain sockets, poll/select/epoll, pipes/FIFOs, shm, fd passing, fork/exec)
- [x] **Bound notifications** (bidirectional TCB↔Notification link, combined IPC wait)
- [x] **SMP locking discipline** (lock ordering enforcement, atomic serial output)
- [x] **Time syscalls** (ClockGetTime, NanoSleep)
- [x] **saltyc C standard library** (stdio, stdlib, string, malloc, unistd, signal, termios, dirent, regex)
- [x] **Terminal line discipline** (ICANON, ECHO, ISIG with Ctrl-C/Ctrl-\/Ctrl-Z, tcgetattr/tcsetattr)
- [x] **Automated test suite** (test_runner with 10 modules: hello, fs, mmap, fork, signal, socket, pipe, time, terminal, epoll)

### Planned

- [ ] **SaltyFS** (copy-on-write filesystem with snapshot support)
- [ ] **aarch64 port**
- [ ] **Network stack**

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Userspace                               │
├──────────┬──────────┬──────────┬──────────┬──────────┬──────────┤
│   init   │ console  │  procmgr │   vfs    │ nameserv │   apps   │
│          │ (serial) │          │          │          │          │
└────┬─────┴────┬─────┴────┬─────┴────┬─────┴────┬─────┴──────────┘
     │          │          │          │          │
     │      IPC (Endpoints + Notifications)     │
     │          │          │          │          │
┌────┴──────────┴──────────┴──────────┴──────────┴─────────────────┐
│                     SaltyOS Microkernel                          │
├──────────┬──────────┬──────────┬──────────┬──────────┬───────────┤
│Capability│   IPC    │Scheduler │  Memory  │   SMP    │   Arch    │
│  System  │Endpoints │  (EDF)   │Management│ (APIC/   │ (x86_64)  │
│          │          │          │          │  IPI)    │           │
└──────────┴──────────┴──────────┴──────────┴──────────┴───────────┘
```

## Building

### Prerequisites

- Rust toolchain (nightly)
- Meson build system (>= 1.1)
- Ninja
- NASM assembler
- Clang (required; gcc is not supported)
- QEMU (for testing)

### Quick Start

```bash
# Install Rust nightly
rustup install nightly
rustup default nightly
rustup component add rust-src

# Configure build (requires CC=clang)
just setup

# Build
just build

# Run in QEMU (BIOS)
just run

# Run in QEMU (UEFI)
just run-uefi
```

### Build Options

```bash
# Enable debug symbols
just reconfigure -Ddebug_symbols=true

# Change log level
just reconfigure -Dkernel_log_level=debug

# Quick rebuild and run
just rr

# Run with GDB server
just run-gdb

# Headless debug (serial only, no GUI)
just run-debug-headless
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
  - [POSIX Compatibility](docs/design/posix.md)
- [Specifications](docs/spec/)
  - [System Calls](docs/spec/syscalls.md)
  - [ABI](docs/spec/abi.md)
  - [Boot Protocol](docs/spec/boot_protocol.md)

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
├── userland/               # Userspace programs
│   ├── init/               # First process (service-based bootstrap)
│   ├── console/            # Serial console server
│   ├── rtld/               # Runtime dynamic linker
│   ├── procmgr/            # Process manager (spawn/exit/waitpid)
│   ├── vfs/                # Virtual filesystem server
│   ├── nameserv/           # Name service (endpoint lookup)
│   ├── drivers/            # Userspace device drivers
│   ├── test_runner/        # Automated test suite
│   └── services/           # Service descriptor files (.service)
├── lib/                    # Shared libraries
│   └── libsalty/           # System library (Rust, syscall wrappers + POSIX compat)
├── tools/                  # Build utilities
│   ├── mkcpio.py           # Pack userland ELFs + services into initrd.cpio
│   └── mkimage.py          # Create bootable disk image
└── docs/                   # Documentation
```

## Design Philosophy

### What the Kernel Does (Implemented)

- SMP multi-core support (ACPI discovery, AP bootstrap, per-CPU state, IPI)
- Thread management and EDF scheduling with budget enforcement and CPU affinity
- Synchronous IPC (endpoints) and async notifications
- Virtual address space management (VSpace) with page tables
- Physical memory allocation (frame allocator, slab allocator)
- Capability-based access control (fat capabilities, CDT)
- Context switching and interrupt handling
- IRQ routing to userspace via notification capabilities
- I/O port access control via IoPort capabilities
- Fault delivery to userspace fault handlers

### What the Kernel Does NOT Do (Userspace)

- Filesystem (VFS is a userspace server)
- Network stack
- Device drivers (userspace, with mapped MMIO)
- Process management policy (userspace procmgr)
- Access control policy (enforced via capabilities)

## Testing

```bash
# Build and run in QEMU — watch serial for KERNEL PANIC or test_runner PASS/FAIL
just run

# SMP smoke test (boots with 2 CPUs — race conditions only show with >1 CPU)
just run-smp

# Stress test with 4 CPUs
just run-smp4

# Headless debug (serial only, logs to qemu.log)
just run-debug-headless
```

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
