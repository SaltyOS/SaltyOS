# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SaltyOS is a capability-based microkernel operating system written in Rust, inspired by seL4, L4, and Minix3. The project is in early development (not yet bootable) with a focus on security through capability-based access control.

**Key architectural principles:**
- All resource access is mediated through unforgeable capability tokens
- Kernel only provides essential services: scheduling, IPC, memory management, capabilities
- Everything else (filesystem, drivers, process management) runs in userspace

## Build Commands

The project uses Meson + Ninja with `just` as a task runner.

### Common Development Commands

```bash
# Initial setup (run once)
just setup

# Build all components
just build

# Run in QEMU (BIOS)
just run

# Run in QEMU (UEFI)
just run-uefi

# Quick rebuild and run
just rr

# Clean build artifacts
just clean

# Full clean (remove build directories)
just distclean
```

### Debugging

```bash
# Run QEMU with GDB server (wait for connection)
just run-gdb

# Connect GDB to running QEMU
just gdb

# Run with debug logging (creates qemu.log)
just run-debug

# Run headless with debug logging (no GUI, for SSH/CI)
just run-debug-headless
just run-uefi-debug-headless
```

### Configuration

```bash
# Show current configuration
just info

# Reconfigure with options
just reconfigure -Dkernel_log_level=debug
just reconfigure -Ddebug_symbols=true
```

### Build Options (via Meson)

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `arch` | combo | x86_64 | Target architecture |
| `build_boot` | bool | true | Build bootloader |
| `build_kernel` | bool | true | Build kernel |
| `build_userland` | bool | false | Build userspace |
| `kernel_log_level` | combo | info | error/warn/info/debug/trace |
| `max_cpus` | int | 16 | Maximum CPUs |
| `kernel_stack_size` | int | 16384 | Kernel stack size |

### Code Quality

```bash
# Format all source code
just fmt

# Check formatting without modifying
just fmt-check

# Count lines of code
just loc
```

## Architecture Overview

### Kernel Object Types

The kernel manages several object types, each accessed via capabilities:

| Type | Description | Key Operations |
|------|-------------|----------------|
| `Endpoint` | Synchronous IPC channel | send, recv, call |
| `Notification` | Async signaling primitive | signal, wait |
| `TCB` | Thread control block | configure, suspend, resume |
| `CNode` | Capability storage | insert, delete, copy, mint |
| `VSpace` | Virtual address space | map, unmap |
| `Frame` | Physical memory page | retype, map |
| `Untyped` | Raw physical memory | retype |
| `IRQHandler` | Interrupt handler | ack, set_notification |
| `SchedContext` | Scheduling parameters (EDF) | configure |

### Capability System

SaltyOS uses "fat" capabilities (32 bytes) with inline metadata:
- Object pointer (8 bytes)
- Rights bitmap (4 bytes)
- Capability type (1 byte)
- Derivation depth (1 byte)
- Badge value (8 bytes)
- Parent capability pointer (8 bytes)

**Key operations:**
- `derive`: Copy with reduced rights
- `mint`: Create badged capability (for endpoints)
- `revoke`: Destroy all derived capabilities
- `delete`: Remove single capability

### Memory Management

**Physical memory flow:**
```
Untyped Memory (raw) → retype() → Kernel Objects (Frames, TCBs, etc.)
```

**Address space layout (x86_64):**
- `0xFFFFFFFFFFFFFFFF` - Kernel space (higher half)
- `0xFFFFFFFF00000000` - Direct physical mapping
- `0xFFFF800000000000` - Kernel heap
- `0x0000800000000000` - Non-canonical hole
- `0x0000000000000000` - User space

**Page table hierarchy:** PML4 → PDPT → PD → PT → Frame

### IPC Architecture

- **Endpoints**: Synchronous rendezvous IPC (blocking send/recv)
- **Notifications**: Async signaling (wait on bitmap, signal with bits)

### Scheduler

- **EDF (Earliest Deadline First)** with time budgets
- Real-time scheduling support
- Each thread has a SchedContext with budget, period, deadline

## Directory Structure

```
kernel/src/
├── lib.rs              # Kernel entry point
├── arch/x86_64/        # Architecture-specific code
│   ├── boot.rs         # Arch initialization
│   ├── gdt.rs          # Global Descriptor Table
│   ├── idt.rs          # Interrupt Descriptor Table
│   └── paging.rs       # Page table management
├── cap/                # Capability system
│   ├── cnode.rs        # CNode implementation
│   └── object.rs       # Kernel objects
├── ipc/                # IPC subsystem
│   ├── endpoint.rs     # Sync IPC
│   └── notification.rs # Async signals
├── mm/                 # Memory management
│   ├── frame.rs        # Physical allocator
│   ├── vspace.rs       # Virtual spaces
│   └── slab.rs         # Kernel allocator
├── sched/              # EDF scheduler
│   ├── thread.rs       # TCB
│   └── scheduler.rs    # EDF implementation
└── syscall/            # System call dispatch

boot/                   # 3-stage bootloader
├── stage1/             # MBR/UEFI entry
├── stage2/             # Protected/Long mode setup
└── stage3/             # Kernel loader

docs/                   # Comprehensive documentation
├── ARCHITECTURE.md     # System architecture
├── BUILDING.md         # Build instructions
├── design/             # Design documents
└── spec/               # Technical specifications
```

## Key Design Decisions

### What the Kernel Does
- Thread management and EDF scheduling
- Synchronous IPC (endpoints) and async notifications
- Virtual address space management (VSpace)
- Physical memory allocation and mapping
- Capability-based access control
- IRQ routing to userspace

### What the Kernel Does NOT Do
- Filesystem (VFS is a userspace server)
- Network stack
- Device drivers (userspace, with mapped MMIO)
- Process management policy (userspace procmgr)

### Security Model
- Capability-based access control is the sole mechanism
- No ambient authority (no global namespaces)
- All capabilities delegatable and revocable
- No direct physical memory access in userspace

## Testing

The project does not yet have formal test infrastructure. Testing is done via QEMU:
```bash
just run                    # Run and observe serial output
just run-gdb                # Debug with GDB
just run-debug-headless     # Headless debug (no GUI, serial only)
just run-uefi-debug-headless  # UEFI headless debug
```

## Documentation

Design documents in `docs/design/` provide detailed specifications:
- `capability.md` - Capability system architecture
- `memory.md` - Memory management design
- `ipc.md` - IPC subsystem design
- `scheduling.md` - EDF scheduler design
- `bootloader.md` - 3-stage bootloader design

Read these before making architectural changes.
