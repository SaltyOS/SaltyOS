# SaltyOS Design Overview

This document describes the high-level design philosophy, goals, and architectural decisions of SaltyOS.

## Design Goals

### Primary Goals

1. **Security through Isolation**
   - Minimal trusted computing base (TCB)
   - All drivers and servers run in userspace
   - Capability-based access control for all resources

2. **Correctness over Performance**
   - Simple, auditable kernel code
   - Formal verification potential (seL4-inspired design)
   - No kernel memory allocation after boot (future goal)

3. **Real-Time Capability**
   - EDF scheduling with budget enforcement
   - Bounded worst-case execution time (WCET) for syscalls
   - Priority inheritance for capability operations

4. **Multi-Architecture Support**
   - Clean architecture abstraction layer
   - x86_64 as primary target
   - aarch64 as secondary target

5. **Full POSIX compatibility**: SaltyOS provides a POSIX subset sufficient for
  modern applications (including GUI stacks like Wayland) while excluding legacy
  features that conflict with capability-based security. See
  [POSIX Compatibility](posix.md) for details.

### Non-Goals
- Maximum performance at cost of complexity
- Legacy hardware support

## Architectural Principles

### Microkernel Philosophy

The kernel provides only mechanisms, not policies:

| Kernel (Mechanism) | Userspace (Policy) |
|-------------------|-------------------|
| Thread scheduling | Process management |
| IPC transport | Protocol/API design |
| Memory mapping | Memory allocation strategy |
| Capability transfer | Access control decisions |
| IRQ delivery | Device drivers |

### Capability-Based Security

Every kernel object is accessed through capabilities:

```
┌─────────────────────────────────────────────────────────────┐
│                   Fat Capability (256 bits / 32 bytes)       │
├─────────────────┬───────────────┬───────────────┬───────────┤
│  Object Pointer │    Rights     │    Badge      │   Type    │
│     (64 bits)   │   (32 bits)   │  (64 bits)    │  (8 bits) │
└─────────────────┴───────────────┴───────────────┴───────────┘
```

Key properties:
- **Unforgeable**: Only kernel can create/modify capabilities
- **Delegatable**: Can be transferred via IPC
- **Revocable**: Parent can revoke derived capabilities
- **Attenuatable**: Rights can only be reduced, never increased

### IPC Model

Dual IPC primitive design:

1. **Synchronous Endpoints** (message passing)
   - Rendezvous-style: sender blocks until receiver ready
   - Zero-copy for large transfers (page donation)
   - Badge identifies sender

2. **Notifications** (signaling)
   - Lightweight async signals (bitmap or counter)
   - Used for IRQ delivery
   - Combined with shared memory for async queues

```
┌──────────┐                              ┌──────────┐
│  Client  │                              │  Server  │
└────┬─────┘                              └────┬─────┘
     │                                         │
     │  call(endpoint, msg)                    │
     ├────────────────────────────────────────►│
     │                     recv(endpoint)      │
     │◄────────────────────────────────────────┤
     │                     reply(msg)          │
     │                                         │
```

### Memory Model

Three-level memory abstraction:

1. **Untyped Memory**: Raw physical frames, root task controls all
2. **Typed Objects**: Kernel objects (TCB, CNode, Endpoint, etc.)
3. **VSpace**: Virtual address space with page table hierarchy

```
                    ┌─────────────────┐
                    │  Untyped Memory │
                    │   (Physical)    │
                    └────────┬────────┘
                             │ retype
            ┌────────────────┼────────────────┐
            ▼                ▼                ▼
    ┌───────────────┐ ┌───────────────┐ ┌───────────────┐
    │     Frame     │ │      TCB      │ │   Endpoint    │
    └───────┬───────┘ └───────────────┘ └───────────────┘
            │ map
            ▼
    ┌───────────────┐
    │    VSpace     │
    │  (Page Table) │
    └───────────────┘
```

## Component Overview

### Kernel Components

| Component | Responsibility |
|-----------|---------------|
| `cap/` | Capability management, CNode operations |
| `ipc/` | Endpoints, Notifications, message transfer |
| `sched/` | EDF scheduler, thread management |
| `mm/` | Bitmap-based physical frame allocator (PMM), VSpace page table management with COW support |
| `syscall/` | System call dispatch and handling |
| `arch/` | Architecture-specific code (GDT, IDT, paging) |

### Userspace Components

Organized in a domain-based layout under `userland/`:

| Component | Path | Responsibility | Status |
|-----------|------|---------------|--------|
| `init` | `core/init/` | System initialization, service-based multi-phase bootstrap | Implemented |
| `rtld` | `core/rtld/` | Runtime dynamic linker (loads libtrona.so) | Implemented |
| `mmsrv` | `core/mmsrv/` | Memory manager server (centralized frame allocation, VSpace mapping) | Implemented |
| `procmgr` | `core/procmgr/` | Process manager (spawn/exit/waitpid/fork/exec) | Implemented |
| `nameserv` | `core/nameserv/` | Service discovery (endpoint lookup) | Implemented |
| `vfs` | `servers/vfs/` | Virtual filesystem (ramfs + devfs + Unix sockets + shm + poll + procfs + pipes) | Implemented |
| `console` | `servers/console/` | Serial console server (IoPort cap for COM1, keyboard input) | Implemented |
| `ttyd` | `servers/ttyd/` | PTY driver server (pseudo-terminal allocation, line discipline) | Implemented |
| `getty` | `servers/getty/` | Terminal login service | Implemented |
| `blkdrv` | `drivers/blkdrv/` | Block device driver (virtio-blk) | Implemented |
| `pcisrv` | `drivers/pcisrv/` | PCI enumeration server | Implemented |
| `display` | `drivers/display/` | Framebuffer display server | Implemented |
| `saltyfs` | `fs/saltyfs/` | SaltyFS filesystem server (on-disk filesystem) | Implemented |
| `test_runner` | `tests/test_runner/` | Automated test suite | Implemented |
| `hello` | `tests/hello/` | Hello world test program | Implemented |

## Boot Sequence

```mermaid
graph TD
    A[BIOS/UEFI] --> B[Stage 1]
    B --> C[Stage 2]
    C --> D[Stage 3]
    D --> E[Kernel Entry]
    E --> F[Kernel Init]
    F --> G[Create Init Task]
    G --> H[Init Userspace]
    H --> I[Start Servers]
```

1. **Stage 1**: Load Stage 2 from fixed location
2. **Stage 2**: Enter long mode, load Stage 3 from partition
3. **Stage 3**: Load kernel + initrd via raw disk extents (no filesystem)
4. **Kernel**: Initialize memory, create root task
5. **Init**: Spawn system servers, mount filesystems

## Design Decisions

### Why Fat Capabilities?

Standard L4/seL4 uses inline capabilities (single word). We chose fat capabilities for:

- **More metadata**: Extended rights, type info
- **Better debugging**: Self-describing objects
- **Simpler revocation**: Parent tracking in capability
- **Trade-off**: More memory per capability, but clearer semantics

### Why EDF Scheduler?

- **Real-time support**: Natural deadline handling
- **Temporal isolation**: Budget enforcement prevents starvation
- **MCS potential**: Mixed-criticality system extension possible
- **Trade-off**: More complex than priority-based, but more powerful

### Why 3-Stage Bootloader?

- **COW filesystem support**: Stage 3 can read SaltyFS
- **Configuration flexibility**: Boot config in filesystem
- **Snapshot boot**: Can boot from filesystem snapshots
- **Trade-off**: More complexity than Limine/GRUB, but full control

### Why Rust for Kernel?

- **Memory safety**: Prevents entire classes of bugs
- **Zero-cost abstractions**: No runtime overhead
- **No runtime**: `#![no_std]` freestanding support
- **Trade-off**: Steeper learning curve, some FFI complexity

## Current Status

### Implemented
- Capability system with fat capabilities (32 bytes), CDT, copy/mint/move/mutate/revoke/delete
- Synchronous IPC (endpoints) with send/recv/call/reply_recv/NBSend
- Asynchronous notifications (signal/wait/poll) with combined endpoint wait
- Bound notification wake: signal wakes RecvBlocked thread on endpoint (bidirectional tcb↔notification link)
- IPC buffer with message overflow (MR4-MR19) and capability transfer
- IPC assembly fastpath for Call + ReplyRecv (short messages, no cap transfer)
- Fault handling via fault endpoints with reply-to-resume
- EDF scheduler with budget enforcement
- Virtual memory management (VSpace map/unmap/MapPT)
- IRQ handling via notifications with IRQHandler capabilities
- I/O port capabilities (IoPort_In8/Out8/In16/Out16/In32/Out32/Configure/Create)
- POSIX signals via notification-based delivery
- Debug syscalls (DebugPutChar, DebugDumpState)
- 3-stage bootloader (BIOS and UEFI)
- Init process with multi-phase bootstrap (service-based)
- Console server (serial I/O via IoPort caps)
- Runtime dynamic linker (rtld)
- Process manager (spawn, exit, waitpid)
- VFS server (ramfs + devfs + initrd + Unix domain sockets + shared memory + poll)
- Name service (endpoint lookup)
- SMP support (ACPI MADT parser, AP trampoline, global ready queue with affinity, IPI reschedule)
- Userland and trona migrated from C to Rust
- POSIX Phase 2 (GUI-ready): Unix domain sockets, poll/select, POSIX shared memory, fd passing
- Ports system: C standard library (basaltc), portbuild tool, bash and FreeBSD utilities

## Future Directions

1. **Formal Verification**: seL4-style proofs for critical paths
2. **Nested Virtualization**: Hypervisor mode for VMs
3. **Network Stack**: Userspace TCP/IP implementation
4. **GUI Compositor**: Wayland-like display server (POSIX socket/shm prerequisites done, framebuffer display server available)

## References

- [seL4 Reference Manual](https://sel4.systems/Info/Docs/seL4-manual-latest.pdf)
- [L4 Microkernel Family](https://os.inf.tu-dresden.de/L4/)
- [Capability-based Computer Systems](https://homes.cs.washington.edu/~levy/capabook/)
- [EDF Scheduling](https://en.wikipedia.org/wiki/Earliest_deadline_first_scheduling)
