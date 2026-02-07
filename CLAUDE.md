# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SaltyOS is a capability-based microkernel OS inspired by seL4, written in Rust (kernel) and C (bootloader, userland). All resource access is mediated through unforgeable capability tokens. The kernel provides only scheduling, IPC, memory management, and capabilities — everything else (filesystem, drivers, process management) runs in userspace.

## Prerequisites

- **Rust nightly** with `rust-src` component (for `core` library cross-compilation)
- **Clang** (enforced — gcc will not work; Meson checks `cc.get_id() == 'clang'`)
- **NASM**, **Meson >= 1.1**, **Ninja**
- **QEMU** (qemu-system-x86_64) for testing
- **OVMF** (edk2-ovmf) for UEFI testing

## Build Commands

```bash
just setup                  # Configure build (run once)
just build                  # Build all components
just run                    # Build + run in QEMU (BIOS, single CPU)
just run-smp                # Run with 2 CPUs
just run-smp4               # Run with 4 CPUs
just run-uefi               # Run with UEFI firmware
just rr                     # Quick rebuild + run
just distclean              # Remove all build dirs (needed before re-setup)

# Debugging
just run-gdb                # QEMU with GDB server (-s -S)
just gdb                    # Connect GDB to running QEMU
just run-debug              # Run with interrupt/reset logging (qemu.log)
just run-debug-headless     # Headless debug (no GUI)

# Testing
just test-integration       # Boot smoke test (single CPU, timeout-based)
just test-smp               # SMP boot test (2 CPUs)
just test-all               # Both tests

# Code quality
just fmt                    # Format Rust (rustfmt) and C (clang-format)
just fmt-check              # Check Rust formatting

# Configuration
just reconfigure -Dkernel_log_level=debug
just reconfigure -Ddebug_symbols=true
```

Build options: `arch` (x86_64), `build_boot`/`build_kernel`/`build_userland` (bool), `kernel_log_level` (error/warn/info/debug/trace), `max_cpus` (16), `kernel_stack_size` (16384).

## Architecture

### Kernel (Rust, `kernel/src/`)

| Module | Purpose |
|--------|---------|
| `lib.rs` | Entry (`kmain`), serial I/O, panic handler |
| `arch/x86_64/` | GDT, IDT, APIC, paging, SMP (AP trampoline), per-CPU data |
| `cap/` | CNode (4-16 bit slots), Untyped retype, CDT, IoPort caps |
| `ipc/` | Endpoints (sync rendezvous), Notifications (async bitmap), IRQ routing |
| `mm/` | VSpace (page tables), Frame allocator, Slab allocator |
| `sched/` | EDF scheduler (per-CPU ready queues), TCB, context switch |
| `syscall/` | 12 syscalls, capability invocation dispatch |

**Key assembly files** in `kernel/src/arch/x86_64/`:
- `syscall.S` — Syscall entry/exit via `syscall`/`sysretq`. User RSP is saved on the **per-thread kernel stack** (not per-CPU `%gs:16`) to prevent RSP corruption during context switches.
- `exceptions.S` — IDT exception handlers
- `ap_tramp.S` — SMP application processor trampoline (real→long mode)

### Syscall ABI

Syscall instruction: `syscall` (not `int 0x80`). Number in `rax`, args in `rdi, rsi, rdx, r10, r8, r9`. Returns error in `rax`, value in `rdx`.

| # | Name | Description |
|---|------|-------------|
| 0 | Send | Blocking send to endpoint |
| 1 | Recv | Blocking receive from endpoint |
| 2 | Call | Send + receive (client RPC) |
| 3 | ReplyRecv | Reply to caller + wait for next |
| 4 | NBSend | Non-blocking send |
| 5 | Signal | Signal notification |
| 6 | Wait | Wait on notification |
| 7 | Poll | Non-blocking poll notification |
| 8 | Yield | Yield CPU |
| 9 | Invoke | Capability invocation (CNode/Untyped/TCB/VSpace/IRQ/IoPort ops) |
| 10 | DebugPutChar | Write char to serial |
| 11 | DebugDumpState | Dump CPU state |

**Message info encoding** (seL4-style): bits 6:0 = length (0-127 MRs), bits 11:7 = extra caps, bits 51:12 = label. MR0-MR3 in registers, MR4-MR19 via IPC buffer.

**Invoke labels** (defined in `lib/libsalty/salty.h`): CNode ops `0x10-0x16`, Untyped `0x20`, SchedContext `0x30-0x34`, TCB `0x40-0x4B`, VSpace `0x50-0x53`, IRQ `0x60-0x63`, IoPort `0x70-0x73`.

### Well-Known Capability Slots

Set by kernel for init; inherited by child processes:

| Slot | Name | Description |
|------|------|-------------|
| 0 | CAP_SELF_TCB | Thread's own TCB |
| 1 | CAP_SELF_VSPACE | Thread's page table root |
| 2 | CAP_SELF_CSPACE | Thread's CNode root |
| 3 | CAP_PROCMGR_EP | Process manager endpoint |
| 4 | CAP_VFS_EP | VFS server endpoint |
| 5 | CAP_NAMESERV_EP | Name service endpoint |
| 8 | CAP_COM1_IOPORT | Serial port I/O port |
| 11 | CAP_CONSOLE_EP | Console server endpoint |
| 16+ | CAP_UNTYPED_START | Untyped memory capabilities |

### Bootloader (C/ASM, `boot/`)

3-stage bootloader supporting BIOS and UEFI:
1. **Stage 1**: MBR (512 bytes) or UEFI PE/COFF entry
2. **Stage 2**: Protected/long mode setup
3. **Stage 3**: Mounts SaltyFS/FAT32, loads kernel.elf + initrd.cpio, builds TLV-encoded BootInfo, jumps to kernel with BootInfo pointer in RDI

Include paths are relative to `boot/` root (Meson `-I` flag). Files in `stage3/arch/x86/bios/` use `../../../../common/` to reach `boot/common/`.

### Userland (C, `userland/`)

| Program | Role |
|---------|------|
| `init` | First process — multi-phase bootstrap: IPC test, fault handling, spawn servers |
| `rtld` | Runtime dynamic linker (loads libsalty.so) |
| `console` | Serial console server (IoPort cap for COM1) |
| `procmgr` | Process manager (spawn/exit) |
| `vfs` | Virtual filesystem server |
| `nameserv` | Name service |
| `hello` | Test program |

All userland ELFs are packed into a CPIO initrd (`tools/mkcpio.py`) which is embedded in the disk image.

### libsalty (`lib/libsalty/`)

Userspace system library providing syscall wrappers and IPC helpers.

- `salty.h` — Syscall numbers, invoke labels, error codes, object types, well-known cap slots, message struct
- `salty_impl.c` — Higher-level wrappers (e.g., retype, map, TCB configure)
- `posix.h` / `posix_mm.h` — POSIX compatibility layer (fork, exec, mmap)
- `elf_loader.h` / `elf_dynamic.h` — ELF loading and dynamic linking
- `cpio.h` — CPIO archive parsing
- `fork.S` — Fork assembly stub

**Static vs dynamic**: When `SALTY_STATIC` is defined, all functions are `static inline` (header-only). Otherwise they're extern declarations linked against `libsalty.so`.

## Key Design Details

- **Fat capabilities**: 32 bytes with inline metadata (object ptr, rights, type, depth, badge, parent ptr)
- **CNode sizing**: 4-16 bits (16 to 65,536 slots)
- **EDF scheduler**: Per-CPU ready queues, IPI-driven reschedule for affinity changes
- **SMP**: ACPI MADT discovery, AP trampoline, per-CPU GDT/TSS/APIC, IPI messaging
- **Frame minimum**: size_bits=12 enforced (4K pages) to prevent misaligned objects

## Testing

No formal unit test framework. Testing is done via QEMU boot and serial output observation:
```bash
just run                        # Manual observation
just test-integration           # Automated boot smoke test
just test-smp                   # Automated SMP test
just run-debug-headless         # Headless debug (serial only)
```

## Documentation

Design documents in `docs/design/` — read before making architectural changes:
- `capability.md`, `ipc.md`, `scheduling.md`, `memory.md`, `bootloader.md`, `saltyfs.md`, `posix.md`

Specifications in `docs/spec/`:
- `syscalls.md`, `abi.md`, `boot_protocol.md`
