# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SaltyOS is a capability-based microkernel OS inspired by seL4, written in Rust (kernel) and C (bootloader). All resource access is mediated through unforgeable capability tokens. The kernel provides only scheduling, IPC, memory management, and capabilities — everything else (filesystem, drivers, process management) runs in userspace.

**Design philosophy:**
- **Minimal trusted computing base** — the kernel is the only trusted code. Keep it small.
- **Correctness over performance** — get it right first. The IPC fastpath is the exception: IPC is on every critical path, so it gets assembly-level optimization.
- **Capability-mediated access** — no ambient authority. Every resource access requires an explicit capability token.

## Prerequisites

- **Rust nightly** with `rust-src` component (for `core` library cross-compilation) — edition 2024
- **Clang** (enforced — gcc will not work; Meson checks `cc.get_id() == 'clang'`)
- **NASM**, **Meson >= 1.1**, **Ninja**
- **QEMU** (qemu-system-x86_64 / qemu-system-aarch64) for testing
- **OVMF** / **AAVMF** for UEFI testing

## Build Commands

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

### Multi-Architecture Builds

The `arch` variable (default: `x86_64`) controls the target for **all** just recipes. Build directories are arch-qualified (`build-x86_64`, `build-aarch64`).

```bash
# The arch= prefix applies to any recipe: setup, build, run, tc, port, sysroot, etc.
just arch=aarch64 setup     # Configure aarch64 build
just arch=aarch64 build     # Build for aarch64
just arch=aarch64 run       # Run in QEMU (aarch64 forces UEFI)
just arch=aarch64 tc build host llvm   # Build host LLVM targeting aarch64
just arch=aarch64 port bash            # Build bash port for aarch64
```

aarch64 is **UEFI-only** (no BIOS bootloader). QEMU uses `virt,gic-version=3` machine with Cortex-A72 CPU.

### Build Options

`arch` (x86_64 | aarch64), `build_boot`/`build_kernel`/`build_userland`/`build_ports` (bool), `kernel_log_level` (error/warn/info/debug/trace), `max_cpus` (1–256, default 16), `kernel_stack_size` (4096–65536, default 16384), `build_libcxx` (auto/true/false).

## Build System Details

No `Cargo.toml` files — all Rust code is compiled via Meson with direct `rustc` invocation. The build chain:

1. `rust/meson.build` — Builds `core` and `compiler_builtins` from `rust-src`
2. `kernel/meson.build` — Compiles kernel Rust → `.o`, assembles `.S` files, links to `kernel.elf`
3. `lib/besalt/lib/meson.build` — Builds libbesalt (Rust → `.o` + `.rmeta`, plus `fork.S` → `.o`, links to `libbesalt.so`)
4. `lib/besalt/c/meson.build` — Builds saltyc (C stdlib → `libc.so`)
5. `lib/besalt/cpp/meson.build` — Builds libc++ (optional, from `toolchain/llvm-project`)
6. `userland/*/meson.build` — Each program compiled against libbesalt `.rmeta`, linked with libbesalt `.o` + `core.o`
7. `tools/mkcpio.py` — Packs all userland ELFs + `.service` files into `initrd.cpio`
8. `tools/mkimage.py` — Creates bootable disk image with bootloader + kernel + initrd

**Kernel rustc flags** (from `kernel/meson.build`):
```
--edition=2024  --target=<arch-specific-target-json>
-C panic=abort  -C opt-level=2  -C debuginfo=2
-C code-model=small  -C relocation-model=pic
```

**Userland** uses built-in rustc targets (`x86_64-unknown-saltyos`, `aarch64-unknown-saltyos`) — these require the patched stage1 rustc from the custom toolchain. The kernel uses custom JSON target specs (`kernel/x86_64-saltyos.json`, `kernel/aarch64-saltyos.json`).

**Init is statically linked** (embeds libbesalt.o directly). Other userland programs use shared `libbesalt.so` loaded by `rtld` (the runtime dynamic linker).

### Build Gotchas

- **Clang is enforced.** The build fails with gcc. Do not suggest `cargo build`, `cargo test`, or create `Cargo.toml` files — this project does not use Cargo.
- **Rust flags live in `meson.build`**, not `.cargo/config.toml`.
- **Linker scripts are per-architecture:** e.g., `kernel/arch/x86_64.ld` and `kernel/arch/aarch64.ld`; similarly each userland program has `arch/x86_64/link.ld` and `arch/aarch64/link.ld`.
- **Meson file discovery runs at setup time** — the `find` in `kernel/meson.build` auto-discovers `.rs` files only during `meson setup`. After adding new source files: `just distclean && just setup && just build`.

## Custom Toolchain

SaltyOS builds a patched LLVM/Clang/LLD and rustc that know the `x86_64-unknown-saltyos` and `aarch64-unknown-saltyos` targets. Source lives in git submodules under `toolchain/llvm-project/` and `toolchain/rust/`.

```bash
just tc setup                    # Create directories
just tc build host llvm          # Build host Clang/LLD (~30 min)
just tc build host rust          # Build host rustc (~20 min)
just tc doctor                   # Validate toolchain
just tc all                      # setup → host llvm → host rust → doctor

# Cross-compilation for self-hosting (arch= applies here too)
just sysroot                     # Generate cross-compilation sysroot
just tc build cross llvm         # Cross-compile Clang/LLD for SaltyOS
just tc build cross rust         # Cross-compile rustc for SaltyOS
just tc package                  # Package cross-compiled toolchain for rootfs
just self-host                   # Full pipeline: sysroot → cross llvm → cross rust → package

# aarch64 example
just arch=aarch64 tc all         # Build host toolchain targeting aarch64
just arch=aarch64 self-host      # Cross-compile toolchain for aarch64 SaltyOS
```

Environment setup: `eval "$(just toolchain-env)"` or `source tools/toolchain/env.sh`.

## Ports System

Third-party software is built via declarative `.port` files in `ports/`. Available ports: **bash**, **freebsd-utils**, **nano**, **nasm**, **ncurses**.

```bash
just port bash              # Build a port (fetch, configure, make, install)
just fetch-ports            # Download all port sources
just port-info bash         # Show parsed port config
```

Port format is INI-style with `[port]`, `[source]`, `[build]`, `[env]`, `[install]`, `[depends]` sections. The port build tool is in `tools/port/` (Rust). Ports are optional (`-Dbuild_ports=true`).

## Rootfs and Images

```bash
just image                  # Create BIOS disk image
just image-uefi             # Create UEFI disk image
just mkrootfs               # Build rootfs.img (binaries + optional LLVM/ports)
just mksaltyfs              # Generate SaltyFS test image
```

## Code Patterns and Safety Rules

### Lock Ordering

Lock ordering (outermost → innermost), from `kernel/src/mm/mod.rs`:

```
CAP_LOCK → SCHED_IPC_LOCK → scheduler.lock_state → VSpace.lock → MM_LOCK (FRAME_LOCK)
```

Nesting patterns:
- **Slowpath syscalls:** CAP_LOCK (cap lookup) → release → SCHED_IPC_LOCK (IPC)
- **IPC cap transfer:** SCHED_IPC_LOCK → CAP_LOCK (slot copy)
- **Fastpath:** CAP_LOCK (cap copy-to-stack) → release → SCHED_IPC_LOCK → scheduler.lock_state
- **Timer/IPI:** SCHED_IPC_LOCK (assembly stub) → scheduler.lock_state
- **do_context_switch:** releases SCHED_IPC_LOCK before switch, reacquires on resume

**IRQ save/restore pattern** (used everywhere):
```rust
let irq = save_irq_disable();
LOCK.lock();
// critical section
LOCK.unlock();
restore_irq(irq);
```

### Kernel Safety Constraints

- **`#![no_std]` with only `core`** — no `alloc` crate, no heap allocation
- **No floating point in kernel** — x86_64: `-mno-sse -mno-mmx -mno-avx`; aarch64: `-mgeneral-regs-only`
- **No kernel heap or slab** — all kernel objects are carved from untyped memory via `retype`. Objects are never freed (owned by untyped memory parent). Pointers to kernel objects remain valid for the lifetime of the system.
- **Never `.unwrap()` or `.expect()`** in kernel hot paths — use `match` or `if let`
- **EOI before schedulable code** — context switch can happen inside `timer_tick()`. Always send `eoi()` before calling any function that might trigger a context switch, or the interrupt controller blocks all further timer interrupts.
- **Per-thread state on kernel stack, not per-CPU globals** — on x86_64, per-CPU `%gs:16` (saved_rsp) is shared state that gets overwritten by other threads' syscalls. Save user RSP on the per-thread kernel stack instead.

### Unsafe Code Conventions

- Every `unsafe {}` block must have a `// SAFETY:` comment explaining the invariant that makes it safe
- Every `unsafe fn` must have a `# Safety` doc section listing caller obligations
- Use `#[unsafe(no_mangle)]` (not `#[no_mangle]`) — Rust 2024 edition requirement
- Use `#[repr(C)]` for all structures shared across FFI boundaries or passed to/from assembly
- `KernelObject` header must be the **first field** of any kernel object struct (for refcount access via pointer cast)

### Error Handling

- **Kernel error types:** `SyscallError`, `CapError`, `VSpaceError` — all enums with specific variants, not strings
- **Map between error types explicitly** with dedicated functions (e.g., `syscall_error_from_cap_error()` in `syscall/mod.rs`). Do not add `impl From<X> for Y` — explicit mapping prevents accidental information loss.
- **Userland error codes** in `lib/besalt/lib/src/consts.rs` (`BESALT_OK`, `BESALT_INVALID_CAPABILITY`, etc.) must match kernel `SyscallError` variants

### FFI Conventions

- Kernel functions called from assembly: `#[unsafe(no_mangle)] pub extern "C" fn`
- libbesalt public exports: `#[unsafe(no_mangle)] pub extern "C" fn` with `besalt_` prefix
- Shared structures: `#[repr(C)]` always
- Constants shared between kernel and userland (syscall numbers, invoke labels, error codes) must be kept in sync manually — `consts.rs` is the userland source of truth

## Architecture

### Kernel (Rust, `kernel/src/`)

| Module | Purpose |
|--------|---------|
| `lib.rs` | Entry (`kmain`), serial I/O, panic handler |
| `bootinfo.rs` | Boot info TLV parsing |
| `builtins.rs` | Compiler built-in stubs (memcpy, memset) |
| `cpio.rs` | CPIO archive parser for initrd |
| `elf.rs` | ELF binary loader |
| `init.rs` | Init task bootstrap, CSpace setup |
| `rng.rs` | RDRAND-based random number generator |
| `arch/x86_64/` | GDT, IDT, APIC, ACPI, paging, SMP, CPUID, FPU, PIT, SMAP/SMEP |
| `arch/aarch64/` | GICv3, PSCI, generic timer, paging (TTBR0/TTBR1), FPU/NEON, PL011 UART |
| `cap/` | CNode, Untyped retype, CDT, IoPort caps, refcounting |
| `console/` | Kernel console output (serial + framebuffer) |
| `ipc/` | Endpoints, Notifications, Futex, IRQ routing, IPC queue |
| `mm/` | VSpace (page tables, COW, demand paging), Bitmap PMM |
| `sched/` | EDF scheduler, TCB, PIP, sleep queue, context switch |
| `syscall/` | 23 syscalls, capability invocation dispatch, IPC fastpath |

**Key x86_64 assembly files** in `kernel/src/arch/x86_64/`:
- `syscall.S` — Syscall entry/exit via `syscall`/`sysretq`. User RSP is saved on the **per-thread kernel stack** (not per-CPU `%gs:16`) to prevent RSP corruption during context switches. IPC fastpath dispatch happens here (checks RAX==2 for Call, RAX==3 for ReplyRecv before slowpath).
- `exceptions.S` — IDT exception handlers
- `ap_tramp.S` — SMP application processor trampoline (real→long mode)

**Key aarch64 details** in `kernel/src/arch/aarch64/`:
- SMP via PSCI `CPU_ON` (HVC call), AP mailbox structure for stack/register handoff
- GICv3: distributor (GICD), redistributor (GICR), CPU interface via system registers (ICC)
- Generic timer: EL1 physical timer (CNTP) with PPI 30, 10ms tick
- FPU: NEON Q0-Q31 (512 bytes) lazy context switch via CPACR_EL1 trapping
- PL011 UART for early console output

### Syscall ABI

Syscall instruction: `syscall` on x86_64 (not `int 0x80`). On aarch64: `svc #0`.

x86_64: Number in `rax`, args in `rdi, rsi, rdx, r10, r8, r9`. Returns error in `rax`, value in `rdx`.

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
| 12 | ClockGetTime | Read monotonic clock |
| 13 | NanoSleep | Sleep for duration |
| 14 | DebugPutStr | Write string to serial |
| 15 | DebugPutBuf | Write buffer to serial |
| 16 | DebugConsoleControl | Enable/disable kernel console |
| 17 | SetInvokeDepths | Set CNode resolve depths |
| 18 | Futex | Userspace futex (wait/wake/requeue) |
| 19 | GetRandom | Get random bytes via RDRAND |
| 20 | Shutdown | ACPI system shutdown |
| 21 | SendTimed | Blocking send with timeout |
| 22 | RecvTimed | Blocking receive with timeout |

**Message info encoding** (seL4-style): bits 6:0 = length (0-127 MRs), bits 11:7 = extra caps, bits 51:12 = label. MR0-MR3 in registers, MR4-MR19 via IPC buffer.

**Invoke labels** (defined in `lib/besalt/lib/src/consts.rs`): CNode ops `0x10-0x18`, Untyped `0x20`, SchedContext `0x30-0x31`, TCB `0x40-0x4D`, VSpace `0x50-0x5A`, IRQ `0x60-0x64`, IoPort `0x70-0x77`.

### Well-Known Capability Slots

**Kernel-side init slots** (set in `kernel/src/init.rs` for the init task):

| Slot | Name | Description |
|------|------|-------------|
| 0 | CAP_SELF_TCB | Thread's own TCB |
| 1 | CAP_SELF_VSPACE | Thread's page table root |
| 2 | CAP_SELF_CSPACE | Thread's CNode root |
| 6 | CAP_KBD_IOPORT | PS/2 keyboard I/O port |
| 7 | CAP_KBD_IRQ | PS/2 keyboard IRQ handler |
| 8 | CAP_COM1_IOPORT | COM1 serial I/O port |
| 9 | CAP_COM1_IRQ | COM1 IRQ handler |
| 10 | CAP_COM1_NOTIFICATION | COM1 IRQ notification |
| 11 | CAP_IRQ_CONTROL | IRQ control (dynamic IoPort creation) |
| 12 | CAP_INITRD_UNTYPED | Initrd device untyped |
| 13 | CAP_FB_UNTYPED | Framebuffer device untyped |
| 15 | CAP_PCI_IOPORT | PCI config space I/O port |
| 16+ | CAP_UNTYPED_START | Untyped memory capabilities |

**Userland child convention** (defined in `lib/besalt/lib/src/consts.rs`, set by procmgr):

| Slot | Name | Description |
|------|------|-------------|
| 0 | CAP_SELF_TCB | Thread's own TCB |
| 1 | CAP_SELF_VSPACE | Thread's page table root |
| 2 | CAP_SELF_CSPACE | Thread's CNode root |
| 3 | CAP_PROCMGR_EP | Process manager endpoint |
| 4 | CAP_VFS_EP | VFS server endpoint |
| 5 | CAP_NAMESERV_EP | Name service endpoint |
| 7 | CAP_MMSRV_EP | Memory manager server endpoint |
| 8 | CAP_COM1_IOPORT | Serial port I/O port |
| 11 | CAP_CONSOLE_EP | Console server endpoint |
| 15 | CAP_PCI_IOPORT | PCI config space I/O port |
| 16+ | CAP_UNTYPED_START | Untyped memory capabilities |

### Bootloader (C/ASM, `boot/`)

3-stage bootloader supporting BIOS (x86_64 only) and UEFI (both architectures):
1. **Stage 1**: MBR (512 bytes) or UEFI PE/COFF entry
2. **Stage 2**: Protected/long mode setup (x86_64 BIOS) or identity map setup (aarch64 UEFI)
3. **Stage 3**: Mounts SaltyFS/FAT32, loads kernel.elf + initrd.cpio, builds TLV-encoded BootInfo, jumps to kernel with BootInfo pointer in RDI (x86_64) or x0 (aarch64)

Include paths are relative to `boot/` root (Meson `-I` flag). Files in `stage3/arch/x86/bios/` use `../../../../common/` to reach `boot/common/`.

### Userland (Rust, `userland/`)

Domain-based layout with programs organized by function:

| Program | Path | Role |
|---------|------|------|
| `init` | `core/init` | First process — service-based multi-phase bootstrap |
| `rtld` | `core/rtld` | Runtime dynamic linker (loads libbesalt.so) |
| `mmsrv` | `core/mmsrv` | Memory manager server (centralized frame allocation, VSpace mapping) |
| `procmgr` | `core/procmgr` | Process manager (spawn/exit/waitpid) |
| `nameserv` | `core/nameserv` | Name service (endpoint lookup) |
| `vfs` | `servers/vfs` | Virtual filesystem server (ramfs + devfs + Unix sockets + shm + poll) |
| `console` | `servers/console` | Serial console server (IoPort cap for COM1) |
| `ttyd` | `servers/ttyd` | TTY daemon |
| `getty` | `servers/getty` | Getty (login prompt) |
| `blkdrv` | `drivers/blkdrv` | Block device driver (virtio) |
| `pcisrv` | `drivers/pcisrv` | PCI server |
| `display` | `drivers/display` | Display driver |
| `saltyfs` | `fs/saltyfs` | SaltyFS filesystem server |
| `test_runner` | `tests/test_runner` | Automated test suite (hello, fs, mmap, fork, signal, socket, pipe, time) |

**Service-based bootstrap**: Init reads `.service` files from `userland/services/` in the initrd to determine boot order and dependencies. Each `.service` file declares `[Service]` (name, binary, type, restart policy) and `[Dependencies]` (After/Before ordering).

All userland ELFs + service files are packed into a CPIO initrd (`tools/mkcpio.py`) embedded in the disk image.

**Architecture-specific code** in userland programs lives in `src/arch/x86_64.rs` and `src/arch/aarch64.rs` modules (e.g., `pcisrv` has PCI ECAM mapping for aarch64 vs I/O port access for x86_64).

### Libraries (`lib/besalt/`)

Three sub-libraries under `lib/besalt/`:

**libbesalt** (`lib/besalt/lib/`, Rust) — Userspace system library:
- `consts.rs` — Syscall numbers, invoke labels, error codes, object types, well-known cap slots, POSIX constants
- `types.rs` — Message struct, PollFd, SockAddrUn, signal types
- `syscall.rs` — Raw syscall wrappers (inline asm)
- `ipc.rs` — IPC wrappers (call, send, recv, reply_recv)
- `invoke.rs` — Capability invocation helpers (CNode/Untyped/TCB/VSpace/IRQ/IoPort ops)
- `posix/` — POSIX compatibility: `at`, `file`, `misc`, `pipe`, `poll`, `proc`, `socket`
- `posix_mm.rs` — POSIX memory management (mmap, shm)
- `signals.rs` — POSIX signal delivery via notifications
- `cpio.rs` / `elf_loader.rs` / `elf_dynamic.rs` — CPIO parsing, ELF loading, dynamic linking support
- `sync.rs` — Synchronization primitives (Mutex, RWLock, Semaphore)
- `pthread.rs` — POSIX threads support
- `fork.S` — Fork assembly stub (arch-specific: `arch/x86_64/fork.S`, `arch/aarch64/fork.S`)

**saltyc** (`lib/besalt/c/`, C) — C standard library:
- POSIX stdio, stdlib, string, unistd, signal, time, termios, dirent, regex
- BSD compatibility (fts, getopt, termcap, pwd, grp)
- Delegates to userspace servers (VFS, procmgr) via libbesalt IPC
- Built as `libc.so`

**libc++** (`lib/besalt/cpp/`, C++) — Optional C++ runtime:
- libcxx + libcxxabi from `toolchain/llvm-project` sources
- `-fno-exceptions -fno-rtti`
- Built as `libc++.so` (auto-detected when llvm-project submodule is present)

## Rust 2024 Edition

**Edition-specific rules that apply to all Rust code:**
- **`unsafe_op_in_unsafe_fn`** (warn by default): Every unsafe operation inside an `unsafe fn` must be wrapped in an explicit `unsafe {}` block. Do not rely on the function signature alone.
- **No `static mut` references**: Taking `&` or `&mut` of a `static mut` is disallowed. Use `core::ptr::addr_of!` / `addr_of_mut!` for raw pointers, or `SyncUnsafeCell` for safe interior mutability.
- **`unsafe extern` blocks**: Items declared in `extern` blocks require explicit `unsafe` or `safe` annotation (e.g., `unsafe extern "C" { safe fn memset(...); }`).
- **RPIT lifetime capture**: `-> impl Trait` return types capture all in-scope lifetimes by default. Narrow with `+ use<'a>` if needed.
- **`gen` keyword reserved**: Do not use `gen` as an identifier.
- **`never` type fallback**: The `!` type falls back to `!` (not `()`).

## Key Design Details

- **Fat capabilities**: 32 bytes with inline metadata (object ptr, rights, type, depth, badge, parent ptr)
- **CNode sizing**: 4-16 bits (16 to 65,536 slots)
- **EDF scheduler**: Per-CPU ready queues, IPI-driven reschedule for affinity changes
- **SMP**: x86_64 uses ACPI MADT + AP trampoline; aarch64 uses PSCI CPU_ON + mailbox handoff
- **Frame minimum**: size_bits=12 enforced (4K pages) to prevent misaligned objects
- **IPC fastpath**: Assembly-dispatched fast path for Call (syscall 2) and ReplyRecv (syscall 3) — bails to slowpath for extra_caps>0, length>4, no waiting partner, cross-CPU, or fault-blocked
- **Bound notifications**: Bidirectional TCB↔Notification link; signals wake RecvBlocked threads

## Adding New Components

### New Kernel Source File

1. Create the `.rs` file in the appropriate `kernel/src/` subdirectory
2. Add `mod my_module;` to the parent module's `mod.rs` or `lib.rs`
3. Run `just distclean && just setup && just build` (the `find` in `kernel/meson.build` auto-discovers `.rs` files, but only on `meson setup`)

### New Userland Program

1. Create `userland/<domain>/<name>/src/main.rs` with `#![no_std]` and `#![no_main]`
2. Create arch-specific linker scripts: `userland/<domain>/<name>/arch/x86_64/link.ld` and `arch/aarch64/link.ld`
3. Create `userland/<domain>/<name>/meson.build` (copy pattern from an existing program like `userland/tests/test_runner/meson.build`)
4. Create `userland/services/<name>.service` with `[Service]` and `[Dependencies]` sections
5. Add `subdir('<domain>/<name>')` to `userland/meson.build`
6. Add the ELF and service file entries to the manifest in `tools/mkcpio.py`
7. Run `just distclean && just setup && just build`

### New Syscall

1. Add variant to the `Syscall` enum and its `TryFrom<u64>` impl in `kernel/src/syscall/mod.rs`
2. Add matching constant to `lib/besalt/lib/src/consts.rs`
3. Add dispatch arm in `syscall_handle_rust()` in `kernel/src/syscall/mod.rs`
4. Add raw syscall wrapper in `lib/besalt/lib/src/syscall.rs`
5. Update `docs/spec/syscalls.md`

### New Capability Invocation

1. Add invoke label constant to `lib/besalt/lib/src/consts.rs`
2. Add dispatch arm in `handle_invoke()` in `kernel/src/syscall/mod.rs`
3. Add wrapper function in `lib/besalt/lib/src/invoke.rs`
4. Update `docs/spec/syscalls.md`

## Testing and Verification

No formal unit test framework. Testing is done via QEMU boot and serial output observation.

```bash
just build                      # Must succeed before any commit
just run                        # Quick smoke test — watch serial for KERNEL PANIC
just run --smp 2                # SMP test — race conditions only show with >1 CPU
just run --smp 4                # Stress test with 4 CPUs
just run --headless --debug     # CI-like testing (serial only, logs to qemu.log)
just fmt-check                  # Check kernel Rust formatting
```

The `test_runner` userland program runs automated tests and prints `PASS`/`FAIL` for each test case via serial output. Watch for these lines to verify correctness.

**Do not use `cargo test`** — this project does not use Cargo.

## Commit Conventions

Format: `<type>(<scope>): <subject>` (scope is optional for cross-cutting changes)

**Types:** `feat`, `fix`, `docs`, `chore`, `refactor`, `test`, `perf`

**Scopes:** `kernel`, `boot`, `ipc`, `sched`, `cap`, `mm`, `vspace`, `syscall`, `libbesalt`, `saltyc`, `init`, `procmgr`, `vfs`, `console`, `nameserv`, `test_runner`, `mmsrv`, `rtld`, `ttyd`, `getty`, `blkdrv`, `pcisrv`, `display`, `saltyfs`

Examples:
```
feat(ipc): add notification polling with timeout
fix(sched): send EOI before timer_tick to prevent APIC lockup
feat: implement POSIX Phase 2 — sockets, poll, shm, fd passing
feat(kernel): aarch64 SMP support — PSCI AP bringup, GICv3 IPI, per-CPU data
docs: update design docs for bound notification
```

## Definition of Done

- [ ] `just build` succeeds with no new warnings
- [ ] `just run` boots to test_runner output without panics
- [ ] `just run --smp 2` does not deadlock or corrupt state
- [ ] `just fmt-check` passes
- [ ] Constants in sync: any new syscall/invoke label/error code in both kernel and `consts.rs`
- [ ] Design docs updated if architectural changes were made

## Documentation

Design documents in `docs/design/` — **read before making architectural changes**:
- `overview.md`, `kernel.md`, `capability.md`, `ipc.md`, `scheduling.md`, `memory.md`, `bootloader.md`, `saltyfs.md`, `posix.md`

Specifications in `docs/spec/` — **read before changing ABI or syscall interfaces**:
- `syscalls.md`, `abi.md`, `boot_protocol.md`
