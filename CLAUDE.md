# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SaltyOS is a capability-based microkernel OS written in Rust (kernel) and C (bootloader). All resource access is mediated through unforgeable capability tokens; the kernel provides only scheduling, IPC/event delivery, memory management, and capabilities — everything else (filesystem, drivers, process/lifecycle management) runs in userspace.

The kernel (`kernite`) blends three influences (see `docs/spec/kernite.md`): an **seL4-style authority model** (untyped memory, CNodes, explicit rights), a **Zircon/Fuchsia-style IPC/event edge** (MessagePipe / DataPipe / EventQueue / object Watches, under SaltyOS names), and a **Linux-style source-tree layout** (one module per plane). It does *not* import Linux process semantics or Zircon's handle-table authority.

**Design philosophy:**
- **Minimal trusted computing base** — the kernel is the only trusted code. Keep it small.
- **Correctness over performance** — get it right first. The IPC fastpath (register-payload `MP_WRITE` / `MP_READ`) is the exception: IPC is on every critical path, so it gets assembly-level optimization.
- **Capability-mediated access** — no ambient authority. Every resource access — including randomness, clock, shutdown, and debug output — requires an explicit capability token.
- **Primitives, not policy** — the kernel exposes small composable objects (pipes, watches, event queues, timers); timeout / multiplexing / retry are userland protocol concerns, not per-combination syscalls.

## Prerequisites

- **Rust nightly** with `rust-src` component (for `core` library cross-compilation) — edition 2024
- **Clang** (enforced — gcc will not work; Meson checks `cc.get_id() == 'clang'`)
- **NASM**, **Meson >= 1.1**, **Ninja**
- **bindgen** (generates the Rust UAPI bindings from the C headers)
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
just warn                   # Force-recheck all sources for warnings (no cache, no disk images)
just arch=aarch64 warn      # Same for aarch64

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

No `Cargo.toml` files — all Rust code is compiled via Meson with direct `rustc` invocation. The top-level `meson.build` descends in this order: `kernite/include/uapi` → `boot` → `kernite` → `lib` → `userland`. The build chain:

1. `kernite/include/uapi/meson.build` — Runs `bindgen` once over the C UAPI headers (`kernite/include/uapi/*.h`) → a single generated `uapi.rs`. That one source is recompiled against three rustc targets (kernel / saltyos-userland / PE) so the kernel, trona, and `kernel32.dll` share byte-identical ABI constants — symbol drift is impossible.
2. `kernite/meson.build` — Builds `core` + `kernite/compiler_builtins.rs` (kernel target), compiles `uapi.rs` → `libuapi-kernel.rmeta`, compiles kernel Rust → `.o`, assembles `.S` files, links `kernite.elf`.
3. `lib/trona/meson.build` — Builds `core` + `lib/trona/compiler_builtins.rs` (userland + RTLD + PE targets), compiles `uapi.rs` → `libuapi.rmeta` / `libuapi-pe.rmeta`, then the six trona crates, `fork.S`, and `kernel32.dll`; links `libtrona.so` / `libtrona.a`. `lib/trona/loader/meson.build` links the dynamic linkers `ldtrona-elf.so` and `ldtrona-pe.so`.
4. `lib/basalt/c/meson.build` — Builds basaltc (C stdlib → `libc.so`).
5. `lib/basalt/cpp/meson.build` — Builds libc++ (optional, from `toolchain/llvm-project`).
6. `userland/*/meson.build` — Each program compiled against the trona `.rmeta`s, linked with trona `.o` + `core.o`.
7. `tools/mkcpio.py` — Builds `initrd.cpio` from the files listed in `images/initramfs.manifest` (the loaders, `libtrona.so`, and the early-boot services needed before the rootfs mounts) — a minimal set, not the whole program tree.
8. `tools/mkimage.py` — Creates a bootable disk image with bootloader + kernel + initrd.

**Kernel rustc flags** (from `kernite/meson.build`):
```
--edition=2024  --target=<arch-specific-target-json>
-C panic=abort  -C opt-level=2  -C debuginfo=2
-C code-model=small  -C relocation-model=pic
```

**Userland** uses built-in rustc targets (`x86_64-unknown-saltyos`, `aarch64-unknown-saltyos`) — these require the patched stage1 rustc from the custom toolchain. The kernel uses custom JSON target specs (`kernite/x86_64-saltyos.json`, `kernite/aarch64-saltyos.json`).

**Init is statically linked** (links the trona crates directly into the ELF). Other userland programs use the shared `libtrona.so`, loaded by `rtld` (the runtime dynamic linker, `ldtrona-elf.so`).

### Build Gotchas

- **Clang is enforced.** The build fails with gcc. Do not suggest `cargo build`, `cargo test`, or create `Cargo.toml` files — this project does not use Cargo.
- **Rust flags live in `meson.build`**, not `.cargo/config.toml`.
- **All Meson targets are `custom` type.** Because the kernel and userland are freestanding and require direct `rustc`/`clang` invocations, Meson's `executable()` and `shared_library()` rules are never used. `meson introspect --targets` reports every target as `type: custom`. Filtering by Meson target type does not distinguish compilation targets from packaging targets — filter by output file extension (`.elf`, `.o`, `.rlib`, etc.) instead.
- **Linker scripts are per-architecture:** e.g., `kernite/arch/x86_64.ld` and `kernite/arch/aarch64.ld`; similarly each userland program has `arch/x86_64/link.ld` and `arch/aarch64/link.ld`.
- **Meson globs only `.S` at setup time** — the `find` in `kernite/meson.build` discovers assembly files during `meson setup` (a new `.S` needs a re-`setup`). Rust sources are **not** globbed: `rustc` compiles the crate from `src/lib.rs` following `mod` declarations, so a new `.rs` file just needs its `mod` decl, no re-`setup`.

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

Third-party software is built via declarative `.port` files in `ports/`. Available ports: **bash**, **bzip2**, **curl**, **freebsd-utils**, **htop**, **make**, **nano**, **nasm**, **ncurses**, **ninja**, **openssl**, **perl**, **python**, **sudo-rs**, **wget**, **xz**, **zlib**, **zstd**.

```bash
just port bash              # Build a port (fetch, configure, make, install)
just fetch-ports            # Download all port sources
just port-info bash         # Show parsed port config
```

Port format is INI-style with `[port]`, `[source]`, `[build]`, `[env]`, `[stage]`, `[stage.exclude]`, `[depends]` sections. Dependencies in `[depends]` support version constraints (`ncurses >= 6.5`, `openssl >= 3.4 < 4`). Each port produces an FHS-shaped `stage-<arch>/` tree (via `make install DESTDIR=…` by default, or an explicit `[stage] mode = script`) that overlays into `build-<arch>/sysroot/` at build time and into the rootfs at image-assembly time (minus a fixed dev-file filter). Legacy `[install]` mappings are rejected — all ports must declare `[stage]`. The port build tool is in `tools/port/` (Rust). Ports are optional (`-Dbuild_ports=true`). See `docs/design/ports.md` for the full spec.

## Rootfs and Images

```bash
just image                  # Create BIOS disk image
just image-uefi             # Create UEFI disk image
just mkrootfs               # Build rootfs.img (binaries + optional LLVM/ports)
just mksaltyfs              # Generate SaltyFS test image
```

## Code Patterns and Safety Rules

### Lock Ordering

Lock ordering (outermost → innermost), authoritatively documented on `CAP_LOCK` in `kernite/src/mm/mod.rs` (the abbreviated copy on `SERIAL_LOCK` in `kernite/src/lib.rs` omits the inner COW-tree / MO levels — trust `mm/mod.rs`):

```
CAP_LOCK
  → IRQ_LOCK                                                   (interrupt delivery)
  → mp_core.lock / dp_core.lock / eq.lock / tcb_lock / sc.lock (per-object)
  → SLEEP_LOCK / FUTEX_LOCK                                    (independent globals)
  → sched.lock_cpu                                             (per-CPU)
  → VmHierarchyState.lock                                      (per-COW-tree)
  → VSpace.lock → ASID_LOCK
  → MO.commit_lock | MO.rmap_lock                              (disjoint, same level)
  → ut.alloc_lock
  → FRAME_LOCK → SERIAL_LOCK                                   (global PMM, leaf)
```

Key invariants:
- **`IRQ_LOCK` nests outside the per-object locks** on the interrupt path: `dispatch_irq` holds it across `IrqHandler::signal_fire` → `eq.lock` (`EventQueue::link_irq`); `eq.lock` is dropped before waking an `EQ_WAIT` waiter, so it never nests `sched.lock_cpu`.
- **`VmHierarchyState.lock`** (the per-COW-tree serialization lock, object type `VM_HIERARCHY_STATE`) nests **outside** `VSpace.lock` and serializes every page-identity / topology / write-protect / fault op across one COW tree. While holding it, never take `CAP_LOCK`, never call `release_object()` (it takes `REAPER_LOCK`), and never wake / signal / enqueue inline — those defer until after the lock drops (deferred-release lists, deferred pager emit/wake, post-unlock `RangeChangeList` TLB flush). That keeps the lock graph acyclic.
- **`MO.commit_lock`** (committed-page radix tree) and **`MO.rmap_lock`** (reverse maps) are disjoint and same-level — holding both at once is forbidden. `MemoryObject::destroy()` uses snapshot + re-validate to traverse `reverse_maps` without nesting `MO.rmap_lock` around `VSpace.lock`.
- **Release is shallow; destruction is deferred.** `release_object()` (called from `delete_capability()` under `CAP_LOCK`) only decrements the refcount and, at zero, enqueues the object onto the reaper (`kernite/src/object/reaper.rs`); the reaper later reacquires `CAP_LOCK` and runs final cleanup. `syscall_handle_rust` drains the reaper after every syscall.

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
- **Map between error types explicitly** with dedicated functions (e.g., `syscall_error_from_cap_error()`). Do not add `impl From<X> for Y` — explicit mapping prevents accidental information loss.
- **The userland-facing wire codes are the `KERNITE_ERR_*` values in `kernite/include/uapi/error.h`** (`KERNITE_OK` = 0 … `KERNITE_ERR_INSUFFICIENT_RESOURCES` = 29), surfaced to Rust via the bindgen-generated `uapi.rs`. The kernel's internal `SyscallError` variants must map onto these stable codes; do not hand-maintain a parallel Rust copy.

### FFI Conventions

- Kernel functions called from assembly: `#[unsafe(no_mangle)] pub extern "C" fn`
- trona public C-ABI exports: `#[unsafe(no_mangle)] pub extern "C" fn` with `trona_` prefix
- Shared structures: `#[repr(C)]` always
- **The single source of truth for every value crossing the kernel/userland boundary** (object types, invoke labels, error codes, rights, state flags, wire structs, ABI version) is the C headers in `kernite/include/uapi/`. `bindgen` generates one `uapi.rs` compiled against all three targets (kernel, trona, PE), so the numeric values are never duplicated in Rust. Caveat: bindgen cannot fold `#define` u64 macros directly, so each scalar is bridged through a `kernite_bindgen_u64_*` definition in `bindgen.h` and re-exported by `bindgen_aliases.rs` — adding a **new** constant means its `#define` plus those two one-line bridges, but the value itself still lives only in the header. The headers — plus `lib/trona/kernel/src/syscall.rs` for the register ABI — are authoritative; trust them over any in-tree spec prose on conflict.

## Architecture

### Kernel (Rust, `kernite/src/`)

The tree is organized by **plane** (see `docs/spec/kernite.md`): task lifecycle, scheduling, IPC, event delivery, and object lifetime are separate modules with explicit ownership.

| Module | Purpose |
|--------|---------|
| `lib.rs` | Entry (`kmain`), serial I/O, panic handler |
| `acpi.rs` | Shared ACPI table parsing (RSDP/XSDT, MCFG/PCIe ECAM) |
| `bootinfo.rs` | Boot info TLV parsing |
| `cpio.rs` | CPIO archive parser for initrd |
| `elf.rs` | ELF binary loader (init bootstrap) |
| `init.rs` | Init task bootstrap, CSpace setup, startup-descriptor build |
| `rng.rs` | RDRAND-based RNG (backs the `KernelRng` cap) |
| `arch/x86_64/` | GDT, IDT, APIC, ACPI, paging, SMP, CPUID, FPU, PIT, SMAP/SMEP |
| `arch/aarch64/` | GICv3, PSCI, generic timer, paging (TTBR0/TTBR1), FPU/NEON, PL011 UART |
| `cap/` | CNode, Untyped retype, CDT, refcounting, IoPort/Pager/system caps, object-size asserts |
| `console/` | Kernel console output (serial + framebuffer) |
| `task/` | **Task plane** — thread lifecycle, wait reasons, stop/configure gating, quiesce |
| `sched/` | **Scheduling plane** — 4-class scheduler (`class/` = deadline/rt/fair/idle), run queues + balance/switch/wake (`scheduler/`), PIP |
| `ipc/` | **IPC plane** — `MessagePipe`, `DataPipe`, capability `transfer`, fault delivery, futex |
| `event/` | **Event plane** — object state flags, `Watch`es, `EventQueue`/records, IRQ + timer → event delivery |
| `object/` | **Object-lifetime plane** — deferred-destruction reaper, final cleanup sequencing |
| `mm/` | VSpace (page tables, COW, demand paging), MemoryObject, bitmap PMM, CPU/memory accounting |
| `syscall/` | Single `INVOKE` dispatch (`dispatch.rs` → `invoke.rs`) split per object family (`tcb`/`vspace`/`mo`/`pipe`/`event`/`cap`/`cspace`/`ioport`/`sc`/`pager`/`system`/`misc`), plus the IPC `fastpath` |

**Key x86_64 assembly files** in `kernite/src/arch/x86_64/`:
- `syscall.S` — Syscall entry/exit via `syscall`/`sysretq`. User RSP is saved on the **per-thread kernel stack** (not per-CPU `%gs:16`) to prevent RSP corruption during context switches. The IPC fastpath is taken for register-payload `MP_WRITE`/`MP_READ` invocations and bails to the slowpath otherwise (see `syscall/fastpath.rs`).
- `exceptions.S` — IDT exception handlers
- `ap_tramp.S` — SMP application processor trampoline (real→long mode)

**Key aarch64 details** in `kernite/src/arch/aarch64/`:
- SMP via PSCI `CPU_ON` (HVC call), AP mailbox structure for stack/register handoff
- GICv3: distributor (GICD), redistributor (GICR), CPU interface via system registers (ICC)
- Generic timer: EL1 physical timer (CNTP) with PPI 30, 10ms tick
- FPU: NEON Q0-Q31 (512 bytes) lazy context switch via CPACR_EL1 trapping
- PL011 UART for early console output

### Kernel ABI — the single `INVOKE` trap

The kernel exposes **one syscall**, `SYS_INVOKE` (number `0`). Every operation is a *capability invocation*: the kernel resolves the cap in `cap_ptr`, reads its object type, and dispatches on the `(obj_type, label)` pair. There is no ambient authority — randomness, clock, shutdown, system info, and debug output are all reached through dedicated capability objects (`KernelRng` / `Clock` / `SystemControl` / `SystemInfo` / `KernelDebug`).

**Calling convention** (authoritative: `lib/trona/kernel/src/syscall.rs`; kernel side is `arch/x86_64/syscall.S` + `arch/aarch64/exceptions.rs`):

| Register | x86_64 (`syscall`) | aarch64 (`svc #0`) |
|----------|--------------------|--------------------|
| syscall number (always `INVOKE` = 0) | `rax` | `x8` |
| cap_ptr | `rdi` | `x0` |
| invoke label (selects the op) | `rsi` | `x1` |
| payload args (4) | `rdx`, `r10`, `r8`, `r9` | `x2`–`x5` |
| return: error code | `rax` | `x0` |
| return: value | `rdx` | `x1` |

The register set carries only the cap, the label, and four payload words; per-IPC length, extra-cap count, and larger payloads live in the per-thread 4 KiB **IPC buffer** (`struct kernite_ipc_buffer`, `kernite/include/uapi/ipc.h`): a `msg[label, length, regs[0..31]]` overlay, `badge`, `mp_flags`, up to 4 cap-transfer slots, the receive-slot target, the `MP_CALL` `txid`, and a reserved area where the kernel publishes the inbound `kernite_event_record` for `EQ_WAIT`/`EQ_POLL`.

**Object types** (`kernite/include/uapi/object.h`, ABI-stable, retired IDs not reused; ID 22 is a gap):

| ID | Type | ID | Type |
|----|------|----|------|
| 1 | `UNTYPED` | 13 | `DATA_PIPE` |
| 2 | `TCB` | 14 | `TIMER` |
| 3 | `CNODE` | 15 | `KERNEL_RNG` |
| 4 | `VSPACE` | 16 | `SYSTEM_CONTROL` |
| 5 | `FRAME` | 17 | `CLOCK` |
| 6 | `IRQ_HANDLER` | 18 | `SYSTEM_INFO` |
| 7 | `IO_PORT` | 19 | `KERNEL_DEBUG` |
| 8 | `SCHED_CONTEXT` | 20 / 21 | `MESSAGE_PIPE_CORE` / `DATA_PIPE_CORE` |
| 9 | `MEMORY_OBJECT` | 23 | `PAGER` |
| 10 | `EVENT_QUEUE` | 24 | `DEVICE_CONTROL` |
| 11 | `WATCH` | 25 | `VM_HIERARCHY_STATE` |
| 12 | `MESSAGE_PIPE` | | |

Each fixed-layout object's exact byte size is recorded as `KERNITE_*_BYTES` in `object.h` and asserted against `size_of::<T>()` at kernel compile time (`cap/object_size_assert.rs`) — a layout drift is a build error.

**Invoke labels** (`kernite/include/uapi/invoke.h`) use a 0x20-stride block per object type; dispatch keys on `(obj_type, label)`, so two types may reuse a hex slot:

| Block | Object | Block | Object |
|-------|--------|-------|--------|
| `0x020` | CNode | `0x140` | Watch (`REGISTER/DISARM/CANCEL`) |
| `0x040` | Untyped (`RETYPE/RESET/GET_STATS`) | `0x160` | MessagePipe (`MP_WRITE/READ/CLOSE/CALL`) |
| `0x060` | TCB | `0x180` | DataPipe (`DP_PRODUCE/CONSUME/QUERY/…`) |
| `0x080` | VSpace (map/protect/COW/MO/futex) | `0x1A0` | Timer (`SET/CANCEL/QUERY`) |
| `0x0A0` | SchedContext | `0x1C0` | KernelRng |
| `0x0C0` | IoPort | `0x1E0` | SystemControl (`SHUTDOWN/REBOOT`) |
| `0x0E0` | IrqHandler (`BIND_EQ/UNBIND_EQ/ACK`) | `0x200` | Clock |
| `0x100` | MemoryObject | `0x220` | SystemInfo |
| `0x120` | EventQueue (`EQ_WAIT/POLL/CANCEL`) | `0x240` | KernelDebug (putchar/putstr/dump) |
| `0x260` / `0x280` | MessagePipeCore / DataPipeCore (`*_PAIR`) | `0x2C0` | Pager (`BIND_EQ/SUPPLY_PAGE/…`) |
| `0x2E0` | DeviceControl (`CREATE_IOPORT/UNTYPED/IRQ`) | | |

**Rights** (`rights.h`): `READ`/`WRITE`/`EXECUTE`/`GRANT`/`MAP`/`CONFIGURE`/`RESUME`/`DUPLICATE`/`SIGNAL`/`WAIT`/`TRANSFER` (`ALL` = `0x7FF`). Mint may only narrow rights; copy/move preserves them.

**IPC / event model** — endpoints and notifications are gone; the edge is built from:
- **`MessagePipe`** — bounded record stream (label + 32 words + up to 4 transferred caps + `flags` + `txid`); the default control-plane transport. `MP_CALL` writes a `CALL`-flagged record and parks the caller until a reply-marked `MP_WRITE` with the matching `txid` arrives (kernel txids carry bit 63 set so userspace cannot forge a reply).
- **`DataPipe`** — kernel-managed byte-stream object for bulk transfer; userland moves data via `DP_PRODUCE` / `DP_CONSUME` with kernel staging. There is **no** MAP op (per `invoke.h`); a zero-copy shared-memory variant would be a separate `MemoryObject` mapping, not a DataPipe mode.
- **`EventQueue` + object `Watch`es** — every state-bearing object exposes a `state_flags` word (`READABLE`/`WRITABLE`/`PEER_CLOSED`/`SIGNALED`/…); a `Watch` binds selected flags to an `EventQueue`, which delivers typed `kernite_event_record`s. This is the lost-wakeup-free replacement for bound notifications, `recv_any`, and timed-IPC variants — timeouts/multiplexing compose from `Timer` objects + `EventQueue`.
- **Faults** — a thread with a bound fault `MessagePipe` (`TCB_SET_FAULT_PIPE`) receives kernel-synthesised records labelled `KERNITE_FAULT_*` (`fault.h`: page fault / illegal insn / breakpoint / OOM / cap fault).
- **Pager** — file-backed MO page-absent faults route through a `Pager`'s bound `EventQueue` as `EVENT_TYPE_PAGER_REQUEST`; the page owner (vfs) replies with `PAGER_SUPPLY_PAGE` / `PAGER_SUPPLY_COPY` or `PAGER_FAIL`.

### Well-Known Capability Slots

Only three slots are ABI-fixed in every CSpace (including the kernel-bootstrapped init task), defined in `object.h`:

| Slot | Name | Description |
|------|------|-------------|
| 0 | `CAP_SELF_TCB` | Thread's own TCB |
| 1 | `CAP_SELF_VSPACE` | Thread's page-table root |
| 2 | `CAP_SELF_CSPACE` | Thread's CNode root |

The capabilities a process is **born with** are described by the **SaltyOS startup descriptor** referenced by the `AT_SALTYOS_STARTUP` (`0x2005`) auxv entry (`kernite/include/uapi/startup.h`): a `SaltyOSStartupLayoutV1` (IPC-buffer / scratch / DSO-window vaddrs, boot untyped, mapped images, framebuffer) plus a `SaltyOSCapTableV1` of `(role_id, slot, rights)` entries. Capabilities are addressed by **role**, not hard-coded slot: preinstalled system/hardware caps use the `SALTYOS_CAP_ROLE_*` IDs (`NAMESRV_CLIENT`, `VFS_CLIENT`, `MMSRV_CLIENT`, `RSRCSRV_CLIENT`, `COM1_IOPORT`, `DEVICE_CONTROL`, `KERNEL_RNG`, `CLOCK`, `SYSTEM_CONTROL`, …), and service-local peer aliases get role IDs derived from the service manifest. Caps not present at startup (e.g. a connection to a service started later) are obtained at runtime via namesrv. Resolve all of these through the trona role getters, never by slot number.

**Do not reintroduce hard-coded slot numbers** for service endpoints, hardware caps, or server-private scratch slots. Server-private slots are allocated dynamically via the trona slot allocator at startup so they cannot collide with the RTLD runtime frame pool.

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
| `init` | `core/init` | First process — service-based multi-phase bootstrap; owns spawn / exit / waitpid / lifecycle supervision |
| `mmsrv` | `core/mmsrv` | Memory manager server (centralized frame allocation, VSpace mapping, MO) |
| `rsrcsrv` | `core/rsrcsrv` | Resource server (kernel object allocation, quotas, owner-based reclaim) |
| `logsrv` | `core/logsrv` | Log server (boot/diagnostic log sink) |
| `namesrv` | `core/namesrv` | Name service (endpoint lookup) |
| `vfs` | `core/vfs` | Virtual filesystem server (ramfs + devfs + procfs + sysctlfs + sockets + shm + poll) |
| `console` | `servers/console` | Serial console server (IoPort cap for COM1) |
| `netsrv` | `servers/netsrv` | TCP/UDP/ICMP network stack (smoltcp) |
| `dnssrv` | `servers/dnssrv` | DNS resolver (recursive, caching) |
| `posix_ttysrv` | `servers/posix/posix_ttysrv` | POSIX TTY/PTY daemon (line discipline, signal generation) |
| `posix_getty` | `servers/posix/posix_getty` | POSIX login prompt |
| `posix_login` | `servers/posix/posix_login` | POSIX session login handler |
| `win32_csrss` | `servers/win32/win32_csrss` | Win32 console subsystem + import resolver |
| `pcidrv` | `drivers/pcidrv` | PCI enumeration server |
| `blkdrv` | `drivers/blkdrv` | Block device driver (virtio-blk) |
| `netdrv` | `drivers/netdrv` | Network device driver (virtio-net) |
| `dispdrv` | `drivers/dispdrv` | Display driver (framebuffer) |
| `saltyfs` | `drivers/filesystems/saltyfs` | SaltyFS filesystem server (COW, B-tree, snapshots) |
| `test_runner` | `tests/test_runner` | Automated test suite |
| `hello_pe` | `tests/hello_pe` | Win32 PE test program (C) |

**Service-based bootstrap**: Init reads `.service` files from `userland/services/` in the initrd to determine boot order and capability wiring. A `.service` declares `[Service]` (name, binary, type, restart policy), `[Dependencies]` (`After`/`Before` ordering, `Requires=` on companion `.socket`/`.cap`/`.target` units, `RequiresInterface=`), `[Capabilities]` (`ProvidesInterface`/`InterfaceRole`/`Exports`, mapping endpoints to `ROLE_*` IDs), and `[Memory]`/`[Quotas]`. Companion `.socket` (service endpoints), `.cap` (hardware caps), and `.target` (sync points) units live alongside. `procmgr` (`core/procmgr`) is **archived, not built** — init absorbed its spawn/lifecycle role; the directory is kept for history only.

The initrd (`tools/mkcpio.py`, driven by `images/initramfs.manifest`) carries only the minimal pre-rootfs set — loaders, `libtrona.so`, and the early-boot services + their unit files; the full program set is installed into the rootfs image.

**Architecture-specific code** in userland programs lives in `src/arch/x86_64.rs` and `src/arch/aarch64.rs` modules (e.g., `pcidrv` has PCI ECAM mapping for aarch64 vs I/O port access for x86_64).

### Libraries

Multi-tier library architecture:

**trona** (`lib/trona/`, Rust) — the system library. `libtrona.so` (+ `libtrona.a` for static init) is built from **six crates**:

- `kernel/` (crate: `trona_kernel`) — the raw kernel-ABI layer: `syscall.rs` (inline-asm `INVOKE` wrapper), `invoke.rs` (typed capability-invocation helpers), `ipc.rs` / `ipc_buffer.rs` (IPC-buffer + MP-record access), `bootinfo.rs`, and the object/handle core types.
- `protocol/` (crate: `trona_protocol`) — cross-server wire constants and reply-payload shapes (vfs, mmsrv, rsrcsrv, namesrv, console/display/block/net/dns/saltyfs drivers, posix, win32). Replaces the old `uapi/protocol/`.
- `server/` (crate: `trona_server`) — server-loop primitives: the `EQ_WAIT` reactor / event loop, receive-slot arena, reply lease, continuation / outbound helpers.
- `runtime/` (crate: `trona_runtime`) — process runtime: slot allocator, lazy cap lookup, TLS, weak-symbol cap roles, C-ABI exports, and `spawn`/`thread`/`client` support.
- `posix/` (crate: `trona_posix`) — POSIX wrappers (at/file/pipe/poll/proc/socket/dns, `mm`, `signals`, `sync`, `pthread`, `tls`) built on the four crates above. Rust API only, no C ABI.
- `loader/` (crate: `trona_loader`) — ELF/PE/CPIO loading and dynamic linking; `loader/rtld/elf/` links the ELF dynamic linker `ldtrona-elf.so` and `loader/rtld/pe/` the PE linker `ldtrona-pe.so`.

Two further pieces in `lib/trona/` are built **separately** from the six-crate `libtrona.so`: `win32/` (crate: `kernel32`) is the Rust-backed `kernel32.dll`, a standalone PE DLL compiled against the windows-gnu target (console / handle / process / error); and `arch/` holds the fork assembly stubs (`x86_64/fork.S`, `aarch64/fork.S`).

The shared ABI constants (object types, invoke labels, errors, rights, wire structs) are **not** a trona crate — they are the bindgen-generated `uapi.rs` from `kernite/include/uapi/` (see Build System Details), compiled to `libuapi.rmeta` and depended on by every crate above.

**basalt** (`lib/basalt/`, C/C++) — C/C++ standard library (thin C ABI surface):

- `c/` (crate: `basaltc`) — C standard library:
  - POSIX stdio, stdlib, string, unistd, signal, time, termios, dirent, regex
  - BSD compatibility (fts, getopt, termcap, pwd, grp)
  - Delegates to userspace servers (vfs, init, mmsrv) via trona IPC
  - Built as `libc.so`

- `cpp/` — Optional C++ runtime:
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
- **4-class scheduler**: classes `SCHED_CLASS_DEADLINE` / `SCHED_CLASS_RT_FIFO` / `SCHED_CLASS_FAIR` / `SCHED_CLASS_IDLE`. Deadline uses EDF-style key (earliest deadline first), RT FIFO uses static priority, Fair is EEVDF-style (vruntime + lag, intrusive treap aliasing `sleep_next`/`futex_next`/`vspace_wait_next`), Idle is the fallback. Per-CPU ready queues per class; IPI-driven reschedule for affinity changes.
- **SMP**: x86_64 uses ACPI MADT + AP trampoline; aarch64 uses PSCI CPU_ON + mailbox handoff
- **Frame minimum**: size_bits=12 enforced (4K pages) to prevent misaligned objects
- **IPC fastpath**: Assembly-dispatched fast path for register-payload `MP_WRITE` / `MP_READ` invocations — bails to the slowpath for cap transfers, oversized payloads, no waiting partner, cross-CPU, or fault-blocked targets (`syscall/fastpath.rs`).
- **Event-driven async**: object `state_flags` + `Watch` + `EventQueue` (lost-wakeup-free) replace bound notifications; `Timer` objects + `EventQueue` compose timeouts and multiplexing instead of timed / `recv_any` syscall variants.
- **MemoryObject** (`OBJ_MEMORY_OBJECT = 9`): Fuchsia-inspired memory abstraction with commit/decommit/clone/resize/snapshot (invoke block `0x100`); VSpace MO mapping (`MAP_MO`, `SHARE_RO_PAGE`, `FORK_RANGE`, …) lives in the VSpace block. COW topology per tree is serialized by a `VM_HIERARCHY_STATE` lock object.
- **Object lifetime**: refcount release is shallow; at zero the object is enqueued to the reaper (`object/reaper.rs`), which runs deferred final cleanup — no deep teardown inline from a refcount drop.
- **Multi-personality subsystem**: POSIX (subsystem ID 0) and Win32 (subsystem ID 1) run side-by-side, each with its own servers (`posix_ttysrv`/`posix_getty`/`posix_login`; `win32_csrss`). Win32 processes use the PE/COFF loader and the `kernel32.dll` shim. (`SUBSYSTEM_POSIX` = 0, `SUBSYSTEM_WIN32` = 1.)
- **Network stack**: TCP/UDP/ICMP via smoltcp in netsrv, with split blocking ops (NET_*_WAIT IPC labels). DNS resolution in dedicated dnssrv. DHCP auto-configuration via netdrv (virtio-net)

## Adding New Components

### New Kernel Source File

1. Create the `.rs` file in the appropriate `kernite/src/` subdirectory
2. Add `mod my_module;` to the parent module's `mod.rs` or `lib.rs`
3. Run `just build` — `rustc` picks up the new module from its `mod` declaration. (Only a new `.S` assembly file requires re-running `meson setup`, since those are glob-discovered.)

### New Userland Program

1. Create `userland/<domain>/<name>/src/main.rs` with `#![no_std]` and `#![no_main]`
2. Create arch-specific linker scripts: `userland/<domain>/<name>/arch/x86_64/link.ld` and `arch/aarch64/link.ld`
3. Create `userland/<domain>/<name>/meson.build` (copy pattern from an existing program like `userland/tests/test_runner/meson.build`)
4. Create `userland/services/<name>.service` (plus any `.socket`/`.cap` companion units) declaring `[Service]`, `[Dependencies]`, and `[Capabilities]`
5. Add `subdir('<domain>/<name>')` to `userland/meson.build`
6. If the program must be in the pre-rootfs initrd, add its ELF + unit-file entries to `images/initramfs.manifest` (the `initrd_path=build_output` manifest that `tools/mkcpio.py` consumes); otherwise it ships via the rootfs
7. Run `just build`

### New Capability Invocation (the way to add kernel operations)

There is only one syscall (`INVOKE`); a new kernel operation is a new invoke label on an object type, never a new syscall number.

1. Add the `KERNITE_INV_*` label to `kernite/include/uapi/invoke.h` (in that object's 0x20 block). For a new object type, also add `KERNITE_OBJ_*` + its `KERNITE_*_BYTES` to `object.h` and a `size_of` assert in `cap/object_size_assert.rs`.
2. Bridge the scalar to Rust: add a `kernite_bindgen_u64_*` line in `bindgen.h` and a matching `pub const … = kernite_bindgen_u64_…;` re-export in `bindgen_aliases.rs` (bindgen can't fold `#define` u64 macros directly). The value still lives only in the header; rebuilding regenerates `uapi.rs` for kernel + trona + PE.
3. Add the dispatch arm in the matching `kernite/src/syscall/<family>.rs` (wired from `syscall/invoke.rs`).
4. Add the typed wrapper in `lib/trona/kernel/src/invoke.rs`.
5. Update `docs/spec/syscalls.md` (and `abi.md` for any new wire struct).

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

The `test_runner` userland program runs its internal test modules (hello, fs, mmap, fork, signal, socket, pipe, time, terminal, epoll, pthread, dns, saltyfs, sse, neon, vfs_stress_mt, win32_console_stress) and prints `PASS`/`FAIL` for each test case via serial output. Watch for these lines to verify correctness. The `hello_pe` PE/COFF test program runs separately from `test_runner`.

**Do not use `cargo test`** — this project does not use Cargo.

## Commit Conventions

Format: `<type>(<scope>): <subject>` (scope is optional for cross-cutting changes)

**Types:** `feat`, `fix`, `docs`, `chore`, `refactor`, `test`, `perf`

**Scopes:** `kernite`, `boot`, `ipc`, `event`, `task`, `object`, `sched`, `cap`, `mm`, `vspace`, `syscall`, `trona`, `uapi`, `basaltc`, `init`, `procmgr`, `vfs`, `console`, `namesrv`, `test_runner`, `mmsrv`, `rsrcsrv`, `logsrv`, `rtld`, `posix_ttysrv`, `posix_getty`, `blkdrv`, `pcidrv`, `dispdrv`, `netdrv`, `netsrv`, `dnssrv`, `saltyfs`, `win32`, `win32_csrss`, `ports`

Examples:
```
feat(ipc): add MessagePipe call-transaction id correlation
fix(sched): send EOI before timer_tick to prevent APIC lockup
feat: implement POSIX Phase 2 — sockets, poll, shm, fd passing
feat(kernite): aarch64 SMP support — PSCI AP bringup, GICv3 IPI, per-CPU data
docs: update design docs for the EventQueue / Watch model
```

## Definition of Done

- [ ] `just warn` passes with no new warnings, then `just build` succeeds
- [ ] `just run` boots to test_runner output without panics
- [ ] `just run --smp 2` does not deadlock or corrupt state
- [ ] `just fmt-check` passes
- [ ] ABI constants live only in `kernite/include/uapi/*.h` (bindgen regenerates the Rust side — never hand-add a parallel copy of the value)
- [ ] Design docs updated if architectural changes were made

## Documentation

Design documents in `docs/design/` — **read before making architectural changes**:
- `overview.md`, `kernel.md`, `capability.md`, `ipc.md`, `scheduling.md`, `memory.md`, `bootloader.md`, `saltyfs.md`, `posix.md`, `trona.md`, `basaltc.md`, `mmsrv.md`, `ports.md`

Specifications in `docs/spec/` — **read before changing ABI or syscall interfaces**. The kernel ABI surface itself is the C headers in `kernite/include/uapi/`; the spec prose mirrors them, so trust the headers on any conflict:
- `kernite.md` (kernel architectural direction), `syscalls.md`, `abi.md`, `boot_protocol.md`, `mmsrv.md`, `vfs.md`, `rtld-loader.md`, `saltyfs-backend-wire.md`

API references in `docs/spec/`:
- `trona-api.md`, `basaltc-api.md`
