# libsalty

libsalty is the SaltyOS system library. It provides raw syscall wrappers, IPC message helpers, capability invocation functions, POSIX-compatible file/process/socket/memory operations, ELF loading, CPIO parsing, and signal handling. All public functions use `#[unsafe(no_mangle)] pub extern "C"` signatures for C ABI compatibility with the runtime dynamic linker (rtld). libsalty is the sole interface between userland programs and the SaltyOS kernel.

## Architecture

```
+----------------------------------------------------------+
|                    Application                           |
|          (init, procmgr, console, vfs, ...)              |
+----------------------------------------------------------+
        |               |               |
+-------v-------+ +----v----+ +--------v--------+
|    POSIX      | |   IPC   | |   Capability    |
|  posix.rs     | | ipc.rs  | |   invoke.rs     |
|  posix_mm.rs  | |         | |   slot_alloc.rs |
|  signals.rs   | |         | |                 |
+-------+-------+ +----+----+ +--------+--------+
        |               |               |
+-------v---------------v---------------v--------+
|                 Syscall Layer                    |
|               syscall.rs (inline asm)            |
+-------------------------------------------------+
        |
+-------v-----------------------------------------+
|                   Kernel                         |
|    (IPC, scheduling, memory, capabilities)       |
+-------------------------------------------------+
```

## Source Files

| File | Lines | Description |
|------|------:|-------------|
| `src/lib.rs` | 634 | Crate root, global state, C ABI exports for IPC/caps/sockets/time |
| `src/consts.rs` | 470 | Syscall numbers, invoke labels, error codes, cap slots, POSIX constants |
| `src/types.rs` | 418 | Core types: SaltyMsg, IpcBuffer, IpcContext, ELF/CPIO structs, POSIX types |
| `src/syscall.rs` | 36 | Raw `syscall` instruction wrapper (inline asm) |
| `src/ipc.rs` | 232 | IPC operations: send, recv, call, reply_recv, nbsend, cap transfer |
| `src/invoke.rs` | 266 | Capability invocations: CNode, Untyped, TCB, VSpace, IRQ, IoPort |
| `src/posix.rs` | 2078 | POSIX file I/O, process mgmt, sockets, poll, epoll, pipes, *at() family |
| `src/posix_mm.rs` | 403 | Memory management: brk, sbrk, mmap (anon + device-backed), munmap, mprotect |
| `src/signals.rs` | 140 | POSIX signal handling via notification polling |
| `src/slot_alloc.rs` | 502 | Dynamic CNode slot allocator with async CSpace/untyped expansion |
| `src/elf_loader.rs` | 686 | ELF64 loader: PT_LOAD mapping, PIE relocation, untyped scanning |
| `src/elf_dynamic.rs` | 243 | ELF dynamic linking: PT_INTERP detection, DT_NEEDED extraction |
| `src/cpio.rs` | 263 | CPIO newc archive parser: find, iterate, extended metadata |
| `src/serial.rs` | 172 | Serial output: putc, puts, hex, dec, LineBuf for atomic multi-part output |
| `src/framebuffer.rs` | 59 | Framebuffer info reader from kernel boot info page |
| `src/layout.rs` | 148 | Child process VA layout planner (IPC buf, code, stack, RTLD regions) |
| `fork.S` | 54 | Fork assembly trampoline: saves/restores callee-saved registers |
| `libsalty.ld` | 20 | Linker script for libsalty.so |
| `meson.build` | 65 | Build rules: rustc, clang (fork.S), lld linking |
| **Total** | **6889** | |

## Build Pipeline

libsalty is built via Meson (not Cargo). The pipeline has three steps:

```
Step 1: rustc
  src/lib.rs  -->  libsalty.o + libsalty.rmeta
  Flags: --edition=2024 --target=x86_64-unknown-none
         -C panic=abort -C opt-level=2
         -C code-model=small -C relocation-model=pic

Step 2: clang
  fork.S  -->  fork.o

Step 3: lld (via clang -fuse-ld=lld)
  libsalty.o + fork.o + core.o + compiler_builtins.o
    --> libsalty.so
  Linked with: -shared -nostdlib -nostartfiles
               -Wl,-soname,libsalty.so
               -T libsalty.ld
```

The `.rmeta` file is consumed by downstream crates (saltyc, userland programs) for type/trait information at compile time. The `.o` file provides the actual code.

## Linking Model

- **init** is statically linked: libsalty.o is embedded directly into the init binary. This is necessary because init runs before rtld is available.
- **All other programs** dynamically link against `libsalty.so` via the runtime dynamic linker (`userland/rtld`). rtld loads libsalty.so into the process address space and resolves symbols before transferring control to the program.

## Key Concepts

### Capability Slots

Every kernel object (endpoint, frame, TCB, VSpace, etc.) is referenced by a capability slot index in the thread's CNode. Well-known slots are assigned by the kernel at boot:

| Slot | Name | Purpose |
|------|------|---------|
| 0 | `CAP_SELF_TCB` | Thread's own TCB |
| 1 | `CAP_SELF_VSPACE` | Thread's page table root |
| 2 | `CAP_SELF_CSPACE` | Thread's CNode root |
| 3 | `CAP_PROCMGR_EP` | Process manager endpoint |
| 4 | `CAP_VFS_EP` | VFS server endpoint |
| 7 | `CAP_UNTYPED` | Untyped memory for frame allocation |
| 16+ | `CAP_UNTYPED_START` | Additional untyped memory capabilities |

See `src/consts.rs` for the complete list.

### IPC Pattern

All POSIX operations follow the same pattern: build a `SaltyMsg`, call the appropriate server endpoint, and decode the reply:

```rust
let mut msg = SaltyMsg::zeroed();
let mut reply = SaltyMsg::zeroed();
msg.label = POSIX_VFS_OPEN;        // operation label
msg.regs[0] = flags as u64;        // pack arguments into regs
// ... pack path into remaining regs ...

ipc::call_ctx(&raw mut __salty_ipc_ctx, CAP_VFS_EP, &msg, &mut reply);

if reply.label == SALTY_OK {
    let fd = reply.regs[0] as i32;  // decode result
}
```

File I/O goes to `CAP_VFS_EP` (VFS server), process operations go to `CAP_PROCMGR_EP` (process manager).

### POSIX Delegation

libsalty does not implement POSIX semantics itself. It marshals arguments into IPC messages and delegates to userspace servers:

- **File I/O** (open, read, write, stat, etc.) -> VFS server
- **Process management** (fork, exec, waitpid, kill) -> Process manager
- **Sockets, pipes, poll, epoll** -> VFS server
- **Signals** -> Notification-based delivery via process manager
- **Memory** (brk, mmap) -> Local frame allocation via kernel capabilities

### Design Documents

- [Kernel design](../../docs/design/kernel.md)
- [IPC design](../../docs/design/ipc.md)
- [Capability system](../../docs/design/capability.md)
- [POSIX compatibility](../../docs/design/posix.md)
- [Memory management](../../docs/design/memory.md)

## Constraints

- **`#![no_std]`** -- only `core` is available. No `alloc`, no heap in the library itself.
- **No floating point** -- the target is `x86_64-unknown-none` with SSE/AVX disabled.
- **Single-threaded** -- each process has one thread. Global state (`__salty_ipc_ctx`, signal handlers) is not synchronized.
- **Rust 2024 edition** -- `unsafe_op_in_unsafe_fn` is enforced; every unsafe operation in an `unsafe fn` requires an explicit `unsafe {}` block.
- **No Cargo** -- built exclusively via Meson with direct `rustc` invocation. Do not create `Cargo.toml` files.
