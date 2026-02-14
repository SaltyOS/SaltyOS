# libsalty Design Document

## 1. Overview

libsalty is the system library for SaltyOS userland. It serves as the sole
interface between user processes and the microkernel, wrapping every system
call, IPC operation, and capability invocation behind a stable API. Written
in Rust under `#![no_std]` with only the `core` library available, it
compiles to a position-independent shared object (`libsalty.so`) that the
runtime dynamic linker (`rtld`) loads into every process.

libsalty has a dual personality:

- **Rust module API** -- Internal modules (`ipc`, `invoke`, `posix`,
  `posix_mm`, `signals`, `slot_alloc`, etc.) are used directly by Rust
  userland programs that link against the `.rmeta` at compile time.
- **C ABI surface** -- Every public entry point is
  `#[unsafe(no_mangle)] pub extern "C" fn salty_*`, making the shared
  library callable from C code, the C standard library (`saltyc`), and
  the runtime linker.

The library is approximately 3,500 lines of Rust plus 55 lines of assembly
(`fork.S`), deliberately kept small to minimize the trusted computing base
outside the kernel.

### Source files

| File | Lines | Purpose |
|------|-------|---------|
| `lib.rs` | 635 | Module declarations, global state, C ABI exports, panic handler |
| `consts.rs` | 471 | Syscall numbers, invoke labels, error codes, capability slots, POSIX constants |
| `types.rs` | 419 | `#[repr(C)]` types: `SaltyMsg`, `IpcBuffer`, `IpcContext`, ELF types, POSIX types |
| `syscall.rs` | 37 | Single `syscall()` function with inline assembly |
| `ipc.rs` | 233 | IPC operations: send, recv, call, reply_recv, nbsend, cap transfer |
| `invoke.rs` | 267 | Capability invocation wrappers for all kernel object types |
| `posix.rs` | 2079 | POSIX file I/O, process management, sockets, poll, terminal I/O, `*at()` family |
| `posix_mm.rs` | 404 | Memory management: brk, sbrk, mmap (anonymous + fd-backed), munmap, mprotect |
| `signals.rs` | 141 | Signal handling: registration, dispatch, blocked mask, SA_RESETHAND |
| `slot_alloc.rs` | 503 | Dynamic CNode slot allocator with async expansion protocol |
| `serial.rs` | 173 | Serial output via DebugPutBuf syscall, atomic `LineBuf` |
| `layout.rs` | 149 | Child process VM layout planner |
| `framebuffer.rs` | 60 | Framebuffer info reader from boot info page |
| `cpio.rs` | 264 | CPIO newc archive parser |
| `elf_loader.rs` | 687 | Userspace ELF64 loader with PIE relocation support |
| `elf_dynamic.rs` | 244 | ELF dynamic linking helpers (PT_INTERP, DT_NEEDED extraction) |
| `fork.S` | 55 | Fork assembly trampoline (callee-save register preservation) |

## 2. Design Principles

**Thin wrappers.** Every function does exactly one thing: pack arguments
into the syscall or IPC message format the kernel expects, issue the
operation, and unpack the result. There is no caching, no retry logic,
and no hidden state beyond what is structurally necessary (the IPC
buffer pointer and slot allocator state).

**C ABI stability.** All public symbols use `extern "C"` with the
`salty_` prefix. The `.so` exposes a flat namespace of C-callable
functions. Internal Rust modules can change freely as long as the
C ABI surface remains stable.

**POSIX delegation.** libsalty does not implement POSIX semantics itself.
File operations, socket management, and directory state are delegated to
userspace servers (VFS, procmgr) via IPC. libsalty only handles message
packing and unpacking.

**Capability-first.** Every resource access goes through capability slot
numbers. There are no file descriptors at the libsalty level -- POSIX fd
numbers are server-side abstractions managed by VFS.

**Fail-safe defaults.** Functions return error codes rather than panicking.
The panic handler writes a diagnostic to serial and enters an infinite
yield loop. No `unwrap()` or `expect()` calls exist in the library.

## 3. Architecture

### Layer Diagram

```
 +------------------------------------------------------------------+
 |                        User Application                          |
 |  (Rust: uses salty::ipc, salty::invoke, salty::posix directly)    |
 |  (C:    calls salty_open(), salty_call(), salty_vspace_map()...)  |
 +----+----+----+----+----+----+----+----+----+----+----+----+------+
      |    |    |    |    |    |    |    |    |    |    |    |
 +----v----v----v----v----v----v----v----v----v----v----v----v------+
 | lib.rs  C ABI surface (salty_send, salty_open, salty_mmap, ...) |
 +--------+----------+-----------+----------+----------+----------+
          |          |           |          |          |
  +-------v--+  +---v------+  +-v--------+ | +-------v--------+
  | ipc.rs   |  | invoke.rs|  | posix.rs | | | posix_mm.rs    |
  | send     |  | CNode    |  | open     | | | brk/sbrk       |
  | recv     |  | Untyped  |  | read     | | | mmap/munmap    |
  | call     |  | TCB      |  | write    | | | mprotect       |
  | reply_   |  | VSpace   |  | fork     | | +----------------+
  | recv     |  | IRQ      |  | exec     | |
  | nbsend   |  | IoPort   |  | socket   | | +----------------+
  +----+-----+  | SchedCtx |  | poll     | +>| signals.rs     |
       |        +----+-----+  | pipe     |   | posix_signal   |
       |             |        | dup      |   | posix_sigcheck |
  +----v-------------v---+    | termios  |   +----------------+
  | syscall.rs            |   | *at()    |
  | syscall(num,a0..a5)   |   +----+-----+ +------------------+
  | inline asm "syscall"  |        |       | slot_alloc.rs    |
  +----------+------------+        |       | slot_alloc()     |
             |                     |       | slot_alloc_frame |
             v                     v       | async expansion  |
  +-----------------------+   +---------+  +------------------+
  |  Kernel syscall entry |   | VFS /   |
  |  (syscall.S)          |   | procmgr |  +------------------+
  +-----------------------+   | servers |  | elf_loader.rs    |
                              +---------+  | cpio.rs          |
                                           | elf_dynamic.rs   |
                                           | layout.rs        |
                                           | framebuffer.rs   |
                                           +------------------+
```

### Module Dependency Graph

```
lib.rs ──> consts.rs
       ──> types.rs
       ──> syscall.rs ──> types.rs
       ──> ipc.rs ──> syscall.rs, consts.rs, types.rs
       ──> invoke.rs ──> syscall.rs, consts.rs, types.rs
       ──> posix.rs ──> ipc.rs, consts.rs, types.rs
       ──> posix_mm.rs ──> invoke.rs, slot_alloc.rs, consts.rs, types.rs
       ──> signals.rs ──> ipc.rs, consts.rs, types.rs
       ──> slot_alloc.rs ──> invoke.rs, ipc.rs, syscall.rs, serial.rs, consts.rs, types.rs
       ──> serial.rs ──> syscall.rs, consts.rs
       ──> layout.rs  (standalone)
       ──> framebuffer.rs ──> consts.rs
       ──> cpio.rs ──> consts.rs, types.rs
       ──> elf_loader.rs ──> invoke.rs, serial.rs, consts.rs, types.rs
       ──> elf_dynamic.rs ──> consts.rs, types.rs
```

## 4. Syscall Wrapper Layer

All kernel interaction flows through a single function in `syscall.rs`:

```rust
#[inline(always)]
pub fn syscall(num: u64, a0..a5: u64) -> SaltyResult { error, value }
```

The inline assembly maps directly to the SaltyOS syscall ABI:

| Register | Direction | Purpose |
|----------|-----------|---------|
| `rax` | in/out | Syscall number in, error code out |
| `rdi` | in | Argument 0 (capability slot or first param) |
| `rsi` | in | Argument 1 (message info or second param) |
| `rdx` | in/out | Argument 2 in, return value out |
| `r10` | in | Argument 3 |
| `r8` | in | Argument 4 |
| `r9` | in | Argument 5 |
| `rcx` | clobbered | Destroyed by `syscall` instruction (saves RIP) |
| `r11` | clobbered | Destroyed by `syscall` instruction (saves RFLAGS) |

The function uses `options(nostack)` because the `syscall` instruction
does not touch the user stack. The `inlateout` constraint on `rax` and
`rdx` allows the compiler to reuse the input registers for the outputs.

## 5. IPC Abstraction Layer

### IpcContext

Every process has a global `IpcContext` that holds a pointer to the
IPC buffer (a kernel-mapped page at a known virtual address) and a
count of capabilities staged for transfer:

```rust
pub struct IpcContext {
    pub ipc_buffer: *mut IpcBuffer,  // kernel-mapped page
    pub send_cap_count: i32,         // 0-4 caps staged in buffer.caps[]
}
```

The global instance `__salty_ipc_ctx` is initialized by the CRT/RTLD
during process startup.

### IPC Buffer Layout

The `IpcBuffer` is a 4096-byte page shared between kernel and userland:

| Field | Offset | Size | Purpose |
|-------|--------|------|---------|
| `msg[0..21]` | 0 | 176 bytes | Message registers (label + length + 20 data regs) |
| `badge` | 176 | 8 bytes | Sender badge (set by kernel on receive) |
| `caps[0..3]` | 184 | 32 bytes | Capability transfer slots (send or receive) |
| `receive_cnode` | 216 | 8 bytes | CNode for receiving transferred caps |
| `receive_index` | 224 | 8 bytes | Slot index within receive CNode |
| `receive_depth` | 232 | 8 bytes | CNode depth for receive slot |
| `reserved[0..477]` | 240 | 3824 bytes | Reserved (used for invoke depth hints) |

### Message Info Encoding

Message info is packed into a single 64-bit value following the seL4
convention:

```
bits [6:0]   = length (0-127 message registers)
bits [11:7]  = extra_caps (0-31 capabilities to transfer)
bits [51:12] = label (40-bit application-defined label)
```

The `msginfo()` function encodes these fields; `msginfo_label()`,
`msginfo_length()`, and `msginfo_extracaps()` decode them.

### Register vs Overflow Messages

Short messages (up to 4 registers) are passed entirely in CPU registers
via the syscall ABI (`rdi`=cap, `rsi`=msginfo, `rdx`=MR0, `r10`=MR1,
`r8`=MR2, `r9`=MR3). Messages with 5-20 registers use overflow:
MR0-MR3 go in registers, MR4-MR19 are written to `ipc_buffer.msg[6..21]`
by `write_overflow_ctx()` before the syscall.

On receive, the kernel writes the full message (label, length, all
registers) into the IPC buffer. The receive-side functions read the
message from the buffer and copy it to the caller's `SaltyMsg`.

### Capability Transfer

Capabilities are transferred through the IPC buffer's `caps[]` array:

- **Sending:** `set_send_cap_ctx()` writes capability slot numbers into
  `buffer.caps[0..3]` and increments `send_cap_count`. The extra_caps
  field in msginfo tells the kernel how many to transfer. After each
  send operation, `clear_send_caps_ctx()` resets the array.

- **Receiving:** `set_receive_slot_ctx()` configures
  `buffer.receive_cnode`, `receive_index`, and `receive_depth` to
  designate where incoming capabilities should be deposited.

### Message Patterns

**RPC (client Call):**
```
call_ctx(ctx, ep, &msg, &mut reply)
  -> SYS_CALL: blocks until server replies
  -> reply contains server's response
```

**Server loop (ReplyRecv):**
```
recv_ctx(ctx, ep, &mut msg, &mut badge)    // first receive
loop {
    // process msg, build reply
    reply_recv_ctx(ctx, ep, &reply, &mut msg, &mut badge)
    // atomically: reply to previous caller + wait for next
}
```

**Fire-and-forget (NBSend):**
```
nbsend_ctx(ctx, ep, &msg)
  -> SYS_NBSEND: returns immediately (WOULD_BLOCK if no receiver)
```

**Signal/Wait (notifications):**
```
salty_signal(ntfn, bits)  // OR bits into notification word
salty_wait(ntfn)          // block until signaled, returns bitmap
salty_poll(ntfn, &bits)   // non-blocking check
```

## 6. Capability Invocations

The `invoke.rs` module provides typed wrappers for all kernel object
operations. Each wrapper calls the central `invoke()` function:

```rust
pub fn invoke(cap: Cap, label: u64, arg0..arg3: u64) -> SaltyResult {
    syscall(SYS_INVOKE, cap, label, arg0, arg1, arg2, arg3)
}
```

The `label` argument selects the operation. Labels are grouped by
object type:

### CNode Operations (0x10-0x18)

| Label | Function | Purpose |
|-------|----------|---------|
| `CNODE_COPY` (0x10) | `cnode_copy()` | Copy cap between slots with rights mask |
| `CNODE_MINT` (0x11) | `cnode_mint()` | Copy cap with badge assignment |
| `CNODE_MOVE` (0x12) | `cnode_move()` | Move cap to new slot (old slot emptied) |
| `CNODE_MUTATE` (0x13) | `cnode_mutate()` | Move with badge change |
| `CNODE_DELETE` (0x14) | `cnode_delete()` | Remove cap from slot |
| `CNODE_REVOKE` (0x15) | `cnode_revoke()` | Delete all derived caps |
| `CNODE_SAVE_CALLER` (0x16) | `cnode_save_caller()` | Save reply cap for deferred reply |
| `CNODE_SET_GUARD` (0x17) | `cnode_set_guard()` | Set CNode guard value and bits |
| `CNODE_GET_INFO` (0x18) | `cnode_get_info()` | Query CNode size and occupancy |

Depth-aware variants (`cnode_copy_depth`, `cnode_delete_depth`,
`cnode_revoke_depth`) write depth values into `ipc_buffer.reserved[0..1]`
before the invoke syscall, supporting hierarchical CNode addressing
after CSpace expansion.

### Untyped Operations (0x20)

| Label | Function | Purpose |
|-------|----------|---------|
| `UNTYPED_RETYPE` (0x20) | `untyped_retype()` | Create new kernel object from untyped memory |

Also has a `untyped_retype_depth()` variant for expanded CSpaces.

### TCB Operations (0x40-0x4B)

| Label | Function | Purpose |
|-------|----------|---------|
| `TCB_CONFIGURE` (0x40) | `tcb_configure()` | Set initial RIP, RSP, IPC buffer |
| `TCB_RESUME` (0x41) | `tcb_resume()` | Make thread runnable |
| `TCB_SUSPEND` (0x42) | `tcb_suspend()` | Remove thread from scheduler |
| `TCB_SET_SPACE` (0x43) | `tcb_set_space()` | Assign CSpace and VSpace |
| `TCB_WRITE_REGISTERS` (0x46) | `tcb_write_registers()` | Write thread register state |
| `TCB_SET_IPC_BUFFER` (0x48) | `tcb_set_ipc_buffer()` | Set IPC buffer address |
| `TCB_BIND_NOTIFICATION` (0x49) | `tcb_bind_notification()` | Bind notification for combined wait |
| `TCB_SET_FAULT_HANDLER` (0x4B) | `tcb_set_fault_handler()` | Set fault endpoint |

### VSpace Operations (0x50-0x57)

| Label | Function | Purpose |
|-------|----------|---------|
| `VSPACE_MAP` (0x50) | `vspace_map()` | Map frame at virtual address |
| `VSPACE_UNMAP` (0x51) | `vspace_unmap()` | Unmap page at virtual address |
| `VSPACE_MAP_PT` (0x52) | `vspace_map_pt()` | Install intermediate page table |
| `VSPACE_WALK` (0x53) | `vspace_walk()` | Walk page table (debugging) |
| `VSPACE_COPY_PAGE` (0x54) | `vspace_copy_page()` | Copy page contents to frame |
| `VSPACE_MAP_DEVICE` (0x55) | `vspace_map_device()` | Map device memory page |
| `VSPACE_CLONE_COW_PAGE` (0x56) | `vspace_clone_cow_page()` | COW clone between VSpaces |
| `VSPACE_MAP_DEVICE_RANGE` (0x57) | `vspace_map_device_range()` | Batch-map device pages |

### Scheduling Operations (0x30-0x31)

| Label | Function | Purpose |
|-------|----------|---------|
| `SC_CONFIGURE` (0x30) | `sc_configure()` | Set budget and period (microseconds) |
| `SC_BIND` (0x31) | `sc_bind()` | Bind scheduling context to TCB |

### IRQ Operations (0x61-0x62)

| Label | Function | Purpose |
|-------|----------|---------|
| `IRQ_HANDLER_ACK` (0x61) | `irq_handler_ack()` | Acknowledge IRQ |
| `IRQ_HANDLER_SET_NOTIFICATION` (0x62) | `irq_handler_set_notification()` | Route IRQ to notification |

### IoPort Operations (0x70-0x73)

| Label | Function | Purpose |
|-------|----------|---------|
| `IOPORT_IN8` (0x70) | `ioport_in8()` | Read 8-bit I/O port |
| `IOPORT_OUT8` (0x71) | `ioport_out8()` | Write 8-bit I/O port |
| `IOPORT_IN16` (0x72) | `ioport_in16()` | Read 16-bit I/O port |
| `IOPORT_OUT16` (0x73) | `ioport_out16()` | Write 16-bit I/O port |

## 7. POSIX Compatibility Layer

### Delegation Model

libsalty does not implement POSIX semantics. It acts as a message-passing
stub that translates POSIX calls into IPC messages to two userspace
servers:

- **VFS** (`CAP_VFS_EP`, slot 4) -- File I/O, directories, sockets,
  pipes, poll/select/epoll, shared memory, terminal I/O, ioctl, fcntl,
  `*at()` family
- **procmgr** (`CAP_PROCMGR_EP`, slot 3) -- Process lifecycle (spawn,
  exit, wait, fork, exec, kill), signal disposition, process groups,
  UID/GID queries, CSpace expansion

Every POSIX function follows the same pattern:

1. Construct a `SaltyMsg` with the appropriate label constant
2. Pack arguments into `msg.regs[0..19]`
3. Call `ipc::call_ctx()` (blocking RPC to the server)
4. Check `reply.label == SALTY_OK`
5. Unpack results from `reply.regs[]`

### Path Packing

Filesystem paths are packed into message registers using `pack_path()`:

```
msg.regs[offset]     = path_len (u8, max 64)
msg.regs[offset+1..] = path bytes packed into u64 words
msg.length           = fixed_fields + ceil(path_len / 8)
```

This allows paths up to 64 bytes to fit within the 20-register message
limit. The path bytes are copied byte-by-byte into the u64 register
array, which the server interprets as a byte buffer.

### Chunked I/O

Read and write operations use chunked transfers to work within the
IPC message size limit:

- **Read:** Requests up to 152 bytes per RPC (19 regs x 8 bytes minus
  header). Loops until EOF or requested count is satisfied.
- **Write:** Sends up to 144 bytes per RPC (18 regs x 8 bytes minus
  header). Loops until all data is sent.

Partial transfers are handled: if a chunk returns fewer bytes than
requested, the loop terminates and returns the total transferred.

### Memory Management

The `posix_mm.rs` module provides `brk`/`sbrk` (heap) and
`mmap`/`munmap`/`mprotect` (memory mapping) using the slot allocator
and capability invocations:

- **Heap (brk/sbrk):** Grows/shrinks by allocating frame caps, mapping
  them at contiguous virtual addresses starting from `heap_base`, and
  zeroing each new page.
- **Anonymous mmap:** Allocates frames from untyped memory, maps them
  at the next available address in the mmap region, tracks them in a
  region table (max 32 regions, 64 pages each).
- **fd-backed mmap:** Sends `POSIX_VFS_MMAP` to VFS, receives a device
  untyped capability via IPC cap transfer, then batch-maps the pages
  using `vspace_map_device_range()` with write-combining flags.
- **munmap:** Unmaps pages and deletes frame capabilities.
- **mprotect:** Unmaps and remaps each page with new permission flags.

The memory manager state (`PosixMmState`) is a module-level static,
initialized during process startup.

### Signal Handling

Signal delivery uses the notification mechanism:

1. **Registration:** `posix_signal()` stores the handler pointer in
   an atomic array (`__sig_handlers`), then informs procmgr of the
   disposition category (default/ignore/catch) via IPC.

2. **Delivery check:** `posix_sigcheck()` polls the process's signal
   notification (`CAP_SIGNAL_NTFN`). Each bit in the notification word
   corresponds to a signal number.

3. **Dispatch:** For each pending signal:
   - If blocked (`__sig_blocked_mask`), re-raise via `SYS_SIGNAL`
   - If SIG_IGN, skip
   - If SIG_DFL with terminate action, call `posix_exit(128 + sig)`
   - If caught, save/apply `sa_mask`, call handler, restore mask

4. **SA_RESETHAND:** If set, handler reverts to SIG_DFL after first
   delivery, and procmgr is notified of the disposition change.

## 8. Resource Management

### Slot Allocator

The `slot_alloc.rs` module manages CNode slot allocation for dynamic
resource creation. Processes need slots to hold capabilities for frames,
endpoints, notifications, and other kernel objects.

**Segment chain:** Slots are organized as a chain of up to 16 segments.
Each segment is a contiguous range of CNode indices with a bump pointer.
The initial segment is assigned by procmgr at spawn time and communicated
via auxv entries (`AT_SALTY_SLOT_BASE`, `AT_SALTY_SLOT_COUNT`).

**Async expansion protocol:** When all segments are exhausted:

1. Send `NBSend(PM_EXPAND_CSPACE_ASYNC, bits=10)` to procmgr
   (fire-and-forget, does not block the caller)
2. On next allocation attempt, re-send NBSend (idempotent) and call
   `PM_EXPAND_COLLECT` (blocking) to collect the result
3. If procmgr has completed the expansion, it returns the base and
   count of the new sub-CNode segment
4. The new segment is appended to the chain

This two-phase protocol (NBSend then Call) ensures the caller never
blocks indefinitely on expansion. If the NBSend is dropped (procmgr
busy), the next attempt resends it.

**Untyped expansion:** When all untyped capabilities are exhausted:

1. Signal the procmgr's bound notification (`expand_ntfn`)
2. Procmgr allocates a new untyped and places it at a deterministic
   CNode slot (`UT_EXPAND_BASE + N`, last 8 slots of the 10-bit CNode)
3. The probe retype (`untyped_retype(expected_slot, OBJ_FRAME, ...)`)
   doubles as both completion check and frame creation

**Convenience wrappers:**
- `slot_alloc()` -- Allocate one CNode slot (sync)
- `slot_alloc_frame()` -- Allocate slot + retype frame from any untyped
- `slot_alloc_frame_map()` -- Allocate + retype + map at virtual address
- `slot_alloc_frame_map_async()` -- Full async version with expansion

### VM Layout Planning

The `layout.rs` module computes virtual address layouts for child
processes. Given the ELF and RTLD sizes, shared library page count,
and initrd window, it produces a `VmLayoutPlan` with non-overlapping
regions:

```
0x0020_0000          IPC buffer (1 page)
0x0021_0000          ELF code (variable)
ELF end + gap        RTLD (variable)
RTLD end + gap       Shared library cache (variable)
0x003F_8000          Stack (4 pages, 16 KiB)
0x003F_F000          Scratch page (1 page)
0x0100_0000          Initrd window (optional)
```

If code regions overflow the first 2 MiB window, a second window at
0x007F_8000 is used for the stack. If both overflow, the plan signals
failure with `stack_top == 0`.

## 9. Dynamic Linking Support

### Library Build

libsalty is compiled as a position-independent shared object:

1. Rust source compiles to `libsalty.o` + `libsalty.rmeta`
2. `fork.S` assembles to `fork.o`
3. All objects link with `core.o` and `compiler_builtins.o` into
   `libsalty.so` using the `libsalty.ld` linker script

The linker script places sections at page-aligned boundaries with
dynamic linking metadata (`.gnu.hash`, `.dynsym`, `.dynstr`,
`.rela.dyn`, `.dynamic`) at the front.

### Runtime Loader Integration

The runtime dynamic linker (`rtld`) loads `libsalty.so` into every
dynamically-linked process. RTLD:

1. Finds `libsalty.so` in the shared library cache region
2. Maps it into the child's address space
3. Resolves relocations (R_X86_64_RELATIVE for PIE)
4. Sets up the GOT and PLT entries

Init is the exception: it is **statically linked** with `libsalty.o`
embedded directly, since it runs before `rtld` and VFS are available.

### ELF Loader

The `elf_loader.rs` module loads ELF64 binaries into child address
spaces. It supports:

- ET_EXEC (fixed address) and ET_DYN (PIE, relocated to `load_base`)
- Multiple PT_LOAD segments with correct permissions
- Overlapping page merging (permission union)
- R_X86_64_RELATIVE relocation patching via scratch page
- Callback-based frame allocation (`alloc_frame_slot` function pointer)
- Page recording callback for COW fork tracking

### CPIO Parser

The `cpio.rs` module parses CPIO newc archives (the initrd format):

- `cpio_find_file()` -- Search by exact filename match
- `cpio_next()` / `cpio_next_ext()` -- Iterate entries sequentially
- `cpio_archive_size()` -- Compute total archive size

### ELF Dynamic Helpers

The `elf_dynamic.rs` module extracts dynamic linking metadata:

- `elf_has_interp()` / `elf_get_interp()` -- Check/read PT_INTERP
- `elf_get_needed()` -- Extract DT_NEEDED library names
- `elf_get_phdr_info()` -- Get program header location for RTLD

## 10. Global State

All mutable global state in libsalty:

| Variable | Type | Module | Purpose |
|----------|------|--------|---------|
| `__salty_ipc_ctx` | `IpcContext` | `lib.rs` | IPC buffer pointer and cap transfer count |
| `__sig_handlers` | `[AtomicUsize; 32]` | `lib.rs` | Signal handler function pointers |
| `__sig_initialized` | `AtomicI32` | `lib.rs` | One-shot signal subsystem init flag |
| `__sig_blocked_mask` | `u32` | `lib.rs` | Bitmask of blocked signals |
| `__sig_sa_mask` | `[u32; 32]` | `lib.rs` | Per-signal sa_mask values |
| `__sig_sa_flags` | `[i32; 32]` | `lib.rs` | Per-signal sa_flags (SA_RESETHAND, etc.) |
| `__salty_next_frame_slot` | `u64` (weak) | `lib.rs` | Legacy frame slot counter (overridden by slot_alloc) |
| `__salty_slot_base` | `u64` (weak) | `lib.rs` | Slot allocator pool base (from auxv) |
| `__salty_slot_count` | `u64` (weak) | `lib.rs` | Slot allocator pool size (from auxv) |
| `__salty_expand_ep` | `u64` (weak) | `lib.rs` | Expansion notification cap (from auxv) |
| `SLOT_ALLOC` | `SlotAllocState` | `slot_alloc.rs` | Segment chain and expansion state |
| `UT_EXPAND_REQUESTED` | `bool` | `slot_alloc.rs` | Whether untyped expansion is in flight |
| `EXTRA_UT_SLOTS` | `[Cap; 8]` | `slot_alloc.rs` | Dynamically-granted untyped caps |
| `EXTRA_UT_COUNT` | `usize` | `slot_alloc.rs` | Number of extra untypeds granted |
| `PENDING_FRAME_SLOT` | `Cap` | `slot_alloc.rs` | Saved slot across async WouldBlock |
| `MM` | `PosixMmState` | `posix_mm.rs` | Memory manager state (heap, mmap regions, frames) |
| `NEXT_UT_HINT` | `Cap` | `elf_loader.rs` | Hint for untyped scanning during ELF load |

**Why this is safe:** SaltyOS userland processes are single-threaded.
Each process has its own address space with private copies of all
statics. There is no shared mutable state between processes. Signal
handlers run synchronously in the context of `posix_sigcheck()`, not
asynchronously, so there are no reentrancy concerns. The weak linkage
on `__salty_slot_*` and `__salty_expand_ep` allows RTLD or CRT to
override these values before the library is used.

## 11. Build and Linking

### Meson Pipeline

```
  src/lib.rs
      |
      v
  rustc --edition=2024 --target=x86_64-unknown-none
        -C panic=abort -C opt-level=2
        -C code-model=small -C relocation-model=pic
        --extern core=<build>/libcore.rmeta
        --emit=obj=libsalty.o,metadata=libsalty.rmeta
      |
      +--- libsalty.rmeta (used by userland programs at compile time)
      |
      v
  fork.S --[clang -c]--> fork.o
      |
      v
  clang -shared -nostdlib -fPIC -fuse-ld=lld
        -Wl,-soname,libsalty.so -Wl,--hash-style=gnu
        -T libsalty.ld
        libsalty.o fork.o core.o compiler_builtins.o
      |
      v
  libsalty.so (packed into initrd by mkcpio.py)
```

### Linker Script

The `libsalty.ld` script creates a shared object with:

- Dynamic linking metadata at the start (`.gnu.hash`, `.dynsym`,
  `.dynstr`, `.rela.dyn`)
- Page-aligned `.text`, `.rodata`, `.data`, and `.bss` sections
- `.got` and `.got.plt` for position-independent addressing
- `.dynamic` section for runtime linker use
- All debug metadata (`.comment`, `.note.*`, `.eh_frame*`) discarded

### Static vs Dynamic Linking

- **Init:** Statically linked. `libsalty.o` is linked directly into the
  init binary because init runs before the runtime linker is available.
- **All other programs:** Dynamically linked via `libsalty.so`. The
  `.rmeta` file provides type information at compile time; the `.so`
  provides code at runtime.

## 12. Cross-References

- [ABI Specification](../spec/abi.md) -- Syscall register convention,
  message info encoding, IPC buffer layout
- [Syscall Specification](../spec/syscalls.md) -- Complete syscall
  numbering and semantics
- [IPC Design](ipc.md) -- Kernel-side endpoint and notification
  implementation
- [Memory Management](memory.md) -- Kernel VSpace and frame allocator
- [Capability System](capability.md) -- CNode structure, CDT, rights
  model
- [POSIX Compatibility](posix.md) -- VFS and procmgr protocol design
- [libsalty API Reference](../spec/libsalty-api.md) -- Complete function
  signatures and error codes
