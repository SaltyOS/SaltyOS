# trona Design Document

## 1. Overview

trona is the system library for SaltyOS userland. It serves as the sole
interface between user processes and the microkernel, wrapping every system
call, IPC operation, and capability invocation behind a stable API. Written
in Rust under `#![no_std]` with only the `core` library available, it
compiles to a position-independent shared object (`libtrona.so`) that the
runtime dynamic linker (`rtld`) loads into every process.

trona has a dual personality:

- **Rust module API** -- Internal modules (`ipc`, `invoke`, `posix`,
  `mm`, `signals`, `slot_alloc`, etc.) are used directly by Rust
  userland programs that link against the `.rmeta` at compile time.
- **C ABI surface** -- Every public entry point is
  `#[unsafe(no_mangle)] pub extern "C" fn trona_*`, making the shared
  library callable from C code, the C standard library (`basaltc`), and
  the runtime linker.

### 5-Crate Architecture

trona is organized as 5 crates plus a dual-format runtime linker:

| Crate | Path | Purpose |
|-------|------|---------|
| **substrate** | `lib/trona/substrate/` | Core syscall wrappers, IPC, capability invocations, slot allocator, serial I/O, layout planner |
| **posix** | `lib/trona/posix/` | POSIX compatibility: file I/O, sockets, poll, mm, signals, pthread, sync, tls, dns, bulk transfers |
| **loader** | `lib/trona/loader/` | ELF64 loader, PE loader, CPIO parser, ELF dynamic helpers |
| **uapi** | `lib/trona/uapi/` | Shared constants, types, and IPC protocol definitions (kernel + server + POSIX) |
| **win32** | `lib/trona/win32/` | Win32 personality support: console, CRT, error handling, process, protocol, handle management |
| **rtld/elf** | `lib/trona/rtld/elf/` | ELF runtime dynamic linker (`ld-trona.so`) |
| **rtld/pe** | `lib/trona/rtld/pe/` | PE runtime dynamic linker (`ld-trona-pe.so`) for Win32 subsystem |

### Source Layout

**substrate** (`lib/trona/substrate/`):

| File | Purpose |
|------|---------|
| `lib.rs` | Module declarations, global state, C ABI exports, panic handler |
| `syscall.rs` | Single `syscall()` function with inline assembly (x86_64 + aarch64) |
| `ipc.rs` | IPC operations: send, recv, call, reply_recv, nbsend, cap transfer |
| `invoke.rs` | Capability invocation wrappers for all kernel object types |
| `slot_alloc.rs` | Dynamic CNode slot allocator with async expansion protocol |
| `serial.rs` | Serial output via DebugPutBuf syscall, atomic `LineBuf` |
| `layout.rs` | Child process VM layout planner |
| `framebuffer.rs` | Framebuffer info reader from boot info page |
| `pending.rs` | Pending operation tracking |
| `protocol.rs` | IPC protocol helpers |
| `consts.rs` | Legacy constants (re-exports from uapi) |
| `types.rs` | Legacy types (re-exports from uapi) |
| `arch/x86_64/fork.S` | Fork assembly trampoline (x86_64) |
| `arch/aarch64/fork.S` | Fork assembly trampoline (aarch64) |

**posix** (`lib/trona/posix/`):

| File | Purpose |
|------|---------|
| `file.rs` | POSIX file I/O: open, read, write, close, stat, lseek, dup, *at() family |
| `proc.rs` | Process management: fork, exec, exit, wait, kill, getpid |
| `socket.rs` | Socket API: AF_UNIX + AF_INET, bind, connect, send, recv |
| `poll.rs` | Event multiplexing: poll, select, epoll |
| `pipe.rs` | Pipes: pipe, pipe2, mkfifo |
| `mm.rs` | Memory management: brk, sbrk, mmap, munmap, mprotect (delegates to mmsrv) |
| `signals.rs` | Signal handling: registration, dispatch, blocked mask, SA_RESETHAND |
| `at.rs` | *at() family: openat, renameat, fstatat, etc. |
| `misc.rs` | Miscellaneous: getcwd, chdir, ioctl, fcntl, terminal I/O |
| `dns.rs` | DNS resolution: getaddrinfo backend (IPC to dnssrv) |
| `bulk.rs` | Bulk data transfer helpers |
| `pthread.rs` | POSIX threads: pthread_create, pthread_join, mutexes, condvars, rwlocks |
| `sync.rs` | Synchronization primitives: futex-based Mutex, RWLock, Semaphore |
| `tls.rs` | Thread-local storage setup and access |
| `protocol.rs` | POSIX IPC protocol definitions |
| `consts.rs` | POSIX constants (O_*, F_*, SEEK_*, etc.) |
| `types.rs` | POSIX types (stat, dirent, sockaddr, etc.) |

**loader** (`lib/trona/loader/`):

| File | Purpose |
|------|---------|
| `elf_loader.rs` | Userspace ELF64 loader with PIE relocation support |
| `elf_dynamic.rs` | ELF dynamic linking helpers (PT_INTERP, DT_NEEDED extraction) |
| `pe_loader.rs` | PE/COFF loader for Win32 personality executables |
| `pe_types.rs` | PE format type definitions |
| `cpio.rs` | CPIO newc archive parser |

**uapi** (`lib/trona/uapi/`):

| Directory | Files | Purpose |
|-----------|-------|---------|
| `consts/` | `kernel.rs`, `posix.rs`, `server.rs` | Syscall numbers, invoke labels, error codes, cap slots, POSIX constants, server labels |
| `protocol/` | `mmsrv.rs`, `procmgr.rs`, `vfs.rs`, `namesrv.rs`, `server.rs`, `posix.rs`, `win32.rs` | IPC message label definitions for all servers |
| `types/` | `core.rs`, `posix.rs`, `pe.rs` | `#[repr(C)]` shared types: TronaMsg, IpcBuffer, PollFd, SockAddrUn, PE types |
| `include/trona/` | `uapi.h` | C header for uapi constants (shared with Win32 PE programs) |

**win32** (`lib/trona/win32/`):

| File | Purpose |
|------|---------|
| `kernel32.rs` | kernel32.dll Rust crate root |
| `console.rs` | Win32 console I/O (ReadConsole/WriteConsole) |
| `crt.rs` | Win32 CRT startup |
| `error.rs` | Win32 error code translation |
| `handle.rs` | Win32 HANDLE management |
| `process.rs` | Win32 process operations |
| `protocol.rs` | Win32 CSRSS IPC protocol |
| `trona.rs` | local PE ABI shim for kernel32.dll |
| `kernel32.def` | kernel32.dll export definitions |

**rtld** (`lib/trona/rtld/`):

| Component | Path | Purpose |
|-----------|------|---------|
| ELF rtld | `rtld/elf/` | `ld-trona.so` -- loads ELF shared libraries (libtrona.so, libc.so) |
| PE rtld | `rtld/pe/` | `ld-trona-pe.so` -- loads PE/COFF executables for Win32 personality |

## 2. Design Principles

**Thin wrappers.** Every function does exactly one thing: pack arguments
into the syscall or IPC message format the kernel expects, issue the
operation, and unpack the result. There is no caching, no retry logic,
and no hidden state beyond what is structurally necessary (the IPC
buffer pointer and slot allocator state).

**C ABI stability.** All public symbols use `extern "C"` with the
`trona_` prefix. The `.so` exposes a flat namespace of C-callable
functions. Internal Rust modules can change freely as long as the
C ABI surface remains stable.

**POSIX delegation.** trona does not implement POSIX semantics itself.
File operations, socket management, and directory state are delegated to
userspace servers (VFS, procmgr) via IPC. trona only handles message
packing and unpacking.

**Capability-first.** Every resource access goes through capability slot
numbers. There are no file descriptors at the trona level -- POSIX fd
numbers are server-side abstractions managed by VFS.

**Fail-safe defaults.** Functions return error codes rather than panicking.
The panic handler writes a diagnostic to serial and enters an infinite
yield loop. No `unwrap()` or `expect()` calls exist in the library.

## 3. Architecture

### Layer Diagram

```
 +------------------------------------------------------------------+
 |                        User Application                          |
 |  POSIX (Rust/C)               |  Win32 (PE)                     |
 +-------------------------------+----------------------------------+
 |  basaltc (libc.so)            |  win32 (kernel32.dll stub)      |
 +-------------------------------+----------------------------------+
 |                                                                  |
 |  posix crate                  |  win32 crate                    |
 |  ├── file.rs, proc.rs         |  ├── console.rs, process.rs     |
 |  ├── socket.rs, poll.rs       |  ├── handle.rs, error.rs        |
 |  ├── mm.rs, signals.rs        |  └── protocol.rs                |
 |  ├── pthread.rs, sync.rs      |                                 |
 |  └── dns.rs, bulk.rs          |                                 |
 +-------------------------------+----------------------------------+
 |                   substrate crate                                |
 |  ipc.rs, invoke.rs, syscall.rs, slot_alloc.rs, serial.rs        |
 +-------------------------------+----------------------------------+
 |                   uapi crate (shared types + constants)          |
 |  consts/{kernel,posix,server}, protocol/{mmsrv,...}, types/{...} |
 +------------------------------------------------------------------+
 |                   loader crate                                   |
 |  elf_loader.rs, pe_loader.rs, cpio.rs, elf_dynamic.rs           |
 +------------------------------------------------------------------+
 |  rtld/elf (ld-trona.so)       |  rtld/pe (ld-trona-pe.so)      |
 +-------------------------------+----------------------------------+
                    |                          |
                    v                          v
 +------------------------------------------------------------------+
 |                    SaltyOS Kernel                                 |
 |  syscall entry (syscall.S / svc #0)                              |
 +------------------------------------------------------------------+
```

### Crate Dependency Graph

```
                  +----------+
                  |   uapi   | (consts, types, protocols — no dependencies)
                  +----+-----+
                       |
          +------------+------------+
          |            |            |
     +----v-----+  +--v-------+  +-v---------+
     | substrate |  | posix    |  | win32     |
     | (syscall, |  | (file,   |  | (console, |
     |  ipc,     |  |  socket, |  |  process, |
     |  invoke,  |  |  mm,     |  |  handle)  |
     |  slot)    |  |  signal) |  +-----------+
     +----+------+  +----+-----+
          |              |
          |   +----------+
          |   |
     +----v---v---+
     |   loader   | (elf_loader, pe_loader, cpio)
     +------------+
```

- **uapi** has zero crate dependencies (pure constants/types)
- **substrate** depends on uapi
- **posix** depends on substrate + uapi
- **win32** depends on substrate + uapi
- **loader** depends on substrate + uapi

## 4. Syscall Wrapper Layer

All kernel interaction flows through a single function in `syscall.rs`:

```rust
#[inline(always)]
pub fn syscall(num: u64, a0..a5: u64) -> TronaResult { error, value }
```

The inline assembly maps directly to the SaltyOS syscall ABI:

**x86_64** (`syscall` instruction):

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

**aarch64** (`svc #0` instruction):

| Register | Direction | Purpose |
|----------|-----------|---------|
| `x8` | in | Syscall number |
| `x0` | in/out | Argument 0 in, error code out |
| `x1` | in/out | Argument 1 in, return value out |
| `x2` | in | Argument 2 |
| `x3` | in | Argument 3 |
| `x4` | in | Argument 4 |
| `x5` | in | Argument 5 |

The function uses `options(nostack)` because the syscall instruction
does not touch the user stack.

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

The global instance `__trona_ipc_ctx` is initialized by the CRT/RTLD
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
`r8`=MR2, `r9`=MR3). Messages with 5-22 registers use overflow:
MR0-MR3 go in registers, MR4-MR19 are written to `ipc_buffer.msg[6..21]`
by `write_overflow_ctx()` before the syscall.

On receive, the kernel writes the full message (label, length, all
registers) into the IPC buffer. The receive-side functions read the
message from the buffer and copy it to the caller's `TronaMsg`.

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
trona_signal(ntfn, bits)  // OR bits into notification word
trona_wait(ntfn)          // block until signaled, returns bitmap
trona_poll(ntfn, &bits)   // non-blocking check
```

## 6. Capability Invocations

The `invoke.rs` module provides typed wrappers for all kernel object
operations. Each wrapper calls the central `invoke()` function:

```rust
pub fn invoke(cap: Cap, label: u64, arg0..arg3: u64) -> TronaResult {
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

### TCB Operations (0x40-0x4E)

| Label | Function | Purpose |
|-------|----------|---------|
| `TCB_CONFIGURE` (0x40) | `tcb_configure()` | Set initial RIP/PC, RSP/SP, IPC buffer |
| `TCB_RESUME` (0x41) | `tcb_resume()` | Make thread runnable |
| `TCB_SUSPEND` (0x42) | `tcb_suspend()` | Remove thread from scheduler |
| `TCB_SET_SPACE` (0x43) | `tcb_set_space()` | Assign CSpace and VSpace |
| `TCB_WRITE_REGISTERS` (0x46) | `tcb_write_registers()` | Write thread register state |
| `TCB_SET_IPC_BUFFER` (0x48) | `tcb_set_ipc_buffer()` | Set IPC buffer address |
| `TCB_BIND_NOTIFICATION` (0x49) | `tcb_bind_notification()` | Bind notification for combined wait |
| `TCB_SET_FAULT_HANDLER` (0x4B) | `tcb_set_fault_handler()` | Set or clear fault endpoint |
| `TCB_COPY_FPU` (0x4C) | `tcb_copy_fpu()` | Copy FPU state between threads |
| `TCB_SET_TLS_BASE` (0x4D) | `tcb_set_tls_base()` | Set thread-local storage base address |
| `TCB_SET_NOTIFICATION_DISPATCHER` (0x4E) | `tcb_set_notification_dispatcher()` | Set notification dispatcher for signal delivery |

### VSpace Operations (0x50-0x5F)

| Label | Function | Purpose |
|-------|----------|---------|
| `VSPACE_MAP` (0x50) | `vspace_map()` | Map frame at virtual address |
| `VSPACE_UNMAP` (0x51) | `vspace_unmap()` | Unmap page at virtual address and tear down tracked MO metadata for that page |
| `VSPACE_MAP_PT` (0x52) | `vspace_map_pt()` | Install intermediate page table |
| `VSPACE_WALK` (0x53) | `vspace_walk()` | Walk page table (debugging) |
| `VSPACE_COPY_PAGE` (0x54) | `vspace_copy_page()` | Copy page contents to frame |
| `VSPACE_MAP_DEVICE` (0x55) | `vspace_map_device()` | Map device memory page |
| `VSPACE_CLONE_COW_PAGE` (0x56) | `vspace_clone_cow_page()` | COW clone between VSpaces |
| `VSPACE_MAP_DEVICE_RANGE` (0x57) | `vspace_map_device_range()` | Batch-map device pages |
| `VSPACE_PROTECT` (0x58) | `vspace_protect()` | Change page protection flags |
| `VSPACE_MAP_DEMAND` (0x59) | `vspace_map_demand()` | Map a demand-paged region |
| `VSPACE_MAP_DEMAND_RANGE` (0x5A) | `vspace_map_demand_range()` | Batch-map demand-paged regions |
| `VSPACE_COW_RESOLVE` (0x5B) | `vspace_cow_resolve()` | Resolve COW fault for a page |
| `VSPACE_SET_COW_POOL` (0x5C) | `vspace_set_cow_pool()` | Set COW frame pool for VSpace |
| `VSPACE_SET_COW_NOTIF` (0x5D) | `vspace_set_cow_notif()` | Set COW notification endpoint |
| `VSPACE_REPLENISH_COW_POOL` (0x5E) | `vspace_replenish_cow_pool()` | Replenish COW frame pool |
| `VSPACE_PROTECT_RANGE` (0x5F) | `vspace_protect_range()` | Batch change page protection |

### MemoryObject Operations (0x90-0x97)

| Label | Function | Purpose |
|-------|----------|---------|
| `MO_COMMIT` (0x90) | `mo_commit()` | Commit a page into a MemoryObject |
| `MO_DECOMMIT` (0x91) | `mo_decommit()` | Decommit a page from a MemoryObject |
| `MO_GET_SIZE` (0x92) | `mo_get_size()` | Query MemoryObject size |
| `MO_CLONE` (0x93) | `mo_clone()` | COW clone a MemoryObject |
| `MO_RESIZE` (0x94) | `mo_resize()` | Resize a MemoryObject |
| `MO_READ` (0x95) | `mo_read()` | Read data from a MemoryObject page |
| `MO_WRITE` (0x96) | `mo_write()` | Write data to a MemoryObject page |
| `MO_HAS_PAGE` (0x97) | `mo_has_page()` | Check if a page is committed |

### VSpace MemoryObject Mapping (0x97, 0x99-0x9A)

| Label | Function | Purpose |
|-------|----------|---------|
| `VSPACE_MAP_MO` (0x97) | `vspace_map_mo()` | Map MemoryObject pages into VSpace |
| `VSPACE_SHARE_RO_PAGE` (0x99) | `vspace_share_ro_page()` | Share a read-only page between VSpaces |
| `VSPACE_FORK_RANGE` (0x9A) | `vspace_fork_range()` | Fork a VA range (COW) between VSpaces |

### Scheduling Operations (0x30-0x31)

| Label | Function | Purpose |
|-------|----------|---------|
| `SC_CONFIGURE` (0x30) | `sc_configure()` | Set budget and period (microseconds) |
| `SC_BIND` (0x31) | `sc_bind()` | Bind scheduling context to TCB |

### IRQ Operations (0x60-0x64)

| Label | Function | Purpose |
|-------|----------|---------|
| `IRQ_CONTROL_GET` (0x60) | `irq_control_get()` | Allocate IRQ handler cap from IRQ control |
| `IRQ_HANDLER_ACK` (0x61) | `irq_handler_ack()` | Acknowledge IRQ |
| `IRQ_HANDLER_SET_NOTIFICATION` (0x62) | `irq_handler_set_notification()` | Route IRQ to notification |
| `IRQ_HANDLER_CLEAR` (0x63) | `irq_handler_clear()` | Clear IRQ handler notification |
| `IRQ_DEVICE_UNTYPED_CREATE` (0x64) | `irq_device_untyped_create()` | Create device untyped from IRQ region |

### IoPort Operations (0x70-0x77)

| Label | Function | Purpose |
|-------|----------|---------|
| `IOPORT_IN8` (0x70) | `ioport_in8()` | Read 8-bit I/O port |
| `IOPORT_OUT8` (0x71) | `ioport_out8()` | Write 8-bit I/O port |
| `IOPORT_IN16` (0x72) | `ioport_in16()` | Read 16-bit I/O port |
| `IOPORT_OUT16` (0x73) | `ioport_out16()` | Write 16-bit I/O port |
| `IOPORT_IN32` (0x74) | `ioport_in32()` | Read 32-bit I/O port |
| `IOPORT_OUT32` (0x75) | `ioport_out32()` | Write 32-bit I/O port |
| `IOPORT_CONFIGURE` (0x76) | `ioport_configure()` | Configure I/O port range |
| `IOPORT_CREATE` (0x77) | `ioport_create()` | Create new IoPort capability |

## 7. POSIX Compatibility Layer

### Delegation Model

trona does not implement POSIX semantics. It acts as a message-passing
stub that translates POSIX calls into IPC messages to userspace servers:

- **VFS** (`CAP_VFS_EP`, slot 4) -- File I/O, directories, sockets
  (AF_UNIX + AF_INET proxy), pipes, poll/select/epoll, shared memory,
  terminal I/O, ioctl, fcntl, `*at()` family
- **procmgr** (`CAP_PROCMGR_EP`, slot 3) -- Process lifecycle (spawn,
  exit, wait, fork, exec, kill), signal disposition, process groups,
  UID/GID queries, CSpace expansion, personality state (POSIX/Win32)
- **mmsrv** (`CAP_MMSRV_EP`, slot 7) -- Frame allocation, VSpace
  mapping, heap management (brk/sbrk), mmap/munmap/mprotect, demand
  paging, shared memory frames
- **dnssrv** -- DNS resolution (getaddrinfo), accessed via trona posix
  dns.rs

Every POSIX function follows the same pattern:

1. Construct a `TronaMsg` with the appropriate label constant
2. Pack arguments into `msg.regs[0..19]`
3. Call `ipc::call_ctx()` (blocking RPC to the server)
4. Check `reply.label == TRONA_OK`
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

The `mm.rs` module (in the posix crate) provides `brk`/`sbrk` (heap) and
`mmap`/`munmap`/`mprotect` (memory mapping) using the slot allocator
and capability invocations:

- **Heap (brk/sbrk):** Grows/shrinks by allocating frame caps, mapping
  them at contiguous virtual addresses starting from `heap_base`, and
  zeroing each new page.
- **Anonymous mmap:** Allocates frames from untyped memory, maps them
  at the next available address in the mmap region, tracks them in a
  region table (max 32 regions, 64 pages each).
- **fd-backed mmap:** Sends `VFS_MMAP` to VFS, receives a device
  untyped capability via IPC cap transfer, then batch-maps the pages
  using `vspace_map_device_range()` with write-combining flags.
- **munmap:** Unmaps pages and deletes frame capabilities.
- **mprotect:** Unmaps and remaps each page with new permission flags.

Memory management is fully delegated to mmsrv (centralized pager).
Anonymous memory operations (`mmap`, `brk`, `sbrk`) send IPC to `CAP_MMSRV_EP`.
No local state tracking for anonymous regions.

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
via auxv entries (`AT_TRONA_SLOT_BASE`, `AT_TRONA_SLOT_COUNT`).

**Expansion protocol:** When all segments are exhausted, the slot
allocator requests a new CNode from objsrv via `OBJ_ALLOC_OBJECT`
(label 0xD2) on `CAP_OBJSRV_EP`. The previous two-phase procmgr-based
protocol (`PM_EXPAND_CSPACE_ASYNC`/`PM_EXPAND_COLLECT`) has been removed.

**Untyped expansion (legacy path for rtld/init bootstrap only):**

When all untyped capabilities are exhausted during early bootstrap
(before mmsrv is available):

1. Signal the procmgr's bound notification (`expand_ntfn`)
2. Procmgr allocates a new untyped and places it at a deterministic
   CNode slot (`UT_EXPAND_BASE + N`, last 8 slots of the 10-bit CNode)
3. The probe retype (`untyped_retype(expected_slot, OBJ_FRAME, ...)`)
   doubles as both completion check and frame creation

**Note:** This direct untyped expansion protocol is only used by rtld
and init during bootstrap, before the memory manager server (mmsrv) is
running. Regular userland processes delegate all frame allocation to
mmsrv via `posix_mmap()`.

**Convenience wrappers:**
- `slot_alloc()` -- Allocate one CNode slot (sync)
- `slot_alloc_async()` -- Allocate with async CSpace expansion

**Frame allocation** is delegated to mmsrv. Use `posix_mmap()` instead.

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

trona is compiled as a position-independent shared object:

1. Rust source compiles to `trona.o` + `trona.rmeta`
2. `fork.S` assembles to `fork.o`
3. All objects link with `core.o` and `compiler_builtins.o` into
   `libtrona.so` using the `libtrona.ld` linker script

The linker script places sections at page-aligned boundaries with
dynamic linking metadata (`.gnu.hash`, `.dynsym`, `.dynstr`,
`.rela.dyn`, `.dynamic`) at the front.

### Runtime Loader Integration

SaltyOS has two runtime dynamic linkers, both in `lib/trona/rtld/`:

**ELF RTLD** (`lib/trona/rtld/elf/` → `ld-trona.so`):
Loads `libtrona.so` and `libc.so` into every POSIX dynamically-linked
process:

1. Finds shared libraries in the shared library cache region
2. Maps them into the child's address space
3. Resolves relocations (R_X86_64_RELATIVE / R_AARCH64_RELATIVE for PIE)
4. Sets up the GOT and PLT entries

**PE RTLD** (`lib/trona/rtld/pe/` → `ld-trona-pe.so`):
Loads PE/COFF executables for the Win32 personality subsystem. Uses the
`pe_loader.rs` module in the loader crate to parse PE headers, map
sections, and resolve imports.

Init is the exception: it is **statically linked** with substrate .o
embedded directly, since it runs before `rtld` and VFS are available.

### ELF Loader

The `elf_loader.rs` module loads ELF64 binaries into child address
spaces. It supports:

- ET_EXEC (fixed address) and ET_DYN (PIE, relocated to `load_base`)
- Multiple PT_LOAD segments with correct permissions
- Overlapping page merging (permission union)
- R_X86_64_RELATIVE / R_AARCH64_RELATIVE relocation patching via scratch page
- Callback-based frame allocation (`alloc_frame_slot` function pointer)
- Page recording callback for COW fork tracking

### PE Loader

The `pe_loader.rs` module (in the loader crate) loads PE/COFF binaries
for the Win32 personality subsystem. It parses PE headers, maps sections
with correct permissions, and resolves import address tables. The
`pe_types.rs` module provides PE format type definitions.

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

All mutable global state in trona:

| Variable | Type | Module | Purpose |
|----------|------|--------|---------|
| `__trona_ipc_ctx` | `IpcContext` | `lib.rs` | IPC buffer pointer and cap transfer count |
| `__sig_handlers` | `[AtomicUsize; 32]` | `lib.rs` | Signal handler function pointers |
| `__sig_initialized` | `AtomicI32` | `lib.rs` | One-shot signal subsystem init flag |
| `__sig_blocked_mask` | `u32` | `lib.rs` | Bitmask of blocked signals |
| `__sig_sa_mask` | `[u32; 32]` | `lib.rs` | Per-signal sa_mask values |
| `__sig_sa_flags` | `[i32; 32]` | `lib.rs` | Per-signal sa_flags (SA_RESETHAND, etc.) |
| `__trona_next_frame_slot` | `u64` (weak) | `lib.rs` | Legacy frame slot counter (overridden by slot_alloc) |
| `__trona_slot_base` | `u64` (weak) | `lib.rs` | Slot allocator pool base (from auxv) |
| `__trona_slot_count` | `u64` (weak) | `lib.rs` | Slot allocator pool size (from auxv) |
| `__trona_cspace_ntfn` | `u64` (weak) | `lib.rs` | CSpace expansion notification cap (from `AT_TRONA_CSPACE_NTFN`) |
| `SLOT_ALLOC` | `SlotAllocState` | `slot_alloc.rs` | Segment chain and expansion state |
| `UT_EXPAND_REQUESTED` | `bool` | `slot_alloc.rs` | Whether untyped expansion is in flight |
| `EXTRA_UT_SLOTS` | `[Cap; 8]` | `slot_alloc.rs` | Dynamically-granted untyped caps |
| `EXTRA_UT_COUNT` | `usize` | `slot_alloc.rs` | Number of extra untypeds granted |
| `PENDING_FRAME_SLOT` | `Cap` | `slot_alloc.rs` | Saved slot across async WouldBlock |
| `DEVICE_REGIONS` | `[DeviceRegion; 4]` | `mm.rs` | Device-backed mmap tracking (framebuffer, etc.) |
| `NEXT_UT_HINT` | `Cap` | `elf_loader.rs` | Hint for untyped scanning during ELF load |

**Why this is safe:** SaltyOS userland processes are single-threaded.
Each process has its own address space with private copies of all
statics. There is no shared mutable state between processes. Signal
handlers run synchronously in the context of `posix_sigcheck()`, not
asynchronously, so there are no reentrancy concerns. The weak linkage
on `__trona_slot_*` and `__trona_cspace_ntfn` allows RTLD or CRT to
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
        --emit=obj=trona.o,metadata=trona.rmeta
      |
      +--- trona.rmeta (used by userland programs at compile time)
      |
      v
  fork.S --[clang -c]--> fork.o
      |
      v
  clang -shared -nostdlib -fPIC -fuse-ld=lld
        -Wl,-soname,libtrona.so -Wl,--hash-style=gnu
        -T libtrona.ld
        trona.o fork.o core.o compiler_builtins.o
      |
      v
  libtrona.so (packed into initrd by mkcpio.py)
```

### Linker Script

The `libtrona.ld` script creates a shared object with:

- Dynamic linking metadata at the start (`.gnu.hash`, `.dynsym`,
  `.dynstr`, `.rela.dyn`)
- Page-aligned `.text`, `.rodata`, `.data`, and `.bss` sections
- `.got` and `.got.plt` for position-independent addressing
- `.dynamic` section for runtime linker use
- All debug metadata (`.comment`, `.note.*`, `.eh_frame*`) discarded

### Static vs Dynamic Linking

- **Init:** Statically linked. `trona.o` is linked directly into the
  init binary because init runs before the runtime linker is available.
- **All other programs:** Dynamically linked via `libtrona.so`. The
  `.rmeta` file provides type information at compile time; the `.so`
  provides code at runtime.

## 12. Cross-References

- [ABI Specification](../spec/abi.md) -- Syscall register convention,
  message info encoding, IPC buffer layout
- [Syscall Specification](../spec/syscalls.md) -- Complete syscall
  numbering and semantics
- [IPC Design](ipc.md) -- Kernel-side endpoint and notification
  implementation
- [Memory Management](memory.md) -- Kernel VSpace, MemoryObject, and
  frame allocator
- [mmsrv Design](mmsrv.md) -- Userspace memory manager server
- [Capability System](capability.md) -- CNode structure, CDT, rights
  model
- [POSIX Compatibility](posix.md) -- VFS and procmgr protocol design,
  networking (netsrv/dnssrv)
- [basaltc Design](basaltc.md) -- C standard library built on trona
- [trona API Reference](../spec/trona-api.md) -- Complete function
  signatures and error codes

---

## Substrate Thread Infrastructure

### Architecture

The substrate owns all thread-local storage (TLS) and thread lifecycle
infrastructure. Personality layers (POSIX, Win32) extend threads via
personality-specific data and callbacks.

```
substrate/tls.rs
  ThreadDesc pool, TLS init, TP management, thread_id, current_tls()
  post_fork_child(), personality callbacks
substrate/worker.rs
  Worker pool: multi-threaded IPC services
         extends via personality_data + owner
           ┌──────┴──────┐
      posix/pthread.rs  win32/thread.rs
      PosixThreadExt    Win32ThreadExt
```

### ThreadDesc

`ThreadDesc` is a substrate-internal Rust type (not C ABI) that tracks
per-thread capabilities, memory layout, identity, and personality extension.
It lives in a static pool of `MAX_THREADS` (64) slots. Each thread's
`ThreadLocalBlock.desc` (opaque `*mut u8`) points to its `ThreadDesc`.

### ThreadOwner

Determines resource cleanup responsibility:
- **Main** — lives for process lifetime, never cleaned up
- **Worker** — substrate handles resource cleanup (unmap, cap delete)
- **Personality** — personality handles cleanup (e.g., POSIX munmap + join)

### Worker Pool

`substrate/worker.rs` provides `run_workers()` for multi-threaded IPC
services. N threads recv on the same endpoint; the kernel dispatches
messages to available workers (FIFO). Workers are first-class threads
with full TLS. See module docs for usage.

### Fork Child Reinit

`_trona_post_fork_child()` (called from `fork.S` child entry) reinits the
substrate thread pool in the child process: updates main thread caps,
invalidates non-main slots (ABA generation bump), invokes personality
fork callback, resets thread ID counter. The child's SC cap is discovered
via `PM_GET_THREAD_CAPS` IPC to procmgr.

### PM_GET_THREAD_CAPS Protocol

Procmgr IPC label `PM_GET_THREAD_CAPS` (36). Returns the caller's
scheduling context cap slot via `reply.regs[0]`. Used by fork children
to discover their SC cap (which differs from the parent's).

### AT_TRONA_SC_CAP Auxv

`AT_TRONA_SC_CAP` (0x100E) passes the main thread's SchedContext
capability slot to the child process via the auxiliary vector. Parsed by
ELF rtld, PE rtld, and the static CRT. Stored in the substrate global
`__trona_sc_cap` and read into `ThreadDesc.sc_cap` during
`init_main_thread_tls()`.
