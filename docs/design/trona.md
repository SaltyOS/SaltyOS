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

### 6-Crate Architecture

trona is organized as 6 crates plus a dual-format runtime linker and a
bindgen-generated kernel ABI crate (`uapi`):

| Crate | Path | Purpose |
|-------|------|---------|
| **trona_kernel** | `lib/trona/kernel/` | Raw kernel ABI: syscall wrappers, IPC operations, capability invocations, IPC buffer layout, boot-info parser, core kernel types |
| **trona_protocol** | `lib/trona/protocol/` | Cross-server wire constants and reply payload shapes for every userspace server |
| **trona_server** | `lib/trona/server/` | Server-loop primitives: EQ_WAIT reactor (`event_loop.rs`), recv-slot arena (`recv_slot.rs`), reply lease (`reply.rs`) |
| **trona_runtime** | `lib/trona/runtime/` | Process runtime: CNode slot allocator (`abi/`), lazy cap lookup (`client/`), TLS and thread lifecycle (`thread/`), C-ABI exports, spawn and cap-table install (`spawn/`) |
| **trona_posix** | `lib/trona/posix/` | POSIX compatibility: file I/O, sockets, poll, mm, signals, pthread, sync, tls, dns, bulk transfers |
| **trona_loader** | `lib/trona/loader/` | ELF64 loader, PE loader, CPIO parser, ELF dynamic helpers, runtime dynamic linkers |

Additionally:

- **uapi** (bindgen-generated) — a `libuapi.rmeta` produced from
  `kernite/include/uapi/*.h` at build time. Every crate above depends on
  it. There is no hand-written `lib/trona/uapi/` directory.
- **kernel32** (`lib/trona/win32/`) — the `kernel32.dll` PE shared
  library for the Win32 personality, compiled with a PE/COFF target.
  Separate from `libtrona.so`.
- **fork stubs** (`lib/trona/posix/arch/<arch>/fork.S`) — per-arch
  assembly trampolines linked into `libtrona.so`.

### Source Layout

**trona_kernel** (`lib/trona/kernel/src/`):

| File | Purpose |
|------|---------|
| `lib.rs` | Crate root |
| `syscall.rs` | Rust ABI wrapper for the single `KERNITE_SYS_INVOKE` trap |
| `arch/<arch>/syscall.S` | Explicit syscall stub for the target trap instruction and register ABI |
| `ipc.rs` | IPC operations: send, recv, call, reply_recv, cap transfer |
| `ipc_buffer.rs` | `IpcBuffer` layout, message info encoding, register accessors |
| `invoke.rs` | Capability invocation wrappers for all kernel object types |
| `bootinfo.rs` | Boot-info TLV parser |
| `core_types.rs` | Fundamental kernel ABI types (`Cap`, `TronaResult`, etc.) |

**trona_protocol** (`lib/trona/protocol/src/`):

| File | Purpose |
|------|---------|
| `lib.rs` | Crate root and re-exports |
| `vfs/` | VFS server wire labels and payload shapes |
| `mm.rs` | mmsrv wire labels |
| `namesrv.rs` | Name service wire labels |
| `rsrcsrv.rs` | Resource server wire labels |
| `posix.rs` | POSIX-subsystem wire labels (ttysrv, VFS POSIX extensions) |
| `posix_abi/` | POSIX ABI structures shared across servers |
| `win32.rs` | Win32 subsystem wire labels (csrss protocol) |
| `console.rs`, `display.rs`, `pci.rs`, `blk.rs`, `netsrv.rs` | Per-driver and per-server wire labels |
| `common.rs`, `control.rs`, `correlation.rs`, `init.rs`, `log.rs` | Shared control and lifecycle labels |

**trona_server** (`lib/trona/server/src/`):

| File | Purpose |
|------|---------|
| `lib.rs` | Crate root |
| `event_loop.rs` | EQ_WAIT reactor: edge-triggered cap-set wait loop |
| `recv_slot.rs` | `RecvSlotArena`: arena of pre-allocated receive capability slots |
| `reply.rs` | `ReplyLease`: scoped reply token for deferred replies |
| `badge.rs` | Badge extraction helpers |
| `continuation.rs` | Continuation state for multi-step request handling |
| `frame_alloc.rs` | Server-local frame allocation helpers |
| `outbound.rs` | Outbound IPC helpers |
| `hash_index.rs`, `slab.rs`, `segmented_array.rs` | Server-side data structure support |

**trona_runtime** (`lib/trona/runtime/src/`):

| File / Dir | Purpose |
|------------|---------|
| `lib.rs` | Crate root, C-ABI exports, panic handler, startup entry |
| `abi/` | CNode slot allocator with self-expansion protocol |
| `client/caps.rs` | Lazy cap lookup via role ID; `local_by_name()` / `local_cap!` |
| `client/lazy_resolve.rs` | Lazy endpoint resolution cache |
| `client/mm.rs`, `client/vfs.rs` | Client helpers for mmsrv and VFS |
| `spawn/cap_table.rs` | `SaltyOSCapTableV1` install and role lookup |
| `spawn/role_consts.rs` | `ROLE_*` constants for well-known capability roles |
| `spawn/layout.rs`, `spawn/stack_plan.rs` | Child VM layout planning |
| `thread/tls.rs` | Thread-local storage setup and `ThreadDesc` pool |
| `thread/thread.rs` | Thread lifecycle: create, join, exit |
| `thread/worker.rs` | Worker pool for multi-threaded IPC servers |
| `thread/sync.rs`, `thread/cap.rs` | Thread synchronization and per-thread cap management |
| `weak.rs` | Weak-symbol cap role registration |
| `panic.rs` | Panic handler (serial dump + yield loop) |
| `debug/` | Serial debug output |
| `core/` | Misc runtime support |

**trona_posix** (`lib/trona/posix/`):

| File | Purpose |
|------|---------|
| `lib.rs` | Crate root |
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
| `tls.rs` | Thread-local storage access (delegates to trona_runtime) |
| `wakeup.rs` | Wakeup notification helpers |
| `types.rs` | POSIX types (stat, dirent, sockaddr, etc.) |
| `arch/<arch>/fork.S` | Fork assembly trampoline (per-arch, linked into `libtrona.so`) |
| `arch/<arch>/pthread.S` | pthread entry trampoline |

**trona_loader** (`lib/trona/loader/`):

| File / Dir | Purpose |
|------------|---------|
| `lib.rs` | Crate root |
| `common/` | Shared loader utilities (arch, ELF helpers, link map, CPIO, PE) |
| `rtld/elf/` | ELF runtime dynamic linker (`ldtrona-elf.so`): loads shared libraries, resolves relocations, sets up GOT/PLT and dlfcn |
| `rtld/pe/` | PE runtime dynamic linker (`ldtrona-pe.so`): loads PE/COFF executables for Win32 personality |

**kernel32** (`lib/trona/win32/`):

| File | Purpose |
|------|---------|
| `kernel32.rs` | `kernel32` crate root (compiled as PE DLL, not linked into `libtrona.so`) |
| `console.rs` | Win32 console I/O (ReadConsole/WriteConsole) |
| `crt.rs` | Win32 CRT startup |
| `error.rs` | Win32 error code translation |
| `handle.rs` | Win32 HANDLE management |
| `process.rs` | Win32 process operations |
| `ipc.rs` | Win32 subsystem IPC helpers |
| `runtime.rs` | Local PE ABI shim connecting kernel32.dll to trona_runtime |
| `pe_types.rs` | PE type definitions |
| `syscall.rs` | Win32 syscall wrappers |
| `kernel32.def` | kernel32.dll export definitions |

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
userspace servers (VFS, init) via IPC. trona only handles message
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
 |  basaltc (libc.so)            |  kernel32 (kernel32.dll)        |
 +-------------------------------+----------------------------------+
 |                                                                  |
 |  trona_posix                  |  trona_loader                   |
 |  ├── file.rs, proc.rs         |  ├── common/ (ELF, PE, CPIO)   |
 |  ├── socket.rs, poll.rs       |  ├── rtld/elf/ (ldtrona-elf.so) |
 |  ├── mm.rs, signals.rs        |  └── rtld/pe/ (ldtrona-pe.so)  |
 |  └── pthread.rs, dns.rs       |                                 |
 +-------------------------------+----------------------------------+
 |                   trona_runtime                                  |
 |  abi/ (slot alloc), client/ (cap lookup), spawn/ (cap table),   |
 |  thread/ (TLS, worker pool), C-ABI exports, panic handler        |
 +-------------------------------+----------------------------------+
 |  trona_protocol               |  trona_server                   |
 |  wire labels, reply shapes    |  event_loop, recv_slot, reply   |
 +-------------------------------+----------------------------------+
 |                   trona_kernel                                   |
 |  syscall.rs, ipc.rs, invoke.rs, ipc_buffer.rs, bootinfo.rs      |
 +------------------------------------------------------------------+
 |                   uapi (bindgen-generated)                       |
 |  libuapi.rmeta from kernite/include/uapi/*.h                     |
 +------------------------------------------------------------------+
 |           core + compiler_builtins (Rust standard layer)         |
 +------------------------------------------------------------------+
                               |
                               v
 +------------------------------------------------------------------+
 |                    SaltyOS Kernel                                 |
 |  syscall entry (syscall.S / svc #0)                              |
 +------------------------------------------------------------------+
```

### Crate Dependency Graph

```
         +-----------------------------------+
         |  uapi (bindgen from uapi/*.h)     |
         |  no Rust crate dependencies       |
         +---+------+------+------+----------+
             |      |      |      |
     +-------+   +--+   +--+   +-+----------+
     |           |      |      |
+----v------+ +--v----+ +v---+ +v-----------+
| trona_    | |trona_ | |    | | trona_     |
| kernel    | |proto- | |    | | server     |
| syscall,  | |col    | |    | | event_loop,|
| ipc,      | |wire   | |    | | recv_slot, |
| invoke    | |labels | |    | | reply      |
+-----------+ +--+----+ |    | +------+-----+
                  |      |   |        |
            +-----+------+   +--------+
            |
      +-----v---------+
      |  trona_runtime |
      |  slot alloc,   |
      |  cap lookup,   |
      |  TLS, spawn    |
      +-----+---------+
            |
     +------+------+
     |             |
+----v------+ +----v-------+
| trona_    | | trona_     |
| posix     | | loader     |
| file, mm, | | ELF, PE,   |
| signals,  | | CPIO, rtld |
| pthread   | |            |
+-----------+ +------------+
```

Dependency edges (each crate depends on everything above it in its chain):
- **uapi** — zero dependencies (pure bindgen output)
- **trona_kernel** — uapi
- **trona_protocol** — uapi, trona_kernel
- **trona_server** — uapi, trona_kernel (not trona_protocol)
- **trona_runtime** — uapi, trona_kernel, trona_protocol
- **trona_posix** — uapi, trona_kernel, trona_protocol, trona_server, trona_runtime
- **trona_loader** — uapi, trona_kernel, trona_protocol, trona_server, trona_runtime

## 4. Syscall Wrapper Layer

All kernel interaction flows through a single function in
`trona_kernel/src/syscall.rs`:

```rust
#[inline(always)]
pub fn syscall(num: u64, a0..a5: u64) -> TronaResult { error, value }
```

The explicit per-architecture syscall stubs map directly to the SaltyOS syscall ABI:

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

`IpcContext` and the IPC buffer layout are defined in `trona_kernel`
(`ipc.rs`, `ipc_buffer.rs`). Every process has a global `IpcContext`
that holds a pointer to the IPC buffer (a kernel-mapped page at a known
virtual address) and a count of capabilities staged for transfer:

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

**Server loop (write-reply/read):**
```
recv_ctx(ctx, ep, &mut msg, &mut badge)    // first receive
loop {
    // process msg, build reply
    mp_write_reply_read_ctx(ctx, ep, &reply, &mut msg, &mut badge)
    // write reply to previous caller + wait for next
}
```

**Fire-and-forget:** `SYS_NBSEND` (slot 4) and its `nbsend_ctx`
wrapper were retired when the per-endpoint ring was removed. Use a
notification signal (`trona_signal`) or a dedicated SHM ring for
fire-and-forget patterns. The kernel keeps syscall slot 4 reserved
and returns `InvalidArgument` to any stale caller — see
`docs/spec/syscalls.md` for details.

**Signal/Wait (notifications):**
```
trona_signal(ntfn, bits)  // OR bits into notification word
trona_wait(ntfn)          // block until signaled, returns bitmap
trona_poll(ntfn, &bits)   // non-blocking check
```

## 6. Capability Invocations

The `trona_kernel/src/invoke.rs` module provides typed wrappers for all
kernel object operations. Each wrapper calls the central `invoke()` function:

```rust
pub fn invoke(cap: Cap, label: u64, arg0..arg3: u64) -> TronaResult {
    syscall(SYS_INVOKE, cap, label, arg0, arg1, arg2, arg3)
}
```

The `label` argument selects the operation. Labels are grouped by
object type:

### CNode Operations (0x20-0x27)

| Label | Function | Purpose |
|-------|----------|---------|
| `CNODE_COPY` (0x020) | `cnode_copy()` | Copy cap between slots with rights mask |
| `CNODE_MINT` (0x021) | `cnode_mint()` | Copy cap with badge assignment |
| `CNODE_MOVE` (0x022) | `cnode_move()` | Move cap to new slot (old slot emptied) |
| `CNODE_MUTATE` (0x023) | `cnode_mutate()` | Move with badge change |
| `CNODE_DELETE` (0x024) | `cnode_delete()` | Remove cap from slot |
| `CNODE_REVOKE` (0x025) | `cnode_revoke()` | Delete all derived caps |
| `CNODE_SET_GUARD` (0x026) | `cnode_set_guard()` | Set CNode guard value and bits |
| `CNODE_GET_INFO` (0x027) | `cnode_get_info()` | Query CNode size and occupancy |

Depth-aware variants (`cnode_copy_depth`, `cnode_delete_depth`,
`cnode_revoke_depth`) write depth values into `ipc_buffer.reserved[0..1]`
before the invoke syscall, supporting hierarchical CNode addressing
after CSpace expansion.

### Untyped Operations (0x40-0x42)

| Label | Function | Purpose |
|-------|----------|---------|
| `UNTYPED_RETYPE` (0x040) | `untyped_retype()` | Create new kernel object from untyped memory |
| `UNTYPED_RESET` (0x041) | `untyped_reset()` | Reset exhausted untyped once all typed children are destroyed |
| `UNTYPED_GET_STATS` (0x042) | `UNTYPED_GET_STATS` | Query remaining bytes in untyped region |

Also has a `untyped_retype_depth()` variant for expanded CSpaces.

### TCB Operations (0x60-0x78)

| Label | Function | Purpose |
|-------|----------|---------|
| `TCB_CONFIGURE` (0x060) | `tcb_configure()` | Set initial RIP/PC, RSP/SP, IPC buffer |
| `TCB_START` (0x061) | `tcb_start()` | Make thread runnable |
| `TCB_STOP` (0x062) | `tcb_stop()` | Remove thread from scheduler |
| `TCB_KILL` (0x063) | `tcb_kill()` | Drive TCB into terminal Dying state |
| `TCB_YIELD` (0x064) | `TCB_YIELD` | Yield CPU on behalf of target thread |
| `TCB_GET_STATE` (0x065) | `TCB_GET_STATE` | Read thread scheduling state |
| `TCB_GET_ABI_VERSION` (0x066) | `TCB_GET_ABI_VERSION` | Query kernel ABI version |
| `TCB_SET_INVOKE_DEPTHS` (0x067) | `TCB_SET_INVOKE_DEPTHS` | Set per-thread CNode resolve depths |
| `TCB_SET_SPACE` (0x068) | `tcb_set_space()` | Assign CSpace and VSpace |
| `TCB_SET_AFFINITY` (0x069) | `TCB_SET_AFFINITY` | Pin thread to CPU set |
| `TCB_READ_REGISTERS` (0x06A) | `TCB_READ_REGISTERS` | Read thread register state |
| `TCB_WRITE_REGISTERS` (0x06B) | `tcb_write_registers()` | Write thread register state |
| `TCB_SET_PRIORITY` (0x06C) | `tcb_set_priority()` | Set class-local scheduling priority |
| `TCB_SET_IPC_BUFFER` (0x06D) | `tcb_set_ipc_buffer()` | Set IPC buffer address |
| `TCB_SET_FAULT_PIPE` (0x06E) | `tcb_set_fault_pipe()` | Set fault MessagePipe for fault delivery |
| `TCB_COPY_FPU` (0x070) | `tcb_copy_fpu()` | Copy FPU state between threads |
| `TCB_SET_TLS_BASE` (0x071) | `tcb_set_tls_base()` | Set thread-local storage base address |
| `TCB_SET_STACK_BOUNDS` (0x072) | `tcb_set_stack_bounds()` | Publish usable stack reserve bounds |
| `TCB_SET_SCHED_CLASS` (0x073) | `tcb_set_sched_class()` | Select scheduler class |
| `TCB_GET_SPACE_INFO` (0x074) | `tcb_get_space_info_ctx()` | Query CSpace depth |
| `TCB_GET_CPU_TIMES` (0x075) | `tcb_get_cpu_times_ctx()` | Read cumulative CPU runtime counters |
| `TCB_GET_TRACE_ID` (0x076) | `tcb_get_trace_id()` | Read stable kernel trace id |
| `TCB_SET_ABI_TP` (0x077) | `tcb_set_abi_tp()` | Set process ABI thread pointer |
| `TCB_EXIT_SELF` (0x078) | `TCB_EXIT_SELF` | Thread self-exit |

### VSpace Operations (0x80-0x99)

| Label | Function | Purpose |
|-------|----------|---------|
| `VSPACE_MAP` (0x080) | `vspace_map()` | Map frame at virtual address |
| `VSPACE_UNMAP` (0x081) | `vspace_unmap()` | Unmap page at virtual address and tear down tracked MO metadata |
| `VSPACE_MAP_PT` (0x082) | `vspace_map_pt()` | Install intermediate page table |
| `VSPACE_WALK` (0x083) | `vspace_walk()` | Walk page table (debugging) |
| `VSPACE_COPY_PAGE` (0x084) | `vspace_copy_page()` | Copy page contents to frame |
| `VSPACE_MAP_DEVICE` (0x085) | `vspace_map_device()` | Map device memory page |
| `VSPACE_MAP_DEVICE_RANGE` (0x086) | `vspace_map_device_range()` | Batch-map device pages |
| `VSPACE_PROTECT` (0x087) | `vspace_protect()` | Change page protection flags |
| `VSPACE_PROTECT_RANGE` (0x088) | `vspace_protect_range()` | Batch change page protection |
| `VSPACE_MAP_DEMAND` (0x089) | `vspace_map_demand()` | Map a demand-paged region |
| `VSPACE_MAP_DEMAND_RANGE` (0x08A) | `vspace_map_demand_range()` | Batch-map demand-paged regions |
| `VSPACE_SET_COW_POOL` (0x08D) | `vspace_set_cow_pool()` | Set COW frame pool for VSpace |
| `VSPACE_REPLENISH_COW_POOL` (0x08E) | `vspace_replenish_cow_pool()` | Replenish COW frame pool |
| `VSPACE_MAP_MO` (0x08F) | `vspace_map_mo()` | Map MemoryObject pages into VSpace |
| `VSPACE_SHARE_RO_PAGE` (0x090) | `vspace_share_ro_page()` | Share a read-only page between VSpaces |
| `VSPACE_FORK_RANGE` (0x091) | `vspace_fork_range()` | Fork a VA range (COW) between VSpaces |
| `VSPACE_UNDO_FORK_RANGE` (0x092) | `vspace_undo_fork_range()` | Reverse a previously successful fork-range chunk |
| `VSPACE_GET_MEM_STATS` (0x093) | `vspace_get_mem_stats_raw()` | Snapshot per-process memory accounting counters |
| `VSPACE_GET_RANGE_STATS` (0x094) | `vspace_get_range_stats_raw()` | Snapshot resident/share/dirty/PSS stats for a range |
| `VSPACE_GET_TRACE_ID` (0x095) | `vspace_get_trace_id()` | Read stable kernel trace id |
| `VSPACE_FUTEX_WAIT` (0x096) | `VSPACE_FUTEX_WAIT` | Futex wait on a VSpace-relative address |
| `VSPACE_FUTEX_WAKE` (0x097) | `VSPACE_FUTEX_WAKE` | Futex wake on a VSpace-relative address |
| `VSPACE_RESOLVE_PAGE` (0x098) | `vspace_resolve_page()` | Resolve a virtual address to physical |
| `VSPACE_FUTEX_REQUEUE` (0x099) | `VSPACE_FUTEX_REQUEUE` | Futex requeue |

### SchedContext Operations (0xA0-0xA1)

| Label | Function | Purpose |
|-------|----------|---------|
| `SC_CONFIGURE` (0x0A0) | `sc_configure()` | Set budget and period (nanoseconds) |
| `SC_BIND` (0x0A1) | `sc_bind()` | Bind scheduling context to TCB |

### IoPort Operations (0xC0-0xC5)

| Label | Function | Purpose |
|-------|----------|---------|
| `IOPORT_READ_8` (0x0C0) | `ioport_read_8()` / `ioport_in8()` | Read 8-bit I/O port |
| `IOPORT_READ_16` (0x0C1) | `ioport_read_16()` / `ioport_in16()` | Read 16-bit I/O port |
| `IOPORT_READ_32` (0x0C2) | `ioport_read_32()` / `ioport_in32()` | Read 32-bit I/O port |
| `IOPORT_WRITE_8` (0x0C3) | `ioport_write_8()` / `ioport_out8()` | Write 8-bit I/O port |
| `IOPORT_WRITE_16` (0x0C4) | `ioport_write_16()` / `ioport_out16()` | Write 16-bit I/O port |
| `IOPORT_WRITE_32` (0x0C5) | `ioport_write_32()` / `ioport_out32()` | Write 32-bit I/O port |

### IrqHandler Operations (0xE0-0xE2)

| Label | Function | Purpose |
|-------|----------|---------|
| `IRQ_BIND_EQ` (0x0E0) | `irq_bind_eq()` | Bind IRQ handler to EventQueue |
| `IRQ_UNBIND_EQ` (0x0E1) | `irq_unbind_eq()` | Detach IRQ handler from EventQueue |
| `IRQ_ACK` (0x0E2) | `irq_ack()` / `irq_handler_ack()` | Acknowledge IRQ (re-enable in controller) |

### MemoryObject Operations (0x100-0x10C)

| Label | Function | Purpose |
|-------|----------|---------|
| `MO_COMMIT` (0x100) | `mo_commit()` | Commit pages into a MemoryObject |
| `MO_DECOMMIT` (0x101) | `mo_decommit()` | Decommit pages from a MemoryObject |
| `MO_GET_SIZE` (0x102) | `mo_get_size()` | Query MemoryObject page count |
| `MO_CLONE` (0x103) | `mo_clone()` | COW clone a MemoryObject |
| `MO_RESIZE` (0x104) | `mo_resize()` | Resize a MemoryObject |
| `MO_READ` (0x105) | `mo_read()` | Read data from a MemoryObject page |
| `MO_WRITE` (0x106) | `mo_write()` | Write data to a MemoryObject page |
| `MO_HAS_PAGE` (0x107) | `mo_has_page()` | Check if a page is committed |
| `MO_GET_MAP_COUNT` (0x108) | `mo_get_map_count()` | Count reverse-map entries |
| `MO_UPDATE_PAGE_FLAGS` (0x109) | `mo_update_page_flags()` | Update/query frame flags for a page |
| `MO_ATTACH_PAGER` (0x10A) | `MO_ATTACH_PAGER` | Attach pager to a MemoryObject |
| `MO_SNAPSHOT` (0x10B) | `MO_SNAPSHOT` | Snapshot a MemoryObject |
| `MO_CLONE_RANGE` (0x10C) | `mo_clone_range()` | COW clone a sub-range of a MemoryObject |

### EventQueue Operations (0x120-0x122)

| Label | Function | Purpose |
|-------|----------|---------|
| `EQ_WAIT` (0x120) | `eq_wait()` | Block until an event arrives or deadline passes |
| `EQ_POLL` (0x121) | `EQ_POLL` | Non-blocking check for pending events |
| `EQ_CANCEL` (0x122) | `EQ_CANCEL` | Cancel a pending EQ_WAIT |

### Watch Operations (0x140-0x142)

| Label | Function | Purpose |
|-------|----------|---------|
| `WATCH_REGISTER` (0x140) | `watch_register()` | Register a Watch on a kernel object |
| `WATCH_DISARM` (0x141) | `WATCH_DISARM` | Disarm a Watch without cancelling pending events |
| `WATCH_CANCEL` (0x142) | `watch_cancel()` | Cancel a Watch and purge queued events |

### MessagePipe Operations (0x160-0x163)

| Label | Function | Purpose |
|-------|----------|---------|
| `MP_WRITE` (0x160) | `MP_WRITE` | Write a record to a MessagePipe |
| `MP_READ` (0x161) | `MP_READ` | Read a record from a MessagePipe |
| `MP_CLOSE` (0x162) | `MP_CLOSE` | Close a MessagePipe side |
| `MP_CALL` (0x163) | `MP_CALL` | Write a record and block for reply |

### DataPipe Operations (0x180-0x186)

| Label | Function | Purpose |
|-------|----------|---------|
| `DP_PRODUCE` (0x180) | `DP_PRODUCE` | Write bytes into a DataPipe |
| `DP_CONSUME` (0x181) | `DP_CONSUME` | Read bytes from a DataPipe |
| `DP_QUERY` (0x182) | `DP_QUERY` | Query DataPipe buffer state |
| `DP_CLOSE` (0x183) | `DP_CLOSE` | Close a DataPipe side |
| `DP_SET_RX_THRESHOLD` (0x184) | `dp_set_rx_threshold()` | Set RX byte threshold for state assertion |
| `DP_SET_TX_THRESHOLD` (0x185) | `dp_set_tx_threshold()` | Set TX free-space threshold for state assertion |
| `DP_SHUTDOWN` (0x186) | `dp_shutdown()` | Half-close write direction |

### Timer Operations (0x1A0-0x1A2)

| Label | Function | Purpose |
|-------|----------|---------|
| `TIMER_SET` (0x1A0) | `timer_set()` | Arm timer with deadline and optional period |
| `TIMER_CANCEL` (0x1A1) | `timer_cancel()` | Disarm a timer |
| `TIMER_QUERY` (0x1A2) | `TIMER_QUERY` | Query remaining time until next fire |

### KernelRng Operations (0x1C0)

| Label | Function | Purpose |
|-------|----------|---------|
| `RNG_READ` (0x1C0) | `RNG_READ` | Read random bytes from kernel RNG |

### SystemControl Operations (0x1E0-0x1E1)

| Label | Function | Purpose |
|-------|----------|---------|
| `SYSTEM_SHUTDOWN` (0x1E0) | `SYSTEM_SHUTDOWN` | ACPI system shutdown |
| `SYSTEM_REBOOT` (0x1E1) | `SYSTEM_REBOOT` | ACPI system reboot |

### Clock Operations (0x200)

| Label | Function | Purpose |
|-------|----------|---------|
| `CLOCK_READ` (0x200) | `CLOCK_READ` | Read monotonic or realtime clock |

### SystemInfo Operations (0x220-0x221)

| Label | Function | Purpose |
|-------|----------|---------|
| `SYSINFO_GET_INFO` (0x220) | `SYSINFO_GET_INFO` | Query system information |
| `SYSINFO_GET_MEMINFO` (0x221) | `SYSINFO_GET_MEMINFO` | Query system memory information |

### KernelDebug Operations (0x240-0x244)

| Label | Function | Purpose |
|-------|----------|---------|
| `KDEBUG_PUTCHAR` (0x240) | `KDEBUG_PUTCHAR` | Write character to serial console |
| `KDEBUG_PUTSTR` (0x241) | `KDEBUG_PUTSTR` | Write string to serial console |
| `KDEBUG_PUTBUF` (0x242) | `KDEBUG_PUTBUF` | Write buffer to serial console |
| `KDEBUG_DUMP_STATE` (0x243) | `KDEBUG_DUMP_STATE` | Dump CPU state to serial |
| `KDEBUG_CONSOLE_CONTROL` (0x244) | `KDEBUG_CONSOLE_CONTROL` | Enable/disable kernel console |

### MessagePipeCore Operations (0x260)

| Label | Function | Purpose |
|-------|----------|---------|
| `MP_CORE_PAIR` (0x260) | `mp_core_pair()` | Split MessagePipeCore into a send/recv pair |

### DataPipeCore Operations (0x280)

| Label | Function | Purpose |
|-------|----------|---------|
| `DP_CORE_PAIR` (0x280) | `dp_core_pair()` | Split DataPipeCore into a producer/consumer pair |

### Pager Operations (0x2C0-0x2C7)

| Label | Function | Purpose |
|-------|----------|---------|
| `PAGER_BIND_EQ` (0x2C0) | `PAGER_BIND_EQ` | Bind pager to EventQueue for fault delivery |
| `PAGER_SUPPLY_PAGE` (0x2C1) | `PAGER_SUPPLY_PAGE` | Donate a Frame cap to satisfy a page-fault request |
| `PAGER_FAIL` (0x2C2) | `PAGER_FAIL` | Signal pager failure (SIGBUS-equivalent) |
| `PAGER_DETACH` (0x2C3) | `PAGER_DETACH` | Detach pager from its MemoryObject |
| `PAGER_BEGIN_WRITEBACK` (0x2C4) | `PAGER_BEGIN_WRITEBACK` | Begin writeback of dirty pages |
| `PAGER_WRITEBACK_DONE` (0x2C5) | `PAGER_WRITEBACK_DONE` | Signal writeback completion |
| `PAGER_EVICT_PAGE` (0x2C6) | `PAGER_EVICT_PAGE` | Reclaim a clean resident page |
| `PAGER_SUPPLY_COPY` (0x2C7) | `PAGER_SUPPLY_COPY` | Supply page via kernel-managed page-cache copy |

### DeviceControl Operations (0x2E0-0x2E2)

| Label | Function | Purpose |
|-------|----------|---------|
| `DEVICE_CONTROL_CREATE_IOPORT` (0x2E0) | `device_control_create_ioport()` | Mint IoPort cap into destination CSpace |
| `DEVICE_CONTROL_CREATE_DEVICE_UNTYPED` (0x2E1) | `device_control_create_device_untyped()` | Create device untyped for MMIO |
| `DEVICE_CONTROL_CREATE_IRQ_HANDLER` (0x2E2) | `device_control_create_irq_handler()` | Allocate IRQ handler cap |

## 7. POSIX Compatibility Layer

### Delegation Model

trona does not implement POSIX semantics. It acts as a message-passing
stub that translates POSIX calls into IPC messages to userspace servers.
Server endpoints are resolved at runtime through the role-based capability
table installed by `trona_runtime` at startup (`SaltyOSCapTableV1`,
`AT_SALTYOS_STARTUP`). Callers retrieve them through role getters
(`trona::caps::local_by_name()`, `local_cap!` macro) rather than
hard-coded slot numbers.

- **VFS** (role `ROLE_VFS_CLIENT`) -- File I/O, directories, sockets
  (AF_UNIX + AF_INET proxy), pipes, poll/select/epoll, shared memory,
  terminal I/O, ioctl, fcntl, `*at()` family
- **init** (role `ROLE_INIT_CONTROL`) -- Process lifecycle (spawn,
  exit, wait, fork, exec, kill), signal disposition, process groups,
  UID/GID queries, CSpace expansion, personality state (POSIX/Win32)
- **mmsrv** (role `ROLE_MMSRV_CLIENT`) -- Frame allocation, VSpace
  mapping, heap management (brk/sbrk), mmap/munmap/mprotect, demand
  paging, shared memory frames
- **dnssrv** (role `ROLE_NAMESRV_CLIENT` via namesrv lookup) -- DNS
  resolution (getaddrinfo), accessed via `trona_posix/dns.rs`

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
Anonymous memory operations (`mmap`, `brk`, `sbrk`) send IPC to mmsrv
via the role `ROLE_MMSRV_CLIENT`.
No local state tracking for anonymous regions.

### Signal Handling

Signal delivery uses the notification mechanism:

1. **Registration:** `posix_signal()` stores the handler pointer in
   an atomic array (`__sig_handlers`), then informs init of the
   disposition category (default/ignore/catch) via IPC.

2. **Delivery check:** `posix_sigcheck()` polls the process's signal
   notification (resolved via role `ROLE_SIGNAL_PIPE`). Each bit in the
   notification word corresponds to a signal number.

3. **Dispatch:** For each pending signal:
   - If blocked (`__sig_blocked_mask`), re-raise via `SYS_SIGNAL`
   - If SIG_IGN, skip
   - If SIG_DFL with terminate action, call `posix_exit(128 + sig)`
   - If caught, save/apply `sa_mask`, call handler, restore mask

4. **SA_RESETHAND:** If set, handler reverts to SIG_DFL after first
   delivery, and init is notified of the disposition change.

## 8. Resource Management

### Slot Allocator

The slot allocator lives in `trona_runtime/src/abi/` and manages CNode
slot allocation for dynamic resource creation. Processes need slots to
hold capabilities for frames, endpoints, notifications, and other kernel
objects.

**Segment chain:** Slots are organized as a chain of up to
`MAX_SEGMENTS = 80` segments (`MAX_CSPACE_EXPANSIONS = 64` self-expansion
sub-CNodes plus headroom for the initial layout segments). Each segment
is a contiguous range of CNode indices with a bitmap for free/used
tracking. The initial segment is assigned by init at spawn time and
communicated through the startup block's `cspace_layout` descriptor.

**Self-expansion:** When all segments are exhausted, `trona_runtime`
drives synchronous self-expansion against the runtime authority endpoint
(rsrcsrv). The procedure runs entirely under `SLOT_LOCK`:

1. `RES_ALLOC_OBJECT(authority_ep, OBJ_CNODE, sub_bits=10)` retypes a
   new sub-CNode into a permanently-reserved temp slot (set up once at
   runtime-phase transition via `reserve_expand_temp_slot`).
2. `cnode_set_guard(temp, 0, 0)` clears the sub-CNode's guard.
3. `cnode_move(SELF, expand_base + count, SELF, temp)` grafts the new
   sub-CNode into the deterministic root expansion window
   (`CSPACE_EXPAND_BASE..CSPACE_EXPAND_BASE + MAX_CSPACE_EXPANSIONS`).
   `cnode_move` empties the temp slot, leaving it ready for the next
   expansion call without recursing into `slot_alloc`.
4. The new segment (`packed_base = dest_root << 10`, count = 1024) is
   appended to the segment table.

Invariant violations during this path (missing authority EP, missing
temp slot, kernel invocation failure, segment table budget skew) are
fatal — `trona_runtime` halts the thread rather than continuing into a
partially-broken allocator state. Reaching the per-process
`MAX_CSPACE_EXPANSIONS` ceiling is *not* a violation; it returns
`ExpandProgress::Failed` so callers can decide what to do.

**Carve-out handler:** rsrcsrv installs its own self-expand callback via
`install_expand_handler` because retyping its own allocation handle
table over IPC to itself would deadlock. The handler runs the same
`untyped_retype + cnode_set_guard + cnode_move + register_external_segment`
sequence locally.

**Convenience wrappers:**
- `slot_alloc()` / `slot_alloc_no_expand()` -- Allocate one slot, with
  or without driving self-expansion on exhaustion.
- `slot_alloc_ref()` / `slot_alloc_no_expand_ref()` -- Same, returning a
  `SlotRef { addr, slot_depth }` so callers can drive cap-transfer at
  the right invoke depth without a separate `cnode_get_info` lookup.
- `self_expand()` -- One-shot eager expansion, used during init's
  runtime-phase transition and rsrcsrv's bootstrap epilogue to
  pre-install sub-CNodes before the first user-driven traffic.

**Frame allocation** is delegated to mmsrv. Use `posix_mmap()` instead.

### VM Layout Planning

The `trona_runtime/src/spawn/layout.rs` module computes virtual address
layouts for child processes. Given the ELF and RTLD sizes, shared library page count,
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

trona is compiled as a position-independent shared object. Each of the
six crates produces an `.o` and `.rmeta`, and they are all linked
together into `libtrona.so`:

1. `trona_uapi` (bindgen) → `libuapi.o` + `libuapi.rmeta`
2. `trona_kernel` → `trona_kernel.o` + `trona_kernel.rmeta`
3. `trona_protocol` → `trona_protocol.o` + `trona_protocol.rmeta`
4. `trona_server` → `trona_server.o` + `trona_server.rmeta`
5. `trona_runtime` → `trona_runtime.o` + `trona_runtime.rmeta`
6. `trona_posix` → `trona_posix.o` + `trona_posix.rmeta`
7. `trona_loader` → `trona_loader.o` + `trona_loader.rmeta`
8. `posix/arch/<arch>/fork.S` assembles to `fork.o`
9. All objects link with `core.o` and `compiler_builtins.o` into
   `libtrona.so` using the `libtrona.ld` linker script

The `.rmeta` files for all six crates are used by userland programs at
compile time; `libtrona.so` provides the code at runtime.

The linker script places sections at page-aligned boundaries with
dynamic linking metadata (`.gnu.hash`, `.dynsym`, `.dynstr`,
`.rela.dyn`, `.dynamic`) at the front.

### Runtime Loader Integration

SaltyOS has two runtime dynamic linkers, both in `lib/trona/loader/rtld/`:

**ELF RTLD** (`lib/trona/loader/rtld/elf/` → `ldtrona-elf.so`):
Loads `libtrona.so` and `libc.so` into every POSIX dynamically-linked
process:

1. Finds shared libraries in the shared library cache region
2. Maps them into the child's address space
3. Resolves relocations (R_X86_64_RELATIVE / R_AARCH64_RELATIVE for PIE)
4. Sets up the GOT and PLT entries

**PE RTLD** (`lib/trona/loader/rtld/pe/` → `ldtrona-pe.so`):
Loads PE/COFF executables for the Win32 personality subsystem. Uses the
`pe_loader.rs` module in the loader crate to parse PE headers, map
sections, and resolve imports.

Init is the exception: it is **statically linked** with the six trona
crate `.o` files embedded directly, since it runs before `rtld` and VFS
are available.

### ELF Loader

The `trona_loader/common/elf/` module loads ELF64 binaries into child
address spaces. It supports:

- ET_EXEC (fixed address) and ET_DYN (PIE, relocated to `load_base`)
- Multiple PT_LOAD segments with correct permissions
- Overlapping page merging (permission union)
- R_X86_64_RELATIVE / R_AARCH64_RELATIVE relocation patching via scratch page
- Callback-based frame allocation (`alloc_frame_slot` function pointer)
- Page recording callback for COW fork tracking

### PE Loader

The `trona_loader/common/pe/` module loads PE/COFF binaries for the Win32
personality subsystem. It parses PE headers, maps sections with correct
permissions, and resolves import address tables. PE type definitions are
in `trona_loader/common/pe/` as well.

### CPIO Parser

The `trona_loader/common/cpio.rs` module parses CPIO newc archives (the
initrd format):

- `cpio_find_file()` -- Search by exact filename match
- `cpio_next()` / `cpio_next_ext()` -- Iterate entries sequentially
- `cpio_archive_size()` -- Compute total archive size

### ELF Dynamic Helpers

The `trona_loader/common/elf/` module extracts dynamic linking metadata:

- `elf_has_interp()` / `elf_get_interp()` -- Check/read PT_INTERP
- `elf_get_needed()` -- Extract DT_NEEDED library names
- `elf_get_phdr_info()` -- Get program header location for RTLD

## 10. Global State

All mutable global state in trona:

| Variable | Type | Crate / Module | Purpose |
|----------|------|----------------|---------|
| `__trona_ipc_ctx` | `IpcContext` | `trona_runtime/lib.rs` | IPC buffer pointer and cap transfer count |
| `__sig_handlers` | `[AtomicUsize; 32]` | `trona_posix/signals.rs` | Signal handler function pointers |
| `__sig_initialized` | `AtomicI32` | `trona_posix/signals.rs` | One-shot signal subsystem init flag |
| `__sig_blocked_mask` | `u32` | `trona_posix/signals.rs` | Bitmask of blocked signals |
| `__sig_sa_mask` | `[u32; 32]` | `trona_posix/signals.rs` | Per-signal sa_mask values |
| `__sig_sa_flags` | `[i32; 32]` | `trona_posix/signals.rs` | Per-signal sa_flags (SA_RESETHAND, etc.) |
| `SLOT_ALLOC` | `SlotAllocState` | `trona_runtime/abi/` | Segment chain (up to 80 segments — initial layout + 64 expansion sub-CNodes), self-expand authority EP / owner_id / temp slot, and an optional carve-out handler. Self-expansion is driven by `trona_runtime` calling `RES_ALLOC_OBJECT(OBJ_CNODE)` against the runtime authority EP installed via `enable_self_expand`. The historical init-bound-notification protocol, the async untyped-grant slots (`UT_EXPAND_REQUESTED` / `EXTRA_UT_SLOTS` / `EXTRA_UT_COUNT` / `PENDING_FRAME_SLOT`), and the `__trona_cspace_ntfn` weak symbol were retired together with this redesign. |
| `DEVICE_REGIONS` | `[DeviceRegion; 4]` | `trona_posix/mm.rs` | Device-backed mmap tracking (framebuffer, etc.) |
| `NEXT_UT_HINT` | `Cap` | `trona_loader/` | Hint for untyped scanning during ELF load |

**Why this is safe:** SaltyOS userland processes are single-threaded.
Each process has its own address space with private copies of all
statics. There is no shared mutable state between processes. Signal
handlers run synchronously in the context of `posix_sigcheck()`, not
asynchronously, so there are no reentrancy concerns.

## 11. Build and Linking

### Meson Pipeline

Each crate is compiled with `rustc` in dependency order (uapi → kernel →
protocol/server → runtime → posix/loader), each emitting an `.o` and
`.rmeta`. The final link assembles them all into `libtrona.so`:

```
  kernite/include/uapi/*.h
      |
      v [bindgen]
  uapi.rs --> libuapi.o + libuapi.rmeta

  kernel/src/lib.rs --[rustc, --extern uapi]--> trona_kernel.o + .rmeta
  protocol/src/lib.rs -[rustc, --extern uapi,kernel]-> trona_protocol.o + .rmeta
  server/src/lib.rs  -[rustc, --extern uapi,kernel]-> trona_server.o + .rmeta
  runtime/src/lib.rs -[rustc, --extern uapi,kernel,protocol]-> trona_runtime.o + .rmeta
  posix/lib.rs       -[rustc, --extern all above]-> trona_posix.o + .rmeta
  loader/lib.rs      -[rustc, --extern all above]-> trona_loader.o + .rmeta

  posix/arch/<arch>/fork.S --[clang -c]--> fork.o

  clang -shared -nostdlib -fPIC -fuse-ld=lld
        -Wl,-soname,libtrona.so -Wl,--hash-style=gnu
        -T libtrona.ld
        libuapi.o trona_kernel.o trona_protocol.o trona_server.o
        trona_runtime.o trona_posix.o trona_loader.o
        fork.o core.o compiler_builtins.o
      |
      v
  libtrona.so (packed into initrd by mkcpio.py)
```

All six `.rmeta` files are also consumed by userland programs at compile
time for type information and inlineable wrappers.

### Linker Script

The `libtrona.ld` script creates a shared object with:

- Dynamic linking metadata at the start (`.gnu.hash`, `.dynsym`,
  `.dynstr`, `.rela.dyn`)
- Page-aligned `.text`, `.rodata`, `.data`, and `.bss` sections
- `.got` and `.got.plt` for position-independent addressing
- `.dynamic` section for runtime linker use
- All debug metadata (`.comment`, `.note.*`, `.eh_frame*`) discarded

### Static vs Dynamic Linking

- **Init:** Statically linked. The six crate `.o` files are linked
  directly into the init binary because init runs before the runtime
  linker is available.
- **All other programs:** Dynamically linked via `libtrona.so`. The
  six `.rmeta` files provide type information at compile time; the `.so`
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
- [POSIX Compatibility](posix.md) -- VFS and init protocol design,
  networking (netsrv/dnssrv)
- [basaltc Design](basaltc.md) -- C standard library built on trona
- [trona API Reference](../spec/trona-api.md) -- Complete function
  signatures and error codes

---

## Thread Infrastructure

### Architecture

`trona_runtime` owns all thread-local storage (TLS) and thread lifecycle
infrastructure. Personality layers (POSIX, Win32) extend threads via
personality-specific data and callbacks.

```
runtime/src/thread/tls.rs
  ThreadDesc pool, TLS init, TP management, thread_id, current_tls()
  post_fork_child(), personality callbacks
runtime/src/thread/worker.rs
  Worker pool: multi-threaded IPC services
         extends via personality_data + owner
           ┌──────┴──────┐
      posix/pthread.rs  win32/thread.rs
      PosixThreadExt    Win32ThreadExt
```

### ThreadDesc

`ThreadDesc` is a `trona_runtime`-internal Rust type (not C ABI) that
tracks per-thread capabilities, memory layout, identity, and personality
extension. It lives in a static pool of `MAX_THREADS` (64) slots. Each
thread's `ThreadLocalBlock.desc` (opaque `*mut u8`) points to its
`ThreadDesc`.

### ThreadOwner

Determines resource cleanup responsibility:
- **Main** — lives for process lifetime, never cleaned up
- **Worker** — `trona_runtime` handles resource cleanup (unmap, cap delete)
- **Personality** — personality handles cleanup (e.g., POSIX munmap + join)

### Worker Pool

`runtime/src/thread/worker.rs` provides `run_workers()` for
multi-threaded IPC services. N threads recv on the same endpoint; the
kernel dispatches messages to available workers (FIFO). Workers are
first-class threads with full TLS. See module docs for usage.

### Fork Child Reinit

`_trona_post_fork_child()` (called from `posix/arch/<arch>/fork.S` child
entry) reinits the runtime thread pool in the child process: updates main
thread caps, invalidates non-main slots (ABA generation bump), invokes
personality fork callback, resets thread ID counter. The child's SC cap
is discovered via `INIT_GET_THREAD_CAPS` IPC to init.

### INIT_GET_THREAD_CAPS Protocol

Init IPC label `INIT_GET_THREAD_CAPS` (36). Returns the caller's
scheduling context cap slot via `reply.regs[0]`. Used by fork children
to discover their SC cap (which differs from the parent's).

### Main-Thread SC Startup Field

The startup cap-table entry `ROLE_SC_CAP` passes the main thread's
SchedContext capability slot to the child process. It is parsed by ELF
rtld, PE rtld, and the static CRT, stored in the `trona_runtime` global
`__trona_sc_cap`, and read into `ThreadDesc.sc_cap` during
`init_main_thread_tls()`.
