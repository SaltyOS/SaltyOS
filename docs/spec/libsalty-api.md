# libbesalt API Reference

**Library:** `lib/besalt/lib/` (Rust, compiled to `libbesalt.so`)
**Edition:** Rust 2024
**ABI:** All public functions use `extern "C"` for FFI compatibility.

This document catalogs every public function, type, and constant exported by
libbesalt. Functions are available both as Rust module APIs (e.g.
`libbesalt::ipc::call_ctx`) and as C ABI symbols (e.g. `besalt_call`) resolved
by the runtime dynamic linker (`rtld`).

---

## 1. Conventions

### Naming

- **C ABI exports** use the `besalt_` prefix (e.g. `besalt_send`, `besalt_vspace_map`).
- **Rust module functions** use snake_case without prefix (e.g. `ipc::send_ctx`, `invoke::vspace_map`).
- **POSIX wrappers** in the `posix` module use the `posix_` prefix (e.g. `posix_open`, `posix_fork`).

### Return Types

| Type | Meaning |
|------|---------|
| `BesaltResult` | Raw syscall return: `error` (0=success) + `value` (payload) |
| `i32` return | 0 on success, -1 on error (POSIX convention) |
| `i64` return | Byte count on success, -1 on error (read/write) |
| `Cap` (`u64`) | Capability slot index in the thread's CNode |

### Error Codes

All error codes are defined in `consts.rs` and must match kernel `SyscallError` variants:

| Constant | Value | Meaning |
|----------|-------|---------|
| `BESALT_OK` | 0 | Success |
| `BESALT_INVALID_CAPABILITY` | 1 | Cap slot is empty or wrong type |
| `BESALT_INVALID_OPERATION` | 2 | Label not valid for this cap type |
| `BESALT_INSUFFICIENT_RIGHTS` | 3 | Cap lacks required rights |
| `BESALT_INVALID_ARGUMENT` | 4 | Bad argument value |
| `BESALT_OUT_OF_MEMORY` | 5 | Untyped exhausted or slab full |
| `BESALT_NOT_FOUND` | 6 | Object not found |
| `BESALT_BUSY` | 7 | Resource is busy |
| `BESALT_ALREADY_EXISTS` | 8 | Object already exists |
| `BESALT_WOULD_BLOCK` | 9 | Operation would block (non-blocking mode) |
| `BESALT_PENDING` | 0x80 | Async operation in progress |

---

## 2. Types

### Core Types (`types.rs`)

| Type | Repr | Description |
|------|------|-------------|
| `Cap` | `u64` | Capability slot index (type alias) |
| `BesaltResult` | `#[repr(C)]` | `{ error: u64, value: u64 }` -- raw syscall return |
| `BesaltMsg` | `#[repr(C)]` | `{ label: u64, length: u64, regs: [u64; 20] }` -- IPC message buffer |
| `IpcBuffer` | `#[repr(C)]` | 4096-byte kernel-shared page: msg[22], badge, caps[4], receive_cnode/index/depth, reserved[478] |
| `IpcContext` | `#[repr(C)]` | `{ ipc_buffer: *mut IpcBuffer, send_cap_count: i32 }` -- per-thread IPC state |

### POSIX Types

| Type | Repr | Description |
|------|------|-------------|
| `BesaltStat` | `#[repr(C)]` | File stat: st_ino, st_mode, st_nlink, st_size, st_uid, st_gid, st_mtime, st_type |
| `BesaltDirent` | `#[repr(C)]` | Directory entry: d_ino, d_type, d_namlen, d_name[62] |
| `PollFd` | `#[repr(C)]` | Poll descriptor: fd, events, revents |
| `EpollEvent` | `#[repr(C)]` | Epoll event: events (u32), data (u64) |
| `SockAddrUn` | `#[repr(C)]` | Unix socket address: sun_family (u16), sun_path[64] |
| `Timespec` | `#[repr(C)]` | Time: tv_sec (u64), tv_nsec (u64) |
| `Timeval` | `#[repr(C)]` | Time: tv_sec (u64), tv_usec (u64) |
| `Termios` | `#[repr(C)]` | Terminal attrs: c_iflag, c_oflag, c_cflag, c_lflag, c_line, c_cc[32], c_ispeed, c_ospeed |
| `SigHandlerT` | `Option<unsafe extern "C" fn(i32)>` | Signal handler function pointer |

### ELF Types

| Type | Repr | Description |
|------|------|-------------|
| `Elf64Ehdr` | `#[repr(C)]` | ELF64 file header (e_ident, e_type, e_entry, e_phoff, etc.) |
| `Elf64Phdr` | `#[repr(C)]` | Program header (p_type, p_flags, p_offset, p_vaddr, p_filesz, p_memsz, p_align) |
| `Elf64Dyn` | `#[repr(C)]` | Dynamic entry (d_tag, d_val) |
| `Elf64Rela` | `#[repr(C)]` | Relocation with addend (r_offset, r_info, r_addend) |
| `ElfLoadResult` | `#[repr(C)]` | Load result: entry, base, brk |
| `ElfPageEntry` | `#[repr(C)]` | Mapped page: vaddr, frame_cap, flags |
| `ElfLoaderCtx` | `#[repr(C)]` | Loader context: untyped, self/child vspace, scratch_vaddr, next_frame_slot, callbacks |

### CPIO Types

| Type | Repr | Description |
|------|------|-------------|
| `CpioEntry` | `#[repr(C)]` | Archive entry: name, name_len, data, data_len |
| `CpioEntryExt` | `#[repr(C)]` | Extended entry: + mode, nlink, mtime, ino |

---

## 3. Well-Known Capability Slots

Set by the kernel for `init`; inherited by child processes.

| Constant | Slot | Description |
|----------|------|-------------|
| `CAP_SELF_TCB` | 0 | Thread's own TCB |
| `CAP_SELF_VSPACE` | 1 | Thread's page table root |
| `CAP_SELF_CSPACE` | 2 | Thread's CNode root |
| `CAP_PROCMGR_EP` | 3 | Process manager endpoint |
| `CAP_VFS_EP` | 4 | VFS server endpoint |
| `CAP_NAMESERV_EP` | 5 | Name service endpoint |
| `CAP_SIGNAL_NTFN` | 6 | Signal delivery notification |
| `CAP_UNTYPED` | 7 | Dedicated untyped memory |
| `CAP_COM1_IOPORT` | 8 | Serial port I/O port cap |
| `CAP_EXPAND_EP` / `CAP_COM1_IRQ` | 9 | Expand EP or COM1 IRQ handler |
| `CAP_COM1_NTFN` | 10 | COM1 IRQ notification |
| `CAP_CONSOLE_EP` | 11 | Console server endpoint |
| `CAP_INITRD_UNTYPED` | 12 | Initrd memory region |
| `CAP_FB_UNTYPED` | 13 | Framebuffer memory region |
| `CAP_READINESS_NTFN` | 14 | Service readiness notification |
| `CAP_DISPLAY_EP` | 15 | Display server endpoint |
| `CAP_UNTYPED_START` | 16 | First general-purpose untyped |

---

## 4. Syscall Wrappers (`syscall.rs`)

### `syscall`

```rust
pub fn syscall(num: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> BesaltResult
```

Issue a raw syscall. `num` is the syscall number (`SYS_SEND`, `SYS_RECV`, etc.).
Arguments map to registers: a0=RDI, a1=RSI, a2=RDX, a3=R10, a4=R8, a5=R9.
Returns `BesaltResult { error, value }`.

**Syscall numbers:**

| Constant | Value | Description |
|----------|-------|-------------|
| `SYS_SEND` | 0 | Blocking send |
| `SYS_RECV` | 1 | Blocking receive |
| `SYS_CALL` | 2 | Send + receive (client RPC) |
| `SYS_REPLY_RECV` | 3 | Reply + wait (server loop) |
| `SYS_NBSEND` | 4 | Non-blocking send |
| `SYS_SIGNAL` | 5 | Signal notification |
| `SYS_WAIT` | 6 | Wait on notification |
| `SYS_POLL` | 7 | Non-blocking poll notification |
| `SYS_YIELD` | 8 | Yield CPU |
| `SYS_INVOKE` | 9 | Capability invocation |
| `SYS_DEBUG_PUTCHAR` | 10 | Write char to serial |
| `SYS_DEBUG_DUMP_STATE` | 11 | Dump CPU state |
| `SYS_CLOCK_GETTIME` | 12 | Read monotonic clock |
| `SYS_NANOSLEEP` | 13 | Sleep for duration |
| `SYS_DEBUG_PUTSTR` | 14 | Write string to serial |
| `SYS_DEBUG_PUTBUF` | 15 | Write buffer to serial (atomic) |
| `SYS_DEBUG_CONSOLE_CONTROL` | 16 | Console control |

---

## 5. IPC Operations (`ipc.rs`)

### Message Info Encoding

```rust
pub fn msginfo(label: u64, length: u64, caps: u64) -> u64
pub fn msginfo_label(info: u64) -> u64
pub fn msginfo_length(info: u64) -> u64
pub fn msginfo_extracaps(info: u64) -> u64
```

Encode/decode a 64-bit message info word: bits 6:0 = length, bits 11:7 = extra_caps, bits 51:12 = label.

### Context Management

```rust
pub unsafe fn ipc_context_init(ctx: *mut IpcContext, ipc_buffer_vaddr: *mut IpcBuffer)
pub unsafe fn clear_send_caps_ctx(ctx: *mut IpcContext)
pub unsafe fn set_send_cap_ctx(ctx: *mut IpcContext, slot_index: i32, cap_slot: u64)
pub unsafe fn set_receive_slot_ctx(ctx: *mut IpcContext, cnode: Cap, index: u64, depth: u64)
```

| Function | C ABI | Description |
|----------|-------|-------------|
| `ipc_context_init` | -- | Initialize IPC context with buffer page address |
| `clear_send_caps_ctx` | -- | Clear all staged send caps, reset count to 0 |
| `set_send_cap_ctx` | -- | Stage cap `cap_slot` at `slot_index` (0-3) for next send |
| `set_receive_slot_ctx` | -- | Configure receive slot: incoming caps go to `cnode[index]` at `depth` |

### IPC Operations

| Rust Function | C ABI Name | Signature |
|---------------|------------|-----------|
| `send_ctx` | `besalt_send` | `(ep: Cap, msg: *const BesaltMsg) -> i32` |
| `recv_ctx` | `besalt_recv` | `(ep: Cap, msg: *mut BesaltMsg, badge: *mut u64) -> i32` |
| `call_ctx` | `besalt_call` | `(ep: Cap, msg: *const BesaltMsg, reply: *mut BesaltMsg) -> i32` |
| `reply_recv_ctx` | `besalt_reply_recv` | `(ep: Cap, reply: *const BesaltMsg, out_msg: *mut BesaltMsg, badge: *mut u64) -> i32` |
| `nbsend_ctx` | `besalt_nbsend` | `(ep: Cap, msg: *const BesaltMsg) -> i32` |

All return 0 on success. The `_ctx` suffix indicates these take an explicit `IpcContext` pointer;
the C ABI wrappers use the global `__besalt_ipc_ctx`.

**`send_ctx`** -- Blocking send on endpoint `ep`. Transfers `msg` and any staged capabilities. Blocks until a receiver is ready.

**`recv_ctx`** -- Blocking receive on endpoint `ep`. Copies received message to `*msg`, writes sender badge to `*badge`.

**`call_ctx`** -- Blocking call (send + receive). Sends `msg` on `ep`, blocks for reply. Reply written to `*reply`. Standard client RPC pattern.

**`reply_recv_ctx`** -- Atomically reply to current caller and wait for next request. Server loop pattern. Sends `reply`, then blocks on `ep` for next message.

**`nbsend_ctx`** -- Non-blocking send. Delivers `msg` if a receiver is waiting, otherwise returns immediately with error.

### Notification Operations (C ABI only, in `lib.rs`)

| C ABI Name | Signature | Description |
|------------|-----------|-------------|
| `besalt_signal` | `(ntfn: Cap, bits: u64) -> i32` | Signal notification (OR bits into word) |
| `besalt_wait` | `(ntfn: Cap) -> u64` | Wait on notification, returns signaled bits |
| `besalt_poll` | `(ntfn: Cap, bits: *mut u64) -> i32` | Non-blocking poll notification |

---

## 6. Capability Invocations (`invoke.rs`)

### Raw Invoke

```rust
pub fn invoke(cap: Cap, label: u64, arg0: u64, arg1: u64, arg2: u64, arg3: u64) -> BesaltResult
```

**C ABI:** `besalt_invoke(cap, label, arg0, arg1, arg2, arg3) -> BesaltResult`

Generic capability invocation. Dispatches to kernel handler based on cap type and label.

### CNode Operations

| Rust Function | C ABI Name | Parameters | Returns |
|---------------|------------|------------|---------|
| `cnode_copy` | `besalt_cnode_copy` | `src_cnode, src_slot, dest_cnode, dest_slot, rights` | `i32` |
| `cnode_mint` | `besalt_cnode_mint` | `src_cnode, src_slot, dest_cnode, dest_slot, badge` | `i32` |
| `cnode_move` | `besalt_cnode_move` | `dest_cnode, dest_slot, src_cnode, src_slot` | `i32` |
| `cnode_mutate` | `besalt_cnode_mutate` | `dest_cnode, dest_slot, src_cnode, src_slot, badge` | `i32` |
| `cnode_save_caller` | `besalt_cnode_save_caller` | `cnode, slot` | `i32` |
| `cnode_delete` | `besalt_cnode_delete` | `cnode, slot` | `i32` |
| `cnode_revoke` | `besalt_cnode_revoke` | `cnode, slot` | `i32` |
| `cnode_set_guard` | -- | `cnode, guard, guard_bits` | `i32` |
| `cnode_get_info` | -- | `cnode` | `BesaltResult` |

**Depth-aware variants** (for expanded CSpace hierarchy):

| Rust Function | Parameters | Description |
|---------------|------------|-------------|
| `cnode_copy_depth` | `+ src_depth, dest_depth` | Copy with explicit CNode depths |
| `cnode_delete_depth` | `+ depth` | Delete with depth |
| `cnode_revoke_depth` | `+ depth` | Revoke with depth |

Invoke labels: `CNODE_COPY` (0x10), `CNODE_MINT` (0x11), `CNODE_MOVE` (0x12), `CNODE_MUTATE` (0x13), `CNODE_DELETE` (0x14), `CNODE_REVOKE` (0x15), `CNODE_SAVE_CALLER` (0x16), `CNODE_SET_GUARD` (0x17), `CNODE_GET_INFO` (0x18).

### Untyped Operations

| Rust Function | C ABI Name | Parameters | Returns |
|---------------|------------|------------|---------|
| `untyped_retype` | `besalt_untyped_retype` | `untyped, new_type, size_bits, dest_slot` | `i32` |
| `untyped_retype_depth` | -- | `+ dest_depth` | `i32` |

Invoke label: `UNTYPED_RETYPE` (0x20).

Object types: `OBJ_UNTYPED` (1), `OBJ_ENDPOINT` (2), `OBJ_NOTIFICATION` (3), `OBJ_TCB` (4), `OBJ_CNODE` (5), `OBJ_VSPACE` (6), `OBJ_FRAME` (7), `OBJ_IRQ_HANDLER` (8), `OBJ_IO_PORT` (9), `OBJ_SCHED_CONTEXT` (10).

### TCB Operations

| Rust Function | C ABI Name | Parameters | Returns |
|---------------|------------|------------|---------|
| `tcb_configure` | `besalt_tcb_configure` | `tcb, rip, rsp, ipc_buf` | `i32` |
| `tcb_resume` | `besalt_tcb_resume` | `tcb` | `i32` |
| `tcb_suspend` | `besalt_tcb_suspend` | `tcb` | `i32` |
| `tcb_set_space` | `besalt_tcb_set_space` | `tcb, cspace, vspace` | `i32` |
| `tcb_set_space_with_depth` | -- | `tcb, cspace, vspace, depth` | `i32` |
| `tcb_set_fault_handler` | `besalt_tcb_set_fault_handler` | `tcb, fault_ep` | `i32` |
| `tcb_set_ipc_buffer` | `besalt_tcb_set_ipc_buffer` | `tcb, addr` | `i32` |
| `tcb_write_registers` | `besalt_tcb_write_registers` | `tcb, flags, rip, rsp` | `i32` |
| `tcb_bind_notification` | -- | `tcb, ntfn` | `i32` |

Invoke labels: `TCB_CONFIGURE` (0x40), `TCB_RESUME` (0x41), `TCB_SUSPEND` (0x42), `TCB_SET_SPACE` (0x43), `TCB_WRITE_REGISTERS` (0x46), `TCB_SET_IPC_BUFFER` (0x48), `TCB_BIND_NOTIFICATION` (0x49), `TCB_SET_FAULT_HANDLER` (0x4B).

### SchedContext Operations

| Rust Function | C ABI Name | Parameters | Returns |
|---------------|------------|------------|---------|
| `sc_configure` | `besalt_sc_configure` | `sc, budget_us, period_us` | `i32` |
| `sc_bind` | `besalt_sc_bind` | `sc, tcb` | `i32` |

Invoke labels: `SC_CONFIGURE` (0x30), `SC_BIND` (0x31).

### VSpace Operations

| Rust Function | C ABI Name | Parameters | Returns |
|---------------|------------|------------|---------|
| `vspace_map` | `besalt_vspace_map` | `vspace, frame, vaddr, flags` | `i32` |
| `vspace_unmap` | `besalt_vspace_unmap` | `vspace, vaddr` | `i32` |
| `vspace_map_pt` | `besalt_vspace_map_pt` | `vspace, frame, vaddr, level` | `i32` |
| `vspace_walk` | `besalt_vspace_walk` | `vspace, start_vaddr, max_entries` | `i32` |
| `vspace_copy_page` | `besalt_vspace_copy_page` | `src_vspace, src_vaddr, dst_frame` | `i32` |
| `vspace_map_device` | -- | `vspace, device_untyped, page_offset, vaddr, flags` | `i32` |
| `vspace_map_device_range` | -- | `vspace, device_untyped, offset_start, vaddr_start, num_pages, flags` | `(i32, u64)` |
| `vspace_clone_cow_page` | `besalt_vspace_clone_cow_page` | `src_vspace, src_vaddr, dst_vspace, dst_vaddr` | `i32` |

Invoke labels: `VSPACE_MAP` (0x50), `VSPACE_UNMAP` (0x51), `VSPACE_MAP_PT` (0x52), `VSPACE_WALK` (0x53), `VSPACE_COPY_PAGE` (0x54), `VSPACE_MAP_DEVICE` (0x55), `VSPACE_CLONE_COW_PAGE` (0x56), `VSPACE_MAP_DEVICE_RANGE` (0x57).

VSpace flags: `VSPACE_FLAG_WRITABLE` (1), `VSPACE_FLAG_USER` (2), `VSPACE_FLAG_EXECUTABLE` (4), `VSPACE_FLAG_CACHE_DISABLE` (8), `VSPACE_FLAG_WRITE_THROUGH` (16), `VSPACE_FLAG_COW` (32).

### IRQ Operations

| Rust Function | C ABI Name | Parameters | Returns |
|---------------|------------|------------|---------|
| `irq_handler_ack` | `besalt_irq_handler_ack` | `irq_handler` | `i32` |
| `irq_handler_set_notification` | `besalt_irq_handler_set_notification` | `irq_handler, ntfn` | `i32` |

Invoke labels: `IRQ_HANDLER_ACK` (0x61), `IRQ_HANDLER_SET_NOTIFICATION` (0x62).

### I/O Port Operations

| Rust Function | C ABI Name | Parameters | Returns |
|---------------|------------|------------|---------|
| `ioport_in8` | -- | `ioport, offset` | `u8` |
| `ioport_out8` | -- | `ioport, offset, value` | `()` |
| `ioport_in16` | -- | `ioport, offset` | `u16` |
| `ioport_out16` | -- | `ioport, offset, value` | `()` |

Invoke labels: `IOPORT_IN8` (0x70), `IOPORT_OUT8` (0x71), `IOPORT_IN16` (0x72), `IOPORT_OUT16` (0x73).

---

## 7. POSIX File I/O (`posix.rs`)

All file I/O operations send IPC messages to the VFS server (`CAP_VFS_EP`).

| Rust Function | C ABI Name | Signature | Returns |
|---------------|------------|-----------|---------|
| `posix_open` | -- | `(path: *const u8, flags: i32) -> i32` | fd or -1 |
| `posix_read` | -- | `(fd: i32, buf: *mut u8, count: u64) -> i64` | bytes read or -1 |
| `posix_write` | -- | `(fd: i32, buf: *const u8, count: u64) -> i64` | bytes written or -1 |
| `posix_close` | -- | `(fd: i32) -> i32` | 0 or -1 |
| `posix_lseek` | -- | `(fd: i32, offset: i64, whence: i32) -> i64` | new offset or -1 |
| `posix_stat` | -- | `(path: *const u8, st: *mut BesaltStat) -> i32` | 0 or -1 |
| `posix_lstat` | -- | `(path: *const u8, st: *mut BesaltStat) -> i32` | 0 or -1 |
| `posix_fstat` | -- | `(fd: i32, st: *mut BesaltStat) -> i32` | 0 or -1 |
| `posix_access` | -- | `(path: *const u8, mode: i32) -> i32` | 0 or -1 |
| `posix_unlink` | -- | `(path: *const u8) -> i32` | 0 or -1 |
| `posix_rename` | -- | `(old_path: *const u8, new_path: *const u8) -> i32` | 0 or -1 |
| `posix_ftruncate` | `besalt_ftruncate` | `(fd: i32, length: u64) -> i32` | 0 or -1 |

**Data transfer chunking:** `posix_read` transfers up to 152 bytes per IPC round-trip; `posix_write` transfers up to 144 bytes. Both loop until the full count is transferred or EOF/error.

**Path encoding:** Paths are packed via `pack_path()` into message registers: `regs[offset]` = path length (max 64), followed by path bytes in subsequent u64 registers.

Open flags: `O_RDONLY` (0), `O_WRONLY` (1), `O_RDWR` (2), `O_CREAT` (0x40), `O_EXCL` (0x80), `O_TRUNC` (0x200), `O_APPEND` (0x400), `O_NONBLOCK` (0x800), `O_CLOEXEC` (0x80000).

Seek constants: `SEEK_SET` (0), `SEEK_CUR` (1), `SEEK_END` (2).

---

## 8. POSIX Directory Operations (`posix.rs`)

| Rust Function | Signature | Returns |
|---------------|-----------|---------|
| `posix_mkdir` | `(path: *const u8, mode: i32) -> i32` | 0 or -1 |
| `posix_rmdir` | `(path: *const u8) -> i32` | 0 or -1 |
| `posix_opendir` | `(path: *const u8) -> i32` | directory fd or -1 |
| `posix_readdir` | `(dir_fd: i32, entry: *mut BesaltDirent) -> i32` | 1 if entry read, 0 at end |
| `posix_closedir` | `(dir_fd: i32) -> i32` | 0 or -1 (delegates to `posix_close`) |

---

## 9. POSIX Process Management (`posix.rs`)

All process operations send IPC messages to the process manager (`CAP_PROCMGR_EP`).

| Rust Function | C ABI Name | Signature | Returns |
|---------------|------------|-----------|---------|
| `posix_exit` | -- | `(status: i32) -> !` | Never returns |
| `posix_getpid` | -- | `() -> i32` | PID or -1 |
| `posix_getppid` | -- | `() -> i32` | Parent PID or -1 |
| `posix_waitpid` | -- | `(pid: i32, status: *mut i32) -> i32` | Child PID or -1 |
| `posix_waitpid3` | -- | `(pid: i32, status: *mut i32, options: i32) -> i32` | Child PID or -1 |
| `posix_fork` | -- | `() -> i32` | Child PID in parent, 0 in child, -1 on error |
| `posix_execve` | -- | `(path: *const u8, argv: *const *const u8, envp: *const *const u8) -> i32` | 0 or -1 |
| `posix_kill` | -- | `(pid: i32, sig: i32) -> i32` | 0 or -1 |

**Wait status macros** (in `types.rs`):

| Function | Signature | Description |
|----------|-----------|-------------|
| `wifexited` | `(s: i32) -> bool` | True if child exited normally |
| `wexitstatus` | `(s: i32) -> i32` | Exit code (bits 15:8) |
| `wifsignaled` | `(s: i32) -> bool` | True if terminated by signal |
| `wtermsig` | `(s: i32) -> i32` | Termination signal number |
| `wifstopped` | `(s: i32) -> bool` | True if child is stopped |
| `wstopsig` | `(s: i32) -> i32` | Stop signal number |

### Process Groups and Session Management

| Rust Function | C ABI Name | Signature | Returns |
|---------------|------------|-----------|---------|
| `posix_setpgid` | `besalt_setpgid` | `(pid: i32, pgid: i32) -> i32` | 0 or -1 |
| `posix_getpgid` | `besalt_getpgid` | `(pid: i32) -> i32` | pgid or -1 |
| `posix_setsid` | `besalt_setsid` | `() -> i32` | session ID or -1 |

### User/Group ID

| Rust Function | C ABI Name | Signature | Returns |
|---------------|------------|-----------|---------|
| `posix_getuid` | `besalt_getuid` | `() -> i32` | UID |
| `posix_geteuid` | `besalt_geteuid` | `() -> i32` | effective UID |
| `posix_getgid` | `besalt_getgid` | `() -> i32` | GID |
| `posix_getegid` | `besalt_getegid` | `() -> i32` | effective GID |
| `posix_getgroups` | `besalt_getgroups` | `(size: i32, list: *mut i32) -> i32` | count or -1 |

### Fork Implementation Detail

`posix_fork()` is defined in `fork.S` (assembly trampoline). It saves callee-saved registers, calls `_posix_fork_impl` (in `lib.rs`) which packs them into a `PM_FORK` IPC message to procmgr. The child resumes at `child_entry` with registers restored by procmgr.

---

## 10. POSIX Sockets (`posix.rs`)

All socket operations are dispatched to the VFS server via IPC.

| Rust Function | C ABI Name | Signature | Returns |
|---------------|------------|-----------|---------|
| `posix_socket` | `besalt_socket` | `(domain: i32, sock_type: i32) -> i32` | fd or -1 |
| `posix_bind` | `besalt_bind` | `(fd: i32, path: *const u8) -> i32` | 0 or -1 |
| `posix_listen` | `besalt_listen` | `(fd: i32, backlog: i32) -> i32` | 0 or -1 |
| `posix_accept` | `besalt_accept` | `(fd: i32) -> i32` | connected fd or -1 |
| `posix_connect` | `besalt_connect` | `(fd: i32, path: *const u8) -> i32` | 0 or -1 |
| `posix_shutdown` | `besalt_shutdown` | `(fd: i32, how: i32) -> i32` | 0 or -1 |
| `posix_socketpair` | `besalt_socketpair` | `(fds: *mut i32) -> i32` | 0 or -1 |
| `posix_sendmsg` | -- | `(fd: i32, data: *const u8, data_len: u64, fds_to_send: *const i32, fd_count: u32) -> i64` | bytes sent or -1 |
| `posix_recvmsg` | -- | `(fd: i32, data: *mut u8, data_len: u64, fds_out: *mut i32, fd_count: *mut u32) -> i64` | bytes received or -1 |

Socket constants: `AF_UNIX` (1), `SOCK_STREAM` (1), `SCM_RIGHTS` (1), `SHUT_RD` (0), `SHUT_WR` (1), `SHUT_RDWR` (2).

---

## 11. POSIX I/O Multiplexing (`posix.rs`)

### poll

```rust
pub unsafe fn posix_poll(fds: *mut PollFd, nfds: u32, timeout: i32) -> i32
```
**C ABI:** `besalt_posix_poll`

Wait for events on up to 8 file descriptors. `timeout` in milliseconds (-1 = block). Returns count of ready fds or -1.

Poll flags: `POLLIN` (0x001), `POLLOUT` (0x004), `POLLERR` (0x008), `POLLHUP` (0x010), `POLLNVAL` (0x020).

### select

```rust
pub unsafe fn posix_select(nfds: i32, readfds: *mut u64, writefds: *mut u64, timeout: i32) -> i32
```

Converts fd_set bitmasks (single u64, max 64 fds) to poll array, calls `posix_poll`, rebuilds bitmasks. Returns count of ready fds or -1.

### epoll

| Rust Function | C ABI Name | Signature | Returns |
|---------------|------------|-----------|---------|
| `posix_epoll_create` | `besalt_epoll_create1` | `() -> i32` | epoll fd or -1 |
| `posix_epoll_ctl` | `besalt_epoll_ctl` | `(epfd: i32, op: i32, fd: i32, events: u32, data: u64) -> i32` | 0 or -1 |
| `posix_epoll_wait` | `besalt_epoll_wait` | `(epfd: i32, events: *mut EpollEvent, maxevents: i32, timeout: i32) -> i32` | count or -1 |

Epoll constants: `EPOLL_CTL_ADD` (1), `EPOLL_CTL_DEL` (2), `EPOLL_CTL_MOD` (3), `EPOLLIN` (0x001), `EPOLLOUT` (0x004), `EPOLLERR` (0x008), `EPOLLHUP` (0x010).

---

## 12. POSIX Pipes and Duplication (`posix.rs`)

| Rust Function | C ABI Name | Signature | Returns |
|---------------|------------|-----------|---------|
| `posix_pipe` | `besalt_pipe` | `(fds: *mut i32) -> i32` | 0 or -1 |
| `posix_pipe2` | `besalt_pipe2` | `(fds: *mut i32, flags: i32) -> i32` | 0 or -1 |
| `posix_dup` | `besalt_dup` | `(oldfd: i32) -> i32` | new fd or -1 |
| `posix_dup2` | `besalt_dup2` | `(oldfd: i32, newfd: i32) -> i32` | newfd or -1 |
| `posix_dup3` | `besalt_dup3` | `(oldfd: i32, newfd: i32, flags: i32) -> i32` | newfd or -1 |
| `posix_mkfifo` | `besalt_mkfifo` | `(path: *const u8, mode: u32) -> i32` | 0 or -1 |

---

## 13. POSIX Shared Memory, Terminal, and Time (`posix.rs`)

### Shared Memory

| Rust Function | C ABI Name | Signature | Returns |
|---------------|------------|-----------|---------|
| `posix_shm_open` | `besalt_shm_open` | `(name: *const u8, flags: i32) -> i32` | shm fd or -1 |
| `posix_shm_unlink` | `besalt_shm_unlink` | `(name: *const u8) -> i32` | 0 or -1 |

Names follow POSIX convention: leading `/` is stripped before sending to VFS.

### Terminal I/O

| Rust Function | C ABI Name | Signature | Returns |
|---------------|------------|-----------|---------|
| `posix_tcgetattr` | `besalt_tcgetattr` | `(fd: i32, termios_p: *mut Termios) -> i32` | 0 or -1 |
| `posix_tcsetattr` | `besalt_tcsetattr` | `(fd: i32, action: i32, termios_p: *const Termios) -> i32` | 0 or -1 |
| `posix_isatty` | `besalt_isatty` | `(fd: i32) -> i32` | 1 if tty, 0 if not |
| `posix_ioctl` | `besalt_ioctl` | `(fd: i32, request: u64, arg: u64) -> i32` | result or -1 |

### File Control

| Rust Function | C ABI Name | Signature | Returns |
|---------------|------------|-----------|---------|
| `posix_fcntl` | `besalt_fcntl` | `(fd: i32, cmd: i32, arg: i64) -> i32` | result or -1 |
| `posix_chdir` | `besalt_chdir` | `(path: *const u8) -> i32` | 0 or -1 |
| `posix_getcwd` | `besalt_getcwd` | `(buf: *mut u8, size: u64) -> i32` | 0 or -1 |

fcntl commands: `F_DUPFD` (0), `F_GETFD` (1), `F_SETFD` (2), `F_GETFL` (3), `F_SETFL` (4), `F_DUPFD_CLOEXEC` (1030).

### Time

| Rust Function | C ABI Name | Signature | Returns |
|---------------|------------|-----------|---------|
| `posix_clock_gettime` | `besalt_clock_gettime` | `(clock_id: i32, ts: *mut Timespec) -> i32` | 0 or -1 |
| `posix_gettimeofday` | `besalt_gettimeofday` | `(tv: *mut Timeval) -> i32` | 0 or -1 |
| `posix_nanosleep` | `besalt_nanosleep` | `(req: *const Timespec, rem: *mut Timespec) -> i32` | 0 or -1 |
| `posix_usleep` | `besalt_usleep` | `(usec: u64) -> i32` | 0 or -1 |
| `posix_sleep` | `besalt_sleep` | `(seconds: u64) -> u64` | 0 or remaining seconds |

Clock IDs: `CLOCK_MONOTONIC` (0), `CLOCK_REALTIME` (1).

`posix_clock_gettime` and `posix_gettimeofday` use `SYS_CLOCK_GETTIME` directly (no IPC to VFS). `posix_nanosleep`/`posix_usleep`/`posix_sleep` use `SYS_NANOSLEEP`.

---

## 14. Memory Management (`posix_mm.rs`)

### Initialization

```rust
pub unsafe fn posix_mm_init(mmsrv_ep: Cap)
```

Initialize the per-process memory client. Must be called once during startup. Stores the process-local mmsrv endpoint used by `brk`/`sbrk`/anonymous `mmap` IPC.

### Heap Management

| Function | Signature | Returns | Description |
|----------|-----------|---------|-------------|
| `posix_brk` | `(addr: u64) -> i32` | 0 or -1 | Set program break. Allocates/frees pages as needed. New pages are zeroed. |
| `posix_sbrk` | `(increment: i64) -> u64` | Previous break or `u64::MAX` | Increment program break. `increment == 0` returns current break. |

### Memory Mapping

| Function | Signature | Returns | Description |
|----------|-----------|---------|-------------|
| `posix_mmap` | `(addr: *mut u8, length: u64, prot: i32, flags: i32, fd: i32, offset: i64) -> *mut u8` | Base address or `MAP_FAILED` | Map pages into address space |
| `posix_munmap` | `(addr: *mut u8, length: u64) -> i32` | 0 or -1 | Unmap a previously mmap'd region |
| `posix_mprotect` | `(addr: *mut u8, length: u64, prot: i32) -> i32` | 0 or -1 | Change protection flags on mmap'd region |

**mmap modes:**
- **Anonymous** (`MAP_ANONYMOUS`): allocates fresh frames, zeroes them, maps at next available address (or at `addr` with `MAP_FIXED`).
- **fd-backed** (`fd >= 0`): sends `POSIX_VFS_MMAP` to VFS, receives device untyped cap, maps with write-combining flags (used for framebuffer).

Protection flags: `PROT_NONE` (0), `PROT_READ` (1), `PROT_WRITE` (2), `PROT_EXEC` (4).
Map flags: `MAP_SHARED` (0x01), `MAP_PRIVATE` (0x02), `MAP_FIXED` (0x10), `MAP_ANONYMOUS` (0x20).

**Memory management is delegated to mmsrv** (centralized pager). Anonymous `mmap()`, `brk()`, `sbrk()` send IPC to mmsrv (slot 7: `CAP_MMSRV_EP`). Device-backed mmaps go through VFS. No hardcoded limits — all regions and frame tracking are growable.

---

## 15. Signals (`signals.rs`)

Signal delivery uses a kernel notification object (`CAP_SIGNAL_NTFN`). The process manager sets bits via `SYS_SIGNAL` when `kill()` is called. Signal disposition is tracked both locally and in procmgr.

### Signal Installation

```rust
pub unsafe fn posix_signal(sig: i32, handler: usize) -> usize
```

Install a signal handler for signal `sig`. `handler` is `SIG_DFL` (0), `SIG_IGN` (1), or a function pointer cast to `usize`. Returns previous handler, or `usize::MAX` (SIG_ERR) on error. Cannot set handlers for `SIGKILL` or `SIGSTOP`.

Notifies procmgr of the new disposition category via `PM_SIGACTION` IPC.

### Signal Checking

```rust
pub unsafe fn posix_sigcheck() -> i32
```

Poll `CAP_SIGNAL_NTFN` for pending signals and dispatch handlers. For each pending signal:
- **Blocked:** re-raised via `SYS_SIGNAL` so it remains pending.
- **SIG_IGN:** silently consumed.
- **SIG_DFL with terminate action:** calls `posix_exit(128 + sig)`.
- **User handler:** saves/restores blocked mask, handles `SA_RESETHAND`, calls handler.

Returns the number of signals dispatched.

### Signal Constants

| Constant | Value | Constant | Value |
|----------|-------|----------|-------|
| `SIGHUP` | 1 | `SIGCHLD` | 17 |
| `SIGINT` | 2 | `SIGCONT` | 18 |
| `SIGQUIT` | 3 | `SIGSTOP` | 19 |
| `SIGABRT` | 6 | `SIGTSTP` | 20 |
| `SIGKILL` | 9 | `SIGTTIN` | 21 |
| `SIGUSR1` | 10 | `SIGTTOU` | 22 |
| `SIGUSR2` | 12 | `NSIG` | 32 |
| `SIGPIPE` | 13 | `SA_RESETHAND` | 0x80000000 |
| `SIGALRM` | 14 | `SIG_DFL` | 0 |
| `SIGTERM` | 15 | `SIG_IGN` | 1 |

### Global Signal State

| Symbol | Type | Description |
|--------|------|-------------|
| `__sig_handlers` | `[AtomicUsize; 32]` | Per-signal handler function pointers |
| `__sig_initialized` | `AtomicI32` | 1 once signal infra is initialized |
| `__sig_blocked_mask` | `u32` | Bitmask of blocked signals |
| `__sig_sa_mask` | `[u32; 32]` | Per-signal additional block mask during handler |
| `__sig_sa_flags` | `[i32; 32]` | Per-signal flags (e.g. SA_RESETHAND) |

---

## 16. Slot Allocator (`slot_alloc.rs`)

Per-process dynamic CNode slot allocator with chained segments and CSpace expansion protocol.

### Types

```rust
pub enum SlotResult {
    Ok(Cap),      // Successfully allocated
    WouldBlock,   // Expansion in progress; yield and retry
    Exhausted,    // Permanently failed
}
```

### Functions

| Function | Signature | Description |
|----------|-----------|-------------|
| `slot_alloc_init` | `(base: Cap, count: u64, expand_ep: u64)` | Initialize allocator with pool from auxv. Called once at startup. |
| `slot_alloc_is_initialized` | `() -> bool` | Check if allocator has been initialized |
| `slot_alloc_base` | `() -> Cap` | Return the first segment's base slot |
| `slot_alloc_count` | `() -> u64` | Total pool size across all segments |
| `slot_alloc_remaining` | `() -> u64` | Slots remaining across all segments |
| `slot_alloc_set_procmgr_ep` | `(ep: Cap)` | Override procmgr EP for expansion |
| `slot_alloc` | `() -> Option<Cap>` | Allocate one CNode slot (sync) |
| `slot_alloc_async` | `() -> SlotResult` | Allocate with async expansion protocol |

**Frame allocation:** Delegated to mmsrv. Use `posix_mmap()` for anonymous memory (IPC to `CAP_MMSRV_EP` slot 7).

### CSpace Expansion Protocol

When all CSpace segments are exhausted:
1. NBSend `PM_EXPAND_CSPACE_ASYNC` to procmgr
2. Call `PM_EXPAND_COLLECT` to get new segment base/count

Auxv types: `AT_BESALT_SLOT_BASE` (0x1007), `AT_BESALT_SLOT_COUNT` (0x1008), `AT_BESALT_EXPAND_EP` (0x1009).

---

## 17. VM Layout (`layout.rs`)

Computes virtual address layouts for child processes.

### Types

```rust
pub struct VmRegion { pub base: u64, pub size: u64 }
pub struct VmLayoutPlan {
    pub ipc_buf: VmRegion,
    pub elf_code: VmRegion,
    pub rtld: VmRegion,
    pub shared_libs: VmRegion,
    pub stack: VmRegion,
    pub scratch: VmRegion,
    pub initrd: VmRegion,
    pub stack_top: u64,
}
```

### Functions

```rust
pub fn compute_vm_layout(
    elf_span: u64,
    rtld_span: u64,
    shared_lib_cache_pages: usize,
    map_initrd: bool,
    initrd_window_size: usize,
) -> VmLayoutPlan
```

Compute a dynamic VA layout given actual ELF/RTLD sizes. Returns a plan with `stack_top == 0` on overflow failure.

### Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `CHILD_STACK_PAGES` | 4 | Stack pages per child (16K) |

Default VA regions: IPC buffer at 0x200000, ELF code at 0x210000, stack at 0x3F8000 (or 0x7F8000 in window 2), initrd at 0x1000000.

---

## 18. ELF Loader and Dynamic Linking

### ELF Loader (`elf_loader.rs`)

| Function | Signature | Returns | Description |
|----------|-----------|---------|-------------|
| `elf_count_load_pages` | `(data: *const u8, data_len: usize) -> usize` | Page count | Count pages needed for all PT_LOAD segments |
| `elf_compute_load_span` | `(data: *const u8, data_len: usize) -> u64` | VA span | Total VA span of all PT_LOAD segments |
| `elf_load` | `(data: *const u8, data_len: usize, load_base: u64, ctx: &mut ElfLoaderCtx, result: *mut ElfLoadResult) -> i32` | `ELF_OK` (0) or error | Load ELF into child VSpace using scratch-map strategy |

**ElfLoaderCtx fields:**
- `untyped`: frame allocation source (0 = skip internal retype)
- `self_vspace` / `child_vspace`: loader's and target's VSpace caps
- `scratch_vaddr`: VA in loader's space for temporary page mapping
- `next_frame_slot`: bump allocator for frame slots
- `alloc_frame_slot`: optional callback override
- `record_page`: optional callback to record each mapping

**Error codes:** `ELF_OK` (0), `ELF_NOT_ELF` (1), `ELF_NOT_64BIT` (2), `ELF_NOT_LE` (3), `ELF_BAD_TYPE` (4), `ELF_BAD_ARCH` (5), `ELF_NO_LOAD` (6), `ELF_RELOC_FAILED` (7), `ELF_OUT_OF_MEMORY` (8), `ELF_TOO_SMALL` (9), `ELF_MAP_FAILED` (11).

The loader supports PIE (ET_DYN) with R_X86_64_RELATIVE relocations, loading at an arbitrary `load_base`. Max 256 pages per binary.

### ELF Dynamic Linking (`elf_dynamic.rs`)

| Function | Signature | Returns | Description |
|----------|-----------|---------|-------------|
| `elf_has_interp` | `(elf_data: *const u8, elf_size: usize) -> bool` | `bool` | Check if ELF has PT_INTERP segment |
| `elf_get_interp` | `(elf_data: *const u8, elf_size: usize) -> *const u8` | Pointer or null | Get interpreter path from PT_INTERP |
| `elf_get_needed` | `(elf_data: *const u8, elf_size: usize) -> NeededLibs` | `NeededLibs` | Extract DT_NEEDED library names from PT_DYNAMIC |
| `elf_get_phdr_info` | `(elf_data: *const u8, elf_size: usize, load_base: u64, phdr_vaddr: *mut u64, phent: *mut u64, phnum: *mut u64) -> i32` | 0 or -1 | Get program header info for auxv |

**NeededLibs structure:**
- `count: usize` -- number of needed libraries (max `MAX_NEEDED_LIBS` = 4)
- `names: [[u8; 24]; 4]` -- library names (max 24 chars each)
- `contains(name: &[u8]) -> bool` -- check if a library is needed

---

## 19. CPIO Parser (`cpio.rs`)

Parses CPIO newc format archives (magic "070701"). All returned pointers reference data within the mapped archive (zero-copy).

| Function | Signature | Returns | Description |
|----------|-----------|---------|-------------|
| `cpio_find_file` | `(archive: *const u8, archive_len: usize, name: *const u8, name_len: usize, entry: *mut CpioEntry) -> i32` | 1 if found, 0 if not | Find file by name in archive |
| `cpio_next` | `(archive: *const u8, archive_len: usize, offset: *mut usize, entry: *mut CpioEntry) -> i32` | 1 if entry read, 0 at end | Iterate to next entry |
| `cpio_next_ext` | `(archive: *const u8, archive_len: usize, offset: *mut usize, entry: *mut CpioEntryExt) -> i32` | 1 if entry read, 0 at end | Iterate with extended metadata (mode, nlink, mtime, ino) |
| `cpio_archive_size` | `(archive: *const u8, max_len: usize) -> usize` | Byte offset past TRAILER | Compute total archive size |

CPIO header size: `CPIO_HEADER_SIZE` (110 bytes).

---

## 20. Serial Output (`serial.rs`) and Framebuffer (`framebuffer.rs`)

### Serial Output

| Function | C ABI Name | Signature | Description |
|----------|------------|-----------|-------------|
| `serial_putc` | -- | `(c: u8)` | Write single byte via `SYS_DEBUG_PUTCHAR` |
| `serial_puts` | `besalt_serial_puts` (via lib.rs) | `(s: &[u8])` | Write byte slice atomically (256 bytes/syscall via `SYS_DEBUG_PUTBUF`) |
| `serial_hex` | `besalt_serial_hex` (via lib.rs) | `(val: u64)` | Write "0x..." hex string atomically |
| `serial_dec` | -- | `(val: u64)` | Write decimal number atomically |

### LineBuf

Accumulates compound output into a 256-byte buffer for atomic flushing:

```rust
pub struct LineBuf { buf: [u8; 256], pos: usize }
```

| Method | Signature | Description |
|--------|-----------|-------------|
| `new` | `() -> Self` | Create empty buffer |
| `str` | `(&mut self, s: &[u8])` | Append byte slice |
| `bytes` | `(&mut self, s: &[u8])` | Alias for `str` |
| `hex` | `(&mut self, val: u64)` | Append "0x..." hex |
| `dec` | `(&mut self, val: u64)` | Append decimal |
| `putc` | `(&mut self, c: u8)` | Append single byte |
| `flush` | `(&mut self)` | Write buffer via `serial_puts` and reset |

### Framebuffer Info

```rust
pub struct FramebufferInfo {
    pub phys_addr: u64,
    pub width: u32, pub height: u32, pub pitch: u32, pub bpp: u8,
    pub red_pos: u8, pub red_size: u8,
    pub green_pos: u8, pub green_size: u8,
    pub blue_pos: u8, pub blue_size: u8,
}

pub unsafe fn read_framebuffer_info() -> Option<FramebufferInfo>
```

Reads framebuffer metadata from the kernel boot info page at `BOOTINFO_VADDR` (0xC00000). Returns `None` if magic is invalid or no framebuffer present.

---

## 21. Constants Reference (`consts.rs`)

### Fixed Virtual Addresses

| Constant | Value | Description |
|----------|-------|-------------|
| `INITRD_VADDR` | 0x0100_0000 | Initrd mapping base |
| `SCRATCH_VADDR` | 0x0200_0000 | Scratch page for ELF loading |
| `BOOTINFO_VADDR` | 0x00C0_0000 | Kernel boot info page |
| `BOOTINFO_MAGIC` | 0x534C5459_424F4F54 | "SLTYBOOT" magic value |

### Capability Rights

| Constant | Value | Description |
|----------|-------|-------------|
| `CAP_RIGHTS_ALL` | 0xFFFF_FFFF | All rights granted |

### Spawn Policy Bitfield

```rust
pub const fn spawn_policy_build(
    readiness_mode: u64, map_initrd: bool, is_display: bool,
    cnode_bits: u8, memory_kb: u16,
) -> u64

pub const fn spawn_policy_readiness(policy: u64) -> u64
pub const fn spawn_policy_map_initrd(policy: u64) -> bool
pub const fn spawn_policy_is_display(policy: u64) -> bool
pub const fn spawn_policy_cnode_bits(policy: u64) -> u8
pub const fn spawn_policy_memory_kb(policy: u64) -> u16
```

Layout: bits [1:0] = readiness_mode, bit [2] = map_initrd, bit [3] = is_display, bits [15:8] = cnode_bits, bits [31:16] = memory_kb.

Readiness modes: `SPAWN_READY_IMMEDIATE` (0), `SPAWN_READY_NOTIFY` (1).

### Console/Display IPC Labels

| Constant | Value | Protocol |
|----------|-------|----------|
| `CONSOLE_WRITE` | 1 | Console server |
| `CONSOLE_READ` | 2 | Console server |
| `CONSOLE_TCGETATTR` | 3 | Console server |
| `CONSOLE_TCSETATTR` | 4 | Console server |
| `DISPLAY_GET_INFO` | 1 | Display server |
| `DISPLAY_PRESENT` | 2 | Display server |
| `DISPLAY_FILL_RECT` | 6 | Display server |
| `DISPLAY_WRITE_TEXT` | 7 | Display server |
| `DISPLAY_TERMINAL_WRITE` | 8 | Display server |

### Name Service Labels

| Constant | Value | Description |
|----------|-------|-------------|
| `POSIX_NS_REGISTER` | 1 | Register endpoint by name |
| `POSIX_NS_LOOKUP` | 2 | Lookup endpoint by name |

---

## 22. Global State (`lib.rs`)

| Symbol | Type | Description |
|--------|------|-------------|
| `__besalt_ipc_ctx` | `IpcContext` | Per-process IPC context (buffer pointer + send-cap count) |
| `__besalt_next_frame_slot` | `u64` (weak) | Next CNode slot for frame allocation |
| `__besalt_slot_base` | `u64` (weak) | Slot pool base from auxv |
| `__besalt_slot_count` | `u64` (weak) | Slot pool size from auxv |
| `__besalt_expand_ep` | `u64` (weak) | Notification cap for UT expansion |

Weak symbols are overridden by `rtld` with per-process values from auxv entries.
