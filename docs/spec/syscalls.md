# System Call Reference

kernite exposes a single trap, `SYS_INVOKE`. Every per-object operation
routes through it via an invoke label against an explicit capability.
There is no ambient kernel authority — randomness, shutdown, clock,
system accounting, and debug output are all reached through dedicated
capability objects.

The single source of truth for every value in this document is the C
UAPI headers in `kernite/include/uapi/` (umbrella `kernite.h`),
generated into Rust via bindgen. The constants here mirror them.

## Calling convention

### x86_64

```
Entry: SYSCALL instruction
  RAX  - 0 (SYS_INVOKE — the only syscall number)
  RDI  - cap_ptr
  RSI  - invoke label (selects the operation)
  RDX  - arg0
  R10  - arg1   (RCX is clobbered by SYSCALL; userland uses R10)
  R8   - arg2
  R9   - arg3

Return:
  RAX  - error code (`KERNITE_OK` = 0 on success)
  RDX  - return value (operation-specific)
```

### aarch64

```
Entry: SVC #0
  X8   - 0 (SYS_INVOKE — the only syscall number)
  X0   - cap_ptr
  X1   - invoke label (selects the operation)
  X2   - arg0
  X3   - arg1
  X4   - arg2
  X5   - arg3

Return:
  X0   - error code
  X1   - return value
```

For the IPC-buffer layout, message-info encoding, and VSpace page
flags, see [abi.md](abi.md).

## Invoke labels

Each object type owns a 0x20-aligned hex range. Sub-ops run from `0x*0`
upward. Empty slots within a range are reserved for future ops on the
same object type.

### CNode (0x20–0x3F)

| Label | Name              | Notes |
|-------|-------------------|-------|
| 0x20  | `CNODE_COPY`      | Copy a capability into a destination slot. |
| 0x21  | `CNODE_MINT`      | Copy with reduced rights / new badge. |
| 0x22  | `CNODE_MOVE`      | Move (no copy) into a destination slot. |
| 0x23  | `CNODE_MUTATE`    | Move + new badge atomically. |
| 0x24  | `CNODE_DELETE`    | Delete a slot's capability. |
| 0x25  | `CNODE_REVOKE`    | Revoke all derived caps. |
| 0x26  | `CNODE_SET_GUARD` | Configure guard bits / depth. |
| 0x27  | `CNODE_GET_INFO`  | Read slot count / depth. |

### Untyped (0x40–0x5F)

| Label | Name | Notes |
|-------|------|-------|
| 0x40  | `UNTYPED_RETYPE`    | Carve a typed kernel object out of an untyped region. |
| 0x41  | `UNTYPED_RESET`     | Free every child of this untyped. |
| 0x42  | `UNTYPED_GET_STATS` | Read remaining capacity / fragmentation. |

### TCB (0x60–0x7F)

`TCB_STOP` / `TCB_START` replace the older suspend/resume pair.
Self-thread operations (yield, exit/kill, get_state, get_abi_version,
set_invoke_depths) are TCB invocations against `CAP_SELF_TCB`.

| Label | Name | Notes |
|-------|------|-------|
| 0x60  | `TCB_CONFIGURE`         | Set entry / stack / IPC buffer; structural. |
| 0x61  | `TCB_START`             | Mark Runnable. |
| 0x62  | `TCB_STOP`              | Mark Stopped. |
| 0x63  | `TCB_KILL`              | Begin destroy (self or remote). |
| 0x64  | `TCB_YIELD`             | Self-yield (target must equal current). |
| 0x65  | `TCB_GET_STATE`         | Read current `ThreadState` discriminant. |
| 0x66  | `TCB_GET_ABI_VERSION`   | Returns `KERNITE_ABI_VERSION`. |
| 0x67  | `TCB_SET_INVOKE_DEPTHS` | Pre-seed depth0/depth1 for the next invoke. |
| 0x68  | `TCB_SET_SPACE`         | Bind CSpace + VSpace roots. |
| 0x69  | `TCB_SET_AFFINITY`      | Pin to a CPU. |
| 0x6A  | `TCB_READ_REGISTERS`    | Read entry RIP/ELR. |
| 0x6B  | `TCB_WRITE_REGISTERS`   | Write entry / RIP / RSP. |
| 0x6C  | `TCB_SET_PRIORITY`      | Class-specific priority value. |
| 0x6D  | `TCB_SET_IPC_BUFFER`    | Map IPC buffer VA. |
| 0x6E  | `TCB_SET_FAULT_PIPE`    | Bind a `MessagePipe` for fault delivery. |
| 0x70  | `TCB_COPY_FPU`          | Copy FPU state from another TCB. |
| 0x71  | `TCB_SET_TLS_BASE`      | Set TLS base register. |
| 0x72  | `TCB_SET_STACK_BOUNDS`  | Stack range + guard hint. |
| 0x73  | `TCB_SET_SCHED_CLASS`   | `SCHED_CLASS_*` selector. |
| 0x74  | `TCB_GET_SPACE_INFO`    | Read CSpace depth. |
| 0x75  | `TCB_GET_CPU_TIMES`     | Read user / system runtime ns. |
| 0x76  | `TCB_GET_TRACE_ID`      | Read scheduler trace id. |
| 0x77  | `TCB_SET_ABI_TP`        | Set ABI thread-pointer (TP) base. |
| 0x78  | `TCB_EXIT_SELF`         | Begin destroy of the **current** thread (ignores cap target); used by `thread_exit` so a CSpace-sharing aux thread exits itself, not slot-0 main. |

### VSpace (0x80–0x9F)

Futex hashing is per-VSpace, so wait/wake invocations live on the
VSpace cap (typically `CAP_SELF_VSPACE`).

| Label | Name | Notes |
|-------|------|-------|
| 0x80  | `VSPACE_MAP`                  | Map a frame at a VA. |
| 0x81  | `VSPACE_UNMAP`                | Unmap a VA. |
| 0x82  | `VSPACE_MAP_PT`               | Map a page-table page. |
| 0x83  | `VSPACE_WALK`                 | Walk the page table for a VA. |
| 0x84  | `VSPACE_COPY_PAGE`            | Copy one page between VSpaces. |
| 0x85  | `VSPACE_MAP_DEVICE`           | Map device-untyped phys. |
| 0x86  | `VSPACE_MAP_DEVICE_RANGE`     | Map device-phys range. |
| 0x87  | `VSPACE_PROTECT`              | Update PTE flags. |
| 0x88  | `VSPACE_PROTECT_RANGE`        | Update flags over a range. |
| 0x89  | `VSPACE_MAP_DEMAND`           | Reserve VA for demand paging. |
| 0x8A  | `VSPACE_MAP_DEMAND_RANGE`     | Reserve a range. |
| 0x8D  | `VSPACE_SET_COW_POOL`         | Bind a CoW page pool. |
| 0x8E  | `VSPACE_REPLENISH_COW_POOL`   | Top up a CoW pool. |
| 0x8F  | `VSPACE_MAP_MO`               | Map a `MemoryObject`. |
| 0x90  | `VSPACE_SHARE_RO_PAGE`        | RO-share a page across VSpaces. |
| 0x91  | `VSPACE_FORK_RANGE`           | Fork a VA range CoW-style. |
| 0x92  | `VSPACE_UNDO_FORK_RANGE`      | Roll back a fork. |
| 0x93  | `VSPACE_GET_MEM_STATS`        | VSpace-scoped memory stats. |
| 0x94  | `VSPACE_GET_RANGE_STATS`      | Per-range stats. |
| 0x95  | `VSPACE_GET_TRACE_ID`         | Read VSpace trace id. |
| 0x96  | `VSPACE_FUTEX_WAIT`           | Block on a userspace word. |
| 0x97  | `VSPACE_FUTEX_WAKE`           | Wake N waiters. |
| 0x98  | `VSPACE_RESOLVE_PAGE`         | Resolve a page (demand-paging assist). |
| 0x99  | `VSPACE_FUTEX_REQUEUE`        | Requeue waiters to a different address. |

### SchedContext (0xA0–0xBF)

| Label | Name |
|-------|------|
| 0xA0  | `SC_CONFIGURE` |
| 0xA1  | `SC_BIND` |

### IoPort (0xC0–0xDF)

x86 port-mapped I/O only. MMIO mapping uses `VSPACE_MAP_DEVICE` instead.

| Label | Name |
|-------|------|
| 0xC0  | `IOPORT_READ_8`   | Read one byte from the port. |
| 0xC1  | `IOPORT_READ_16`  | Read one word. |
| 0xC2  | `IOPORT_READ_32`  | Read one dword. |
| 0xC3  | `IOPORT_WRITE_8`  | Write one byte. |
| 0xC4  | `IOPORT_WRITE_16` | Write one word. |
| 0xC5  | `IOPORT_WRITE_32` | Write one dword. |

### IrqHandler (0xE0–0xFF)

| Label | Name |
|-------|------|
| 0xE0  | `IRQ_BIND_EQ`   | Bind an `EventQueue` to receive IRQ notifications. |
| 0xE1  | `IRQ_UNBIND_EQ` | Unbind the current `EventQueue`. |
| 0xE2  | `IRQ_ACK`       | Acknowledge the interrupt to the controller. |

### DeviceControl (0x2E0–0x2FF)

Privileged hardware-resource broker. Mints narrower device-resource caps
into a destination CSpace. The destination slot depth is supplied via
`TCB_SET_INVOKE_DEPTHS` `depth0`.

| Label | Name |
|-------|------|
| 0x2E0 | `DEVICE_CONTROL_CREATE_IOPORT`          | Mint an IoPort cap for `base_port`…`base_port+num_ports-1`. |
| 0x2E1 | `DEVICE_CONTROL_CREATE_DEVICE_UNTYPED`  | Mint a device-untyped pinned to a phys range. |
| 0x2E2 | `DEVICE_CONTROL_CREATE_IRQ_HANDLER`     | Mint an IrqHandler cap for the given IRQ line. |

### MemoryObject (0x100–0x11F)

| Label | Name |
|-------|------|
| 0x100 | `MO_COMMIT` |
| 0x101 | `MO_DECOMMIT` |
| 0x102 | `MO_GET_SIZE` |
| 0x103 | `MO_CLONE` |
| 0x104 | `MO_RESIZE` |
| 0x105 | `MO_READ` |
| 0x106 | `MO_WRITE` |
| 0x107 | `MO_HAS_PAGE` |
| 0x108 | `MO_GET_MAP_COUNT` |
| 0x109 | `MO_UPDATE_PAGE_FLAGS` |
| 0x10A | `MO_ATTACH_PAGER` |
| 0x10B | `MO_SNAPSHOT` |
| 0x10C | `MO_CLONE_RANGE` |

### EventQueue (0x120–0x13F)

| Label | Name |
|-------|------|
| 0x120 | `EQ_WAIT`   — block until a record arrives. |
| 0x121 | `EQ_POLL`   — non-blocking dequeue. |
| 0x122 | `EQ_CANCEL` — pull caller off the waiter list. |

### Watch (0x140–0x15F)

| Label | Name |
|-------|------|
| 0x140 | `WATCH_REGISTER` — bind to a watched object + EventQueue. |
| 0x141 | `WATCH_DISARM`   — explicit cancel. |
| 0x142 | `WATCH_CANCEL`   — cancel a pending watch and drain its pending event. |

### MessagePipe (0x160–0x17F)

| Label | Name |
|-------|------|
| 0x160 | `MP_WRITE`  | Enqueue into the peer's queue. |
| 0x161 | `MP_READ`   | Drain head record. |
| 0x162 | `MP_CLOSE`  | Half-close this end. |
| 0x163 | `MP_CALL`   | Write + block on reply. |
| 0x164 | reserved | Retired; replies are `MP_WRITE` records carrying `KERNITE_MP_FLAG_REPLY`. |

### DataPipe (0x180–0x19F)

| Label | Name |
|-------|------|
| 0x180 | `DP_PRODUCE`          | Copy bytes into the peer's ring. |
| 0x181 | `DP_CONSUME`          | Copy bytes out of this ring. |
| 0x182 | `DP_QUERY`            | Read state flags + fill level. |
| 0x183 | `DP_CLOSE`            | Half-close this end. |
| 0x184 | `DP_SET_RX_THRESHOLD` | Set the receive-ready watermark. |
| 0x185 | `DP_SET_TX_THRESHOLD` | Set the transmit-ready watermark. |
| 0x186 | `DP_SHUTDOWN`         | Half-close: disable this side's writes. |

### Timer (0x1A0–0x1BF)

| Label | Name |
|-------|------|
| 0x1A0 | `TIMER_SET`    | Arm with absolute deadline + optional period. |
| 0x1A1 | `TIMER_CANCEL` | Disarm. |
| 0x1A2 | `TIMER_QUERY`  | Read remaining ns. |

### KernelRng (0x1C0–0x1DF)

| Label | Name |
|-------|------|
| 0x1C0 | `RNG_READ` — fill the user buffer with kernel CSPRNG bytes. |

### SystemControl (0x1E0–0x1FF)

| Label | Name |
|-------|------|
| 0x1E0 | `SYSTEM_SHUTDOWN` |
| 0x1E1 | `SYSTEM_REBOOT` |

### Clock (0x200–0x21F)

| Label | Name |
|-------|------|
| 0x200 | `CLOCK_READ` — `arg0` selects `CLOCK_REALTIME` (0) or `CLOCK_MONOTONIC` (1). |

### SystemInfo (0x220–0x23F)

| Label | Name |
|-------|------|
| 0x220 | `SYSINFO_GET_INFO`    |
| 0x221 | `SYSINFO_GET_MEMINFO` |

### KernelDebug (0x240–0x25F)

| Label | Name |
|-------|------|
| 0x240 | `KDEBUG_PUTCHAR`         |
| 0x241 | `KDEBUG_PUTSTR`          |
| 0x242 | `KDEBUG_PUTBUF`          |
| 0x243 | `KDEBUG_DUMP_STATE`      |
| 0x244 | `KDEBUG_CONSOLE_CONTROL` |

### MessagePipeCore (0x260–0x27F)

A `MessagePipeCore` holds the shared ring buffers for a `MessagePipe`
pair. Both pipe endpoints reference the same core object.

| Label | Name |
|-------|------|
| 0x260 | `MP_CORE_PAIR` — allocate a matched MessagePipe endpoint pair from this core. |

### DataPipeCore (0x280–0x29F)

A `DataPipeCore` holds the shared byte-stream buffers for a `DataPipe`
pair.

| Label | Name |
|-------|------|
| 0x280 | `DP_CORE_PAIR` — allocate a matched DataPipe endpoint pair from this core. |

### Pager (0x2C0–0x2DF)

A file-backed MO supplier. The pager cap is held by the task that owns
the file → page-cache translation (typically `vfs`). `mmsrv` attaches it
to a file-backed `MemoryObject` at map time; the kernel then routes
page-absent faults through the pager's bound `EventQueue` as
`KERNITE_EVENT_TYPE_PAGER_REQUEST`.

| Label | Name |
|-------|------|
| 0x2C0 | `PAGER_BIND_EQ`         | Bind an `EventQueue` to receive pager fault requests. |
| 0x2C1 | `PAGER_SUPPLY_PAGE`     | Donate a `Frame` cap into the MO at the faulting offset. |
| 0x2C2 | `PAGER_FAIL`            | Surface a SIGBUS-equivalent to the faulting thread. |
| 0x2C3 | `PAGER_DETACH`          | Detach this pager from its MO. |
| 0x2C4 | `PAGER_BEGIN_WRITEBACK` | Signal start of writeback for a dirty page. |
| 0x2C5 | `PAGER_WRITEBACK_DONE`  | Signal completion of writeback. |
| 0x2C6 | `PAGER_EVICT_PAGE`      | Unmap + free a clean resident page; refuses if dirty. |
| 0x2C7 | `PAGER_SUPPLY_COPY`     | Supply a page via kernel-managed page-cache copy (no Frame cap donated). |

## ABI version

Userland verifies the ABI at startup via `TCB_GET_ABI_VERSION`
(`0x66`) on its own `CAP_SELF_TCB`. The returned u64 packs major /
minor / patch:

```
KERNITE_ABI_VERSION = (major << 32) | (minor << 16) | patch
```

Current ABI version: `0.0.2`.

## Error codes (`KERNITE_OK` / `KERNITE_ERR_*`)

Returned in the error register on every invocation. The full table
lives in `kernite/include/uapi/error.h`. Code 0 is always success;
all non-zero values are stable. Callers must treat unknown codes as
opaque — the kernel may extend this table at the tail.

| Code | Name | Meaning |
|------|------|---------|
| 0    | `KERNITE_OK`                        | Success. |
| 1    | `KERNITE_ERR_INVALID_CAPABILITY`    | Cap slot empty or wrong object type. |
| 2    | `KERNITE_ERR_INVALID_OPERATION`     | Label not defined for this object type. |
| 3    | `KERNITE_ERR_INSUFFICIENT_RIGHTS`   | Cap rights do not permit this operation. |
| 4    | `KERNITE_ERR_INVALID_ARGUMENT`      | Argument out of range or structurally invalid. |
| 5    | `KERNITE_ERR_OUT_OF_MEMORY`         | Untyped memory exhausted. |
| 6    | `KERNITE_ERR_NOT_FOUND`             | Requested object or slot does not exist. |
| 7    | `KERNITE_ERR_BUSY`                  | Object is in use; try again. |
| 8    | `KERNITE_ERR_ALREADY_EXISTS`        | Target slot already occupied (use a different slot). |
| 9    | `KERNITE_ERR_WOULD_BLOCK`           | Non-blocking op has no data ready. |
| 10   | `KERNITE_ERR_BAD_ADDRESS`           | User pointer is unmapped or misaligned. |
| 11   | `KERNITE_ERR_OUT_OF_RANGE`          | Numeric value exceeds object bounds. |
| 12   | `KERNITE_ERR_CANCELLED`             | Blocking op was cancelled by another thread. |
| 13   | `KERNITE_ERR_RESTART`               | Internal: syscall must be restarted (not user-visible). |
| 14   | `KERNITE_ERR_DEADLOCK`              | Futex operation would deadlock. |
| 15   | `KERNITE_ERR_INTERRUPTED`           | Blocking op interrupted by a signal. |
| 16   | `KERNITE_ERR_TOO_LARGE`             | Transfer size or object size exceeds limit. |
| 17   | `KERNITE_ERR_NOT_SUPPORTED`         | Operation not supported on this platform or config. |
| 18   | `KERNITE_ERR_READONLY`              | Write attempted on a read-only mapping or object. |
| 19   | `KERNITE_ERR_SLOT_OCCUPIED`         | Destination CNode slot already holds a cap. |
| 20   | `KERNITE_ERR_ALREADY_MAPPED`        | VA range already has a mapping. |
| 21   | `KERNITE_ERR_PEER_CLOSED`           | The peer of a `MessagePipe` / `DataPipe` is gone. |
| 22   | `KERNITE_ERR_QUEUE_OVERFLOW`        | An `EventQueue` rolled a record into the dropped counter. |
| 23   | `KERNITE_ERR_WATCH_CANCELLED`       | A `Watch` returned because of explicit cancel or object death. |
| 24   | retired                             | No public ABI symbol; reserved. |
| 25   | `KERNITE_ERR_ABI_MISMATCH`          | `TCB_GET_ABI_VERSION` mismatch detected at startup. |
| 26   | `KERNITE_ERR_IO_ERROR`              | Hardware or backing-store I/O failure. |
| 27   | `KERNITE_ERR_TIMED_OUT`             | Deadline passed before the operation completed. |
| 28   | `KERNITE_ERR_PENDING`               | Operation accepted but not yet complete (async path). |
| 29   | `KERNITE_ERR_INSUFFICIENT_RESOURCES` | Kernel fixed-size pool exhausted (distinct from `OUT_OF_MEMORY`). |
