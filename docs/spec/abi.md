# kernite ABI Specification

The kernite ABI is the linkage contract between userland and the
microkernel. The single source of truth is the C UAPI headers in
`kernite/include/uapi/` (umbrella `kernite.h`), generated into Rust
via bindgen; everything in this document mirrors values and types
defined there.

For the full invoke-label reference, see [syscalls.md](syscalls.md).

## Object model

Every kernel resource is a typed object, identified to userland by an
`OBJ_*` discriminant. Capabilities are user-visible handles to those
objects; rights and badges live on the capability slot. Objects are
created by retyping memory out of an `Untyped` region
(`UNTYPED_RETYPE`).

```
OBJ_NULL             = 0   // not a valid retype target
OBJ_UNTYPED          = 1
OBJ_TCB              = 2
OBJ_CNODE            = 3
OBJ_VSPACE           = 4
OBJ_FRAME            = 5
OBJ_IRQ_HANDLER      = 6
OBJ_IO_PORT          = 7
OBJ_SCHED_CONTEXT    = 8
OBJ_MEMORY_OBJECT    = 9
OBJ_EVENT_QUEUE      = 10
OBJ_WATCH            = 11
OBJ_MESSAGE_PIPE     = 12
OBJ_DATA_PIPE        = 13
OBJ_TIMER            = 14
OBJ_KERNEL_RNG       = 15
OBJ_SYSTEM_CONTROL   = 16
OBJ_CLOCK            = 17
OBJ_SYSTEM_INFO      = 18
OBJ_KERNEL_DEBUG     = 19
OBJ_MESSAGE_PIPE_CORE  = 20
OBJ_DATA_PIPE_CORE     = 21
// 22 is retired/gap
OBJ_PAGER              = 23
OBJ_DEVICE_CONTROL     = 24
OBJ_VM_HIERARCHY_STATE = 25
```

`MessagePipe` / `DataPipe` are bidirectional and created as a peer
pair from a single retype. `Watch` is a one-shot or repeating
state-flag watcher. `Timer` fires monotonic-deadline events into a
bound `EventQueue`. The kernel-authority caps (`KernelRng`,
`SystemControl`, `Clock`, `SystemInfo`, `KernelDebug`) carry no
per-instance state — they grant the right to perform a system-wide
operation.

## State flags

Watchable objects expose a 64-bit `state_flags` word. Userland
registers a `Watch` against a `(state_flags, mask)` pair; when any
masked bit becomes asserted in the object's state, an `EventRecord` is
enqueued into the watch's bound `EventQueue`.

```
STATE_READABLE          = 1 << 0
STATE_WRITABLE          = 1 << 1
STATE_PEER_CLOSED       = 1 << 2
STATE_CLOSED            = 1 << 3
STATE_ERROR             = 1 << 4
STATE_HANGUP            = 1 << 5
STATE_OVERRUN           = 1 << 6
STATE_SIGNALED          = 1 << 7
STATE_TIMED_OUT         = 1 << 8
STATE_READ_THRESHOLD    = 1 << 9   // DataPipe RX bytes >= rx_threshold
STATE_WRITE_THRESHOLD   = 1 << 10  // DataPipe TX free >= tx_threshold
```

The semantics are object-typed:

| Object        | Bits asserted |
|---------------|---------------|
| `EventQueue`  | `READABLE` while non-empty; `CLOSED` on destroy. |
| `MessagePipe` | `READABLE` / `WRITABLE` track queue level; `PEER_CLOSED` set when the other end half-closes. |
| `DataPipe`    | Same as `MessagePipe`, byte-level. |
| `Timer`       | `SIGNALED` set on each fire; userland clears via `Watch` ack or `TIMER_SET`. |
| `IrqHandler`  | `SIGNALED` set on IRQ assertion; `IRQ_HANDLER_ACK` clears. |

## EventRecord wire format

`EQ_WAIT` and `EQ_POLL` deliver one `kernite_event_record` per call.
The kernel writes the record into `reserved[]` in the IPC buffer at
`KERNITE_IPC_RESERVED_EVENT_RECORD_BASE`. The struct layout is:

```
struct kernite_event_record {
    kind       : u32   // EVENT_TYPE_*
    status     : u32   // EVENT_STATUS_*
    cookie     : u64   // opaque caller-supplied tag
    object_id  : u64   // watched-object identity (Watch arms)
    state_set  : u64   // STATE_* bits asserted
    state_seen : u64   // STATE_* bits userland already knew about
    payload0   : u64
    payload1   : u64
    payload2   : u64
}
```

`kind` (`EVENT_TYPE_*`):

```
EVENT_TYPE_NONE           = 0
EVENT_TYPE_STATE          = 1   // state_flags transition
EVENT_TYPE_IRQ            = 2
EVENT_TYPE_TIMER          = 3
EVENT_TYPE_PIPE           = 4   // MP/DP record arrival
EVENT_TYPE_USER           = 5   // userland-pushed record
EVENT_TYPE_OVERFLOW       = 6   // dropped-event marker
EVENT_TYPE_PAGER_REQUEST  = 7   // file-backed page fault — vfs supplies
```

`status` (`EVENT_STATUS_*`):

```
EVENT_STATUS_OK            = 0
EVENT_STATUS_CANCELLED     = 1
EVENT_STATUS_PEER_CLOSE    = 2
EVENT_STATUS_OBJECT_CLOSED = 3
EVENT_STATUS_DROPPED       = 4
```

An `OVERFLOW` record signals that one or more events were dropped;
after delivering it the queue resumes normal record delivery.

## MessagePipe wire format

`MP_WRITE` / `MP_READ` operate on `kernite_mp_record` structs:

```
struct kernite_mp_record {
    label     : u64        // arbitrary message label
    length    : u64        // count of valid words in words[]
    cap_count : u64        // count of carrier caps
    flags     : u64        // KERNITE_MP_FLAG_*
    badge     : u64        // sender opaque tag (set by kernel on read)
    txid      : u64        // MP_CALL correlation id
    words     : [u64; 32]  // inline message payload
}
```

MP record flags (`KERNITE_MP_FLAG_*`):

```
MP_FLAG_NONE   = 0
MP_FLAG_CALL   = 1 << 0   // sender expects reply
MP_FLAG_REPLY  = 1 << 1   // this record is a reply
MP_FLAG_FAULT  = 1 << 2   // kernel-injected fault record
```

`txid` correlates `MP_CALL` senders with their eventual reply. The
kernel generates sync call txids with bit 63 set
(`KERNITE_MP_TXID_KERNEL_BIT`); userspace async request/reply txids
must keep bit 63 clear so a user write cannot forge a sync reply.
`txid == 0` is the "no correlation" sentinel.

Capability transfer happens out-of-band: senders pass cap CSpace
indices in their IPC buffer's `caps[]` area; the kernel mints those
into hidden carriers at `MP_WRITE` time. Receivers see installed
receive-side slot indices in their own IPC buffer's `caps[]` area at
`MP_READ` time, sourced from `receive_cnode`/`receive_index`/`receive_depth`.

## IPC buffer layout

Each TCB has a 4 KiB IPC buffer mapped at `TCB_SET_IPC_BUFFER`. Layout:

```
offset 0x000  msg[34]        (overlay: label, length, regs[0..31])  272 bytes
offset 0x110  badge          (set by kernel on inbound)                8 bytes
offset 0x118  mp_flags       (KERNITE_MP_FLAG_* from inbound record)   8 bytes
offset 0x120  caps[4]        (cap slot indices for transfer)           32 bytes
offset 0x140  receive_cnode                                             8 bytes
offset 0x148  receive_index                                             8 bytes
offset 0x150  receive_depth                                             8 bytes
offset 0x158  mp_txid        (MP_CALL correlation id)                  8 bytes
offset 0x160  reserved[468]  (per-syscall extension; see below)     3744 bytes
```

`msg[]` is the spillover area for messages whose `length > 4`.
`mp_flags` surfaces the `flags` field of the inbound `kernite_mp_record`
so receivers can inspect call/reply/fault bits without parsing the raw record.
`mp_txid` carries the correlation id for `MP_CALL`; servers copy it into
reply records so the kernel can wake the parked caller.
`caps[]` is the four-slot capture/destination array for cap transfer.
`reserved[]` is the per-call extension area; well-known indices:

```
reserved[0]  KERNITE_IPC_RESERVED_RECEIVE_SLOT_DEPTH  nested receive-slot depth
reserved[1]  KERNITE_IPC_RESERVED_RECEIVED_CAP_COUNT  count of caps installed by kernel
reserved[2]  KERNITE_IPC_RESERVED_EVENT_RECORD_BASE   kernite_event_record (9 u64 words)
```

## VSpace page flags

Mapping ops (`VSPACE_MAP`, `VSPACE_PROTECT`, …) take a flags word:

```
PAGE_FLAG_WRITABLE     = 1 << 0
PAGE_FLAG_USER         = 1 << 1
PAGE_FLAG_EXECUTABLE   = 1 << 2
PAGE_FLAG_COW          = 1 << 3
PAGE_FLAG_DEMAND       = 1 << 4
PAGE_FLAG_NOCACHE      = 1 << 5
// bit 6 reserved
PAGE_FLAG_WRITETHROUGH = 1 << 7
```

Region kinds (`KERNITE_REGION_KIND_*`) passed alongside the flags word
to attribute mappings:

```
REGION_KIND_NONE       = 0
REGION_KIND_IMAGE_TEXT = 1
REGION_KIND_IMAGE_DATA = 2
REGION_KIND_IMAGE_BSS  = 3
REGION_KIND_HEAP       = 4
REGION_KIND_STACK      = 5
REGION_KIND_MMAP       = 6
REGION_KIND_SHARED_LIB = 7
```

## Well-known capability slots

Every thread starts with three capability slots preinstalled in its
CSpace. All other caps reach the thread via the userland startup
descriptor (Trona startup block — userland concern, not kernite ABI).

```
CAP_SELF_TCB    = 0
CAP_SELF_VSPACE = 1
CAP_SELF_CSPACE = 2
```

## ABI version

`SYS_INVOKE` against `CAP_SELF_TCB` with label `TCB_GET_ABI_VERSION`
(`0x66`) returns the running kernel's ABI version word. Userland
verifies the version on startup and refuses to proceed on mismatch.

```
KERNITE_ABI_MAJOR   = 0
KERNITE_ABI_MINOR   = 0
KERNITE_ABI_PATCH   = 2
KERNITE_ABI_VERSION = 0x0000000000000002  // (major << 32) | (minor << 16) | patch
```

## Boot handoff

`BOOTINFO_VADDR` and `BOOTINFO_MAGIC` define the location and
sentinel of the bootloader-built BootInfo TLV. The detailed TLV
schema lives in [boot_protocol.md](boot_protocol.md).
