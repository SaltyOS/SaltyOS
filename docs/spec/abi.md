# SaltyOS ABI Specification

This document defines the low-level Application Binary Interface (ABI) between
userspace and the SaltyOS kernel. It covers system call calling conventions for
both supported architectures, the IPC buffer layout, message info encoding, and
VSpace page mapping flags.

For the full system call table and capability invocation reference, see
[syscalls.md](syscalls.md).

---

## 1. System Call Calling Conventions

SaltyOS provides a single system call entry point per architecture. The syscall
number selects the operation; arguments are passed in registers.

### 1.1 x86_64

**Entry instruction:** `syscall`

#### Register Convention

| Register | Role |
|----------|------|
| RAX | System call number (0-27) |
| RDI | Argument 0 (capability pointer) |
| RSI | Argument 1 (msg_info / label) |
| RDX | Argument 2 (MR0 / arg0) |
| R10 | Argument 3 (MR1 / arg1) -- RCX is clobbered by `syscall` |
| R8 | Argument 4 (MR2 / arg2) |
| R9 | Argument 5 (MR3 / arg3) |

#### Return Convention

| Register | Role |
|----------|------|
| RAX | Error code (0 = success, see [Error Codes](#5-error-codes)) |
| RDX | Return value (syscall-specific payload) |

#### Clobbered Registers

The `syscall` instruction clobbers RCX (saved RIP) and R11 (saved RFLAGS).
Userspace wrappers must move RCX to R10 before entry:

```nasm
; User-space syscall wrapper
syscall_invoke:
    mov r10, rcx        ; Save arg3 (RCX clobbered by SYSCALL)
    syscall
    ret
```

#### Kernel-Internal Mapping

Assembly in `kernite/src/arch/x86_64/syscall.S` remaps user registers to
System V AMD64 calling convention before calling `syscall_handle_rust`:

```
User register   Kernel parameter   System V register
─────────────   ────────────────   ─────────────────
RAX             syscall number     RDI
RDI             cap_ptr            RSI
RSI             arg0 (msg_info)    RDX
RDX             arg1               RCX
R10             arg2               R8
R8              arg3               R9
R9              arg4               stack
```

The `SyscallResult` struct (`{ error: u64, value: u64 }`) is returned in
RAX:RDX per the System V AMD64 ABI for two-member structs.

---

### 1.2 aarch64

**Entry instruction:** `svc #0`

#### Register Convention

| Register | Role |
|----------|------|
| x8 | System call number (0-27) |
| x0 | Argument 0 (capability pointer) |
| x1 | Argument 1 (msg_info / label) |
| x2 | Argument 2 (MR0 / arg0) |
| x3 | Argument 3 (MR1 / arg1) |
| x4 | Argument 4 (MR2 / arg2) |
| x5 | Argument 5 (MR3 / arg3) |

#### Return Convention

| Register | Role |
|----------|------|
| x0 | Error code (0 = success, see [Error Codes](#5-error-codes)) |
| x1 | Return value (syscall-specific payload) |

#### Notes

- The SVC exception (EC=0x15) is handled in `kernite/src/arch/aarch64/exceptions.rs`.
- x0-x5 map directly to AAPCS64 function arguments, so no register remapping
  is needed before calling `syscall_handle_rust`.
- Return values are written back to the exception frame's x0 and x1 slots via
  `restore_el0_frame_from_current_tcb(frame, result.error, result.value)`.

---

### 1.3 IPC Fastpath

For performance-critical IPC operations, the kernel provides an assembly-level
fastpath that bypasses the full slowpath dispatch. The fastpath is attempted for:

- **Call** (syscall 2)
- **ReplyRecv** (syscall 3)
- **ReplyRecvAny** (syscall 24)

The fastpath bails to the slowpath when:
- `extra_caps > 0` (capability transfer required)
- `length > 4` (message exceeds inline registers)
- No waiting partner on the endpoint
- Cross-CPU transfer (remote endpoint)
- Thread has a pending fault

On x86_64, the fastpath is dispatched in `syscall.S` before entering the C/Rust
slowpath. On aarch64, the dispatch occurs in the SVC handler in `exceptions.rs`
before calling `syscall_handle_rust`.

---

## 2. IPC Buffer Layout

Every thread has a single IPC buffer page (4096 bytes) mapped into its virtual
address space. The kernel and userspace share this page for extended IPC data
that does not fit in registers.

### 2.1 Structure

```
Offset  Size     Field
──────  ───────  ──────────────────────────────────────────────────
0x000   176 B    msg[22]         Message buffer (label, length, MR0-MR19)
0x0B0     8 B    badge           Received sender badge
0x0B8    32 B    caps[4]         Capability slots to transfer (sender-side)
0x0D8     8 B    receive_cnode   CNode capability for receiving caps
0x0E0     8 B    receive_index   Starting slot index in receive CNode
0x0E8     8 B    receive_depth   CNode depth for cap lookup
0x0F0  3824 B    reserved[478]   Extended payload / invoke helper area
──────  ───────  ──────────────────────────────────────────────────
Total: 4096 B    (one 4KB page)
```

### 2.2 msg[] Array Overlay

The `msg[22]` array is overlaid by the userland `trona_msg` structure:

| Index | Field | Description |
|-------|-------|-------------|
| 0 | `label` | Application-defined message label |
| 1 | `length` | Number of message registers used |
| 2-21 | `regs[0..19]` | Message registers MR0 through MR19 |

MR0-MR3 are passed in CPU registers (fastpath). MR4-MR19 overflow to the IPC
buffer when `length > 4`.

### 2.3 Capability Transfer

To transfer capabilities during IPC:

1. **Sender** writes source capability slot indices into `caps[0..3]` and sets
   `extra_caps` in the message info word.
2. **Receiver** pre-configures `receive_cnode`, `receive_index`, and
   `receive_depth` to specify where received capabilities should be placed.

Up to 4 capabilities can be transferred per IPC operation.

### 2.4 Reserved Area

The `reserved[478]` area (word offsets 30-507) is used by:

- **RecvAny/ReplyRecvAny** syscalls: endpoint capability pointers are read from
  `reserved[0..N-1]` where N is the endpoint count. For `ReplyRecvAnyTimed`,
  the timeout is read from `reserved[N]`.
- **VSPACE_WALK** invoke: writes physical address / flags tuples starting at
  word offset 30.
- **Invoke extensions**: various capability invocations use this area for
  bulk data transfer.

---

## 3. Message Info Encoding

All IPC syscalls (Send, Recv, Call, ReplyRecv, NBSend, and their variants) use a
packed 64-bit `msg_info` word.

### 3.1 Bit Layout

```
 63       52  51                 12  11      7  6        0
┌───────────┬────────────────────┬──────────┬───────────┐
│ Reserved  │       Label        │ExtraCaps │  Length   │
│  (zero)   │     (40 bits)      │ (5 bits) │ (7 bits) │
└───────────┴────────────────────┴──────────┴───────────┘
```

### 3.2 Field Definitions

| Field | Bits | Width | Range | Description |
|-------|------|-------|-------|-------------|
| Length | 6:0 | 7 | 0-127 | Number of message registers used |
| ExtraCaps | 11:7 | 5 | 0-31 | Number of capabilities to transfer via IPC buffer |
| Label | 51:12 | 40 | -- | Application-defined message label |
| Reserved | 63:52 | 12 | 0 | Must be zero |

### 3.3 Construction

```c
#define TRONA_MSGINFO(label, length, extra_caps) \
    (((uint64_t)(label) << 12) | \
     ((uint64_t)(extra_caps) << 7) | \
     ((uint64_t)(length) & 0x7F))
```

### 3.4 Extraction

```c
#define TRONA_MSGINFO_LENGTH(info)     ((info) & 0x7F)
#define TRONA_MSGINFO_EXTRA_CAPS(info) (((info) >> 7) & 0x1F)
#define TRONA_MSGINFO_LABEL(info)      (((info) >> 12) & 0xFFFFFFFFFF)
```

### 3.5 Invoke Label Convention

For capability invocations (syscall 9), the `label` field of msg_info carries
the invoke operation code. See [syscalls.md](syscalls.md) for the complete
invoke label table.

---

## 4. VSpace Page Flags

Page mapping operations (`VSpace_Map`, `VSpace_MapDemand`, `VSpace_Protect`,
etc.) accept a `flags` argument as a bitmask.

### 4.1 Flag Definitions

| Bit | Constant | Value | Description |
|-----|----------|-------|-------------|
| 0 | `VSPACE_FLAG_WRITABLE` | 0x01 | Page is writable |
| 1 | `VSPACE_FLAG_USER` | 0x02 | Page is accessible from user mode (EL0) |
| 2 | `VSPACE_FLAG_EXECUTABLE` | 0x04 | Page is executable (NX/XN cleared) |
| 3 | `VSPACE_FLAG_CACHE_DISABLE` | 0x08 | Disable caching (for MMIO) |
| 4 | `VSPACE_FLAG_WRITE_THROUGH` | 0x10 | Write-through caching |
| 5 | `VSPACE_FLAG_COW` | 0x20 | Copy-on-write: shared read-only until written |

### 4.2 Common Flag Combinations

| Use Case | Flags | Value |
|----------|-------|-------|
| User code (RX) | USER \| EXECUTABLE | 0x06 |
| User data (RW) | USER \| WRITABLE | 0x03 |
| User read-only | USER | 0x02 |
| User COW | USER \| WRITABLE \| COW | 0x23 |
| Device MMIO | USER \| WRITABLE \| CACHE_DISABLE \| WRITE_THROUGH | 0x1B |

### 4.3 Architecture Translation

These flags use architecture-neutral bit positions. The kernel translates them
to hardware-specific page table entry formats:

- **x86_64:** Flags map directly to x86 PTE bits (Present, R/W, U/S, PCD, PWT, NX).
- **aarch64:** The paging module (`kernite/src/arch/aarch64/paging.rs`)
  translates logical x86-style flags to ARM hardware descriptors (AP, UXN, PXN,
  AttrIndx for MAIR). Shared kernel code (vspace.rs) always operates on the
  logical format; the translation is transparent.

---

## 5. Error Codes

System calls return error codes in RAX (x86_64) or x0 (aarch64). All codes are
positive integers.

| Code | Name | Description |
|------|------|-------------|
| 0 | `TRONA_OK` | Success |
| 1 | `TRONA_INVALID_CAPABILITY` | Capability is null or invalid type |
| 2 | `TRONA_INVALID_OPERATION` | Wrong object type or unsupported operation |
| 3 | `TRONA_INSUFFICIENT_RIGHTS` | Capability lacks required rights |
| 4 | `TRONA_INVALID_ARGUMENT` | Bad argument value |
| 5 | `TRONA_OUT_OF_MEMORY` | No memory available |
| 6 | `TRONA_NOT_FOUND` | Object not found (empty slot, unmapped page) |
| 7 | `TRONA_BUSY` | Resource is busy (e.g., thread is Running) |
| 8 | `TRONA_ALREADY_EXISTS` | Resource already exists (mapped page, occupied slot) |
| 9 | `TRONA_WOULD_BLOCK` | Non-blocking operation has no work |
| 10 | `TRONA_BAD_ADDRESS` | Invalid memory address |
| 11 | `TRONA_OUT_OF_RANGE` | Value exceeds valid range |
| 12 | `TRONA_CANCELLED` | Operation was cancelled or timed out |
| 13 | `TRONA_RESTART` | Syscall should be restarted |
| 14 | `TRONA_DEADLOCK` | Deadlock detected |
| 15 | `TRONA_INTERRUPTED` | Interrupted by notification dispatch |
| 0x10 | `TRONA_IN_PROGRESS` | Async operation in progress |
| 0x80 | `TRONA_PENDING` | Deferred result pending |

---

## 6. Kernel Object Types

Object type constants for `Untyped_Retype` (invoke label 0x20):

| Value | Name | Description |
|-------|------|-------------|
| 1 | `OBJ_UNTYPED` | Raw physical memory |
| 2 | `OBJ_ENDPOINT` | Synchronous IPC channel |
| 3 | `OBJ_NOTIFICATION` | Async signaling primitive |
| 4 | `OBJ_TCB` | Thread control block |
| 5 | `OBJ_CNODE` | Capability storage node |
| 6 | `OBJ_VSPACE` | Virtual address space (page table root) |
| 7 | `OBJ_FRAME` | Physical memory page (min size_bits=12 for 4KB) |
| 8 | `OBJ_IRQ_HANDLER` | Interrupt handler object |
| 9 | `OBJ_IO_PORT` | I/O port range (x86_64 only) |
| 10 | `OBJ_SCHED_CONTEXT` | Scheduling parameters |
| 11 | `OBJ_MEMORY_OBJECT` | Memory object (page-granular backing store) |

---

## 7. Capability Rights

Capabilities carry a rights bitmask that restricts permitted operations.

| Constant | Value | Description |
|----------|-------|-------------|
| `CAP_RIGHTS_ALL` | 0xFFFF_FFFF | All rights granted |

Individual rights (READ, WRITE, GRANT, etc.) are checked by invoke handlers.
The `CNode_Copy` operation accepts a rights mask to restrict the copy.

---

## 8. Well-Known Virtual Addresses

| Constant | Value | Description |
|----------|-------|-------------|
| `BOOTINFO_VADDR` | 0x0000_0000_001F_F000 | BootInfo structure (init task only) |
| `INITRD_VADDR` | 0x0000_0000_0100_0000 | Initrd CPIO archive mapping |
| `SCRATCH_VADDR` | 0x0000_0000_0200_0000 | Scratch memory region |

---

## 9. Subsystem IDs

Used by procmgr to track per-process personality state:

| Value | Name | Description |
|-------|------|-------------|
| 0 | `SUBSYSTEM_POSIX` | POSIX personality |
| 1 | `SUBSYSTEM_WIN32` | Win32 personality |
| 2 | `SUBSYSTEM_STARNITE` | Starnite Linux compatibility (planned) |

---

## Cross-References

- [System Call Reference](syscalls.md) -- full syscall table and invoke labels
- [Boot Protocol](boot_protocol.md) -- kernel entry state and BootInfo ABI
- [trona API Reference](trona-api.md) -- userspace syscall wrappers
- [Capability Design](../design/capability.md) -- capability model details
- [IPC Design](../design/ipc.md) -- IPC protocol design
