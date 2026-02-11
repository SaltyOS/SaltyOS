# System Call Reference

This document defines the system call interface for SaltyOS.

## Overview

SaltyOS uses a capability-invocation model for system calls. Most operations are performed by invoking capabilities rather than traditional numbered system calls.

### Calling Convention (x86_64)

```
User Registers (before SYSCALL instruction):
  RAX  - System call number
  RDI  - Argument 0 (capability pointer)
  RSI  - Argument 1 (msg_info / label)
  RDX  - Argument 2 (mr0 / arg0)
  R10  - Argument 3 (mr1 / arg1) — RCX is clobbered by SYSCALL
  R8   - Argument 4 (mr2 / arg2)
  R9   - Argument 5 (mr3 / arg3)

Return:
  RAX  - Error code (0 = success)
  RDX  - Return value (syscall-specific)

Note: RCX and R11 are clobbered by the SYSCALL instruction (RCX=RIP, R11=RFLAGS).
```

### System Call Entry

```nasm
; User-space syscall wrapper
syscall_invoke:
    mov r10, rcx        ; Save arg4 (RCX clobbered by SYSCALL)
    syscall
    ret
```

## System Call Table

| Number | Name | Description |
|--------|------|-------------|
| 0 | `Send` | Send message via endpoint |
| 1 | `Recv` | Receive message from endpoint |
| 2 | `Call` | Send and wait for reply |
| 3 | `ReplyRecv` | Reply to caller and wait for next |
| 4 | `NBSend` | Non-blocking send |
| 5 | `Signal` | Signal a notification |
| 6 | `Wait` | Wait on a notification |
| 7 | `Poll` | Non-blocking notification check |
| 8 | `Yield` | Yield CPU time |
| 9 | `Invoke` | Invoke capability (generic) |
| 10 | `DebugPutChar` | Debug output (development only) |
| 11 | `DebugDumpState` | Dump thread state (development only) |
| 12 | `ClockGetTime` | Read monotonic clock (nanoseconds) |
| 13 | `NanoSleep` | Sleep for specified duration |
| 14 | `DebugPutStr` | Debug string output (development only) |
| 15 | `DebugPutBuf` | Debug buffer output (development only) |

## Message Info Word Format

All IPC syscalls (Send, Recv, Call, ReplyRecv, NBSend) use a packed `msg_info` word in RSI:

```
┌─────────────────────────────────────────────────────────────────┐
│  63:52   │  51:12   │  11:7     │  6:0    │
│ Reserved │  Label   │ ExtraCaps │ Length  │
└─────────────────────────────────────────────────────────────────┘
```

| Field | Bits | Description |
|-------|------|-------------|
| Length | 6:0 | Number of message registers used (0-127) |
| ExtraCaps | 11:7 | Number of capabilities to transfer via IPC buffer (0-31) |
| Label | 51:12 | Application-defined message label (40 bits) |
| Reserved | 63:52 | Must be zero |

```c
#define SALTY_MSGINFO(label, length, extra_caps) \
    (((uint64_t)(label) << 12) | \
     ((uint64_t)(extra_caps) << 7) | \
     ((uint64_t)(length) & 0x7F))
```

## IPC System Calls

### Send (0)

Send a message through an endpoint capability.

```c
long sys_send(
    cap_t endpoint,     // RDI: Endpoint capability
    uint64_t msg_info,  // RSI: Message info word
    uint64_t mr0,       // RDX: Message register 0
    uint64_t mr1,       // R10: Message register 1
    uint64_t mr2,       // R8:  Message register 2
    uint64_t mr3        // R9:  Message register 3
);
```

**Arguments:**
- `endpoint`: Capability to endpoint (must have SEND right)
- `msg_info`: Packed message info (label, length, extra_caps)
- `mr0-mr3`: Inline message registers

**Returns:**
- `0`: Success
- `1` (InvalidCapability): Invalid capability
- `3` (InsufficientRights): Missing SEND right

**Behavior:**
- If receiver is waiting: immediate transfer, both threads resume
- If no receiver: sender blocks until receiver arrives

---

### Recv (1)

Receive a message from an endpoint.

```c
long sys_recv(
    cap_t endpoint,     // RDI: Endpoint capability
    uint64_t msg_info,  // RSI: (unused on input)
    // Returns: msg_info in RSI, mr0-mr3 in RDX/R10/R8/R9, badge in RDX
);
```

**Arguments:**
- `endpoint`: Capability to endpoint (must have RECV right)

**Returns:**
- RAX = `0`: Success, badge in RDX
- RAX = `1`: Invalid capability

**Behavior:**
- If sender is waiting: immediate transfer
- If no sender: receiver blocks until sender arrives
- Message registers and badge are written to the caller's saved registers

---

### Call (2)

Send a message and wait for reply (RPC pattern).

```c
long sys_call(
    cap_t endpoint,     // RDI: Endpoint capability
    uint64_t msg_info,  // RSI: Message info word
    uint64_t mr0,       // RDX: Message register 0
    uint64_t mr1,       // R10: Message register 1
    uint64_t mr2,       // R8:  Message register 2
    uint64_t mr3        // R9:  Message register 3
);
```

**Arguments:**
- `endpoint`: Capability to endpoint (must have CALL right)
- `msg_info`: Message info word
- `mr0-mr3`: Message registers

**Returns:**
- RAX = `0`: Success, reply message in MR registers
- RAX = error code on failure

**Behavior:**
1. Sends message (with implicit reply capability)
2. Blocks waiting for reply
3. Returns reply message in MR registers

---

### ReplyRecv (3)

Reply to current caller and wait for next request.

```c
long sys_reply_recv(
    cap_t endpoint,     // RDI: Endpoint to receive on
    uint64_t msg_info,  // RSI: Reply message info
    uint64_t mr0,       // RDX: Reply message register 0
    uint64_t mr1,       // R10: Reply MR1
    uint64_t mr2,       // R8:  Reply MR2
    uint64_t mr3        // R9:  Reply MR3
);
```

**Behavior:**
1. Sends reply to saved caller (from previous Call)
2. Immediately waits for next message on endpoint
3. Atomic operation (no window for missed messages)

---

### NBSend (4)

Non-blocking send.

```c
long sys_nbsend(
    cap_t endpoint,     // RDI
    uint64_t msg_info,  // RSI
    uint64_t mr0,       // RDX
    uint64_t mr1,       // R10
    uint64_t mr2,       // R8
    uint64_t mr3        // R9
);
```

**Returns:**
- `0`: Message sent
- `9` (WouldBlock): No receiver waiting

---

### Signal (5)

Signal a notification.

```c
long sys_signal(
    cap_t notification,  // RDI: Notification capability
    uint64_t bits        // RSI: Bits to set (passed in msg_info position)
);
```

**Arguments:**
- `notification`: Notification capability (must have WRITE right)
- `bits`: Bits to OR into notification word (passed in RSI)

**Returns:**
- `0`: Success

**Behavior:**
- Atomically ORs bits into notification word
- If thread is waiting, wakes it

---

### Wait (6)

Wait on a notification.

```c
long sys_wait(
    cap_t notification   // RDI: Notification capability
);
```

**Arguments:**
- `notification`: Notification capability (must have READ right)

**Returns:**
- RAX = `0`, RDX = notification word value (word is cleared)
- RAX = error code on failure

**Behavior:**
- If notification word is non-zero: returns immediately with value
- If zero: blocks until signaled

---

### Poll (7)

Non-blocking notification check.

```c
long sys_poll(
    cap_t notification   // RDI
);
```

**Returns:**
- RAX = `0`, RDX = notification word value
- RAX = `9` (WouldBlock): No notification pending

---

### Yield (8)

Voluntarily yield CPU.

```c
long sys_yield(void);
```

**Returns:**
- `0`: Always succeeds

**Behavior:**
- Moves thread to end of ready queue
- Scheduler picks next thread

## Capability Invocation

### Invoke (9)

Generic capability invocation.

```c
long sys_invoke(
    cap_t capability,    // RDI: Capability to invoke
    uint64_t label,      // RSI: Operation label (msg_info format)
    uint64_t arg0,       // RDX: Operation argument 0
    uint64_t arg1,       // R10: Operation argument 1
    uint64_t arg2,       // R8:  Operation argument 2
    uint64_t arg3        // R9:  Operation argument 3
);
```

The `label` field (extracted from msg_info bits 51:12) determines the operation. Arguments are operation-specific.

### DebugPutChar (10)

Write a character to the kernel debug serial port. Development use only.

```c
long sys_debug_putchar(
    char c               // RDI: Character to output (cast to u64)
);
```

### DebugDumpState (11)

Dump the current thread's register state to the kernel debug serial port.

```c
long sys_debug_dump_state(void);
```

### ClockGetTime (12)

Read the monotonic clock. Returns the current time in nanoseconds.

```c
long sys_clock_gettime(
    uint64_t clock_id   // RDI: 0 = CLOCK_REALTIME, 1 = CLOCK_MONOTONIC
);
```

**Returns:**
- RAX = `0`, RDX = time in nanoseconds
- RAX = `4` (InvalidArgument): clock_id > 1

### NanoSleep (13)

Sleep for the specified duration.

```c
long sys_nanosleep(
    uint64_t seconds,      // RDI: Whole seconds to sleep
    uint64_t nanoseconds   // RSI: Additional nanoseconds (0-999,999,999)
);
```

**Returns:**
- RAX = `0`: Sleep completed
- RAX = `4` (InvalidArgument): nanoseconds >= 1,000,000,000

**Behavior:**
- If duration is 0, returns immediately
- Thread is blocked until the wakeup time is reached

### DebugPutStr (14)

Write a string to the kernel debug serial port. Development use only.

```c
long sys_debug_putstr(
    const char *buf,    // RDI: Pointer to string buffer
    uint64_t len        // RSI: String length in bytes
);
```

### DebugPutBuf (15)

Write a buffer to the kernel debug serial port. Development use only.

```c
long sys_debug_putbuf(
    const char *buf,    // RDI: Pointer to buffer
    uint64_t len        // RSI: Buffer length in bytes
);
```

## Capability Operations

### TCB Invocations

| Label | Operation | Description |
|-------|-----------|-------------|
| 0x40 | `TCB_Configure` | Configure thread (entry, stack, IPC buffer) |
| 0x41 | `TCB_Resume` | Resume thread |
| 0x42 | `TCB_Suspend` | Suspend thread |
| 0x43 | `TCB_SetSpace` | Set CSpace/VSpace roots |
| 0x44 | `TCB_SetAffinity` | Set CPU affinity (0xFFFFFFFF = any CPU) |
| 0x45 | `TCB_ReadRegisters` | Read saved registers |
| 0x46 | `TCB_WriteRegisters` | Write saved registers |
| 0x47 | `TCB_SetPriority` | Set scheduling priority |
| 0x48 | `TCB_SetIPCBuffer` | Set IPC buffer address |
| 0x49 | `TCB_BindNotification` | Bind notification for combined wait |
| 0x4A | `TCB_UnbindNotification` | Unbind notification |
| 0x4B | `TCB_SetFaultHandler` | Set fault handler endpoint |

#### TCB_Configure (0x40)

Configure a thread's entry point, stack, and IPC buffer.

```
arg0 = entry_rip     (instruction pointer)
arg1 = entry_rsp     (stack pointer)
arg2 = ipc_buffer    (IPC buffer virtual address)
```

#### TCB_SetAffinity (0x44)

```
arg0 = cpu_id        (target CPU, 0xFFFFFFFF = any CPU)
```

#### TCB_ReadRegisters (0x45)

Read a thread's saved registers. Thread must not be Running.

```
arg0 = flags         (reserved, must be 0)
```

**Returns:** RIP in value field. Requires READ right. Returns `Busy` if thread is Running.

#### TCB_WriteRegisters (0x46)

Write a thread's saved registers. Thread must not be Running.

```
arg0 = flags         (bit 0: resume thread after write)
arg1 = rip           (new instruction pointer)
arg2 = rsp           (new stack pointer)
```

Requires WRITE right. Returns `Busy` if thread is Running.

#### TCB_SetPriority (0x47)

Set thread scheduling priority (EDF deadline value).

```
arg0 = priority      (deadline value for EDF scheduling)
```

If thread is in Ready state, it is re-enqueued with the updated priority.

#### TCB_SetIPCBuffer (0x48)

```
arg0 = addr          (new IPC buffer virtual address)
```

#### TCB_BindNotification (0x49)

Bind a notification object to this thread for combined IPC wait.

```
arg0 = ntfn_cap_ptr  (capability pointer to Notification)
```

Returns `Busy` if a notification is already bound.

#### TCB_UnbindNotification (0x4A)

Unbind the current notification from this thread.

Returns `InvalidOperation` if no notification is bound.

#### TCB_SetFaultHandler (0x4B)

Set the fault handler endpoint for a thread. When the thread faults (e.g., page fault), a fault message is delivered to this endpoint.

```
arg0 = fault_ep_cap_ptr  (capability pointer to Endpoint)
```

The fault endpoint must be an Endpoint capability. Set to 0 to clear the fault handler.

---

### CNode Invocations

| Label | Operation | Description |
|-------|-----------|-------------|
| 0x10 | `CNode_Copy` | Copy capability with rights mask |
| 0x11 | `CNode_Mint` | Copy with badge (for endpoint badging) |
| 0x12 | `CNode_Move` | Move capability between CNodes |
| 0x13 | `CNode_Mutate` | Move with badge change |
| 0x14 | `CNode_Delete` | Delete single capability |
| 0x15 | `CNode_Revoke` | Revoke capability and all descendants |
| 0x16 | `CNode_SaveCaller` | Save reply capability to slot |

#### CNode_Copy (0x10)

Invoked on the **source** CNode capability.

```
Register mapping (via Invoke syscall):
  cap_ptr (RDI) - Source CNode capability (invoked)
  label   (RSI) - 0x10 (CNode_Copy)
  arg0    (RDX) - Source slot index within source CNode
  arg1    (R10) - Destination CNode capability pointer (looked up from CSpace)
  arg2    (R8)  - Destination slot index
  arg3    (R9)  - Rights mask
```

#### CNode_Mint (0x11)

Create a badged copy of a capability. Invoked on the **source** CNode.

```
  cap_ptr (RDI) - Source CNode capability (invoked)
  label   (RSI) - 0x11 (CNode_Mint)
  arg0    (RDX) - Source slot index
  arg1    (R10) - Destination CNode capability pointer
  arg2    (R8)  - Destination slot index
  arg3    (R9)  - Badge value
```

The new capability has the badge set and Grant right removed. Badged capabilities identify the sender to the receiver.

#### CNode_Move (0x12)

Move a capability from one CNode to another. Invoked on the **destination** CNode.

```
  cap_ptr (RDI) - Destination CNode capability (invoked)
  label   (RSI) - 0x12 (CNode_Move)
  arg0    (RDX) - Destination slot index
  arg1    (R10) - Source CNode capability pointer
  arg2    (R8)  - Source slot index
```

The source slot becomes empty after the move.

#### CNode_Mutate (0x13)

Move a capability and change its badge. Invoked on the **destination** CNode. Only works on endpoint capabilities.

```
  cap_ptr (RDI) - Destination CNode capability (invoked)
  label   (RSI) - 0x13 (CNode_Mutate)
  arg0    (RDX) - Destination slot index
  arg1    (R10) - Source CNode capability pointer
  arg2    (R8)  - Source slot index
  arg3    (R9)  - New badge value
```

#### CNode_Delete (0x14)

Delete a single capability from a CNode. Invoked on the CNode containing the capability.

```
  cap_ptr (RDI) - CNode capability (invoked)
  label   (RSI) - 0x14 (CNode_Delete)
  arg0    (RDX) - Slot index to delete
```

Fails with `HasChildren` error if the capability has derived children (use Revoke instead).

#### CNode_Revoke (0x15)

Revoke a capability and all its descendants in the CDT.

```
  cap_ptr (RDI) - CNode capability (invoked)
  label   (RSI) - 0x15 (CNode_Revoke)
  arg0    (RDX) - Slot index to revoke
```

#### CNode_SaveCaller (0x16)

Save the current thread's reply capability into a CNode slot. This enables deferred reply patterns where a server can reply to a client later rather than immediately in ReplyRecv.

```
  cap_ptr (RDI) - CNode capability (invoked)
  label   (RSI) - 0x16 (CNode_SaveCaller)
  arg0    (RDX) - Destination slot index
```

The reply capability is one-shot and is cleared from the current thread's TCB.

---

### VSpace Invocations

| Label | Operation | Description |
|-------|-----------|-------------|
| 0x50 | `VSpace_Map` | Map frame into VSpace |
| 0x51 | `VSpace_Unmap` | Unmap page |
| 0x52 | `VSpace_MapPT` | Install page table at specific level |

#### VSpace_Map (0x50)

```
arg0 = frame_cap_ptr  (capability pointer to frame)
arg1 = virt_addr       (virtual address to map at)
arg2 = flags_bits      (see flags below)
```

**Flags bits:**
| Bit | Name | Description |
|-----|------|-------------|
| 0 | writable | Page is writable |
| 1 | user | Page is accessible from user mode |
| 2 | executable | Page is executable (NX cleared) |
| 3 | cache_disable | PCD: disable caching (for MMIO) |
| 4 | write_through | PWT: write-through caching |

#### VSpace_MapPT (0x52)

Install a pre-allocated page table frame into the page table hierarchy.

```
arg0 = frame_cap_ptr  (capability pointer to frame for page table)
arg1 = virt_addr       (virtual address to install table for)
arg2 = level           (1=PT, 2=PD, 3=PDPT)
```

The frame is zeroed and installed as a page table at the specified level. Returns `AlreadyExists` if an entry already exists at that level.

---

### Untyped Invocations

| Label | Operation | Description |
|-------|-----------|-------------|
| 0x20 | `Untyped_Retype` | Create typed objects |

#### Untyped_Retype (0x20)

```
arg0 = object_type   (ObjectType enum, 1..=10)
arg1 = size_bits     (for variable-size objects)
arg2 = dest_offset   (destination slot index in current CSpace)
```

**Object Types:**
| Value | Type | Description |
|-------|------|-------------|
| 1 | Untyped | Raw physical memory |
| 2 | Endpoint | Synchronous IPC channel |
| 3 | Notification | Async signaling primitive |
| 4 | TCB | Thread control block |
| 5 | CNode | Capability storage node |
| 6 | VSpace | Virtual address space (PML4) |
| 7 | Frame | Physical memory page (min size_bits=12 for 4KB) |
| 8 | IrqHandler | Interrupt handler object |
| 9 | IoPort | I/O port range |
| 10 | SchedContext | Scheduling parameters |

---

### SchedContext Invocations

| Label | Operation | Description |
|-------|-----------|-------------|
| 0x30 | `SC_Configure` | Configure parameters (budget, period) |
| 0x31 | `SC_Bind` | Bind to TCB |
| 0x32 | `SC_Unbind` | Unbind from TCB |
| 0x33 | `SC_YieldTo` | Yield to another SC |
| 0x34 | `SC_Consumed` | Query consumed time |

#### SC_Configure (0x30)

```
arg0 = budget_us     (budget per period, in microseconds, must be > 0)
arg1 = period_us     (period in microseconds, 0 = sporadic, else >= budget)
```

Converted internally: 1 tick = 1ms = 1000us. Budget must be at least 1000us (1 tick).

#### SC_Consumed (0x34)

Query cumulative consumed time (in ticks) for this scheduling context.

**Returns:** Consumed ticks in value field. Requires READ right.

---

### IRQ Invocations

| Label | Operation | Description |
|-------|-----------|-------------|
| 0x60 | `IRQControl_Get` | Acquire IRQ handler for a specific IRQ |
| 0x61 | `IRQHandler_Ack` | Acknowledge IRQ (re-enable delivery) |
| 0x62 | `IRQHandler_SetNotification` | Bind notification to IRQ |
| 0x63 | `IRQHandler_Clear` | Unbind notification from IRQ |

#### IRQControl_Get (0x60)

Register a hardware IRQ handler. The invoked capability is the IRQ handler object.

```
arg0 = irq_num       (hardware IRQ number, 0-255)
arg1 = dest_cnode    (reserved)
arg2 = dest_slot     (reserved)
```

Returns `AlreadyExists` if the IRQ already has a handler. Returns `OutOfRange` if irq_num >= 256.

#### IRQHandler_Ack (0x61)

Acknowledge an IRQ after handling it. Until acknowledged, the IRQ will not be delivered again (edge-triggered model).

#### IRQHandler_SetNotification (0x62)

Bind a notification to the IRQ handler. When the IRQ fires, the notification is signaled with `1 << (irq_num % 64)`.

```
arg0 = ntfn_cap_ptr  (capability pointer to Notification)
```

#### IRQHandler_Clear (0x63)

Unbind the notification from the IRQ handler.

---

### IoPort Invocations

I/O port capabilities provide controlled access to x86 I/O ports. Each IoPort capability covers a range of ports (base address + size).

| Label | Operation | Description |
|-------|-----------|-------------|
| 0x70 | `IoPort_In8` | Read 8-bit value from port |
| 0x71 | `IoPort_Out8` | Write 8-bit value to port |
| 0x72 | `IoPort_In16` | Read 16-bit value from port |
| 0x73 | `IoPort_Out16` | Write 16-bit value to port |

#### IoPort_In8 (0x70)

Read an 8-bit value from an I/O port.

```
arg0 = offset        (port offset within the IoPort range)
```

**Returns:** Value in RDX. Requires READ right.

#### IoPort_Out8 (0x71)

Write an 8-bit value to an I/O port.

```
arg0 = offset        (port offset within the IoPort range)
arg1 = value         (8-bit value to write)
```

Requires WRITE right.

#### IoPort_In16 (0x72)

Read a 16-bit value from an I/O port.

```
arg0 = offset        (port offset within the IoPort range)
```

**Returns:** Value in RDX. Requires READ right.

#### IoPort_Out16 (0x73)

Write a 16-bit value to an I/O port.

```
arg0 = offset        (port offset within the IoPort range)
arg1 = value         (16-bit value to write)
```

Requires WRITE right.

---

## Error Codes

SaltyOS uses positive error codes (returned in RAX).

| Code | Name | Description |
|------|------|-------------|
| 0 | `None` | Success |
| 1 | `InvalidCapability` | Capability is null or invalid |
| 2 | `InvalidOperation` | Wrong object type or unsupported operation |
| 3 | `InsufficientRights` | Capability lacks required rights |
| 4 | `InvalidArgument` | Bad argument value |
| 5 | `OutOfMemory` | No memory available |
| 6 | `NotFound` | Object not found (empty slot, unmapped page) |
| 7 | `Busy` | Resource is busy (e.g., thread is Running) |
| 8 | `AlreadyExists` | Resource already exists (mapped page, occupied slot) |
| 9 | `WouldBlock` | Non-blocking operation has no work |
| 10 | `BadAddress` | Invalid memory address |
| 11 | `OutOfRange` | Value exceeds valid range |
| 12 | `Cancelled` | Operation was cancelled |
| 13 | `Restart` | Syscall should be restarted |
| 14 | `Deadlock` | Deadlock detected |

## IPC Buffer Layout

```
Offset  Size   Field
──────  ─────  ─────────────────
0x000   160    msg[20] — Message registers MR0-MR19
0x0A0   8      badge — Received sender badge
0x0A8   32     caps[4] — Capability slots to transfer (sender-side)
0x0C8   8      receive_cnode — CNode cap for receiving caps
0x0D0   8      receive_index — Starting slot index in receive CNode
0x0D8   8      receive_depth — CNode depth for cap lookup
0x0E0   3840   reserved[480] — Reserved for future use
──────  ─────  ─────────────────
Total:  4096   (one 4KB page)
```

MR0-MR3 are passed in CPU registers for the fastpath. MR4-MR19 overflow to the IPC buffer when length > 4.

## Example Usage

### Simple RPC

```c
// Client side
struct salty_msg msg = {
    .label = REQUEST_ADD,
    .length = 2,
    .regs = { 42, 0, 0, 0 },
};
salty_call(server_ep, &msg);
uint64_t result = msg.regs[0];

// Server side
struct salty_msg msg, reply;
uint64_t badge;
salty_recv(endpoint, &msg, &badge);

for (;;) {
    uint64_t result = handle_request(msg.label, msg.regs[0]);

    reply.label = SALTY_OK;
    reply.length = 1;
    reply.regs[0] = result;

    salty_reply_recv(endpoint, &reply, &msg, &badge);
}
```
