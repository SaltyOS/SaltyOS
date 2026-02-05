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
  RDX  - Argument 2
  R10  - Argument 3 (RCX is clobbered by SYSCALL instruction)
  R8   - Argument 4
  R9   - Argument 5 (reserved)

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

## IPC System Calls

### Send (0)

Send a message through an endpoint capability.

```c
long sys_send(
    cap_t endpoint,     // Endpoint capability
    uint64_t msg_info,  // Message info word
    uint64_t mr0,       // Message register 0
    uint64_t mr1,       // Message register 1
    uint64_t mr2,       // Message register 2
    uint64_t mr3        // Message register 3
);
```

**Arguments:**
- `endpoint`: Capability to endpoint (must have SEND right)
- `msg_info`: Encoded message info (see below)
- `mr0-mr3`: Message registers (inline data)

**Message Info Format:**
```
┌─────────────────────────────────────────────────────────────────┐
│  63:12  │  11:8   │   7:4    │   3:0   │
│ Reserved│ExtraCaps│ CapsUnwr │ Length  │
└─────────────────────────────────────────────────────────────────┘
```
- `Length`: Number of message words (0-15)
- `CapsUnwr`: Number of capabilities to unwrap
- `ExtraCaps`: Number of extra capabilities to transfer

**Returns:**
- `0`: Success
- `-EINVAL`: Invalid capability
- `-EPERM`: Insufficient rights
- `-ENOENT`: Endpoint deleted

**Behavior:**
- If receiver is waiting: immediate transfer, both threads resume
- If no receiver: sender blocks until receiver arrives

---

### Recv (1)

Receive a message from an endpoint.

```c
long sys_recv(
    cap_t endpoint,         // Endpoint capability
    uint64_t *sender_badge, // Output: sender's badge
    uint64_t *msg_info,     // Output: message info
    uint64_t *mr0,          // Output: message register 0
    uint64_t *mr1,          // Output: message register 1
    uint64_t *mr2,          // Output: message register 2
    uint64_t *mr3           // Output: message register 3
);
```

**Arguments:**
- `endpoint`: Capability to endpoint (must have RECV right)

**Returns:**
- `>= 0`: Sender's badge
- `-EINVAL`: Invalid capability
- `-EPERM`: Insufficient rights

**Behavior:**
- If sender is waiting: immediate transfer
- If no sender: receiver blocks until sender arrives
- If thread has bound notification and it's pending: returns notification instead

---

### Call (2)

Send a message and wait for reply (RPC pattern).

```c
long sys_call(
    cap_t endpoint,     // Endpoint capability
    uint64_t msg_info,  // Message info word
    uint64_t mr0,       // Message register 0
    uint64_t mr1,       // Message register 1
    uint64_t mr2,       // Message register 2
    uint64_t mr3        // Message register 3
);
```

**Arguments:**
- `endpoint`: Capability to endpoint (must have CALL right)
- `msg_info`: Message info word
- `mr0-mr3`: Message registers

**Returns:**
- `>= 0`: Reply message info
- Negative: Error code

**Behavior:**
1. Generates one-shot reply capability
2. Sends message with reply cap
3. Blocks waiting for reply
4. Returns reply message

---

### ReplyRecv (3)

Reply to current caller and wait for next request.

```c
long sys_reply_recv(
    cap_t endpoint,     // Endpoint to receive on
    uint64_t msg_info,  // Reply message info
    uint64_t mr0,       // Reply message register 0
    uint64_t mr1,
    uint64_t mr2,
    uint64_t mr3
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
    cap_t endpoint,
    uint64_t msg_info,
    uint64_t mr0,
    uint64_t mr1,
    uint64_t mr2,
    uint64_t mr3
);
```

**Returns:**
- `0`: Message sent
- `-EWOULDBLOCK`: No receiver waiting

---

### Signal (5)

Signal a notification.

```c
long sys_signal(
    cap_t notification,  // Notification capability
    uint64_t bits        // Bits to set
);
```

**Arguments:**
- `notification`: Notification capability (must have WRITE right)
- `bits`: Bits to OR into notification word

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
    cap_t notification   // Notification capability
);
```

**Arguments:**
- `notification`: Notification capability (must have READ right)

**Returns:**
- `>= 0`: Notification word value (word is cleared)
- Negative: Error code

**Behavior:**
- If notification word is non-zero: returns immediately with value
- If zero: blocks until signaled

---

### Poll (7)

Non-blocking notification check.

```c
long sys_poll(
    cap_t notification
);
```

**Returns:**
- `>= 0`: Notification word value
- `-EWOULDBLOCK`: No notification pending

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
    cap_t capability,    // Capability to invoke
    uint64_t label,      // Operation label
    uint64_t *msg        // Message buffer
);
```

This is the generic syscall for all capability operations not covered by IPC.

The `label` determines the operation. The message buffer contains operation-specific arguments.

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

#### TCB_Configure (0x40)

Configure a thread's entry point, stack, and IPC buffer. The fault handler endpoint is set separately via `TCB_BindNotification`.

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

**Returns:** RIP in value field. Requires READ right. Returns `EBUSY` if thread is Running.

#### TCB_WriteRegisters (0x46)

Write a thread's saved registers. Thread must not be Running.

```
arg0 = flags         (bit 0: resume thread after write)
arg1 = rip           (new instruction pointer)
arg2 = rsp           (new stack pointer)
```

Requires WRITE right. Returns `EBUSY` if thread is Running.

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

Returns `EBUSY` if a notification is already bound.

#### TCB_UnbindNotification (0x4A)

Unbind the current notification from this thread.

Returns `InvalidOperation` if no notification is bound.

---

### CNode Invocations

| Label | Operation | Description |
|-------|-----------|-------------|
| 0x10 | `CNode_Copy` | Copy capability |
| 0x11 | `CNode_Mint` | Copy with badge |
| 0x12 | `CNode_Move` | Move capability |
| 0x13 | `CNode_Mutate` | Move with badge |
| 0x14 | `CNode_Delete` | Delete capability |
| 0x15 | `CNode_Revoke` | Revoke derived capabilities |
| 0x16 | `CNode_SaveCaller` | Save reply capability |

#### CNode_Copy

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
| Value | Type |
|-------|------|
| 1 | Untyped |
| 2 | Endpoint |
| 3 | Notification |
| 4 | TCB |
| 5 | CNode |
| 6 | VSpace |
| 7 | Frame |
| 8 | IrqHandler |
| 9 | IoPort |
| 10 | SchedContext |

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
0x000   8      Message Info
0x008   8      MR0
0x010   8      MR1
0x018   8      MR2
0x020   8      MR3
0x028   128    Extra MRs (MR4-MR19)
0x0A8   8      Badge (receive only)
0x0B0   8      Receive CNode
0x0B8   8      Receive Index
0x0C0   8      Receive Depth
0x0C8   128    Capability receive slots
0x148   ...    Reserved
```

## Example Usage

### Simple RPC

```c
// Client side
uint64_t result = sys_call(
    server_endpoint,
    MAKE_MSG_INFO(2, 0, 0),  // 2 words, 0 caps
    REQUEST_ADD,             // mr0: operation
    42,                      // mr1: argument
    0, 0
);
// Result in mr0

// Server side
for (;;) {
    uint64_t badge;
    uint64_t msg_info = sys_recv(endpoint, &badge, ...);

    uint64_t op = mr0;
    uint64_t arg = mr1;

    uint64_t result = handle_request(op, arg);

    sys_reply_recv(endpoint,
        MAKE_MSG_INFO(1, 0, 0),
        result, 0, 0, 0
    );
}
```
