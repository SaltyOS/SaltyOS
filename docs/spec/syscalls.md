# System Call Reference

This document defines the system call interface for SaltyOS.

## Overview

SaltyOS uses a capability-invocation model for system calls. Most operations are performed by invoking capabilities rather than traditional numbered system calls.

### Calling Conventions

For the complete ABI specification including both x86_64 and aarch64 register
conventions, IPC buffer layout, message info encoding, and VSpace page flags,
see [abi.md](abi.md).

#### x86_64

```
Entry: SYSCALL instruction
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

#### aarch64

```
Entry: SVC #0 instruction
  x8   - System call number
  x0   - Argument 0 (capability pointer)
  x1   - Argument 1 (msg_info / label)
  x2   - Argument 2 (MR0 / arg0)
  x3   - Argument 3 (MR1 / arg1)
  x4   - Argument 4 (MR2 / arg2)
  x5   - Argument 5 (MR3 / arg3)

Return:
  x0   - Error code (0 = success)
  x1   - Return value (syscall-specific)
```

### System Call Entry

```nasm
; x86_64 user-space syscall wrapper
syscall_invoke:
    mov r10, rcx        ; Save arg3 (RCX clobbered by SYSCALL)
    syscall
    ret
```

```asm
// aarch64 user-space syscall wrapper
syscall_invoke:
    mov x8, x7          // syscall number from argument
    svc #0
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
| 16 | `DebugConsoleControl` | Enable/disable kernel console (development only) |
| 17 | `SetInvokeDepths` | Set CNode resolve depths for invoke |
| 18 | `Futex` | Userspace futex operations |
| 19 | `GetRandom` | Get random bytes via RDRAND |
| 20 | `Shutdown` | ACPI system shutdown |
| 21 | `SendTimed` | Blocking send with timeout |
| 22 | `RecvTimed` | Blocking receive with timeout |
| 23 | `RecvAny` | Receive from any of multiple endpoints |
| 24 | `ReplyRecvAny` | Reply and wait on any of multiple endpoints |
| 25 | `RecvAnyTimed` | RecvAny with timeout |
| 26 | `ReplyRecvAnyTimed` | ReplyRecvAny with timeout |
| 27 | `NotifReturn` | Return from notification dispatcher |

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
#define TRONA_MSGINFO(label, length, extra_caps) \
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

### DebugConsoleControl (16)

Enable or disable the kernel debug console. Development use only.

```c
long sys_debug_console_control(
    uint64_t enable     // RDI: 1 = enable, 0 = disable
);
```

**Arguments:**
- `enable`: Non-zero to enable kernel console output, zero to disable

**Returns:**
- `0`: Success

---

### SetInvokeDepths (17)

Set CNode resolve depths for subsequent invoke operations.

```c
long sys_set_invoke_depths(
    uint64_t src_depth,  // RDI: Source CNode resolve depth
    uint64_t dst_depth   // RSI: Destination CNode resolve depth
);
```

**Arguments:**
- `src_depth`: Bit depth for resolving the source CNode capability
- `dst_depth`: Bit depth for resolving the destination CNode capability

**Returns:**
- `0`: Success
- `4` (InvalidArgument): Depth out of valid range

---

### Futex (18)

Userspace futex operations for synchronization primitives.

```c
long sys_futex(
    uint64_t *addr,      // RDI: Pointer to futex word
    uint64_t op,         // RSI: Operation (0=wait, 1=wake, 2=wait_timeout)
    uint64_t val,        // RDX: Expected value (wait) or count (wake)
    uint64_t timeout_ns  // R10: Timeout in nanoseconds (wait_timeout only)
);
```

**Arguments:**
- `addr`: Pointer to a 64-bit futex word in user memory
- `op`: Operation code:
  - `0` (FUTEX_WAIT): Block if `*addr == val`
  - `1` (FUTEX_WAKE): Wake up to `val` waiters
  - `2` (FUTEX_WAIT_TIMEOUT): Block if `*addr == val`, with timeout
- `val`: Expected value for wait operations, or number of threads to wake
- `timeout_ns`: Timeout in nanoseconds (only for op=2)

**Returns:**
- RAX = `0`: Success (wait completed or threads woken)
- RAX = `9` (WouldBlock): `*addr != val` at time of check (wait operations)
- RAX = `4` (InvalidArgument): Invalid operation code
- RAX = `10` (BadAddress): Invalid futex address
- RAX = `12` (Cancelled): Wait timed out (op=2)

---

### GetRandom (19)

Return a hardware random 64-bit value via the RDRAND instruction.

```c
uint64_t sys_getrandom(void);
```

**Arguments:** None.

**Returns:**
- RAX = `0`, RDX = random 64-bit value
- RAX = `2` (InvalidOperation): RDRAND instruction unavailable

---

### Shutdown (20)

Initiate ACPI system shutdown. This powers off the machine.

```c
long sys_shutdown(void);
```

**Returns:**
- Does not return on success (system powers off)
- RAX = `2` (InvalidOperation): ACPI shutdown not available

---

### SendTimed (21)

Blocking send with a timeout.

```c
long sys_send_timed(
    cap_t endpoint,      // RDI: Endpoint capability
    uint64_t msg_info,   // RSI: Message info word
    uint64_t mr0,        // RDX: Message register 0
    uint64_t timeout_ns  // R10: Timeout in nanoseconds
);
```

**Arguments:**
- `endpoint`: Capability to endpoint (must have SEND right)
- `msg_info`: Packed message info (label, length, extra_caps)
- `mr0`: First message register
- `timeout_ns`: Maximum time to wait for a receiver, in nanoseconds

**Returns:**
- `0`: Success (message delivered)
- `1` (InvalidCapability): Invalid capability
- `3` (InsufficientRights): Missing SEND right
- `12` (Cancelled): Timeout expired before a receiver arrived

**Behavior:**
- Like Send, but returns with `Cancelled` if no receiver arrives within the timeout
- If timeout_ns is 0, behaves like NBSend

---

### RecvTimed (22)

Blocking receive with a timeout.

```c
long sys_recv_timed(
    cap_t endpoint,      // RDI: Endpoint capability
    uint64_t timeout_ns  // RSI: Timeout in nanoseconds
);
```

**Arguments:**
- `endpoint`: Capability to endpoint (must have RECV right)
- `timeout_ns`: Maximum time to wait for a sender, in nanoseconds

**Returns:**
- RAX = `0`: Success, badge in RDX (sender badge; message written to IPC buffer)
- RAX = `1` (InvalidCapability): Invalid capability
- RAX = `12` (Cancelled): Timeout expired before a sender arrived

**Behavior:**
- Like Recv, but returns with `Cancelled` if no sender arrives within the timeout
- On success, the message is written to the thread's IPC buffer and the sender badge is returned in RDX

---

### RecvAny (23)

Receive from any of multiple endpoints. The endpoint capability pointers are
read from the thread's IPC buffer `reserved[]` area.

```c
long sys_recv_any(
    uint64_t endpoint_count  // RDI: Number of endpoints (read from IPC buffer)
);
```

**Arguments:**
- `endpoint_count`: Number of endpoint capability pointers stored in IPC buffer `reserved[0..N-1]`

**Returns:**
- RAX = `0`: Success, RDX = source endpoint index (0-based)
- RAX = `4` (InvalidArgument): Count is 0 or exceeds maximum, or duplicate endpoint
- RAX = `10` (BadAddress): Invalid IPC buffer address

**Behavior:**
- Reads endpoint capability pointers from the IPC buffer's `reserved[0..N-1]` words
- Blocks until a message arrives on any of the specified endpoints
- Message is written to the IPC buffer; badge is stored in `ipc_buffer.badge`
- Returns the index of the endpoint that received the message

---

### ReplyRecvAny (24)

Reply to current caller and wait for next message on any of multiple endpoints.

```c
long sys_reply_recv_any(
    uint64_t endpoint_count,  // RDI: Number of endpoints
    uint64_t msg_info,        // RSI: Reply message info
    uint64_t mr0,             // RDX: Reply MR0
    uint64_t mr1,             // R10: Reply MR1
    uint64_t mr2,             // R8:  Reply MR2
    uint64_t mr3              // R9:  Reply MR3
);
```

**Behavior:**
1. Sends reply to saved caller (from previous Call)
2. Waits for next message on any of the specified endpoints
3. Returns source endpoint index in RDX

---

### RecvAnyTimed (25)

RecvAny with a timeout.

```c
long sys_recv_any_timed(
    uint64_t endpoint_count,  // RDI: Number of endpoints
    uint64_t timeout_ns       // RSI: Timeout in nanoseconds
);
```

**Returns:**
- RAX = `0`: Success, RDX = source endpoint index
- RAX = `12` (Cancelled): Timeout expired

---

### ReplyRecvAnyTimed (26)

ReplyRecvAny with a timeout. The timeout is read from the IPC buffer at
`reserved[endpoint_count]` (the word immediately after the endpoint list).

```c
long sys_reply_recv_any_timed(
    uint64_t endpoint_count,  // RDI: Number of endpoints
    uint64_t msg_info,        // RSI: Reply message info
    uint64_t mr0,             // RDX: Reply MR0
    uint64_t mr1,             // R10: Reply MR1
    uint64_t mr2,             // R8:  Reply MR2
    uint64_t mr3              // R9:  Reply MR3
);
```

**Returns:**
- RAX = `0`: Success, RDX = source endpoint index
- RAX = `12` (Cancelled): Timeout expired

---

### NotifReturn (27)

Return from a notification dispatcher. Restores the user context from a
notification frame on the user stack.

```c
long sys_notif_return(
    uint64_t frame_ptr  // RDI: Pointer to NotifFrame on user stack
);
```

**Arguments:**
- `frame_ptr`: Pointer to a `NotifFrame` structure saved by the kernel when
  dispatching a notification signal

**Returns:**
- Always returns `15` (Interrupted). SA_RESTART is handled at the POSIX library
  level, not in the kernel, because:
  - The notification handler may have issued IPC that overwrote the IPC buffer
  - For ReplyRecv interruptions, the message was already delivered to the server
- RAX = `10` (BadAddress): Invalid frame pointer
- RAX = `4` (InvalidArgument): Invalid magic in NotifFrame

**Behavior:**
- Validates the NotifFrame magic and address
- Restores the full register context (GPRs, FPU/NEON state) from the frame
- Resumes execution at the point where the notification interrupted the thread

---

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
| 0x4C | `TCB_CopyFpu` | Copy FPU state between TCBs |
| 0x4D | `TCB_SetTlsBase` | Set thread-local storage base |
| 0x4E | `TCB_SetNotificationDispatcher` | Set notification dispatcher entry point |
| 0x4F | `TCB_GetSpaceInfo` | Read CSpace depth and address space info |

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

#### TCB_CopyFpu (0x4C)

Copy FPU/SSE state from one TCB to another. Used during fork to duplicate floating-point context.

```
arg0 = src_tcb_cap_ptr  (capability pointer to source TCB)
```

Copies the full FXSAVE/XSAVE area from the source TCB to the invoked TCB. Both TCBs must not be Running. Requires WRITE right on destination and READ right on source.

#### TCB_SetTlsBase (0x4D)

Set the thread-local storage base address (FS base register) for a thread.

```
arg0 = tls_base          (virtual address for FS base)
```

Sets the FS segment base (x86_64) or TPIDR_EL0 (aarch64) for the target thread. Takes effect on next context switch to the thread. Requires WRITE right.

#### TCB_SetNotificationDispatcher (0x4E)

Set the user-mode notification dispatcher entry point for a thread.

```
arg0 = dispatcher        (virtual address of dispatcher function, or 0 to clear)
```

When non-zero, the kernel injects a notification frame onto the user stack and
redirects control to this address instead of returning EINTR when a bound
notification fires during a blocking syscall. The thread uses `NotifReturn` (27)
to restore the original context after handling the notification.

Requires CONFIGURE right. Returns `InvalidArgument` if the address is in kernel
space (>= 0x0000_8000_0000_0000).

#### TCB_GetSpaceInfo (0x4F)

Read the CSpace depth (and future address space metadata) of a thread.

```
Returns via IPC buffer:
  msg[0] = cspace_depth   (0 = flat mode, non-zero = multi-level tree)
```

Requires READ right. Returns `InsufficientRights` otherwise.

Used by the substrate thread infrastructure to discover the current process's
CSpace depth when spawning worker threads via `tcb_set_space_with_depth`.

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
| 0x17 | `CNode_SetGuard` | Set CNode guard bits |
| 0x18 | `CNode_GetInfo` | Get CNode metadata |

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

#### CNode_SetGuard (0x17)

Set the guard bits for a CNode. Guards allow multiple CNodes to be composed into a multi-level CSpace via guarded page-table-like lookup.

```
  cap_ptr (RDI) - CNode capability (invoked)
  label   (RSI) - 0x17 (CNode_SetGuard)
  arg0    (RDX) - Guard value (bits to match during CSpace lookup)
  arg1    (R10) - Guard size in bits (0 = no guard)
```

Requires WRITE right. Returns `InvalidArgument` if guard size exceeds maximum.

#### CNode_GetInfo (0x18)

Query CNode metadata (size, guard, depth).

```
  cap_ptr (RDI) - CNode capability (invoked)
  label   (RSI) - 0x18 (CNode_GetInfo)
```

**Returns:** CNode size bits in RDX. Requires READ right.

---

### VSpace Invocations

| Label | Operation | Description |
|-------|-----------|-------------|
| 0x50 | `VSpace_Map` | Map frame into VSpace |
| 0x51 | `VSpace_Unmap` | Unmap page (tracking-aware for MO-backed VmAreas) |
| 0x52 | `VSpace_MapPT` | Install page table at specific level |
| 0x53 | `VSpace_Walk` | Walk page tables, return mapping info |
| 0x54 | `VSpace_CopyPage` | Copy page content between VSpaces |
| 0x55 | `VSpace_MapDevice` | Map device memory (uncacheable) |
| 0x56 | `VSpace_CloneCowPage` | Clone page with COW semantics |
| 0x57 | `VSpace_MapDeviceRange` | Batch device mapping |
| 0x58 | `VSpace_Protect` | Change page protection flags |
| 0x59 | `VSpace_MapDemand` | Map demand-paged region |
| 0x5A | `VSpace_MapDemandRange` | Batch demand-page mapping |
| 0x5B | `VSpace_CowResolve` | Resolve COW fault with new frame |
| 0x5C | `VSpace_SetCowPool` | Set COW page pool for fast resolution |
| 0x5D | `VSpace_SetCowNotif` | Set COW pool depletion notification |
| 0x5E | `VSpace_ReplenishCowPool` | Replenish COW page pool |
| 0x5F | `VSpace_ProtectRange` | Change protection for a range of pages |

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
| 5 | cow | Copy-on-write: page is shared read-only until written |

#### VSpace_MapPT (0x52)

Install a pre-allocated page table frame into the page table hierarchy.

```
arg0 = frame_cap_ptr  (capability pointer to frame for page table)
arg1 = virt_addr       (virtual address to install table for)
arg2 = level           (1=PT, 2=PD, 3=PDPT)
```

The frame is zeroed and installed as a page table at the specified level. Returns `AlreadyExists` if an entry already exists at that level.

#### VSpace_Walk (0x53)

Walk the page tables and return mapping information for a virtual address.

```
arg0 = virt_addr       (virtual address to query)
```

**Returns:** Physical address and flags in RDX if mapped, or `NotFound` if the address is not mapped. Requires READ right.

#### VSpace_CopyPage (0x54)

Copy page content from one VSpace to another.

```
arg0 = src_vspace_cap  (capability pointer to source VSpace)
arg1 = src_vaddr       (source virtual address)
arg2 = dst_vaddr       (destination virtual address in invoked VSpace)
```

Copies the contents of one 4KB page to another. Both pages must be mapped. Requires WRITE right on destination VSpace and READ right on source VSpace.

#### VSpace_MapDevice (0x55)

Map device memory (MMIO) with uncacheable attributes.

```
arg0 = frame_cap_ptr   (capability pointer to frame)
arg1 = virt_addr       (virtual address to map at)
arg2 = flags_bits      (flags with cache_disable forced on)
```

Like VSpace_Map but forces PCD (cache disable) and PWT (write-through) flags, suitable for memory-mapped I/O regions.

#### VSpace_CloneCowPage (0x56)

Clone a page with copy-on-write semantics.

```
arg0 = src_vaddr       (source virtual address)
arg1 = dst_vspace_cap  (capability pointer to destination VSpace)
arg2 = dst_vaddr       (destination virtual address)
```

Maps the same physical frame into the destination VSpace as read-only with the COW flag set. A write fault on either mapping triggers a copy.

#### VSpace_MapDeviceRange (0x57)

Batch device memory mapping for contiguous MMIO regions.

```
arg0 = frame_cap_ptr   (capability pointer to first frame)
arg1 = virt_addr       (starting virtual address)
arg2 = num_pages       (number of 4KB pages to map)
```

Maps `num_pages` contiguous frames starting at `frame_cap_ptr` with device (uncacheable) attributes.

#### VSpace_Protect (0x58)

Change protection flags on an existing page mapping.

```
arg0 = virt_addr       (virtual address of mapped page)
arg1 = new_flags       (new flags bits, same format as VSpace_Map)
```

Updates the page table entry flags without remapping. Requires WRITE right. Returns `NotFound` if the page is not mapped.

#### VSpace_MapDemand (0x59)

Map a demand-paged region. The physical frame is not allocated until first access.

```
arg0 = virt_addr       (virtual address to map)
arg1 = flags_bits      (flags for the eventual mapping)
```

Creates a page table entry that triggers a page fault on first access. The fault handler (mmsrv) allocates a frame and completes the mapping.

#### VSpace_MapDemandRange (0x5A)

Batch demand-page mapping for contiguous virtual regions.

```
arg0 = virt_addr       (starting virtual address)
arg1 = num_pages       (number of 4KB pages)
arg2 = flags_bits      (flags for the eventual mappings)
```

Like VSpace_MapDemand but for a contiguous range of pages.

#### VSpace_CowResolve (0x5B)

Resolve a COW fault by providing a new frame.

```
arg0 = virt_addr       (faulting virtual address)
arg1 = frame_cap_ptr   (capability pointer to new frame)
arg2 = flags_bits      (page flags for the new mapping)
```

#### VSpace_SetCowPool (0x5C)

Set a pool of pre-allocated frames for fast COW resolution.

```
arg0 = pool_frame_cap_ptr  (capability pointer to pool frame)
arg1 = src_cnode_cap_ptr   (CNode containing pool frames)
arg2 = count               (number of frames in pool)
```

#### VSpace_SetCowNotif (0x5D)

Set a notification to signal when the COW pool is depleted.

```
arg0 = ring_frame_cap_ptr  (capability pointer to ring buffer frame)
arg1 = notif_cap_ptr       (capability pointer to notification)
```

#### VSpace_ReplenishCowPool (0x5E)

Replenish the COW page pool with additional frames.

```
arg0 = src_cnode_cap_ptr   (CNode containing new frames)
arg1 = start_slot          (starting slot index)
arg2 = count               (number of frames to add)
```

#### VSpace_ProtectRange (0x5F)

Change protection flags for a contiguous range of pages.

```
arg0 = virt_addr       (starting virtual address)
arg1 = num_pages       (number of 4KB pages)
arg2 = flags_bits      (new page flags)
```

---

### VSpace MemoryObject Invocations

| Label | Operation | Description |
|-------|-----------|-------------|
| 0x97 | `VSpace_MapMO` | Map MemoryObject pages into VSpace |
| 0x99 | `VSpace_ShareRoPage` | Share a page read-only to another VSpace |
| 0x9A | `VSpace_ForkRange` | COW-fork a range of MO-backed pages |

#### VSpace_MapMO (0x97)

Map pages from a MemoryObject into the VSpace.

```
arg0 = mo_cap_ptr         (capability pointer to MemoryObject)
arg1 = vaddr              (virtual address to map at)
arg2 = mo_offset          (page offset within MO)
arg3 = count_and_flags    (page count in upper 32 bits, flags in lower 32 bits)
```

#### VSpace_ShareRoPage (0x99)

Share a page read-only from this VSpace to another.

```
arg0 = src_vaddr          (source virtual address)
arg1 = dst_vspace_cap_ptr (capability pointer to destination VSpace)
arg2 = dst_vaddr          (destination virtual address)
```

#### VSpace_ForkRange (0x9A)

COW-fork a range of MO-backed pages from parent to child VSpace.

```
arg0 = child_vspace_cap   (capability pointer to child VSpace)
arg1 = child_mo_cap       (capability pointer to child MemoryObject)
arg2 = va_start           (starting virtual address)
arg3 = count_and_offset   (page_count in upper 32 bits, mo_offset in lower 32 bits)
```

---

### MemoryObject Invocations

| Label | Operation | Description |
|-------|-----------|-------------|
| 0x90 | `MO_Commit` | Commit physical pages to MO |
| 0x91 | `MO_Decommit` | Release physical pages from MO |
| 0x92 | `MO_GetSize` | Query MO size in pages |
| 0x93 | `MO_Clone` | Create COW clone of MO |
| 0x94 | `MO_Resize` | Resize MO |
| 0x95 | `MO_Read` | Read data from MO pages |
| 0x96 | `MO_Write` | Write data to MO pages |
| 0x97 | `MO_HasPage` | Check if a page is committed |

#### MO_Commit (0x90)

Commit physical pages to a MemoryObject. Pages can be sourced from an untyped
capability (primary path) or from the PMM fallback allocator.

```
arg0 = offset        (page offset within MO)
arg1 = count         (number of pages to commit)
arg2 = ut_cap_ptr    (untyped capability pointer, or 0 for PMM fallback)
```

#### MO_Decommit (0x91)

Release committed physical pages from a MemoryObject.

```
arg0 = offset        (page offset within MO)
arg1 = count         (number of pages to decommit)
```

#### MO_GetSize (0x92)

Query the size of a MemoryObject in pages.

**Returns:** Page count in value field. Requires READ right.

#### MO_Clone (0x93)

Create a COW clone of a MemoryObject.

```
arg0 = dest_slot     (destination capability slot index)
arg1 = flags         (clone flags)
```

The clone shares physical pages with the original. Writes to either copy trigger
COW resolution.

#### MO_Resize (0x94)

Resize a MemoryObject.

```
arg0 = new_page_count    (new size in pages)
```

#### MO_Read (0x95)

Read data from MemoryObject pages into the IPC buffer.

```
arg0 = offset        (page offset within MO)
arg1 = count         (number of pages to read)
```

#### MO_Write (0x96)

Write data from the IPC buffer to MemoryObject pages.

```
arg0 = offset        (page offset within MO)
arg1 = count         (number of pages to write)
```

#### MO_HasPage (0x97)

Check if a specific page is committed in the MemoryObject.

```
arg0 = page_index    (page index to check)
```

**Returns:** 1 if page is committed, 0 if not. Requires READ right.

---

### Untyped Invocations

| Label | Operation | Description |
|-------|-----------|-------------|
| 0x20 | `Untyped_Retype` | Create typed objects |

#### Untyped_Retype (0x20)

```
arg0 = object_type   (ObjectType enum, 1..=11)
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
| 11 | MemoryObject | Memory object (page-granular backing store) |

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
| 0x64 | `Device_UntypedCreate` | Create device untyped from MMIO physical address |

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

#### Device_UntypedCreate (0x64)

Create a device untyped capability covering a physical MMIO address range. Used to grant userspace drivers access to device memory regions.

```
arg0 = phys_addr       (physical base address of device MMIO region)
arg1 = size_bits       (log2 of region size, e.g., 12 for 4KB)
arg2 = dest_cnode_cap  (capability pointer to destination CNode)
arg3 = dest_slot       (destination slot index within destination CNode)
```

**Returns:**
- `0`: Success, device untyped capability placed in dest_slot
- `4` (InvalidArgument): Invalid size_bits or unaligned address
- `8` (AlreadyExists): Destination slot is occupied

The resulting untyped capability can be retyped into Frame objects for device memory mapping.

---

### IoPort Invocations

I/O port capabilities provide controlled access to x86 I/O ports. Each IoPort capability covers a range of ports (base address + size).

| Label | Operation | Description |
|-------|-----------|-------------|
| 0x70 | `IoPort_In8` | Read 8-bit value from port |
| 0x71 | `IoPort_Out8` | Write 8-bit value to port |
| 0x72 | `IoPort_In16` | Read 16-bit value from port |
| 0x73 | `IoPort_Out16` | Write 16-bit value to port |
| 0x74 | `IoPort_In32` | Read 32-bit value from port |
| 0x75 | `IoPort_Out32` | Write 32-bit value to port |
| 0x76 | `IoPort_Configure` | Configure port range |
| 0x77 | `IoPort_Create` | Create new IoPort capability |

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

#### IoPort_In32 (0x74)

Read a 32-bit value from an I/O port.

```
arg0 = offset        (port offset within the IoPort range)
```

**Returns:** Value in RDX. Requires READ right.

#### IoPort_Out32 (0x75)

Write a 32-bit value to an I/O port.

```
arg0 = offset        (port offset within the IoPort range)
arg1 = value         (32-bit value to write)
```

Requires WRITE right.

#### IoPort_Configure (0x76)

Configure the port range covered by an IoPort capability.

```
arg0 = base_port     (starting I/O port number)
arg1 = size          (number of ports in range)
```

Requires WRITE right. Returns `InvalidArgument` if the port range is invalid or exceeds 0xFFFF.

#### IoPort_Create (0x77)

Create a new IoPort capability for a specified port range.

```
arg0 = base_port     (starting I/O port number)
arg1 = size          (number of ports in range)
arg2 = dest_slot     (destination slot index in current CSpace)
```

**Returns:**
- `0`: Success, IoPort capability placed in dest_slot
- `4` (InvalidArgument): Invalid port range
- `8` (AlreadyExists): Destination slot is occupied

---

## Error Codes

SaltyOS uses positive error codes (returned in RAX on x86_64, x0 on aarch64).

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
| 15 | `Interrupted` | Interrupted by notification dispatch |
| 0x10 | `InProgress` | Async operation in progress |
| 0x80 | `Pending` | Deferred result pending |

## IPC Buffer Layout

```
Offset  Size   Field
──────  ─────  ─────────────────
0x000   176    msg[22] — Message buffer (label, length, MR0-MR19)
0x0B0   8      badge — Received sender badge
0x0B8   32     caps[4] — Capability slots to transfer (sender-side)
0x0D8   8      receive_cnode — CNode cap for receiving caps
0x0E0   8      receive_index — Starting slot index in receive CNode
0x0E8   8      receive_depth — CNode depth for cap lookup
0x0F0   3824   reserved[478] — Extended payload area for slowpath IPC/invoke helpers
──────  ─────  ─────────────────
Total:  4096   (one 4KB page)
```

MR0-MR3 are passed in CPU registers for the fastpath. MR4-MR19 overflow to the IPC buffer when length > 4.

## Example Usage

### Simple RPC

```c
// Client side
struct trona_msg msg = {
    .label = REQUEST_ADD,
    .length = 2,
    .regs = { 42, 0, 0, 0 },
};
trona_call(server_ep, &msg);
uint64_t result = msg.regs[0];

// Server side
struct trona_msg msg, reply;
uint64_t badge;
trona_recv(endpoint, &msg, &badge);

for (;;) {
    uint64_t result = handle_request(msg.label, msg.regs[0]);

    reply.label = TRONA_OK;
    reply.length = 1;
    reply.regs[0] = result;

    trona_reply_recv(endpoint, &reply, &msg, &badge);
}
```

---

## Cross-References

- [ABI Specification](abi.md) -- register conventions, IPC buffer layout, message info encoding, page flags
- [Boot Protocol](boot_protocol.md) -- kernel entry state and BootInfo ABI
- [trona API Reference](trona-api.md) -- userspace syscall wrappers
- [basaltc API Reference](basaltc-api.md) -- C standard library functions
- [Capability Design](../design/capability.md) -- capability model details
- [IPC Design](../design/ipc.md) -- IPC protocol design
- [Memory Design](../design/memory.md) -- MemoryObject architecture
