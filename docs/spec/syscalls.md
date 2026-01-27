# System Call Reference

This document defines the system call interface for SaltyOS.

## Overview

SaltyOS uses a capability-invocation model for system calls. Most operations are performed by invoking capabilities rather than traditional numbered system calls.

### Calling Convention (x86_64)

```
Registers:
  RAX  - System call number
  RDI  - Argument 1 (capability pointer or syscall-specific)
  RSI  - Argument 2
  RDX  - Argument 3
  R10  - Argument 4 (RCX is clobbered by SYSCALL)
  R8   - Argument 5
  R9   - Argument 6

Return:
  RAX  - Return value (0 = success, negative = error)
  RDI  - Additional return value (syscall-specific)
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
| 0x01 | `TCB_ReadRegisters` | Read thread registers |
| 0x02 | `TCB_WriteRegisters` | Write thread registers |
| 0x03 | `TCB_Configure` | Configure thread |
| 0x04 | `TCB_SetPriority` | Set thread priority |
| 0x05 | `TCB_SetIPCBuffer` | Set IPC buffer address |
| 0x06 | `TCB_SetSpace` | Set CSpace/VSpace |
| 0x07 | `TCB_Suspend` | Suspend thread |
| 0x08 | `TCB_Resume` | Resume thread |
| 0x09 | `TCB_BindNotification` | Bind notification to thread |
| 0x0A | `TCB_UnbindNotification` | Unbind notification |

#### TCB_Configure

```c
struct tcb_configure_args {
    cap_t fault_handler;     // Fault handler endpoint
    cap_t cspace_root;       // CSpace root
    uint64_t cspace_data;    // CSpace guard/depth
    cap_t vspace_root;       // VSpace root
    uint64_t vspace_data;    // VSpace data
    uint64_t ipc_buffer;     // IPC buffer address
    cap_t ipc_buffer_frame;  // IPC buffer frame
};
```

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

```c
struct cnode_copy_args {
    cap_t dest_cnode;        // Destination CNode
    uint64_t dest_index;     // Destination slot
    uint64_t dest_depth;     // Destination depth
    cap_t src_cnode;         // Source CNode
    uint64_t src_index;      // Source slot
    uint64_t src_depth;      // Source depth
    uint64_t rights;         // Rights to grant
};
```

---

### VSpace Invocations

| Label | Operation | Description |
|-------|-----------|-------------|
| 0x20 | `VSpace_Map` | Map frame into VSpace |
| 0x21 | `VSpace_Unmap` | Unmap page |
| 0x22 | `VSpace_MapPT` | Map page table |

#### VSpace_Map

```c
struct vspace_map_args {
    cap_t frame;             // Frame capability
    uint64_t vaddr;          // Virtual address
    uint64_t rights;         // MapRights (R/W/X)
    uint64_t attr;           // Cache attributes
};
```

**Rights:**
- `0x01`: Read
- `0x02`: Write
- `0x04`: Execute

---

### Untyped Invocations

| Label | Operation | Description |
|-------|-----------|-------------|
| 0x30 | `Untyped_Retype` | Create typed objects |

#### Untyped_Retype

```c
struct untyped_retype_args {
    uint64_t object_type;    // CapType enum
    uint64_t size_bits;      // For variable-size objects
    cap_t dest_cnode;        // Destination CNode
    uint64_t dest_index;     // First destination slot
    uint64_t dest_depth;     // Destination depth
    uint64_t num_objects;    // Number of objects to create
};
```

**Object Types:**
| Value | Type |
|-------|------|
| 1 | Endpoint |
| 2 | Notification |
| 3 | TCB |
| 4 | CNode |
| 5 | VSpace |
| 6 | Frame (4KB) |
| 7 | LargePage (2MB) |
| 8 | HugePage (1GB) |
| 9 | PageTable |
| 10 | IRQHandler |
| 11 | SchedContext |

---

### IRQ Invocations

| Label | Operation | Description |
|-------|-----------|-------------|
| 0x40 | `IRQControl_Get` | Get IRQ handler |
| 0x41 | `IRQHandler_Ack` | Acknowledge IRQ |
| 0x42 | `IRQHandler_SetNotification` | Set notification |
| 0x43 | `IRQHandler_Clear` | Clear handler |

---

### SchedContext Invocations

| Label | Operation | Description |
|-------|-----------|-------------|
| 0x50 | `SC_Configure` | Configure parameters |
| 0x51 | `SC_Bind` | Bind to TCB |
| 0x52 | `SC_Unbind` | Unbind from TCB |
| 0x53 | `SC_Consumed` | Get consumed time |
| 0x54 | `SC_YieldTo` | Yield to another SC |

## Error Codes

| Code | Name | Description |
|------|------|-------------|
| 0 | `OK` | Success |
| -1 | `EINVAL` | Invalid argument |
| -2 | `EPERM` | Permission denied |
| -3 | `ENOENT` | Object not found |
| -4 | `ENOMEM` | Out of memory |
| -5 | `EBUSY` | Resource busy |
| -6 | `EEXIST` | Already exists |
| -7 | `EFAULT` | Bad address |
| -8 | `ERANGE` | Value out of range |
| -9 | `EWOULDBLOCK` | Operation would block |
| -10 | `ECANCELED` | Operation cancelled |
| -11 | `ERESTART` | Restart syscall |
| -12 | `EDEADLK` | Deadlock detected |

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
