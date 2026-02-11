# SaltyOS ABI Specification

This document defines the Application Binary Interface (ABI) for SaltyOS.

## Overview

SaltyOS uses a custom ABI based on the System V AMD64 ABI with modifications for capability-based IPC.

## Data Types

### Fundamental Types

| Type | Size | Alignment |
|------|------|-----------|
| `int8_t` / `uint8_t` | 1 | 1 |
| `int16_t` / `uint16_t` | 2 | 2 |
| `int32_t` / `uint32_t` | 4 | 4 |
| `int64_t` / `uint64_t` | 8 | 8 |
| `size_t` | 8 | 8 |
| `ssize_t` | 8 | 8 |
| pointer | 8 | 8 |
| `cap_t` | 8 | 8 |

### Capability Types

```c
// Capability pointer (index into CSpace)
typedef uint64_t cap_t;

// Invalid capability constant
#define CAP_NULL ((cap_t)0)

// Message info word
typedef uint64_t salty_msginfo_t;

// Badge from received IPC
typedef uint64_t badge_t;
```

## Calling Convention

### Function Calls (System V AMD64 ABI)

**Integer/Pointer Arguments:**
- Arguments 1-6: RDI, RSI, RDX, RCX, R8, R9
- Additional arguments: stack (right-to-left)

**Floating Point Arguments:**
- Arguments 1-8: XMM0-XMM7 (not used in kernel)

**Return Values:**
- Integer/Pointer: RAX (and RDX for 128-bit)

**Callee-saved Registers:**
- RBX, RBP, R12-R15

**Caller-saved Registers:**
- RAX, RCX, RDX, RSI, RDI, R8-R11

**Stack:**
- 16-byte aligned before CALL
- Red zone: 128 bytes below RSP (not in kernel mode)

### System Call Convention

**Entry:**
```
RAX = System call number
RDI = Argument 1 (capability pointer / first arg)
RSI = Argument 2 (msg_info / label)
RDX = Argument 3 (mr0 / arg0)
R10 = Argument 4 (mr1 / arg1) — RCX is clobbered by SYSCALL
R8  = Argument 5 (mr2 / arg2)
R9  = Argument 6 (mr3 / arg3)
```

**Return:**
```
RAX = Error code (0 = success)
RDX = Return value (syscall-specific)
```

**Clobbered:**
- RCX (contains return RIP after SYSCALL)
- R11 (contains RFLAGS after SYSCALL)

### IPC Register Convention

For IPC syscalls, message registers map to CPU registers:

| Field | Register | Purpose |
|-------|----------|---------|
| cap_ptr | RDI | Endpoint capability slot |
| msg_info | RSI | Packed message info word |
| MR0 | RDX | First message register |
| MR1 | R10 | Second message register |
| MR2 | R8 | Third message register |
| MR3 | R9 | Fourth message register |

Badge is returned in RDX on Recv/ReplyRecv.

## IPC Message Format

### Message Info Word

```
┌─────────────────────────────────────────────────────────────────┐
│  63:52   │  51:12   │  11:7     │  6:0    │
│ Reserved │  Label   │ ExtraCaps │ Length  │
└─────────────────────────────────────────────────────────────────┘
```

| Field | Bits | Description |
|-------|------|-------------|
| Length | 6:0 | Number of message registers used (0-127) |
| ExtraCaps | 11:7 | Number of capabilities to transfer (0-31) |
| Label | 51:12 | Application-defined message label (40 bits) |
| Reserved | 63:52 | Must be zero |

### Macros

```c
#define SALTY_MSGINFO(label, length, extra_caps) \
    (((uint64_t)(label) << 12) | \
     ((uint64_t)(extra_caps) << 7) | \
     ((uint64_t)(length) & 0x7F))

#define SALTY_MSGINFO_LABEL(info)      (((info) >> 12) & 0xFFFFFFFFFFULL)
#define SALTY_MSGINFO_LENGTH(info)     ((info) & 0x7F)
#define SALTY_MSGINFO_EXTRACAPS(info)  (((info) >> 7) & 0x1F)
```

## Error Codes

SaltyOS uses sequential positive error codes (returned in RAX).

```c
typedef enum {
    SALTY_OK                = 0,   // Success
    SALTY_INVALID_CAP       = 1,   // Invalid or null capability
    SALTY_INVALID_OPERATION = 2,   // Wrong object type or unsupported op
    SALTY_INSUFFICIENT_RIGHTS = 3, // Capability lacks required rights
    SALTY_INVALID_ARGUMENT  = 4,   // Bad argument value
    SALTY_OUT_OF_MEMORY     = 5,   // No memory available
    SALTY_NOT_FOUND         = 6,   // Empty slot, unmapped page
    SALTY_BUSY              = 7,   // Resource is busy
    SALTY_ALREADY_EXISTS    = 8,   // Occupied slot, mapped page
    SALTY_WOULD_BLOCK       = 9,   // Non-blocking op has no work
    SALTY_BAD_ADDRESS       = 10,  // Invalid memory address
    SALTY_OUT_OF_RANGE      = 11,  // Value exceeds valid range
    SALTY_CANCELLED         = 12,  // Operation was cancelled
    SALTY_RESTART           = 13,  // Syscall should be restarted
    SALTY_DEADLOCK          = 14,  // Deadlock detected
} salty_error_t;
```

## Object Layout

### Thread Control Block (TCB)

The TCB layout is kernel-internal, but userspace sees:

```c
// Userspace TCB configuration
struct tcb_config {
    cap_t   fault_ep;       // Fault handler endpoint
    cap_t   cspace_root;    // CSpace root CNode
    uint8_t cspace_depth;   // CSpace depth
    cap_t   vspace_root;    // VSpace root
    void   *ipc_buffer;     // IPC buffer virtual address
    cap_t   ipc_buffer_cap; // IPC buffer frame capability
};
```

### IPC Buffer

```c
// IPC Buffer layout (4KB page, 512 x uint64_t)
struct salty_ipc_buffer {
    uint64_t msg[20];           // 0x000: MR0..MR19 (160 bytes)
    uint64_t badge;             // 0x0A0: Received badge
    uint64_t caps[4];           // 0x0A8: Cap slots to transfer (sender-side)
    uint64_t receive_cnode;     // 0x0C8: CNode for receiving caps
    uint64_t receive_index;     // 0x0D0: Starting slot index
    uint64_t receive_depth;     // 0x0D8: CNode depth
    uint64_t reserved[480];     // 0x0E0: Reserved / future use
};

_Static_assert(sizeof(struct salty_ipc_buffer) == 4096, "IPC buffer size");
```

**Register vs. IPC buffer message passing:**

- MR0-MR3 are passed in CPU registers (RDX, R10, R8, R9) for low latency.
- If `length > 4`, MR4-MR19 overflow to the thread's IPC buffer (`msg[4]` through `msg[19]`).
- The kernel reads/writes the IPC buffer at the virtual address set via `TCB_SetIPCBuffer`.

## Virtual Address Space Layout

### Userspace Layout

```
0x0000000000000000 ─┬─ NULL page (unmapped)
                    │
0x0000000000001000 ─┼─ User text start
                    │
                    │  .text
                    │  .rodata
                    │  .data
                    │  .bss
                    │
0x0000700000000000 ─┼─ Heap start
                    │
                    │  (grows up)
                    │
0x00007F0000000000 ─┼─ mmap region
                    │
                    │  Shared libraries
                    │  Anonymous mappings
                    │
0x00007FFFFFFFE000 ─┼─ Stack (grows down)
                    │
0x00007FFFFFFFFFFF ─┴─ User space end

0x0000800000000000 ─── Non-canonical gap ───

0xFFFF800000000000 ─┬─ Kernel space start
                    │  (inaccessible to user)
0xFFFFFFFFFFFFFFFF ─┴─ End
```

### Key Addresses

```c
// User space limits
#define USER_SPACE_START    0x0000000000001000UL
#define USER_SPACE_END      0x00007FFFFFFFFFFFUL

// Recommended regions
#define USER_HEAP_START     0x0000700000000000UL
#define USER_MMAP_START     0x00007F0000000000UL
#define USER_STACK_TOP      0x00007FFFFFFFE000UL

// Kernel space
#define KERNEL_SPACE_START  0xFFFF800000000000UL
```

## Stack Layout

### User Stack Frame

```
High addresses
┌─────────────────────────┐
│  argv[n]               │
│  ...                   │
│  argv[0]               │
│  argc                  │
├─────────────────────────┤
│  envp[n]               │
│  ...                   │
│  envp[0]               │
│  NULL                  │
├─────────────────────────┤
│  auxv entries          │
│  AT_NULL               │
├─────────────────────────┤ ← Initial RSP (16-byte aligned)
│  Return address (0)    │
│  ...                   │
└─────────────────────────┘
Low addresses
```

### Auxiliary Vector (auxv)

```c
typedef struct {
    uint64_t a_type;
    uint64_t a_val;
} Elf64_auxv_t;

#define AT_NULL         0   // End of auxv
#define AT_PHDR         3   // Program headers address
#define AT_PHENT        4   // Program header entry size
#define AT_PHNUM        5   // Number of program headers
#define AT_PAGESZ       6   // Page size
#define AT_BASE         7   // Interpreter base address
#define AT_ENTRY        9   // Program entry point
#define AT_UID          11  // Real UID
#define AT_EUID         12  // Effective UID
#define AT_GID          13  // Real GID
#define AT_EGID         14  // Effective GID
```

## ELF Binary Format

### Required Sections

| Section | Purpose |
|---------|---------|
| `.text` | Executable code |
| `.rodata` | Read-only data |
| `.data` | Initialized data |
| `.bss` | Uninitialized data |
| `.dynamic` | Dynamic linking info (if dynamic) |

### Program Headers

```c
// Loadable segment
Elf64_Phdr {
    p_type = PT_LOAD,
    p_flags = PF_R | PF_X,  // or PF_R | PF_W for data
    p_offset = ...,
    p_vaddr = 0x...,        // Virtual address
    p_paddr = 0,
    p_filesz = ...,
    p_memsz = ...,
    p_align = 4096,
};
```

## Thread-Local Storage (TLS)

### Model

SaltyOS uses the Local Exec TLS model:

```c
// TLS access (thread pointer in FS base)
__thread int my_tls_var;

// Access via FS segment
// mov eax, fs:[my_tls_var@TPOFF]
```

### TLS Block Layout

```
┌─────────────────────────┐ ← FS base (TCB pointer)
│  TCB (user portion)     │
│  - self pointer         │
│  - stack guard          │
│  - errno                │
├─────────────────────────┤
│  TLS data               │
│  (negative offsets)     │
└─────────────────────────┘
```

## Versioning

### ABI Version

```c
#define SALTY_ABI_VERSION_MAJOR 1
#define SALTY_ABI_VERSION_MINOR 0

#define SALTY_ABI_VERSION \
    ((SALTY_ABI_VERSION_MAJOR << 16) | SALTY_ABI_VERSION_MINOR)
```

### Compatibility

- Major version change: Breaking ABI changes
- Minor version change: Backwards-compatible additions

Programs built for ABI 1.x should work on kernel 1.y where y >= x.

## Symbol Naming

### System Library

System library functions use the `salty_` prefix:

```c
// IPC
int salty_send(cap_t ep, struct salty_msg *msg);
int salty_recv(cap_t ep, struct salty_msg *msg, uint64_t *badge);
int salty_call(cap_t ep, struct salty_msg *msg);
int salty_reply_recv(cap_t ep, struct salty_msg *reply,
                     struct salty_msg *msg, uint64_t *badge);

// Capability operations
int salty_cnode_copy(cap_t src_cnode, uint64_t src_slot,
                     cap_t dest_cnode, uint64_t dest_slot, uint64_t rights);
int salty_cnode_mint(cap_t src_cnode, uint64_t src_slot,
                     cap_t dest_cnode, uint64_t dest_slot, uint64_t badge);
int salty_cnode_move(cap_t dest_cnode, uint64_t dest_slot,
                     cap_t src_cnode, uint64_t src_slot);
int salty_cnode_delete(cap_t cnode, uint64_t slot);
int salty_cnode_revoke(cap_t cnode, uint64_t slot);

// Memory
int salty_vspace_map(cap_t vspace, cap_t frame, uint64_t vaddr, uint64_t flags);
int salty_vspace_unmap(cap_t vspace, uint64_t vaddr);

// Debug
void salty_debug_putchar(char c);
void salty_debug_dump_state(void);
```

### Reserved Prefixes

| Prefix | Usage |
|--------|-------|
| `salty_` | System library functions |
| `_salty_` | Internal system library |
| `__salty_` | Compiler/runtime internals |
| `SALTY_` | System constants/macros |
