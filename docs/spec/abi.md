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
typedef uint64_t seL4_MessageInfo_t;

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
RDI = Argument 1
RSI = Argument 2
RDX = Argument 3
R10 = Argument 4 (RCX clobbered by SYSCALL)
R8  = Argument 5
R9  = Argument 6
```

**Return:**
```
RAX = Return value / Error code
RDI = Additional return value (syscall-specific)
```

**Clobbered:**
- RCX (contains return RIP after SYSCALL)
- R11 (contains RFLAGS after SYSCALL)

### IPC Register Convention

For fast IPC, message registers map directly to CPU registers:

| MR | Register | Purpose |
|----|----------|---------|
| Label | RDI | Operation/type identifier |
| MR0 | RSI | First message word |
| MR1 | RDX | Second message word |
| MR2 | R10 | Third message word |
| MR3 | R8 | Fourth message word |

Badge is returned in R9.

## IPC Message Format

### Message Info Word

```
┌─────────────────────────────────────────────────────────────────┐
│  63:58  │  57:52  │  51:12  │  11:7   │  6:0   │
│  Caps   │ ExCaps  │  Label  │ Reserved│ Length │
└─────────────────────────────────────────────────────────────────┘
```

| Field | Bits | Description |
|-------|------|-------------|
| Length | 6:0 | Number of message words (0-127) |
| Caps | 63:58 | Number of capabilities transferred |
| ExCaps | 57:52 | Extra capability slots |
| Label | 51:12 | Message label (40 bits) |

### Macros

```c
#define MSGINFO_LENGTH(info)    ((info) & 0x7F)
#define MSGINFO_CAPS(info)      (((info) >> 58) & 0x3F)
#define MSGINFO_LABEL(info)     (((info) >> 12) & 0xFFFFFFFFFF)

#define MAKE_MSGINFO(label, caps, length) \
    ((((uint64_t)(label) & 0xFFFFFFFFFF) << 12) | \
     (((uint64_t)(caps) & 0x3F) << 58) | \
     ((length) & 0x7F))
```

## Error Codes

### Kernel Error Codes

```c
typedef enum {
    SALTY_OK = 0,
    
    // Generic errors (1-99)
    SALTY_EINVAL = 1,           // Invalid argument
    SALTY_EPERM = 2,            // Permission denied
    SALTY_ENOENT = 3,           // Not found
    SALTY_ENOMEM = 4,           // Out of memory
    SALTY_EBUSY = 5,            // Resource busy
    SALTY_EEXIST = 6,           // Already exists
    SALTY_EFAULT = 7,           // Bad address
    SALTY_ERANGE = 8,           // Out of range
    
    // IPC errors (100-199)
    SALTY_ESEND = 100,          // Send failed
    SALTY_ERECV = 101,          // Receive failed
    SALTY_ECALL = 102,          // Call failed
    SALTY_ETIMEOUT = 103,       // Operation timed out
    SALTY_ETRUNCATED = 104,     // Message truncated
    
    // Capability errors (200-299)
    SALTY_ECAP_INVALID = 200,   // Invalid capability
    SALTY_ECAP_REVOKED = 201,   // Capability revoked
    SALTY_ECAP_RIGHTS = 202,    // Insufficient rights
    SALTY_ECAP_TYPE = 203,      // Wrong capability type
    SALTY_ECAP_RANGE = 204,     // Invalid CNode range
    
    // Memory errors (300-399)
    SALTY_EMAP_ALIGN = 300,     // Alignment error
    SALTY_EMAP_PERM = 301,      // Mapping permission error
    SALTY_EMAP_OVERLAP = 302,   // Mapping overlap
    SALTY_EMAP_NOFRAME = 303,   // No frame mapped
    
    // Scheduling errors (400-499)
    SALTY_ESCHED_BUDGET = 400,  // Budget exceeded
    SALTY_ESCHED_BOUND = 401,   // Already bound
    
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
// IPC Buffer layout (4KB page)
struct ipc_buffer {
    // Message data (offset 0x000)
    uint64_t msg[64];       // Up to 64 message words
    
    // Receive info (offset 0x200)
    uint64_t badge;
    cap_t    receive_slot[16];
    uint64_t receive_cnode;
    uint64_t receive_index;
    uint64_t receive_depth;
    
    // Send info (offset 0x2A0)
    cap_t    send_caps[8];
    
    // Reserved (offset 0x2E0)
    uint64_t reserved[36];
    
    // User data (offset 0x400)
    uint8_t  user_data[3072];
};

_Static_assert(sizeof(struct ipc_buffer) == 4096, "IPC buffer size");
```

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
salty_error_t salty_send(cap_t ep, salty_msginfo_t info);
salty_error_t salty_recv(cap_t ep, badge_t *badge);
salty_error_t salty_call(cap_t ep, salty_msginfo_t info);

// Capability operations
salty_error_t salty_cap_copy(cap_t dest, cap_t src);
salty_error_t salty_cap_delete(cap_t cap);
salty_error_t salty_cap_revoke(cap_t cap);

// Memory
salty_error_t salty_map(cap_t vspace, cap_t frame, void *addr, int prot);
salty_error_t salty_unmap(cap_t vspace, void *addr);
```

### Reserved Prefixes

| Prefix | Usage |
|--------|-------|
| `salty_` | System library functions |
| `_salty_` | Internal system library |
| `__salty_` | Compiler/runtime internals |
| `SALTY_` | System constants/macros |
