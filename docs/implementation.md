# SaltyOS Implementation Plan

## Overview
SaltyOS is a Unix-like microkernel operating system written in Rust, targeting x86/x86_64 with multi-architecture extensibility.

**Tech Stack**: Rust + Assembly, Cargo + Meson build system
**Targets**: VMware, QEMU, VirtualBox (UEFI/BIOS support)

**Naming Conventions**:
- Filesystem: **SaltyFS** (COW + checksums)
- Syscall ABI: **SSABI** (SaltySys ABI - minimal kernel primitives)
- IPC Protocol: **SSIP** (SaltySys IPC - userspace service contract)
- Boot ABI: **SKA** (SaltyKernel ABI - bootloader→kernel contract)
- Drivers: snake_case (svga, ahci, virtio_blk, etc.)

**Phase Legend**:
| Phase | Meaning |
|-------|---------|
| **1-2** | Boot + minimal kernel primitives |
| **3-4** | IPC + external pager + device management |
| **5-6** | Core servers + filesystem |
| **7** | POSIX emulation |
| **8+** | Multi-arch, hardening, advanced features |

---

## Layered Architecture

```
+------------------------------------------------------------------+
|                        User Space                                 |
+------------------------------------------------------------------+
|  Shell  |  Utilities  |  POSIX emulation (libc)                  |
|                     |  Servers (svga, ahci, saltyfs, etc.)       |
+------------------------------------------------------------------+
|                      SSIP (SaltySys IPC)                          |
|              Service contract / Message format                    |
+------------------------------------------------------------------+
|                      SSABI (SaltySys ABI)                         |
|        Minimal primitives: thread, page, cap, ipc-send/recv      |
+------------------------------------------------------------------+
|                      Kernel Core (Microkernel)                   |
|  +--------+  +--------+  +--------+  +------------------------+  |
|  | IPC    |  | Thread |  | VM     |  | Foundation (HAL)        |  |
|  | Router |  | Mgmt   |  | Pager  |  | - time/clock            |  |
|  +--------+  +--------+  +--------+  | - interrupt/irq         |  |
|  +--------+  +--------+                  | - dma/mmio              |  |
|  | Cap    |  | Device  |                | - device/pci            |  |
|  | Manager|  | Manager |                +------------------------+  |
|  +--------+  +--------+                                         |
+------------------------------------------------------------------+
|                   Architecture Layer (arch/)                     |
|  +----------------+  +----------------+  +----------------+      |
|  | x86_64         |  | x86            |  | (extensible)   |      |
|  +----------------+  +----------------+  +----------------+      |
+------------------------------------------------------------------+
```

---

## ABI Structure

```
abi/
├── ssabi/                # SSABI: Minimal kernel primitives
│   ├── src/
│   │   ├── lib.rs
│   │   ├── numbers.rs    # Syscall numbers
│   │   ├── types.rs      # Capability, VM map types
│   │   └── error.rs      # Kernel error codes
│   └── README.md
│
├── ssip/                 # SSIP: Userspace service contract
│   ├── src/
│   │   ├── lib.rs
│   │   ├── message.rs    # Message header format
│   │   ├── cap.rs        # Capability passing format
│   │   ├── handshake.rs  # Service discovery/versioning
│   │   └── protocol/     # Service-specific protocols
│   │       ├── fs.rs     # Filesystem protocol
│   │       ├── graphics.rs # Graphics protocol
│   │       └── block.rs  # Block device protocol
│   └── README.md
│
└── ska/                  # SKA: Bootloader→kernel contract
    ├── src/
    │   ├── lib.rs
    │   ├── bootinfo.rs   # Unified BootInfo structure
    │   ├── memory.rs     # Memory map format
    │   ├── framebuffer.rs # FB info
    │   └── module.rs     # Initrd/cmdline
    └── README.md
```

---

## SSABI (SaltySys ABI) - Minimal Kernel Primitives

**Philosophy**: SSABI provides only machine-level primitives that depend on architecture/trap mechanism.

**Syscalls (minimal set)**:
```rust
// Thread management
sys_thread_create(entry: usize, arg: usize) -> Result<ThreadId>
sys_thread_block(token: BlockToken) -> Result<()>
sys_thread_unblock(tid: ThreadId) -> Result<()>
sys_thread_exit() -> !

// Virtual memory (object-based)
sys_vm_map(as: AddressSpace, mem: MemCap, va: VirtAddr,
           offset: usize, len: usize, prot: ProtFlags) -> Result<()>
sys_vm_unmap(as: AddressSpace, va: VirtAddr, len: usize) -> Result<()>
sys_pager_register(cap: PagerCap) -> Result<()>  // Set external pager

// Address space management
sys_address_space_create() -> Result<AddressSpace>
sys_address_space_switch(as: AddressSpace) -> Result<()>

// Capability operations
sys_cap_dup(cap: CapHandle, rights: CapRights) -> Result<CapHandle>
sys_cap_revoke(cap: CapHandle) -> Result<()>
sys_cap_type(cap: CapHandle) -> Result<CapType>
sys_cap_info(cap: CapHandle) -> Result<CapInfo>

// IPC (primitive)
sys_ipc_send(endpoint: Endpoint, msg: &Message) -> Result<()>
sys_ipc_recv(endpoint: Endpoint, buf: &mut Message) -> Result<()>
sys_ipc_call(endpoint: Endpoint, req: &Message, resp: &mut Message) -> Result<()>
```

**What SSABI does NOT provide**:
- No `fork()`, `exec()`, `wait()` - POSIX emulation in userspace
- No `open()`, `read()`, `write()` - Fileserver protocol via SSIP
- No `ioctl()` - Device-specific SSIP protocols

---

### VM Model: Object-Based Memory

**Design Principle**: Virtual memory is composition of AddressSpace + MemoryObject capabilities.

**Core Types**:
```rust
// Address space: container for mappings
pub struct AddressSpace {
    pub handle: CapHandle,  // Cap to address space
}

// Memory object: backing for mappings
pub struct MemCap {
    pub handle: CapHandle,
    pub size: usize,
    pub mem_type: MemType,
}

pub enum MemType {
    Physical(PhysAddr),     // Physical memory (DMA, MMIO)
    Anonymous,              // Zero-filled pages
    FileBacked,             // Pager-controlled
    Shared,                 // Multiple mappings allowed
}

// Mapping: composition in address space
pub struct Mapping {
    pub base: VirtAddr,
    pub size: usize,
    pub mem: MemCap,        // Backing memory object
    pub offset: usize,      // Offset into MemCap
    pub prot: ProtFlags,    // R/W/X permissions
}
```

**sys_vm_map Semantics**:
```rust
// Maps memory object into address space at specified VA
// - Does NOT create new pages (just establishes mapping)
// - Page allocation happens on fault (via pager)
// - Multiple mappings of same MemCap allowed (if Shared)
sys_vm_map(
    as: AddressSpace,   // Target address space
    mem: MemCap,        // Memory object to map
    va: VirtAddr,       // Virtual address (hint or fixed)
    offset: usize,      // Offset into memory object
    len: usize,        // Length to map
    prot: ProtFlags,    // R/W/X
) -> Result<()>
```

**Anonymous Memory Policy**:
- If no external pager is registered, the kernel zero-fills pages on fault.
- If a pager is registered, it controls allocation policy for `Anonymous` too.

**Page Fault Flow**:
```
1. Access to unmapped/pageable page
2. Kernel captures fault (address, type)
3. Kernel sends SSIP message to registered pager
   - Includes faulting AddressSpace cap and fault VA
4. Pager responds with MemCap for backing
5. Pager calls sys_vm_map(fault_as, mem, fault_va, ...)
```

**Page-Level vs Range-Level**:
- **Phase 1-7**: Range-level operations (simpler)
- **Phase 8+**: Page-level granularity for COW, dirty tracking

---

### Capability Model (Detailed)

**Design Principle**: Capabilities are unforgeable references to kernel objects with rights-based access control.

**Core Types**:
```rust
#[repr(C)]
pub struct CapHandle {
    pub id: u64,        // Object ID + Generation (for revocation)
}

bitflags! {
    pub struct CapRights: u64 {
        const READ   = 1 << 0;   // Read access
        const WRITE  = 1 << 1;   // Write access
        const EXEC   = 1 << 2;   // Execute access
        const MAP    = 1 << 3;   // Map into address space
        const IRQ    = 1 << 4;   // Receive IRQs
        const SUBMIT = 1 << 5;   // Submit I/O
        const DUP    = 1 << 6;   // Can duplicate
        const REVOKE = 1 << 7;   // Can revoke
    }
}

pub enum CapType {
    Endpoint,       // IPC endpoint
    Memory,         // Memory region
    AddressSpace,   // Address space
    IrqLine,        // IRQ line
    Device,         // Device (MMIO/IRQ bundle)
    DmaBuffer,      // DMA-capable buffer
    Pager,          // Pager capability
}
```

**Lifetime Semantics**:
- **Process termination**: All capabilities held by process are automatically revoked
- **Reference counting**: Each capability has internal refcount
- **No GC**: Explicit revocation only (no garbage collection)

**Revocation Semantics**:
```rust
// Capability ID with derivation tracking (reserved for future)
pub struct CapId {
    pub index: u32,        // Slot index in capability table
    pub generation: u32,    // Increments on revoke
    pub creator: u32,       // RESERVED: Derivation tracking (parent slot)
}

// Current revocation (Phase 1-7):
// - Revoke invalidates ALL copies immediately
// - Generation bump invalidates existing handles
// - No subtree revoke (all copies treated equally)

// Future revocation (Phase 8+):
// - Derivation tree: parent → children relationship
// - Revoke(parent) invalidates entire subtree
// - Selective revoke: revoke only specific children
// - CapId.creator field enables this
```

**Delegation Rules**:
- `sys_cap_dup()` with subset of rights (partial delegation)
- Original holder retains full rights
- **Phase 1-7**: Cannot revoke delegated caps individually
- **Phase 8+**: Tree-based revoke (using creator field)
- Capabilities are immutable after creation (only rights can be restricted on dup)

**SSIP Serialization**:
```rust
// Capabilities in SSIP messages are transmitted as:
pub struct MsgCap {
    pub handle: CapHandle,   // The capability handle
    pub rights: CapRights,   // Rights being transferred
}

// Receiver validates:
// 1. CapHandle exists and generation matches
// 2. Sender has DUP right
// 3. Requested rights <= sender's rights
```

---

## SSIP (SaltySys IPC) - Userspace Service Contract

**Philosophy**: SSIP defines the contract between userspace services (filesystems, drivers, servers).

**Core Message Format**:
```rust
pub struct Message {
    pub header: Header,
    pub payload_tag: PayloadTag,
    pub payload: PayloadUnion,
}

pub struct Header {
    pub sender: TaskId,
    pub receiver: TaskId,
    pub msg_id: u64,        // SSIP-level correlation only
    pub protocol: ProtocolId,
    pub op: u32,            // Operation code
    pub flags: MessageFlags,
    pub reply: Option<Endpoint>, // One-shot reply endpoint (if any)
}

// ABI stability rule: repr(C), fixed-size fields, no Vec/Rust enums.

#[repr(u32)]
pub enum PayloadTag {
    Inline = 1,
    Shared = 2,
}

#[repr(C)]
pub union PayloadUnion {
    pub inline: InlinePayload,
    pub shared: SharedPayload,
}

#[repr(C)]
pub struct InlinePayload {
    pub data: [u8; 256],
}

#[repr(C)]
pub struct SharedPayload {
    pub mem_cap: MemCapHandle,   // Memory object (NOT virt addr)
    pub offset: usize,           // Offset into memory object
    pub len: usize,              // Length to share
    pub caps: [MsgCap; 4],       // Additional capabilities
}
```

---

### SSIP Memory Transfer Model

**Payload Types**:
```rust
// Tag selects which union member is active.
pub enum PayloadTag {
    Inline = 1,
    Shared = 2,
}

pub union PayloadUnion {
    inline: InlinePayload,
    shared: SharedPayload,
}

// NO virt addr in payload - receiver chooses mapping
// Memory is identified ONLY by capability
```

**Transfer Policies**:

1. **Inline** (≤256 bytes):
   - Zero-copy register passing
   - No capability validation overhead
   - For control messages, small structs

2. **Shared** (>256 bytes):
   - Requires capability with MAP right
   - Receiver must have MAP right to access
   - Kernel validates permissions before mapping

**Mapping Semantics**:
```rust
// Option A: Temporary mapping (kernel-managed)
// - Kernel unmaps after message processed
// - Safer, but slower

// Option B: Persistent mapping (receiver-controlled)
// - Receiver must sys_vm_map() explicitly
// - Faster, but requires careful lifetime management

// Phase 1-7: Option B with explicit mapping
// Receiver must call sys_vm_map() with received cap
```

**Zero-Copy Rules**:
- Shared memory regions are NOT copied
- Sender retains original mapping
- Receiver gets separate mapping (same physical pages)
- Receiver calls sys_vm_map() with received MemCap to choose VA
- Copy-on-write only if receiver modifies (future optimization)

---

### IPC Synchronization Model

**Call/Reply Pattern**:
```rust
// sys_ipc_call: blocking call with reply
sys_ipc_call(endpoint: Endpoint, req: &Message, resp: &mut Message)

// Implementation:
// 1. Kernel generates one-time reply endpoint
// 2. Sends request with reply endpoint in message header
// 3. Blocks caller
// 4. Server replies to reply_cap
// 5. Kernel delivers response, unblocks caller
```

**Message Matching**:
```rust
pub struct Header {
    pub msg_id: u64,        // SSIP-level correlation only
    // ...
}

// Call flow:
// Caller: msg_id = random(), sends request
// Server: copies msg_id to response
// Kernel: matches response by reply endpoint only
```

**Timeout & Cancellation** (Future):
```rust
// Phase 1-7: No timeout (infinite block)
// Phase 8+: sys_ipc_call_with_timeout()

// Cancellation:
// sys_thread_cancel(thread_id) - aborts blocked IPC
// Server gets notification if call was cancelled
```

**Reply Endpoint**:
- Implicit: Kernel creates one-time endpoint per call
- Reply endpoint is delivered in the message header (`reply`)
- Server cannot reply multiple times
- Reply cap cannot be duplicated or transferred

---

### Service Discovery & Registry

**Security Principle**: Service discovery must be capability-protected.

**Registry Server** (`servers/registry/`):
- Maintains service name → endpoint mapping
- Requires `RegistryCap` to query/register
- Init server grants initial caps at boot

**Discovery Protocol**:
```rust
// Query (requires RegistryCap)
pub struct RegistryLookup {
    pub name: ServiceName,    // e.g., "fs", "graphics", "block"
    pub version_min: u32,
}

pub struct RegistryResponse {
    pub endpoint: Option<Endpoint>,  // None if not found
    pub version: u32,
}

// Announce (requires RegistryCap)
pub struct RegistryRegister {
    pub name: ServiceName,
    pub version: u32,
    pub endpoint: Endpoint,
}
```

**Capability Flow at Boot**:
```
1. Kernel boots, spawns init (PID 1)
2. Init has initial "bootstrap cap" for registry
3. Init starts registry server with registry cap
4. Registry grants lookup caps to trusted servers
5. Servers query registry to discover each other
```

**Phase 1-2 Alternative (Simpler Discovery)**:
- Init acts as registry itself
- Direct SSIP messages to init for discovery
- No separate registry server initially

---

### Bootstrap: Initial Capability Set

**Kernel→Init Handoff**:
When kernel spawns init (PID 1), it grants these capabilities:

| Capability | Purpose | Source |
|------------|---------|--------|
| `BootInfoCap` | Access SKA BootInfo structure | Kernel |
| `LogCap` | Console/serial output | Kernel |
| `RegistryAdminCap` | Create/manage service registry | Kernel |
| `ProcessAdminCap` | Spawn new tasks | Kernel |
| `VmAdminCap` | Create address spaces | Kernel |

**Implementation**: These caps are hardcoded in kernel's init spawn logic.

**Init's Responsibilities**:
1. Parse BootInfo via BootInfoCap
2. Start registry server with RegistryAdminCap
3. Spawn other servers using ProcessAdminCap
4. Grant subset of caps to each server

**Example Cap Distribution**:
```
Init → Registry:  RegistryAdminCap
Init → Pager:     VmAdminCap + BootInfoCap (for memory)
Init → DevMgr:    ProcessAdminCap + DeviceDiscoveryCap
Init → SaltyFS:   ProcessAdminCap + (storage device cap from DevMgr)
```

---

### POSIX Emulation via SSIP

**Scope (Phase 7)**:
- Process lifecycle: `fork`, `exec`, `wait`, `exit`
- Filesystem: `open`, `read`, `write`, `stat`, `close`, `pipe`
- Basic signals: `SIGTERM`, `SIGINT`, `SIGCHLD`
- TTY: canonical input, basic job control

**Non-goals (Phase 7)**:
- Full POSIX compliance and edge-case semantics
- `ptrace`, `cgroups`, `setns`, `io_uring`
- Full `mmap`/`munmap` parity with Linux

**Priority Order**:
1. Shell usability (sh/bash-compatible core)
2. Filesystem correctness and consistency
3. Process semantics for common utilities

---

## SKA (SaltyKernel ABI) - Bootloader→Kernel Contract

**Philosophy**: Single unified BootInfo regardless of firmware (UEFI/BIOS).

**Unified BootInfo Structure**:
```rust
#[repr(C)]
pub struct BootInfo {
    pub magic: u32,           // "SKA\0"
    pub version: u32,
    pub flags: BootFlags,

    // Memory
    pub memory_map: PhysAddr,  // Ptr to MemoryMap
    pub memory_map_entries: u32,

    // Framebuffer (if available)
    pub framebuffer: Option<FramebufferInfo>,

    // Initrd
    pub initrd: Option<ModuleInfo>,

    // Command line
    pub cmdline: PhysAddr,
    pub cmdline_len: u32,

    // ACPI (optional)
    pub rsdp: Option<PhysAddr>,  // RSDP pointer
}

pub struct MemoryEntry {
    pub base: PhysAddr,
    pub length: u64,
    pub type: MemoryType,     // Available, Reserved, ACPI, etc.
}
```

**Bootloader Contract**:
- UEFI bootloader and BIOS bootloader BOTH produce this structure
- Kernel ONLY parses BootInfo - doesn't care about firmware
- Version field allows backward compatibility

---

### BIOS Bootloader Path (Self-Implementation)

**Boot Sequence**:
```
Real Mode (16-bit)
    │
    ├─► Enable A20 gate
    ├─► Load stage2 (ELF loader)
    │
    ▼
Protected Mode (32-bit)
    │
    ├─► Load GDT
    ├─► Enable protected mode
    ├─► Load kernel ELF from disk (BIOS interrupts)
    │
    ▼
Long Mode (64-bit) [if x86_64]
    │
    ├─► Setup page tables
    ├─► Enable PAE
    ├─► Enable long mode
    │
    ▼
Kernel Entry
    │
    └─► Pass BootInfo in registers (RDI/RAX/etc.)
```

**Stage 1 (MBR)**:
- Located at first sector of disk
- Loads stage2 from disk using BIOS INT 13h
- Minimal: fits in 512 bytes

**Stage 2 (Protected Mode)**:
- ELf loader functionality
- Reads kernel from disk
- Parses ELF format
- Builds SKA BootInfo structure
- Enables long mode (if x86_64)
- Jumps to kernel entry point

**Key Differences from UEFI**:
- Disk loading via BIOS INT 13h (no file protocols)
- Memory map from BIOS INT 15h/E820
- Framebuffer via VBE (VESA BIOS Extensions)
- ACPI tables: Parse RSDP if available (see SKA BootInfo.rsdp)

---

### SMP & ACPI: Kernel Initialization Path

**Early Boot (Kernel Entry)**:
```
1. Parse SKA BootInfo (from either UEFI or BIOS)
2. Check if rsdp is present
   - If yes: ACPI available (SMP, power management)
   - If no: Single-core, limited features
3. Initialize APIC/IOAPIC (ACPI MADT required for SMP)
```

**ACPI Responsibility Split**:
| Phase | Component | Responsibility |
|-------|-----------|----------------|
| **Phase 1-7** | Kernel | Parse ACPI, enable APIC/IOAPIC, basic SMP |
| **Phase 8+** | userspace/acpi | Power management, PCI hotplug, advanced |

**Kernel ACPI Tasks (Early Boot)**:
```rust
// In kernel, before userspace starts
fn init_acpi(rsdp: PhysAddr) {
    // 1. Parse RSDT/XSDT
    let tables = AcpiTables::parse(rsdp);

    // 2. Find MADT (APIC)
    if let Some(madt) = tables.find_madt() {
        // 3. Enable IOAPIC
        ioapic::init(madt.ioapic_addr);

        // 4. Enable Local APIC on BSP
        lapic::bsp_enable();

        // 5. Start APs (application processors)
        for cpu in madt.application_processors {
            cpu.start();
        }
    }

    // 6. Set up IRQ routing (kernel-managed initially)
    irq::setup_routing();
}
```

**Userspace ACPI Server (Phase 8+)**:
- Power management (sleep, suspend, hibernate)
- Thermal management
- Battery status (laptops)
- PCI hotplug events
- **NOT**: IRQ routing (stays in kernel for stability)

**This Split Ensures**:
- Early stability: Kernel handles critical initialization
- Flexibility: Advanced features in userspace
- Userspace drivers work: APIC/IOAPIC already configured

---

## Driver Model & Device Manager

**Design Decision**: Device enumeration in kernel, drivers in userspace

**Kernel Responsibility** (`kernel/src/foundation/device/`):
- PCI enumeration (discover all PCI devices)
- Assign capabilities to devices:
  - **MMIO capability**: Mapped BAR regions
  - **IRQ capability**: Registered IRQ line
  - **DMA capability**: DMA-usable memory region (IOMMU-protected)

**Device Capability Structure**:
```rust
pub struct DeviceCapability {
    pub device_id: u32,      // PCI BDF or platform ID
    pub resources: Vec<Resource>,
}

pub enum Resource {
    Mmio { base: PhysAddr, size: usize },
    Irq { line: u8, trigger: TriggerMode },
    Dma {
        base: PhysAddr,      // Physical address of DMA buffer
        size: usize,
        iommu_domain: Option<IommuDomain>,  // IOMMU protection
    },
}
```

**Userspace Driver Contract**:
1. Driver receives DeviceCapability via SSIP from device manager
2. Driver uses capabilities to access hardware (no direct access)
3. IRQ delivery via SSIP message to driver's endpoint
4. DMA buffers are pre-allocated and IOMMU-mapped

---

### DMA & IOMMU Model

**Phase 1-6 (Trusted Drivers)**:
- Drivers are trusted (no malicious DMA possible)
- Kernel allocates DMA buffers from physical memory
- Driver receives physical address range via capability
- No IOMMU enforcement initially

**Future Hardening (IOMMU)**:
```rust
// IOMMU domain for isolation
pub struct IommuDomain {
    pub id: u32,
    pub devices: Vec<DeviceId>,  // Devices in this domain
}

// DMA buffer with IOMMU protection
pub struct DmaBuffer {
    pub cpu_addr: VirtAddr,      // CPU-visible address
    pub dma_addr: PhysAddr,      // Device-visible address (IOMMU translated)
    pub size: usize,
    pub iommu_mapped: bool,      // Is IOMMU active?
}

// DMA flow with IOMMU:
// 1. Kernel allocates buffer
// 2. Kernel maps buffer into driver's IOMMU domain
// 3. Driver gets (dma_addr, size) capability
// 4. Device can only access this range (IOMMU enforced)
// 5. On revoke/cap deletion, IOMMU unmaps
```

**IOMMU Roadmap**:
- **Phase 1-6**: Trusted drivers, no IOMMU
- **Phase 7+**: Add VT-d/AMD-VI support
- **Phase 8+**: Per-driver IOMMU domains
- **Phase 9+**: Untrusted driver support

**Device Manager Server** (`servers/devmgr/`):
- Maintains device database
- Handles driver registration
- Matches drivers to devices (by PCI ID, class, etc.)
- Delivers DeviceCapabilities to drivers

**IRQ Delivery**:
- Kernel receives hardware IRQ
- Kernel translates to SSIP message
- Message sent to driver's registered endpoint

---

## Memory Management & User Pager

**Design Decision**: External pager model for extensibility

**Kernel Responsibility**:
- Physical page allocator
- Page table manipulation
- Page fault interception

**Userspace Pager** (`servers/pager/`):
- Receives page fault via SSIP
- Decides mapping policy (zero-fill, COW, file-backed)
- Requests page allocation from kernel
- Maps page into faulting address space

**Page Fault Flow**:
```
1. User page fault occurs
2. Kernel captures fault address
3. Kernel sends SSIP message to registered pager
4. Pager decides action (allocate, COW, load from disk)
5. Pager calls sys_vm_map() into the faulting address space
6. Kernel resumes faulting thread
```

**Faulting Address Space Access**:
- Kernel includes the faulting `AddressSpace` capability in the fault message
- Pager must hold MAP rights on that cap to call `sys_vm_map()`
- This avoids hidden kernel mapping and keeps policy in userspace

---

### External Pager Safety Rules

**Kernel Enforcement (How No-Fault is Guaranteed)**:
```rust
// sys_pager_register: explicit role assignment
sys_pager_register(cap: PagerCap) -> Result<()>

// When pager thread is registered:
// 1. Kernel marks thread as "is_pager = true"
// 2. Sets PagerNoFault flag in thread control block
// 3. Pins pager's stack memory (non-pageable)
// 4. Allocates kernel-mapped scratch region
```

**MM-Level Policy**:
```rust
// When pager thread faults:
match fault.thread.flags {
    ThreadFlags::IS_PAGER => {
        // Pager faulted - CRITICAL ERROR
        panic!("Pager thread faulted - kernel bug!");
    }
    _ => {
        // Normal fault handling
        send_to_pager(fault);
    }
}

// Pager memory ranges are marked as:
// - VM_PINNED: Never paged out
// - Page table entries have "global" bit set
// - Never swapped to disk
```

**Scheduler-Level Policy**:
- Pager threads run with elevated priority
- Preemptive scheduling still enabled
- No special scheduling exceptions needed

**Deadlock Prevention**:
```
Critical Rule: Pager must NEVER fault while handling a page fault

Faulting thread ─┐
                │ blocks
                ▼
          Kernel sends fault msg to pager
                │
                ▼
          Pager thread processes fault
                │
                ├─► MUST NOT fault (no user memory access)
                │   only uses:
                │   - Pre-pinned stack (kernel-enforced)
                │   - Kernel-mapped scratch pages (non-pageable)
                │   - Pre-allocated data structures
                │
                └─► May block on I/O (disk read)
                    but faulting thread stays blocked
```

**Pinned Memory Pool**:
```rust
// Pager pre-allocates at startup (kernel-enforced non-pageable)
pub struct PagerPool {
    // Kernel-mapped, never paged out
    pub scratch_pages: [PhysAddr; 16],  // For temporary data
    pub stack: VirtAddr,                // Pinned stack (VM_PINNED)
    pub metadata: VirtAddr,             // Paged-in metadata (VM_PINNED)
}

// Kernel ensures these ranges are never paged:
// - Page table entries marked "global" + "writable"
// - MMU never generates faults for these addresses
```

**Reentrancy Rules**:
1. **Pager threads** run with special "no-fault" flag
2. **No user memory access** during fault handling
3. **Only kernel-mapped memory** is accessible
4. **I/O is allowed** (disk reads may block)
5. **No recursive faults** (kernel verifies fault address is not in pager's memory)

**I/O Handling**:
```
When pager needs to load from disk:
1. Sends SSIP message to block driver (async I/O)
2. Waits for response (blocks)
3. Original faulting thread remains blocked
4. Block driver completes I/O, notifies pager
5. Pager maps page, resumes faulting thread
```

**SaltyFS + VM Integration**:
- File data pages are COW-mapped from SaltyFS server
- SaltyFS maintains page cache
- Page faults to file-backed pages → SaltyFS pager
- SaltyFS pager uses same pinned pool model

---

## SaltyFS Design (Enhanced)

**On-Disk Structure**:
```
+-------------------+
| Superblock (x3)   |  # Redundant copies
+-------------------+
| Checksum Tree     |  # Block integrity (xxHash)
+-------------------+
| Allocation Tree   |  # Free space (B-tree)
+-------------------+
| Filesystem Tree   |  # Directory structure (B-tree)
+-------------------+
| Extent Tree       |  # File data mapping (B-tree)
+-------------------+
| Data Blocks       |  # File data with checksums
+-------------------+
```

**Superblock with Versioning**:
```rust
#[repr(C)]
pub struct Superblock {
    // Identification
    pub magic: [u8; 8],           // "SaltyFS\0"
    pub version: u16,             // Major.Minor in high/low
    pub compat_flags: u64,        // Compatible features (ok if unknown)
    pub incompat_flags: u64,      // Incompatible features (error if unknown)
    pub ro_compat_flags: u64,     // RO-compatible features

    // Checksum
    pub checksum_algo: u16,       // 0 = xxHash64, 1 = CRC32C
    pub checksum: [u8; 32],       // Checksum of superblock

    // Size
    pub block_size: u32,          // 4096 default
    pub total_blocks: u64,
    pub used_blocks: u64,

    // Roots
    pub fs_tree_root: u64,        // Filesystem tree block
    pub extent_tree_root: u64,    // Extent tree block
    pub alloc_tree_root: u64,     // Allocation tree block
    pub checksum_tree_root: u64,  // Checksum tree block

    // Transaction
    pub generation: u64,          // Increments on each commit
    pub transaction_id: u64,

    // Reserved
    pub reserved: [u8; 384],
}
```

**Feature Flags**:
```rust
// Compatible features
const FEATURE_SNAPSHOTS: u64 = 0x01;
const FEATURE_COMPRESSION: u64 = 0x02;

// Incompatible features
const FEATURE_INCOMPAT_RAID1: u64 = 0x01;

// RO-compatible features
const FEATURE_RO_COMPAT_EXTENDED_REFS: u64 = 0x01;
```

**Transaction Commit Protocol**:
1. Allocate new blocks for modified data
2. Write new blocks (with checksums)
3. Update B-tree roots in temporary superblock
4. Write new superblock (atomic 512-byte write)
5. Old blocks are now free (reference count drops)

**Crash Recovery**:
- Read all 3 superblock copies
- Pick the one with highest `generation`
- Verify checksum
- If all corrupted, filesystem needs rebuild

---

## Graphics Architecture (Separated)

**Design**: Hardware driver ← protocol → graphics server

**Hardware Driver** (`servers/svga/`):
- Only talks to hardware (SVGA registers, FIFO)
- Implements **Graphics Device Protocol (GDP)**
- No compositor logic

**Graphics Server** (`servers/graphics/`):
- Compositor and window manager
- Uses GDP to talk to any graphics driver
- Independent of hardware (svga, virtio-gpu, bochs-vbe)

---

### Graphics Device Protocol (GDP)

**Request Types**:
```rust
pub enum GdpRequest {
    // Mode setting
    SetMode { width: u32, height: u32, fmt: PixelFormat },

    // Buffer operations
    CreateBuffer {
        handle: BufferHandle,
        size: (u32, u32),
        type: BufferType,  // NEW: buffer type
    },
    DestroyBuffer { handle: BufferHandle },
    Present { buffer: BufferHandle, regions: &[Rect] },

    // Cursor
    SetCursor { visible: bool, hotspot: (u32, u32), data: &[u8] },
    MoveCursor { x: i32, y: i32 },

    // Memory mapping
    MapBuffer { buffer: BufferHandle },  // Returns mmap capability
}
```

**Buffer Types & Ownership**:
```rust
pub enum BufferType {
    // CPU-accessible shared memory (most common)
    LinearCpuBuffer,

    // Device-local memory (VRAM, faster for GPU operations)
    DeviceSurface,

    // Hybrid: CPU-writable, GPU-readable
    UploadTexture,
}
```

**Ownership Rules**:

1. **LinearCpuBuffer**:
   - Graphics server creates (allocates shared memory)
   - Server renders to buffer (CPU writes)
   - Driver maps buffer for hardware presentation
   - Driver never owns the memory
   - Useful for: software rendering, simple 2D

2. **DeviceSurface**:
   - Driver creates (allocates VRAM)
   - Server gets handle for presentation only
   - Server cannot directly read/write
   - All GPU operations via driver commands
   - Useful for: 3D rendering, hardware acceleration

3. **UploadTexture**:
   - Server creates CPU buffer
   - Upload command copies to DeviceSurface
   - Server retains original CPU copy
   - Useful for: textures uploaded once, used many times

**MapBuffer Semantics**:
```rust
// For LinearCpuBuffer:
// - Returns shared memory capability in the SSIP response payload
// - Server and driver both can map
// - Coherency: CPU writes visible to GPU immediately

// For DeviceSurface:
// - MapBuffer fails (not CPU-mappable)
// - Or returns "device-local" marker
// - Server must use blit commands

// For UploadTexture:
// - MapBuffer returns CPU buffer cap in the response
// - Separate UploadTexture command copies to GPU
```

**Dirty Tracking** (Future):
- LinearCpuBuffer: implicit dirty (all writes visible)
- DeviceSurface: explicit Present marks dirty region
- UploadTexture: single dirty on upload

**This allows**:
- VMware uses svga driver
- QEMU uses virtio-gpu driver
- VirtualBox uses vboxvideo driver
- All via same GDP interface

---

## POSIX Emulation Strategy

**Design**: POSIX is entirely userspace emulation

**Libc Responsibilities** (`userspace/libc/`):
- Translates POSIX syscalls to SSABI + SSIP messages
- Emulates `fork()`, `exec()`, `wait()` using process server
- Emulates `open()`, `read()`, `write()` using filesystem server

**Example: `fork()` Implementation**:
```rust
// In libc
pub fn fork() -> pid_t {
    // Send SSIP message to process server
    let req = ProcessRequest::Fork {
        parent: current_task_id(),
    };

    let resp = process_server.call(req);

    match resp {
        ProcessResponse::ForkOk { child_pid } => child_pid,
        ProcessResponse::ForkParent => 0,
        ProcessResponse::Error { err } => {
            set_errno(err);
            -1
        }
    }
}
```

**Example: `open()` Implementation**:
```rust
pub fn open(path: &CStr, flags: i32) -> i32 {
    let req = FsRequest::Open {
        path: path.to_bytes(),
        flags: flags,
    };

    let resp = fs_server.call(req);

    match resp {
        FsResponse::OpenOk { fd } => fd,
        FsResponse::Error { err } => {
            set_errno(err);
            -1
        }
    }
}
```

**This means**:
- Kernel never knows about "files" or "processes" in POSIX sense
- POSIX semantics can change without kernel modification
- Different libc implementations possible (musl, glibc-style, etc.)

---

## Project Structure

```
SaltyOS/
├── Cargo.toml                      # Workspace root
├── meson.build                     # Top-level build orchestration
│
├── bootloader/
│   ├── uefi/                       # UEFI bootloader
│   ├── bios/                       # BIOS/legacy bootloader
│   └── common/                     # Shared code, ELF loader
│
├── kernel/                         # Microkernel core
│   └── src/
│       ├── main.rs
│       │
│       ├── arch/
│       │   ├── mod.rs
│       │   ├── x86_64/
│       │   │   ├── boot.S
│       │   │   ├── cpu.rs
│       │   │   ├── gdt.rs
│       │   │   ├── idt.rs
│       │   │   └── paging.rs
│       │   └── x86/
│       │
│       ├── foundation/             # HAL
│       │   ├── time/
│       │   │   ├── interface.rs
│       │   │   ├── pit.rs
│       │   │   └── apic_timer.rs
│       │   ├── interrupt/
│       │   │   ├── interface.rs
│       │   │   ├── pic.rs
│       │   │   ├── ioapic.rs
│       │   │   └── handler.rs
│       │   ├── dma/
│       │   │   ├── interface.rs
│       │   │   └── allocator.rs
│       │   └── device/
│       │       ├── interface.rs
│       │       ├── pci.rs
│       │       └── manager.rs
│       │
│       ├── mm/
│       │   ├── physical.rs
│       │   ├── virtual.rs
│       │   ├── heap.rs
│       │   └── pager.rs           # External pager interface
│       │
│       ├── cap/
│       │   ├── mod.rs
│       │   ├── type.rs
│       │   └── manager.rs
│       │
│       ├── thread/
│       │   ├── mod.rs
│       │   ├── thread.rs
│       │   ├── scheduler.rs
│       │   └── state.rs
│       │
│       ├── ipc/
│       │   ├── mod.rs
│       │   ├── endpoint.rs
│       │   ├── router.rs
│       │   └── message.rs
│       │
│       ├── ssabi/                 # SSABI syscall implementation
│       │   ├── mod.rs
│       │   ├── handler.rs
│       │   └── table.rs
│       │
│       └── lib/
│           ├── sync.rs
│           ├── console.rs
│           └── panic.rs
│
├── abi/
│   ├── ssabi/
│   ├── ssip/
│   └── ska/
│
├── servers/
│   ├── init/
│   ├── devmgr/                    # Device manager server
│   ├── pager/                     # External pager server
│   ├── process/                   # Process server (fork/exec emulation)
│   ├── saltyfs/
│   ├── svga/                      # SVGA hardware driver
│   ├── graphics/                  # Compositor (GDP client)
│   ├── ahci/
│   ├── terminal/
│   └── ps2kbd/
│
├── userspace/
│   ├── libc/                      # POSIX emulation + SSABI/SSIP client
│   └── utils/
│       ├── ls/
│       ├── cat/
│       └── echo/
│
├── shell/
│
├── target-specs/
├── scripts/
└── docs/
```

---

## Build Artifact Graph

**Artifacts**:
```
+----------------+     +----------------+
| uefi_bootloader |     | bios_bootloader |
+-------+--------+     +--------+-------+
        |                       |
        v                       v
+----------------+     +----------------+
|  bootx64.efi    |     |  bios.bin      |
+----------------+     +----------------+
        \                       /
         \                     /
          v                   v
        +-------------------------------+
        |        kernel.elf             |
        +---------------+---------------+
                        |
                        v
        +-------------------------------+
        |      saltyos.img              |
        |  +-------------------------+  |
        |  | ESP (EFI System Part.)  |  |
        |  |   - bootx64.efi         |  |
        |  | +---------------------+  |  |
        |  | | Partition          |  |  |
        |  | | - kernel.elf       |  |  |
        |  | | - initrd.img       |  |  |
        |  | +---------------------+  |  |
        |  +-------------------------+  |
        +-------------------------------+
```

**Build Phases**:
1. **Bootloader**: `bootx64.efi` (UEFI), `bios.bin` (BIOS)
2. **Kernel**: `kernel.elf` (flat binary or ELF)
3. **Initrd**: `initrd.img` (contains servers, shell, utilities)
4. **Image**: `saltyos.img` (disk image with ESP + partition)

**Note**: Bootloaders are inputs to the disk image only. The kernel is built once and shared across boot paths.

**Meson Integration**:
```python
# UEFI bootloader
uefi_boot = cargo.build('bootloader/uefi',
    target='x86_64-unknown-uefi')

# BIOS bootloader
bios_boot = cargo.build('bootloader/bios',
    target='x86_64-saltyos-bios')

# Kernel
kernel = cargo.build('kernel',
    target='x86_64-saltyos-kernel')

# Initrd (cpio archive with manifest)
initrd = custom_target('initrd',
    output: 'initrd.img',
    command: [scripts/mkinitrd.sh, servers, shell, userspace])

# Disk image
disk = custom_target('disk',
    output: 'saltyos.img',
    command: [scripts/mkdisk.sh, uefi_boot, kernel, initrd])
```

---

### Initrd Structure & Integrity

**Format**: CPIO archive (newc format)

**Structure**:
```
initrd.img
├── manifest.txt         # File manifest with hashes
├── servers/
│   ├── init
│   ├── registry
│   ├── pager
│   ├── saltyfs
│   ├── svga
│   ├── graphics
│   └── ...
├── shell/
│   └── saltysh
└── lib/
    └── libc.so
```

**Manifest Format** (`manifest.txt`):
```
# SaltyOS Initrd Manifest
# Format: <hash> <size> <path>

sha256:abc123... 45678 servers/init
sha256:def456... 12345 servers/registry
sha256:789012... 78901 servers/pager
sha256:345678... 234567 servers/saltyfs
sha256:901234... 89012 servers/svga
sha256:567890... 45678 servers/graphics
sha256:234567... 34567 shell/saltysh
sha256:678901... 67890 lib/libc.so

# End of manifest
```

**Integrity Verification**:
```rust
// Kernel or init verifies initrd before use
pub struct InitrdManifest {
    pub entries: Vec<ManifestEntry>,
}

pub struct ManifestEntry {
    pub path: String,
    pub hash: [u8; 32],      // SHA-256
    pub size: u64,
}

// Verification process:
// 1. Parse manifest.txt
// 2. For each entry:
//    - Read file from CPIO
//    - Compute SHA-256
//    - Compare with manifest
// 3. If any mismatch, panic/recovery mode
```

**Capability Distribution Policy** (Future):
- Init manifest can include "initial capabilities" for each server
- Init reads manifest, grants caps accordingly
- Example:
  ```
  cap:fs       servers/saltyfs     filesystem_cap
  cap:graphics servers/svga        gpu_access_cap
  cap:block    servers/ahci        disk_io_cap
  ```

**Security Roadmap**:
- **Phase 1-6**: No verification (development)
- **Phase 7**: Kernel verifies manifest hashes (integrity only)
- **Phase 8**: Bootloader verifies signed manifest (ed25519) and kernel re-verifies hashes
- **Phase 9**: Capability-based init policy

---

### Root of Trust & Signing Keys

**Problem**: Manifest hash inside initrd cannot verify itself

**Root of Trust Options**:
```
Option A: Embedded Public Key (Phase 8+)
┌─────────────────────────────────────┐
│ Bootloader                          │
│  - Contains embedded public key     │
│  - Verifies initrd signature        │
│  - Passes verification result to    │
│    kernel via SKA BootInfo          │
└─────────────────────────────────────┘

Option B: UEFI Secure Boot (Phase 9+)
┌─────────────────────────────────────┐
│ UEFI Firmware                       │
│  - Verifies bootloader signature    │
│  - Bootloader verifies initrd       │
│  - Chain of trust: firmware → OS   │
└─────────────────────────────────────┘

Option C: TPM/Measured Boot (Phase 9+)
┌─────────────────────────────────────┐
│ TPM                                 │
│  - Measures each boot stage         │
│  - Kernel can request TPM quote     │
│  - Remote attestation possible      │
└─────────────────────────────────────┘
```

**Key Storage**:
| Phase | Key Location | Verification |
|-------|--------------|--------------|
| **1-7** | None (development) | No verification |
| **8** | Embedded in bootloader | Bootloader verifies initrd.sig |
| **9** | UEFI db (Secure Boot) | Firmware verifies bootloader |
| **9+** | TPM (optional) | Measured boot chain |

**Signature Format** (Phase 8+):
```
initrd.img + initrd.sig

initrd.sig contains:
- manifest.txt SHA-256 hash
- Ed25519 signature over hash
- Signing key ID (for key rotation)
```

**Bootloader Responsibility** (Phase 8+):
```rust
// Before jumping to kernel
fn verify_initrd(initrd: &Data, sig: &Data) -> bool {
    // 1. Extract manifest hash from initrd
    let manifest_hash = extract_manifest_hash(initrd);

    // 2. Verify signature with embedded public key
    let public_key = EMBEDDED_PUBKEY;  // Compiled into bootloader
    let valid = ed25519_verify(sig, manifest_hash, public_key);

    // 3. Pass result to kernel via SKA
    bootinfo.initrd_verified = valid;

    valid
}
```

**Kernel Behavior**:
```rust
// Kernel checks SKA BootInfo
if !bootinfo.initrd_verified {
    // Phase 7: Warning only
    // Phase 8+: Panic or recovery mode
}
```

---

## Implementation Phases

### Phase 1: SKA + Bootloader (Minimal Boot)

**Goal**: Boot to "Hello, SaltyOS!" with SKA

**Critical Files**:
- `abi/ska/src/bootinfo.rs` - Unified BootInfo
- `bootloader/uefi/src/main.rs` - UEFI bootloader produces SKA BootInfo
- `bootloader/bios/src/main.rs` - BIOS bootloader produces SKA BootInfo
- `kernel/src/arch/x86_64/boot.S` - Parse BootInfo, jump to kernel
- `kernel/src/main.rs` - Parse BootInfo, print message

**Success**: Both UEFI and BIOS boot to same kernel

---

### Phase 2: SSABI + Foundation Layer

**Goal**: Minimal kernel with SSABI syscalls

**Critical Files**:
- `abi/ssabi/` - SSABI definitions
- `kernel/src/foundation/time/interface.rs` - Timer trait
- `kernel/src/foundation/interrupt/interface.rs` - IRQ trait
- `kernel/src/foundation/device/pci.rs` - PCI enumeration
- `kernel/src/mm/physical.rs` - Frame allocator
- `kernel/src/mm/virtual.rs` - Page tables
- `kernel/src/ssabi/handler.rs` - Syscall dispatcher

**Success**: Can handle syscalls from userspace

---

### Phase 3: External Pager + Thread Management

**Goal**: Page fault handling via IPC

**Critical Files**:
- `kernel/src/mm/pager.rs` - External pager interface
- `servers/pager/src/main.rs` - Userspace pager
- `kernel/src/thread/scheduler.rs` - Thread scheduler
- `kernel/src/ipc/endpoint.rs` - IPC endpoints

**Success**: Page faults cause IPC to pager, which allocates pages

---

### Phase 4: SSIP + Device Manager

**Goal**: Service discovery and device management

**Critical Files**:
- `abi/ssip/` - SSIP protocol definitions
- `servers/devmgr/src/main.rs` - Device manager
- `kernel/src/foundation/device/manager.rs` - Kernel device management
- `kernel/src/cap/manager.rs` - Capability manager

**Success**: Drivers can discover and register for devices

---

### Phase 5: First Servers (RAM Disk, Basic Graphics)

**Goal**: Userspace servers running

**Critical Files**:
- `servers/init/src/main.rs` - PID 1
- `servers/saltyfs/src/main.rs` - RAM filesystem (temporary)
- `servers/svga/src/main.rs` - SVGA driver (GDP implementation)
- `shell/src/main.rs` - Minimal shell

**Success**: Shell runs, can list files in RAM disk

---

### Phase 6: SaltyFS (COW + Checksums)

**Goal**: Persistent filesystem

**Critical Files**:
- `servers/saltyfs/src/superblock.rs` - Versioned superblock
- `servers/saltyfs/src/btree.rs` - B-tree implementation
- `servers/saltyfs/src/cow.rs` - COW allocation
- `servers/saltyfs/src/checksum.rs` - xxHash checksums
- `servers/ahci/src/main.rs` - AHCI driver

**Success**: Can create files that persist across reboot

---

### Phase 7: POSIX Emulation

**Goal**: Run bash/sh

**Critical Files**:
- `userspace/libc/src/ssabi.rs` - SSABI syscall wrappers
- `userspace/libc/src/ssip.rs` - SSIP client library
- `userspace/libc/src/posix.rs` - POSIX emulation
- `servers/process/src/main.rs` - Process server (fork/exec)

**Success**: Bash runs, can execute shell scripts

---

### Phase 8: Multi-Architecture + Hypervisors

**Goal**: x86 + x86_64, all hypervisors

**Critical Files**:
- `kernel/src/arch/x86/` - 32-bit support
- `scripts/test-vmware.sh`
- `scripts/test-virtualbox.sh`

**Success**: Boots on QEMU, VMware, VirtualBox

---

## Key Dependencies

**abi/ssabi/Cargo.toml**:
```toml
[dependencies]
bitflags = "2.4"
```

**abi/ssip/Cargo.toml**:
```toml
[dependencies]
bitflags = "2.4"
serde = { version = "1.0", default-features = false, features = ["derive"] }
```

**abi/ska/Cargo.toml**:
```toml
[dependencies]
```

**kernel/Cargo.toml**:
```toml
[dependencies]
spin = "0.9"
lazy_static = "1.4"
buddy_system_allocator = "0.10"
x86_64 = "0.14"
volatile = "0.5"
bitflags = "2.4"
saltyos-ssabi = { path = "../abi/ssabi" }
saltyos-ska = { path = "../abi/ska" }
```

**servers/*/Cargo.toml**:
```toml
[dependencies]
saltyos-ssip = { path = "../../abi/ssip" }
saltyos-ssabi = { path = "../../abi/ssabi" }
```

**userspace/libc/Cargo.toml**:
```toml
[dependencies]
saltyos-ssip = { path = "../../abi/ssip" }
saltyos-ssabi = { path = "../../abi/ssabi" }
```

---

## Custom Target Specifications

**x86_64-saltyos-kernel.json**:
```json
{
  "llvm-target": "x86_64-unknown-none",
  "data-layout": "e-m:e-i64:64-f80:128-n8:16:32:64-S128",
  "arch": "x86_64",
  "target-endian": "little",
  "target-pointer-width": "64",
  "target-c-int-width": "32",
  "os": "none",
  "executables": true,
  "linker-flavor": "ld.lld",
  "linker": "rust-lld",
  "features": "-mmx,-sse,+soft-float",
  "disable-redzone": true,
  "panic-strategy": "abort"
}
```

---

## Testing Strategy

**QEMU**:
```bash
qemu-system-x86_64 -drive format=raw,file=target/saltyos.img -m 512M -serial stdio
```

**VMware**: Convert `saltyos.img` to VMDK via `qemu-img` (script TBD)

**VirtualBox**: Convert `saltyos.img` to VDI via `qemu-img` (script TBD)

---

## Key Design Decisions

| Aspect | Choice | Rationale |
|--------|--------|-----------|
| Architecture | Microkernel | Better separation, userspace drivers |
| Language | Rust | Memory safety, modern tooling |
| Syscall ABI | SSABI (minimal) | Only machine-level primitives |
| IPC Protocol | SSIP (separate) | Userspace service contract |
| Boot ABI | SKA (unified) | Firmware-agnostic kernel |
| POSIX | Userspace emulation | Kernel independent of POSIX |
| Filesystem | SaltyFS | COW + checksums, versioned |
| Drivers | Userspace + capabilities | Secure, restartable |
| Graphics | GDP protocol | Hardware-independent |
| Pager | External | Extensible VM policy |

---

## Next Steps (Phase 1)

1. Create directory structure
2. Define SKA BootInfo structure
3. Initialize Cargo workspace
4. Write Meson build files
5. Implement UEFI bootloader (produces SKA)
6. Implement BIOS bootloader (produces SKA)
7. Implement kernel entry (parses SKA)
8. Create QEMU test script

**Success Criteria**: Both UEFI and BIOS boot to same kernel, displaying "Hello, SaltyOS!"

---

## Phase-Driven Checklist (Appendix)

**Phase 1-2: Boot + SSABI**
- `docs/implementation.md`: SKA BootInfo, BIOS/UEFI boot path, SSABI syscall list
- Done criteria: both firmware paths boot same `kernel.elf` and handle a minimal SSABI syscall
- `docs/implementation.md`: Build phases + artifact graph
- Done criteria: `saltyos.img` builds with bootloader + kernel + initrd artifacts

**Phase 3-4: IPC + Pager + Devices**
- `docs/implementation.md`: SSIP message format, IPC call/reply, service discovery
- Done criteria: SSIP request/response works across two user tasks
- `docs/implementation.md`: External pager flow and safety rules
- Done criteria: user page fault triggers pager and resolves without kernel fault
- `docs/implementation.md`: Device manager and capability delivery
- Done criteria: devmgr enumerates PCI and hands a device cap to a driver

**Phase 5-6: Servers + Filesystem**
- `docs/implementation.md`: Init, registry, pager, devmgr, graphics server
- Done criteria: init launches core servers and registry lookup returns endpoints
- `docs/implementation.md`: SaltyFS design and transaction model
- Done criteria: create/read/write a file and persist across reboot

**Phase 7: POSIX Emulation**
- `docs/implementation.md`: POSIX scope/non-goals/priorities
- Done criteria: shell runs a pipeline and exits cleanly
- `docs/implementation.md`: libc SSABI/SSIP translation flow
- Done criteria: libc `open/read/write` round-trips through SSIP

**Phase 8+: Multi-Arch + Hardening**
- `docs/implementation.md`: x86/x86_64 targets, hypervisor support
- Done criteria: boots on QEMU + one additional hypervisor target
- `docs/implementation.md`: Initrd signing and root of trust roadmap
- Done criteria: bootloader verifies signed manifest and kernel enforces result
