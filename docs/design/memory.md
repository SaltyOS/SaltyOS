# Memory Management Design

This document describes the memory management subsystem of SaltyOS.

## Overview

SaltyOS memory management follows the capability-based model:

- **Untyped Memory**: Raw physical memory, the source of all objects
- **Frames**: 4KB physical pages that can be mapped
- **VSpace**: Virtual address space (page table hierarchy, including intermediate levels PML4/PDPT/PD/PT on x86_64)

Page tables are managed internally by VSpace operations -- there is no separate `PageTable` kernel object type. All memory access requires appropriate capabilities.

## Physical Memory Management

Physical frame allocation uses a bitmap-based PMM (`mm/frame.rs`), not a buddy
allocator or slab allocator. Each bit represents one 4KB frame. The bitmap is
a fixed-size static array sized for the maximum supported physical memory.

### Memory Map from Bootloader

```rust
/// Memory region types
#[repr(u32)]
pub enum MemoryType {
    Usable = 1,
    Reserved = 2,
    AcpiReclaimable = 3,
    AcpiNvs = 4,
    BadMemory = 5,
    Bootloader = 1000,
    Kernel = 1001,
    Framebuffer = 1002,
}

/// Memory region descriptor
#[repr(C)]
pub struct MemoryRegion {
    pub base: PhysAddr,
    pub size: usize,
    pub mem_type: MemoryType,
}

/// Boot memory map
pub struct MemoryMap {
    pub regions: &'static [MemoryRegion],
}
```

### Untyped Memory

Untyped memory is the root of all kernel objects:

```rust
/// Untyped memory region
pub struct Untyped {
    /// Physical base address
    base: PhysAddr,
    
    /// Size in bytes (always power of 2)
    size: usize,
    
    /// Current allocation watermark
    watermark: usize,
    
    /// Is this device memory (uncacheable)?
    is_device: bool,
    
    /// Children tracked via Capability Derivation Tree (CDT)
    /// -- no Vec/heap; parent-child links are embedded in capabilities
}

impl Untyped {
    /// Remaining free bytes
    pub fn free_bytes(&self) -> usize {
        self.size - self.watermark
    }
    
    /// Retype to create a kernel object.
    /// Called via Untyped_Retype invocation (label 0x20).
    /// The new object is initialized in-place at the watermark offset.
    /// The caller provides a destination CNode slot; the kernel writes
    /// a capability for the new object into that slot.
    pub fn retype(
        &mut self,
        object_type: CapType,
        size_bits: u8,
        dest_cnode: *mut CNode,
        dest_index: usize,
        dest_depth: u8,
    ) -> Result<(), MemError> {
        let obj_size = object_size(object_type, size_bits);

        // Alignment check
        let aligned_watermark = align_up(self.watermark, obj_size);

        if aligned_watermark + obj_size > self.size {
            return Err(MemError::InsufficientMemory);
        }

        let phys = self.base + aligned_watermark;
        // SAFETY: phys points to zeroed memory within the untyped region
        let obj_ptr = create_object_at(object_type, phys, size_bits)?;

        // Install capability into destination CNode slot
        install_cap(dest_cnode, dest_index, dest_depth, object_type, obj_ptr)?;

        self.watermark = aligned_watermark + obj_size;
        Ok(())
    }
}
```

### Object Sizes

```rust
/// Get size of a kernel object type
pub fn object_size(obj_type: CapType, size_bits: u8) -> usize {
    match obj_type {
        CapType::Endpoint => size_of::<Endpoint>(),
        CapType::Notification => size_of::<Notification>(),
        CapType::Tcb => size_of::<Tcb>(),
        CapType::SchedContext => size_of::<SchedContext>(),
        
        // Variable-size objects
        CapType::CNode => size_of::<Capability>() * (1 << size_bits),
        CapType::Untyped => 1 << size_bits,
        
        // Page-sized objects (no separate PageTable type;
        // intermediate page tables are managed by VSpace internally)
        CapType::Frame => PAGE_SIZE,
        CapType::VSpace => PAGE_SIZE,  // Top-level page table (+ VSpaceTracking at phys+4096)
        
        _ => 0,
    }
}

pub const PAGE_SIZE: usize = 4096;
pub const PAGE_BITS: usize = 12;
```

## Frames

A Frame represents a 4KB physical page. Frames are standalone kernel objects
created via `Untyped_Retype` with `object_type = Frame`. The `FrameObject`
struct (defined in `cap/untyped.rs`) tracks the physical address and size:

```rust
/// Single frame object (for Frame capabilities)
/// Defined in kernel/src/cap/untyped.rs
#[repr(C)]
pub struct FrameObject {
    /// Kernel object header (must be first for refcount access)
    pub header: KernelObject,
    pub phys_addr: PhysAddr,
    pub size_bits: u8,
}
```

The kernel's bitmap-based physical memory manager (`mm/frame.rs`) tracks
which 4KB physical frames are allocated using a bitmap (one bit per frame).
Frame capabilities point to the `FrameObject` and carry rights inline in
the capability metadata.

### Frame Sizes

| Size | x86_64 Name | Size Bits |
|------|-------------|-----------|
| 4 KB | Page | 12 |
| 2 MB | Large Page | 21 |
| 1 GB | Huge Page | 30 |

## Virtual Address Spaces

### VSpace Structure

```rust
/// Virtual address space
pub struct VSpace {
    /// Root page table physical address
    root: PhysAddr,
    
    /// Architecture-specific data
    arch: ArchVSpace,
    
    /// ASID (Address Space ID) for TLB
    asid: u16,
}

/// x86_64-specific VSpace data
pub struct ArchVSpace {
    /// PML4 table (level 4)
    pml4: PageTable,
}
```

### Page Table Entries (kernel-internal)

Page tables are not exposed as a separate kernel object type. They are managed
internally by VSpace operations (MAP_PT allocates from an untyped frame and
installs it in the page table hierarchy). The kernel accesses page table entries
as raw 512-entry arrays via the physical-to-virtual direct map:

```rust
/// A page table is a 4KB-aligned array of 512 entries,
/// accessed via phys_to_virt() on the physical address.
/// (No standalone PageTable struct -- just raw pointer access.)

/// Page table entry
#[repr(transparent)]
pub struct PageTableEntry(u64);

impl PageTableEntry {
    // Flags
    pub const PRESENT: u64 = 1 << 0;
    pub const WRITABLE: u64 = 1 << 1;
    pub const USER: u64 = 1 << 2;
    pub const WRITE_THROUGH: u64 = 1 << 3;
    pub const CACHE_DISABLE: u64 = 1 << 4;
    pub const ACCESSED: u64 = 1 << 5;
    pub const DIRTY: u64 = 1 << 6;
    pub const HUGE_PAGE: u64 = 1 << 7;
    pub const GLOBAL: u64 = 1 << 8;
    pub const NO_EXECUTE: u64 = 1 << 63;
    
    pub fn new(phys: PhysAddr, flags: u64) -> Self {
        Self((phys.as_u64() & 0x000F_FFFF_FFFF_F000) | flags)
    }
    
    pub fn phys_addr(&self) -> PhysAddr {
        PhysAddr::new(self.0 & 0x000F_FFFF_FFFF_F000)
    }
    
    pub fn is_present(&self) -> bool {
        self.0 & Self::PRESENT != 0
    }
}
```

### Page Table Hierarchy (x86_64)

```
Virtual Address (48-bit canonical):
┌────────────────────────────────────────────────────────────────┐
│ Sign │  PML4  │  PDPT  │   PD   │   PT   │     Offset         │
│ Ext  │  [47:  │  [38:  │  [29:  │  [20:  │     [11:0]         │
│[63:48]│  39]  │  30]   │  21]   │  12]   │                    │
│ 16bit│  9bit │  9bit  │  9bit  │  9bit  │     12bit          │
└────────────────────────────────────────────────────────────────┘

Page Table Walk:
    CR3 ──► PML4 ──► PDPT ──► PD ──► PT ──► Physical Frame
            [9bit]   [9bit]  [9bit] [9bit]
```

## Address Translation

### Manual Page Walk

```rust
impl VSpace {
    /// Translate virtual address to physical
    pub fn translate(&self, vaddr: VirtAddr) -> Option<PhysAddr> {
        let pml4_idx = (vaddr.as_u64() >> 39) & 0x1FF;
        let pdpt_idx = (vaddr.as_u64() >> 30) & 0x1FF;
        let pd_idx = (vaddr.as_u64() >> 21) & 0x1FF;
        let pt_idx = (vaddr.as_u64() >> 12) & 0x1FF;
        let offset = vaddr.as_u64() & 0xFFF;
        
        // Walk PML4
        let pml4 = self.read_page_table(self.root);
        let pml4e = pml4.entries[pml4_idx as usize];
        if !pml4e.is_present() {
            return None;
        }
        
        // Walk PDPT
        let pdpt = self.read_page_table(pml4e.phys_addr());
        let pdpte = pdpt.entries[pdpt_idx as usize];
        if !pdpte.is_present() {
            return None;
        }
        if pdpte.is_huge() {
            // 1GB page
            let base = pdpte.phys_addr().as_u64() & !((1 << 30) - 1);
            let page_offset = vaddr.as_u64() & ((1 << 30) - 1);
            return Some(PhysAddr::new(base + page_offset));
        }
        
        // Walk PD
        let pd = self.read_page_table(pdpte.phys_addr());
        let pde = pd.entries[pd_idx as usize];
        if !pde.is_present() {
            return None;
        }
        if pde.is_huge() {
            // 2MB page
            let base = pde.phys_addr().as_u64() & !((1 << 21) - 1);
            let page_offset = vaddr.as_u64() & ((1 << 21) - 1);
            return Some(PhysAddr::new(base + page_offset));
        }
        
        // Walk PT
        let pt = self.read_page_table(pde.phys_addr());
        let pte = pt.entries[pt_idx as usize];
        if !pte.is_present() {
            return None;
        }
        
        Some(PhysAddr::new(pte.phys_addr().as_u64() + offset))
    }
}
```

## Mapping Operations

### Map Frame to VSpace

```rust
/// Map a frame into a virtual address space
pub fn map_frame(
    vspace: &mut VSpace,
    vaddr: VirtAddr,
    frame: &Frame,
    rights: MapRights,
) -> Result<(), MemError> {
    // Check alignment
    if !vaddr.is_aligned(PAGE_SIZE) {
        return Err(MemError::InvalidAlignment);
    }
    
    // Check address is in user space
    if !is_user_address(vaddr) {
        return Err(MemError::InvalidAddress);
    }
    
    // Build page table entry flags
    let mut flags = PageTableEntry::PRESENT | PageTableEntry::USER;
    if rights.contains(MapRights::WRITE) {
        flags |= PageTableEntry::WRITABLE;
    }
    if !rights.contains(MapRights::EXECUTE) {
        flags |= PageTableEntry::NO_EXECUTE;
    }
    if frame.is_device {
        flags |= PageTableEntry::CACHE_DISABLE;
    }
    
    // Ensure page table hierarchy exists
    ensure_page_tables(vspace, vaddr)?;
    
    // Set the mapping
    let pt = get_page_table(vspace, vaddr, 1)?;  // Level 1 = PT
    let pt_idx = (vaddr.as_u64() >> 12) & 0x1FF;
    
    if pt.entries[pt_idx as usize].is_present() {
        return Err(MemError::AlreadyMapped);
    }
    
    pt.entries[pt_idx as usize] = PageTableEntry::new(frame.phys, flags);
    
    // Flush TLB for this address
    arch::flush_tlb_page(vaddr);
    
    // Mapping is tracked in VSpaceTracking (embedded in the VSpace's
    // untyped allocation at vspace_phys + 4096), not in the frame itself.

    Ok(())
}
```

### Unmap

```rust
/// Unmap a page from a virtual address space
pub fn unmap(
    vspace: &mut VSpace,
    vaddr: VirtAddr,
) -> Result<(), MemError> {
    let pt = get_page_table(vspace, vaddr, 1)?;
    let pt_idx = (vaddr.as_u64() >> 12) & 0x1FF;
    
    if !pt.entries[pt_idx as usize].is_present() {
        return Err(MemError::NotMapped);
    }
    
    // Clear the entry
    pt.entries[pt_idx as usize] = PageTableEntry(0);
    
    // Flush TLB
    arch::flush_tlb_page(vaddr);
    
    Ok(())
}
```

### Page Table Allocation

```rust
/// Ensure page tables exist for a virtual address
fn ensure_page_tables(
    vspace: &mut VSpace,
    vaddr: VirtAddr,
) -> Result<(), MemError> {
    // For each level (4 down to 2), ensure table exists
    for level in (2..=4).rev() {
        if !has_page_table(vspace, vaddr, level) {
            // Need to allocate a page table
            // This requires an Untyped retype in the calling code
            return Err(MemError::MissingPageTable { level });
        }
    }
    Ok(())
}
```

## Kernel Object Allocation (seL4-style)

SaltyOS follows the seL4 model: **all kernel objects are carved from untyped memory
via the `retype` operation**. There is no kernel heap, slab allocator, or dynamic
memory pool. This provides several properties:

1. **Deterministic allocation** — no hidden OOM inside the kernel
2. **Authority tracking** — every object has an untyped parent in the Capability
   Derivation Tree (CDT), enabling revocation
3. **No kernel-internal fragmentation** — userspace controls memory layout

### Retype Flow

```
Untyped capability (user) ──retype──► Typed object (kernel creates in-place)
                                      │
                                      ├─ TCB
                                      ├─ CNode
                                      ├─ Endpoint
                                      ├─ Notification
                                      ├─ VSpace (+ VSpaceTracking at phys+4096)
                                      ├─ Frame (min size_bits=12, 4KB)
                                      └─ SchedContext
```

Each object is initialized at the untyped's watermark offset. The watermark
advances monotonically — objects are never freed back to the untyped. To
reclaim memory, the entire untyped must be revoked (which destroys all derived
capabilities and objects).

### VSpaceTracking

When a VSpace object is retyped, an additional 4KB `VSpaceTracking` structure is
placed immediately after the page table root (at `vspace_phys + 4096`). This
structure tracks per-page metadata (COW refcounts, mapping state) and is embedded
in the untyped allocation rather than using a separate slab.

### Centralized Memory Server (mmsrv)

In userspace, `mmsrv` is the centralized pager that owns the root untyped
capabilities and serves frame allocation requests from all processes:

- **MM_REGISTER/DEREGISTER** — register/deregister a client process
- **MM_MAP_BATCH** — allocate N frames and map into a client's VSpace
- **MM_MAP_WINDOW** — dual-map frames into both target and caller VSpaces
  (write window pattern for stack/boot-info initialization)
- **MM_UNMAP_WINDOW** — remove caller's write window, target mapping persists
- **MM_BRK / MM_MMAP / MM_MUNMAP** — POSIX-style heap and mmap
- **MM_FORK_REGIONS** — COW-clone a parent's VSpace regions for fork

## Kernel Address Space

### Layout

```
┌─────────────────────────────────────────┐ 0xFFFFFFFFFFFFFFFF
│           Kernel Reserved               │
├─────────────────────────────────────────┤ 0xFFFFFFFFFFE00000
│           Kernel Stack                  │
├─────────────────────────────────────────┤ 0xFFFFFFFF80000000
│           Kernel Text/Data/BSS          │
│           (Loaded by bootloader)        │
├─────────────────────────────────────────┤ 0xFFFFFFFF00000000
│           Kernel Object Space            │
│           (Untyped retype region)       │
├─────────────────────────────────────────┤ 0xFFFFFFFE00000000
│           Device MMIO                   │
├─────────────────────────────────────────┤ 0xFFFF800000000000
│           Direct Physical Map           │
│     (All physical memory mapped)        │
├─────────────────────────────────────────┤ 0xFFFF000000000000
│                                         │
│           Non-canonical hole            │
│                                         │
├─────────────────────────────────────────┤ 0x0000800000000000
│                                         │
│           User Space                    │
│                                         │
└─────────────────────────────────────────┘ 0x0000000000000000
```

### Physical Memory Access

```rust
/// Convert physical address to virtual (via direct map)
#[inline]
pub fn phys_to_virt(phys: PhysAddr) -> VirtAddr {
    VirtAddr::new(phys.as_u64() + PHYS_MAP_OFFSET)
}

/// Convert virtual address back to physical
#[inline]
pub fn virt_to_phys(virt: VirtAddr) -> PhysAddr {
    debug_assert!(virt.as_u64() >= PHYS_MAP_OFFSET);
    PhysAddr::new(virt.as_u64() - PHYS_MAP_OFFSET)
}

const PHYS_MAP_OFFSET: u64 = 0xFFFF_8000_0000_0000;
```

## Page Fault Handling

### Kernel Page Faults

```rust
/// Handle page fault in kernel context
fn handle_kernel_page_fault(addr: VirtAddr, error: u64) -> ! {
    panic!(
        "Kernel page fault at {:#x}\n\
         Error code: {:#x}\n\
         Present: {}\n\
         Write: {}\n\
         User: {}\n\
         Reserved: {}\n\
         Instruction fetch: {}",
        addr.as_u64(),
        error,
        error & 1 != 0,
        error & 2 != 0,
        error & 4 != 0,
        error & 8 != 0,
        error & 16 != 0,
    );
}
```

### User Page Faults

User page faults are delivered to the thread's fault handler via IPC:

```rust
/// Handle page fault in user context
fn handle_user_page_fault(
    tcb: &mut Tcb,
    addr: VirtAddr,
    error: u64,
) {
    // Check if thread has a fault handler
    if let Some(fault_ep) = &tcb.fault_handler {
        // Build fault message
        let msg = FaultMessage {
            fault_type: FaultType::VMFault,
            address: addr.as_u64(),
            fault_flags: error,
            instruction_pointer: tcb.context.rip,
        };
        
        // Send fault IPC
        send_fault_ipc(tcb, fault_ep, msg);
    } else {
        // No fault handler - terminate thread
        kprintln!(
            "Thread {} killed: page fault at {:#x}",
            tcb.id,
            addr.as_u64()
        );
        tcb.state = ThreadState::Suspended;
    }
}
```

## VSpace Page Flags

Flags passed in the `rights`/`flags` argument of VSpace mapping operations:

| Bit | Value | Name | Description |
|-----|-------|------|-------------|
| 0 | 0x01 | VSPACE_FLAG_WRITABLE | Page is writable |
| 1 | 0x02 | VSPACE_FLAG_USER | Page is accessible from user mode |
| 2 | 0x04 | VSPACE_FLAG_EXECUTABLE | Page is executable (NX bit cleared) |
| 3 | 0x08 | VSPACE_FLAG_CACHE_DISABLE | Disable caching (for device memory) |
| 4 | 0x10 | VSPACE_FLAG_WRITE_THROUGH | Write-through caching |
| 5 | 0x20 | VSPACE_FLAG_COW | Copy-on-write semantics |

## VSpace Operations via Syscalls

All VSpace operations are invoked via `Invoke` (syscall 9) on a VSpace capability. The label determines the operation:

| Label | Name | Description |
|-------|------|-------------|
| 0x50 | VSPACE_MAP | Map a frame into the VSpace |
| 0x51 | VSPACE_UNMAP | Unmap a page from the VSpace |
| 0x52 | VSPACE_MAP_PT | Map an intermediate page table |
| 0x53 | VSPACE_WALK | Walk page tables, return mapping info for an address |
| 0x54 | VSPACE_COPY_PAGE | Copy page content between VSpaces |
| 0x55 | VSPACE_MAP_DEVICE | Map device memory (uncacheable) |
| 0x56 | VSPACE_CLONE_COW_PAGE | Clone a page with COW semantics |
| 0x57 | VSPACE_MAP_DEVICE_RANGE | Batch device mapping (multiple contiguous pages) |
| 0x58 | VSPACE_PROTECT | Change page protection flags on an existing mapping |
| 0x59 | VSPACE_MAP_DEMAND | Map a demand-paged region (page fault triggers allocation) |
| 0x5A | VSPACE_MAP_DEMAND_RANGE | Batch demand-page mapping |

```rust
/// VSpace capability invocation dispatch
fn invoke_vspace(
    tcb: &mut Tcb,
    cap: &Capability,
    label: u64,
    msg: &IpcMessage,
) -> InvokeResult {
    // SAFETY: cap.object points to a VSpace allocated via untyped retype
    let vspace = unsafe { &mut *(cap.object as *mut VSpace) };

    match label {
        // Map a frame into the VSpace
        VSPACE_MAP => {
            let frame_cap = msg.get_cap(0);
            let vaddr = VirtAddr::new(msg.get_word(0));
            let flags = msg.get_word(1) as u32;
            vspace_map(vspace, frame_cap, vaddr, flags)
        }

        // Unmap a page
        VSPACE_UNMAP => {
            let vaddr = VirtAddr::new(msg.get_word(0));
            vspace_unmap(vspace, vaddr)
        }

        // Map an intermediate page table at a given level
        VSPACE_MAP_PT => {
            let pt_cap = msg.get_cap(0);
            let vaddr = VirtAddr::new(msg.get_word(0));
            let level = msg.get_word(1) as u8;
            vspace_map_pt(vspace, pt_cap, vaddr, level)
        }

        // Walk page tables, return physical address and flags
        VSPACE_WALK => {
            let vaddr = VirtAddr::new(msg.get_word(0));
            vspace_walk(vspace, vaddr)
        }

        // Copy page content between VSpaces
        VSPACE_COPY_PAGE => {
            let src_vaddr = VirtAddr::new(msg.get_word(0));
            let dst_vspace_cap = msg.get_cap(0);
            let dst_vaddr = VirtAddr::new(msg.get_word(1));
            vspace_copy_page(vspace, src_vaddr, dst_vspace_cap, dst_vaddr)
        }

        // Map device memory (uncacheable)
        VSPACE_MAP_DEVICE => {
            let phys = PhysAddr::new(msg.get_word(0));
            let vaddr = VirtAddr::new(msg.get_word(1));
            let flags = msg.get_word(2) as u32;
            vspace_map_device(vspace, phys, vaddr, flags)
        }

        // Clone a page with COW semantics
        VSPACE_CLONE_COW_PAGE => {
            let src_vaddr = VirtAddr::new(msg.get_word(0));
            let dst_vspace_cap = msg.get_cap(0);
            let dst_vaddr = VirtAddr::new(msg.get_word(1));
            vspace_clone_cow_page(vspace, src_vaddr, dst_vspace_cap, dst_vaddr)
        }

        // Batch device mapping (multiple contiguous pages)
        VSPACE_MAP_DEVICE_RANGE => {
            let phys = PhysAddr::new(msg.get_word(0));
            let vaddr = VirtAddr::new(msg.get_word(1));
            let num_pages = msg.get_word(2) as usize;
            let flags = msg.get_word(3) as u32;
            vspace_map_device_range(vspace, phys, vaddr, num_pages, flags)
        }

        // Change page protection flags
        VSPACE_PROTECT => {
            let vaddr = VirtAddr::new(msg.get_word(0));
            let new_flags = msg.get_word(1) as u32;
            vspace_protect(vspace, vaddr, new_flags)
        }

        // Map a demand-paged region (page fault triggers allocation)
        VSPACE_MAP_DEMAND => {
            let vaddr = VirtAddr::new(msg.get_word(0));
            let flags = msg.get_word(1) as u32;
            vspace_map_demand(vspace, vaddr, flags)
        }

        // Batch demand-page mapping
        VSPACE_MAP_DEMAND_RANGE => {
            let vaddr = VirtAddr::new(msg.get_word(0));
            let num_pages = msg.get_word(1) as usize;
            let flags = msg.get_word(2) as u32;
            vspace_map_demand_range(vspace, vaddr, num_pages, flags)
        }

        _ => InvokeResult::Error(SyscallError::InvalidOperation),
    }
}
```

## Memory Safety Properties

### Isolation Guarantees

1. **VSpace Isolation**: Each task has its own VSpace, preventing unauthorized access
2. **Capability Mediation**: All memory access requires Frame/VSpace capabilities
3. **No Direct Physical Access**: Userspace cannot access physical memory without mapping
4. **SMEP/SMAP**: CPU features prevent kernel from executing user code or accessing user memory without explicit request

### Revocation

When a Frame capability is revoked:
1. All mappings of that Frame are removed
2. TLB is flushed on all CPUs
3. Any threads accessing that memory will fault

Revocation walks the Capability Derivation Tree (CDT) to find all
derived capabilities. For each mapping tracked in VSpaceTracking, the
kernel unmaps the page and flushes the TLB:

```rust
fn revoke_frame(cap: &Capability) {
    // Walk CDT children of this frame capability
    // For each derived mapping, unmap from the target VSpace
    // (VSpaceTracking at vspace_phys + 4096 records per-page metadata)

    // Flush TLB on all CPUs via IPI
    arch::flush_tlb_all();
}
```
