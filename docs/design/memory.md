# Memory Management Design

This document describes the memory management subsystem of SaltyOS.

## Overview

SaltyOS memory management follows the capability-based model:

- **Untyped Memory**: Raw physical memory, the source of all objects
- **Frames**: 4KB physical pages that can be mapped
- **VSpace**: Virtual address space (page table hierarchy)
- **Page Tables**: Intermediate levels (PML4, PDPT, PD, PT on x86_64)

All memory access requires appropriate capabilities.

## Physical Memory Management

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
    
    /// Children (for revocation)
    children: Vec<ObjectRef>,
}

impl Untyped {
    /// Remaining free bytes
    pub fn free_bytes(&self) -> usize {
        self.size - self.watermark
    }
    
    /// Retype to create kernel objects
    pub fn retype(
        &mut self,
        object_type: CapType,
        size_bits: u8,
        count: usize,
    ) -> Result<Vec<ObjectRef>, MemError> {
        let obj_size = object_size(object_type, size_bits);
        let total = obj_size * count;
        
        // Alignment check
        let aligned_watermark = align_up(self.watermark, obj_size);
        
        if aligned_watermark + total > self.size {
            return Err(MemError::InsufficientMemory);
        }
        
        let mut objects = Vec::with_capacity(count);
        
        for i in 0..count {
            let phys = self.base + aligned_watermark + (i * obj_size);
            let obj = create_object_at(object_type, phys, size_bits)?;
            self.children.push(obj.clone());
            objects.push(obj);
        }
        
        self.watermark = aligned_watermark + total;
        Ok(objects)
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
        
        // Page-sized objects
        CapType::Frame => PAGE_SIZE,
        CapType::PageTable => PAGE_SIZE,
        CapType::VSpace => PAGE_SIZE,  // Top-level page table
        
        _ => 0,
    }
}

pub const PAGE_SIZE: usize = 4096;
pub const PAGE_BITS: usize = 12;
```

## Frames

A Frame represents a 4KB physical page:

```rust
/// Physical memory frame
pub struct Frame {
    /// Physical address
    phys: PhysAddr,
    
    /// Frame size (usually 4KB, but can be 2MB or 1GB for huge pages)
    size_bits: u8,
    
    /// Is this device memory?
    is_device: bool,
    
    /// Current mappings (for unmapping on revoke)
    mappings: Vec<Mapping>,
}

/// A mapping of this frame in a VSpace
struct Mapping {
    vspace: VSpaceRef,
    vaddr: VirtAddr,
}
```

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

### Page Table Structure

```rust
/// Generic page table
pub struct PageTable {
    /// Physical address of this table
    phys: PhysAddr,
    
    /// Entries
    entries: [PageTableEntry; 512],
}

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
    
    // Record mapping for revocation
    frame.mappings.push(Mapping {
        vspace: vspace.as_ref(),
        vaddr,
    });
    
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

## Slab Allocator

The kernel uses a slab allocator for fixed-size kernel objects:

```rust
/// Slab allocator for kernel objects
pub struct SlabAllocator {
    /// Slabs for different object sizes
    slabs: [Slab; NUM_SLAB_SIZES],
}

/// A slab for one object size
pub struct Slab {
    /// Object size
    size: usize,
    
    /// List of partially full pages
    partial: LinkedList<SlabPage>,
    
    /// List of completely full pages
    full: LinkedList<SlabPage>,
    
    /// Free object count
    free_count: usize,
}

/// A page used for slab allocation
pub struct SlabPage {
    /// Bitmap of free slots
    free_bitmap: u64,
    
    /// Number of free slots
    free_slots: u8,
    
    /// Object size
    obj_size: u16,
    
    /// Start of object array
    objects: [u8; PAGE_SIZE - 16],
}

impl SlabAllocator {
    /// Allocate an object of given size
    pub fn alloc(&mut self, size: usize) -> Option<*mut u8> {
        let slab_idx = size_to_slab_index(size)?;
        let slab = &mut self.slabs[slab_idx];
        
        // Try to allocate from partial slab
        if let Some(page) = slab.partial.front_mut() {
            if let Some(ptr) = page.alloc() {
                if page.is_full() {
                    let page = slab.partial.pop_front().unwrap();
                    slab.full.push_back(page);
                }
                return Some(ptr);
            }
        }
        
        // Need a new slab page
        // (This would need to come from untyped memory)
        None
    }
    
    /// Free an object
    pub fn free(&mut self, ptr: *mut u8, size: usize) {
        let slab_idx = size_to_slab_index(size).unwrap();
        let slab = &mut self.slabs[slab_idx];
        
        // Find which page contains this pointer
        // ... and mark slot as free
    }
}
```

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
│           Kernel Heap                   │
│           (Slab allocator)              │
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

## VSpace Operations via Syscalls

```rust
/// VSpace capability invocation
fn invoke_vspace(
    tcb: &mut Tcb,
    cap: &Capability,
    label: u64,
    msg: &IpcMessage,
) -> InvokeResult {
    let vspace = unsafe { &mut *(cap.object as *mut VSpace) };
    
    match label {
        // Map a frame
        VSPACE_MAP => {
            let frame_cap = msg.get_cap(0);
            let vaddr = VirtAddr::new(msg.get_word(0));
            let rights = MapRights::from_bits_truncate(msg.get_word(1) as u32);
            
            vspace_map(vspace, frame_cap, vaddr, rights)
        }
        
        // Unmap a page
        VSPACE_UNMAP => {
            let vaddr = VirtAddr::new(msg.get_word(0));
            vspace_unmap(vspace, vaddr)
        }
        
        // Map a page table object
        VSPACE_MAP_PT => {
            let pt_cap = msg.get_cap(0);
            let vaddr = VirtAddr::new(msg.get_word(0));
            let level = msg.get_word(1) as u8;
            
            vspace_map_pt(vspace, pt_cap, vaddr, level)
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

```rust
fn revoke_frame(frame: &mut Frame) {
    // Remove all mappings
    for mapping in frame.mappings.drain(..) {
        let vspace = mapping.vspace.get_mut();
        let _ = unmap(vspace, mapping.vaddr);
    }
    
    // Flush TLB on all CPUs
    arch::flush_tlb_all();
}
```
