//! Virtual Memory Manager
//!
//! x86_64 page table management with support for mapping/unmapping pages,
//! address space management, and TLB invalidation.

#![no_std]

use core::sync::atomic::{AtomicU64, Ordering};

use spin::Mutex;
use saltyos_ska::{BootInfo, PhysAddr, PAGE_SIZE};

use super::{
    VirtAddr, DIRECT_MAP_OFFSET, MAX_MANAGED_MEMORY,
    Frame, FrameNumber, allocate_frame, deallocate_frame,
};

/// Recursive mapping base (PML4 index 510 points to PML4 itself)
/// Using PML4[510] instead of [511] to avoid conflicts
const RECURSIVE_MAP_OFFSET: u64 = 0xffff_ff00_0000_0000;

/// Page table entry flags
#[derive(Clone, Copy, Debug)]
pub struct PageFlags(u64);

impl core::ops::BitOr for PageFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl PageFlags {
    pub const fn empty() -> Self { Self(0) }
    pub const PRESENT: Self = Self(1 << 0);
    pub const WRITABLE: Self = Self(1 << 1);
    pub const USER_ACCESSIBLE: Self = Self(1 << 2);
    pub const WRITE_THROUGH: Self = Self(1 << 3);
    pub const CACHE_DISABLE: Self = Self(1 << 4);
    pub const ACCESSED: Self = Self(1 << 5);
    pub const DIRTY: Self = Self(1 << 6);
    pub const GLOBAL: Self = Self(1 << 8);
    pub const HUGE_PAGE: Self = Self(1 << 7);

    pub fn contains(self, flags: PageFlags) -> bool {
        (self.0 & flags.0) == flags.0
    }

    pub fn insert(&mut self, flags: PageFlags) {
        self.0 |= flags.0;
    }

    pub fn remove(&mut self, flags: PageFlags) {
        self.0 &= !flags.0;
    }
}

/// Page table entry
#[repr(transparent)]
#[derive(Clone, Copy)]
struct PageTableEntry(u64);

impl PageTableEntry {
    fn is_unused(&self) -> bool {
        self.0 & 0x1 == 0
    }

    fn set(&mut self, frame: FrameNumber, flags: PageFlags) {
        assert!(frame.0 < (1 << 52), "Physical address too high");
        self.0 = (frame.0 * PAGE_SIZE) | flags.0;
    }

    fn frame(&self) -> Option<FrameNumber> {
        if self.is_unused() {
            None
        } else {
            Some(FrameNumber::from_phys_addr(PhysAddr::new(self.0 & 0x000f_ffff_ffff_f000)))
        }
    }

    fn flags(&self) -> PageFlags {
        PageFlags(self.0 & 0xefffffff00000fff)
    }

    fn set_flags(&mut self, flags: PageFlags) {
        // Preserve the frame address, update flags
        let addr = self.0 & 0x000f_ffff_ffff_f000;
        self.0 = addr | flags.0;
    }
}

/// Page table (512 entries)
#[repr(C)]
#[repr(align(4096))]
struct PageTable {
    entries: [PageTableEntry; 512],
}

/// Kernel address space
static KERNEL_AS: Mutex<Option<AddressSpace>> = Mutex::new(None);

/// Direct map initialized flag
static DIRECT_MAP_READY: AtomicU64 = AtomicU64::new(0);

/// An address space with its own page table
pub struct AddressSpace {
    pml4_frame: Frame,
}

impl AddressSpace {
    /// Get the current (active) address space
    pub unsafe fn current() -> Self {
        let cr3 = read_cr3();
        Self {
            pml4_frame: Frame {
                number: FrameNumber::from_phys_addr(PhysAddr::new(cr3)),
            },
        }
    }

    /// Get the PML4 table for this address space
    unsafe fn pml4(&self) -> &mut PageTable {
        let virt = frame_to_virt(self.pml4_frame);
        &mut *(virt.as_u64() as *mut PageTable)
    }
}

impl Drop for AddressSpace {
    fn drop(&mut self) {
        // Don't free the kernel's page table
        // For user address spaces, we would free the frames here
    }
}

/// Read CR3 register
unsafe fn read_cr3() -> u64 {
    let val: u64;
    core::arch::asm!("mov {}, cr3", out(reg) val, options(nostack, preserves_flags));
    val
}

/// Write CR3 register
unsafe fn write_cr3(addr: u64) {
    core::arch::asm!("mov cr3, {}", in(reg) addr, options(nostack, preserves_flags));
}

/// Invalidate TLB for a specific page
pub unsafe fn flush_tlb(addr: VirtAddr) {
    core::arch::asm!("invlpg [{}]", in(reg) addr.as_u64(), options(nostack, preserves_flags));
}

/// Get the PML4 index for a virtual address
const fn pml4_index(addr: VirtAddr) -> usize {
    ((addr.as_u64() >> 39) & 0x1ff) as usize
}

/// Get the PDPT index for a virtual address
const fn pdpt_index(addr: VirtAddr) -> usize {
    ((addr.as_u64() >> 30) & 0x1ff) as usize
}

/// Get the PD index for a virtual address
const fn pd_index(addr: VirtAddr) -> usize {
    ((addr.as_u64() >> 21) & 0x1ff) as usize
}

/// Get the PT index for a virtual address
const fn pt_index(addr: VirtAddr) -> usize {
    ((addr.as_u64() >> 12) & 0x1ff) as usize
}

/// Convert a physical frame to virtual address using recursive mapping
///
/// Uses recursive page table mapping (0xffff_ff80_0000_0000) to access
/// page tables before the direct map is ready.
fn phys_to_virt_recursive(frame: Frame) -> VirtAddr {
    let phys = frame.number.to_phys_addr().as_u64();

    if DIRECT_MAP_READY.load(Ordering::Acquire) != 0 {
        return VirtAddr::new(DIRECT_MAP_OFFSET + phys);
    }

    // Use recursive mapping: 0xffff_ff80_0000_0000 + (PML4_index << 39) + (PDPT_index << 30) + (PD_index << 21) + (PT_index << 12)
    let pml4_idx = (phys >> 39) & 0x1ff;
    let pdpt_idx = (phys >> 30) & 0x1ff;
    let pd_idx = (phys >> 21) & 0x1ff;
    let pt_idx = (phys >> 12) & 0x1ff;

    let virt = RECURSIVE_MAP_OFFSET
        | (pml4_idx << 39)
        | (pdpt_idx << 30)
        | (pd_idx << 21)
        | (pt_idx << 12);

    VirtAddr::new(virt)
}

/// Convert physical frame to virtual address for page table access
///
/// Uses identity mapping before direct map is ready, then direct map afterwards.
pub fn frame_to_virt(frame: Frame) -> VirtAddr {
    let phys = frame.number.to_phys_addr().as_u64();

    if DIRECT_MAP_READY.load(Ordering::Acquire) != 0 {
        if phys < MAX_MANAGED_MEMORY {
            return VirtAddr::new(DIRECT_MAP_OFFSET + phys);
        }
    }

    // Bootcore provides identity mapping for low physical memory.
    // This avoids touching recursive mappings before the direct map is set up.
    VirtAddr::new(phys)
}

/// Create a new page table
fn create_page_table() -> Option<Frame> {
    let frame = allocate_frame()?;
    unsafe {
        let virt = frame_to_virt(frame);
        core::ptr::write_bytes(virt.as_u64() as *mut u8, 0, PAGE_SIZE as usize);
    }
    Some(frame)
}

/// Map a page at the specified virtual address
pub unsafe fn map_page(addr: VirtAddr, frame: Frame, flags: PageFlags) -> Result<(), &'static str> {
    let addr = addr.align_down(PAGE_SIZE);
    let user = flags.contains(PageFlags::USER_ACCESSIBLE);
    let table_flags = if user {
        PageFlags::PRESENT | PageFlags::WRITABLE | PageFlags::USER_ACCESSIBLE
    } else {
        PageFlags::PRESENT | PageFlags::WRITABLE
    };

    let pml4;
    {
        let as_guard = KERNEL_AS.lock();
        let as_ref = as_guard.as_ref().ok_or("Address space not initialized")?;
        pml4 = as_ref.pml4_frame;
    }

    let pml4_addr = frame_to_virt(pml4).as_u64() as *mut PageTable;
    let pml4 = &mut *pml4_addr;

    // Track newly allocated page tables for cleanup on error
    let mut new_pdpt_frame: Option<Frame> = None;
    let mut new_pd_frame: Option<Frame> = None;
    let mut new_pt_frame: Option<Frame> = None;

    // PML4 entry
    let pml4_entry = &mut pml4.entries[pml4_index(addr)];
    let pdpt_frame = if pml4_entry.is_unused() {
        let new_frame = create_page_table().ok_or("Out of memory")?;
        pml4_entry.set(new_frame.number, table_flags);
        new_pdpt_frame = Some(new_frame);
        new_frame
    } else {
        if user && !pml4_entry.flags().contains(PageFlags::USER_ACCESSIBLE) {
            pml4_entry.set_flags(pml4_entry.flags() | PageFlags::USER_ACCESSIBLE);
        }
        Frame { number: pml4_entry.frame().unwrap() }
    };

    // PDPT
    let pdpt_addr = frame_to_virt(pdpt_frame).as_u64() as *mut PageTable;
    let pdpt = &mut *pdpt_addr;

    // PDPT entry
    let pdpt_entry = &mut pdpt.entries[pdpt_index(addr)];
    let pd_frame = if pdpt_entry.is_unused() {
        let new_frame = create_page_table().ok_or("Out of memory")?;
        pdpt_entry.set(new_frame.number, table_flags);
        new_pd_frame = Some(new_frame);
        new_frame
    } else {
        if user && !pdpt_entry.flags().contains(PageFlags::USER_ACCESSIBLE) {
            pdpt_entry.set_flags(pdpt_entry.flags() | PageFlags::USER_ACCESSIBLE);
        }
        Frame { number: pdpt_entry.frame().unwrap() }
    };

    // PD
    let pd_addr = frame_to_virt(pd_frame).as_u64() as *mut PageTable;
    let pd = &mut *pd_addr;

    // PD entry
    let pd_entry = &mut pd.entries[pd_index(addr)];
    let pt_frame = if pd_entry.is_unused() {
        let new_frame = create_page_table().ok_or("Out of memory")?;
        pd_entry.set(new_frame.number, table_flags);
        new_pt_frame = Some(new_frame);
        new_frame
    } else if pd_entry.flags().contains(PageFlags::HUGE_PAGE) {
        // Split 2 MiB huge page into 4 KiB pages.
        let huge_frame = pd_entry.frame().ok_or("Invalid huge PD entry")?;
        let base_phys = huge_frame.to_phys_addr().as_u64();
        let new_frame = create_page_table().ok_or("Out of memory")?;
        let pt_addr = frame_to_virt(new_frame).as_u64() as *mut PageTable;
        let pt = &mut *pt_addr;
        let mut flags = pd_entry.flags();
        flags.remove(PageFlags::HUGE_PAGE);
        flags.insert(PageFlags::PRESENT);
        for i in 0..512u64 {
            let phys = base_phys + i * PAGE_SIZE;
            let frame = FrameNumber::from_phys_addr(PhysAddr::new(phys));
            pt.entries[i as usize].set(frame, flags);
        }
        pd_entry.set(new_frame.number, table_flags);
        new_pt_frame = Some(new_frame);
        new_frame
    } else {
        if user && !pd_entry.flags().contains(PageFlags::USER_ACCESSIBLE) {
            pd_entry.set_flags(pd_entry.flags() | PageFlags::USER_ACCESSIBLE);
        }
        Frame { number: pd_entry.frame().unwrap() }
    };

    // PT
    let pt_addr = frame_to_virt(pt_frame).as_u64() as *mut PageTable;
    let pt = &mut *pt_addr;

    // PT entry
    let pt_entry = &mut pt.entries[pt_index(addr)];
    if !pt_entry.is_unused() {
        // Allow replacing mappings for user pages (used by user loader).
        if flags.contains(PageFlags::USER_ACCESSIBLE) {
            pt_entry.set(frame.number, flags);
            flush_tlb(addr);
            return Ok(());
        }
        // Clean up newly allocated page tables
        if let Some(f) = new_pt_frame { deallocate_frame(f); }
        if let Some(f) = new_pd_frame { deallocate_frame(f); }
        if let Some(f) = new_pdpt_frame { deallocate_frame(f); }
        return Err("Page already mapped");
    }
    pt_entry.set(frame.number, flags);

    flush_tlb(addr);
    Ok(())
}

/// Unmap a page at the specified virtual address
pub unsafe fn unmap_page(addr: VirtAddr) -> Result<(), &'static str> {
    let addr = addr.align_down(PAGE_SIZE);

    let pml4;
    {
        let as_guard = KERNEL_AS.lock();
        let as_ref = as_guard.as_ref().ok_or("Address space not initialized")?;
        pml4 = as_ref.pml4_frame;
    }

    let pml4_addr = frame_to_virt(pml4).as_u64() as *mut PageTable;
    let pml4 = &mut *pml4_addr;

    // Follow the page table hierarchy
    let pml4_entry = pml4.entries[pml4_index(addr)];
    if pml4_entry.is_unused() {
        return Err("Page not mapped");
    }
    let pdpt_frame = Frame { number: pml4_entry.frame().unwrap() };

    let pdpt_addr = frame_to_virt(pdpt_frame).as_u64() as *mut PageTable;
    let pdpt = &mut *pdpt_addr;

    let pdpt_entry = pdpt.entries[pdpt_index(addr)];
    if pdpt_entry.is_unused() {
        return Err("Page not mapped");
    }
    let pd_frame = Frame { number: pdpt_entry.frame().unwrap() };

    let pd_addr = frame_to_virt(pd_frame).as_u64() as *mut PageTable;
    let pd = &mut *pd_addr;

    let pd_entry = pd.entries[pd_index(addr)];
    if pd_entry.is_unused() {
        return Err("Page not mapped");
    }
    if pd_entry.flags().contains(PageFlags::HUGE_PAGE) {
        return Err("Cannot unmap 4K page inside a huge page");
    }
    let pt_frame = Frame { number: pd_entry.frame().unwrap() };

    let pt_addr = frame_to_virt(pt_frame).as_u64() as *mut PageTable;
    let pt = &mut *pt_addr;

    let pt_entry = &mut pt.entries[pt_index(addr)];
    if pt_entry.is_unused() {
        return Err("Page not mapped");
    }

    // Free the frame and clear the entry
    if let Some(frame) = pt_entry.frame() {
        deallocate_frame(Frame { number: frame });
    }
    pt_entry.0 = 0;

    flush_tlb(addr);
    Ok(())
}

/// Create the direct map for physical memory access
///
/// Maps the managed physical range to 0xffff_8800_0000_0000
fn create_direct_map() -> Result<(), &'static str> {
    // Map 0x0000_0000..MAX_MANAGED_MEMORY to 0xffff_8800_0000_0000
    // Use 2 MiB pages for efficiency

    let phys_end = MAX_MANAGED_MEMORY;

    unsafe {
        let phys_end_usize = phys_end as usize;
        for phys_addr in (0..phys_end_usize).step_by(2 * 1024 * 1024) {
            let phys_addr = phys_addr as u64;
            let frame = Frame {
                number: FrameNumber::from_phys_addr(PhysAddr::new(phys_addr)),
            };
            let virt_addr = VirtAddr::new(DIRECT_MAP_OFFSET + phys_addr);

            // For 2 MiB huge pages, we need to set the HUGE_PAGE flag
            // This requires mapping at the PD level instead of PT level
            let addr = virt_addr.align_down(PAGE_SIZE);

            let pml4;
            {
                let as_guard = KERNEL_AS.lock();
                let as_ref = as_guard.as_ref().ok_or("Address space not initialized")?;
                pml4 = as_ref.pml4_frame;
            }

            let pml4_table_addr = frame_to_virt(pml4).as_u64() as *mut PageTable;
            let pml4_table = &mut *pml4_table_addr;

            // PML4 entry
            let pml4_entry = &mut pml4_table.entries[pml4_index(addr)];
            let pdpt_frame = if pml4_entry.is_unused() {
                let new_frame = create_page_table().ok_or("Out of memory")?;
                pml4_entry.set(new_frame.number, PageFlags::PRESENT | PageFlags::WRITABLE);
                new_frame
            } else {
                Frame { number: pml4_entry.frame().ok_or("Invalid PML4 entry")? }
            };

            // PDPT
            let pdpt_addr = frame_to_virt(pdpt_frame).as_u64() as *mut PageTable;
            let pdpt = &mut *pdpt_addr;

            // PDPT entry
            let pdpt_entry = &mut pdpt.entries[pdpt_index(addr)];
            let pd_frame = if pdpt_entry.is_unused() {
                let new_frame = create_page_table().ok_or("Out of memory")?;
                pdpt_entry.set(new_frame.number, PageFlags::PRESENT | PageFlags::WRITABLE);
                new_frame
            } else {
                Frame { number: pdpt_entry.frame().ok_or("Invalid PDPT entry")? }
            };

            // PD
            let pd_addr = frame_to_virt(pd_frame).as_u64() as *mut PageTable;
            let pd = &mut *pd_addr;

            // PD entry - map as 2 MiB huge page
            let pd_entry = &mut pd.entries[pd_index(addr)];
            if pd_entry.is_unused() {
                pd_entry.set(frame.number, PageFlags::PRESENT | PageFlags::WRITABLE | PageFlags::HUGE_PAGE);
                flush_tlb(virt_addr);
            }
        }
    }
    Ok(())
}

/// Initialize virtual memory manager
///
/// # Safety
/// Must be called after physical allocator initialization.
pub unsafe fn init(_bootinfo: &BootInfo) {
    // Get current PML4 from CR3
    let pml4_phys = read_cr3();

    // Setup recursive mapping BEFORE storing KERNEL_AS
    // Map PML4[510] to point to PML4 itself
    // (Using 510 instead of 511 to avoid conflicts with kernel mapping)
    {
        let pml4_virt = VirtAddr::new(pml4_phys); // Use identity mapping (bootloader provides this)
        let pml4 = &mut *(pml4_virt.as_u64() as *mut PageTable);

        let entry_510 = &mut pml4.entries[510];
        let pml4_frame = FrameNumber::from_phys_addr(PhysAddr::new(pml4_phys));
        entry_510.set(pml4_frame, PageFlags::PRESENT | PageFlags::WRITABLE);
    }

    // Flush TLB for the recursive mapping region
    flush_tlb(VirtAddr::new(RECURSIVE_MAP_OFFSET));

    // Store kernel address space
    KERNEL_AS.lock().replace(AddressSpace {
        pml4_frame: Frame {
            number: FrameNumber::from_phys_addr(PhysAddr::new(pml4_phys)),
        },
    });

    // Create direct map (now using recursive mapping for page table access)
    if let Err(e) = create_direct_map() {
        panic!("Failed to create direct map: {}", e);
    }

    // Mark direct map as ready
    DIRECT_MAP_READY.store(1, Ordering::Release);
}
