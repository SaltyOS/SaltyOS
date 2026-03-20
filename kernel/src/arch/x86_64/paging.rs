//! x86_64 Paging
//!
//! SPDX-License-Identifier: GPL-2.0-only

use crate::mm::{alloc_frame, phys_to_virt, mark_frame_kernel_runtime, mark_frame_pt_owned, PAGE_SIZE, PHYS_MAP_OFFSET};

/// Maximum direct physical mapping size (512 GB cap)
const MAX_DIRECT_MAP_SIZE: usize = 512 * 1024 * 1024 * 1024;

/// Page table entry flags
#[repr(u64)]
pub enum PageFlags {
    Present = 1 << 0,
    Writable = 1 << 1,
    User = 1 << 2,
    WriteThrough = 1 << 3,
    CacheDisable = 1 << 4,
    Accessed = 1 << 5,
    Dirty = 1 << 6,
    HugePage = 1 << 7,
    Global = 1 << 8,
    NoExecute = 1 << 63,
}

/// Mask for the physical-address portion of a page-table entry.
const ENTRY_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// Page table (512 entries, 4KB aligned)
#[repr(C, align(4096))]
pub struct PageTable {
    entries: [u64; 512],
}

impl PageTable {
    pub const fn new() -> Self {
        Self { entries: [0; 512] }
    }

    pub fn entry(&self, index: usize) -> u64 {
        // Volatile read: PTEs are read by the hardware page walker and may be
        // modified by other CPUs. Prevents the compiler from caching or
        // eliminating PTE reads across invlpg/IPI boundaries.
        unsafe { core::ptr::read_volatile(&self.entries[index]) }
    }

    pub fn set_entry(&mut self, index: usize, entry: u64) {
        // Volatile write: every PTE store is architecturally significant.
        // Prevents the compiler from reordering or eliminating stores
        // relative to subsequent TLB invalidation.
        unsafe { core::ptr::write_volatile(&mut self.entries[index], entry) }
    }
}

/// Get current CR3 value
pub fn read_cr3() -> u64 {
    let value: u64;
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) value, options(nomem, nostack));
    }
    value
}

/// Set CR3 value (switch page table)
pub unsafe fn write_cr3(value: u64) {
    // SAFETY: Caller ensures value is a valid page table address
    unsafe {
        core::arch::asm!("mov cr3, {}", in(reg) value, options(nostack));
    }
}

/// Flush TLB for a single page
pub fn invlpg(addr: u64) {
    unsafe {
        core::arch::asm!("invlpg [{}]", in(reg) addr, options(nostack));
    }
}

/// Ensure that a non-leaf page table exists at `index` and return its physical address.
///
/// # Safety
/// - `table` must point to a valid page table in the active kernel address space.
/// - Must be called only when creating kernel-global mappings during boot or while
///   otherwise serialized against concurrent page-table modification.
unsafe fn ensure_next_table(
    table: &mut PageTable,
    index: usize,
    context: &'static str,
) -> u64 {
    let entry = table.entry(index);
    if entry & PageFlags::Present as u64 != 0 {
        if entry & PageFlags::HugePage as u64 != 0 {
            panic!("kernel 4K mapping collided with huge page");
        }
        return entry & ENTRY_ADDR_MASK;
    }

    let frame = alloc_frame().expect(context);
    mark_frame_pt_owned(frame);
    mark_frame_kernel_runtime(frame);

    // SAFETY: `frame` is a freshly allocated page-table frame reachable through
    // the existing direct map, and zeroing it initializes all entries to empty.
    unsafe {
        core::ptr::write_bytes(phys_to_virt(frame) as *mut u8, 0, PAGE_SIZE);
    }

    table.set_entry(
        index,
        frame | (PageFlags::Present as u64) | (PageFlags::Writable as u64),
    );
    frame
}

/// Map one 4KB MMIO page into the higher-half physmap slot with uncached attributes.
///
/// The direct map only covers usable RAM. Device MMIO pages that live above
/// `max_phys` are installed sparsely on demand at the same virtual address shape
/// (`PHYS_MAP_OFFSET + phys`) so existing physmap-based callers can safely access
/// them without assuming the whole MMIO hole is RAM-backed.
///
/// Returns the virtual address corresponding to `phys`.
///
/// # Safety
/// - Must be called after `init_direct_map()` has established access to page tables
///   via `phys_to_virt()`.
/// - The caller must ensure the requested physical page is valid MMIO and that
///   mapping it writable and uncached is appropriate for the device.
pub unsafe fn map_mmio_page(phys: u64) -> u64 {
    let page_mask = PAGE_SIZE as u64 - 1;
    let phys_page = phys & !page_mask;
    let virt_page = PHYS_MAP_OFFSET + phys_page;

    let cr3 = read_cr3();
    // SAFETY: CR3 points at the active kernel PML4, which is reachable via the
    // already-established direct map.
    let pml4 = unsafe { &mut *(phys_to_virt(cr3) as *mut PageTable) };

    let pdpt_phys = unsafe {
        ensure_next_table(
            pml4,
            ((virt_page >> 39) & 0x1FF) as usize,
            "Failed to allocate PDPT for kernel MMIO mapping",
        )
    };
    // SAFETY: `pdpt_phys` is a present page-table frame returned by ensure_next_table.
    let pdpt = unsafe { &mut *(phys_to_virt(pdpt_phys) as *mut PageTable) };

    let pd_phys = unsafe {
        ensure_next_table(
            pdpt,
            ((virt_page >> 30) & 0x1FF) as usize,
            "Failed to allocate PD for kernel MMIO mapping",
        )
    };
    // SAFETY: `pd_phys` is a present page-table frame returned by ensure_next_table.
    let pd = unsafe { &mut *(phys_to_virt(pd_phys) as *mut PageTable) };

    let pt_phys = unsafe {
        ensure_next_table(
            pd,
            ((virt_page >> 21) & 0x1FF) as usize,
            "Failed to allocate PT for kernel MMIO mapping",
        )
    };
    // SAFETY: `pt_phys` is a present page-table frame returned by ensure_next_table.
    let pt = unsafe { &mut *(phys_to_virt(pt_phys) as *mut PageTable) };

    let pte_idx = ((virt_page >> 12) & 0x1FF) as usize;
    let current = pt.entry(pte_idx);
    if current & PageFlags::Present as u64 != 0 {
        let current_phys = current & ENTRY_ADDR_MASK;
        if current_phys != phys_page {
            panic!("kernel MMIO mapping collided with existing page");
        }
    }

    // PCD=1, PWT=1 selects PAT3, which remains UC after init_pat().
    let entry = phys_page
        | (PageFlags::Present as u64)
        | (PageFlags::Writable as u64)
        | (PageFlags::WriteThrough as u64)
        | (PageFlags::CacheDisable as u64)
        | (PageFlags::NoExecute as u64);
    pt.set_entry(pte_idx, entry);
    invlpg(virt_page);

    virt_page + (phys & page_mask)
}

/// Initialize direct physical mapping
///
/// Maps physical memory [0..direct_map_size] to virtual address space
/// starting at PHYS_MAP_OFFSET using 2MB huge pages. The size is derived
/// from `max_phys`, rounded up to 2MB and capped at 512 GB.
///
/// # Safety
/// Must be called after frame allocator is initialized.
/// Must only be called once during boot.
///
/// # Note
/// Uses identity mapping (physical = virtual) for page table access during
/// initialization, as PHYS_MAP_OFFSET doesn't exist yet. The bootloader
/// provides identity mapping for low memory regions.
unsafe fn init_direct_map(max_phys: u64) {
    // Round max_phys up to 2MB boundary, cap at MAX_DIRECT_MAP_SIZE
    let huge_page_size: usize = 2 * 1024 * 1024;
    let direct_map_size = core::cmp::min(
        ((max_phys as usize + (huge_page_size - 1)) / huge_page_size) * huge_page_size,
        MAX_DIRECT_MAP_SIZE,
    );
    if direct_map_size == 0 {
        return;
    }

    {
        let s = crate::SerialGuard::acquire();
        s.puts("[PAGING] Direct map size: ");
        s.hex(direct_map_size as u64);
        s.puts(" (max_phys=");
        s.hex(max_phys);
        s.puts(")\n");
    }

    let cr0_orig: u64;
    unsafe {
        core::arch::asm!("mov {}, cr0", out(reg) cr0_orig, options(nomem, nostack));
        if cr0_orig & (1 << 16) != 0 {
            core::arch::asm!("mov cr0, {}", in(reg) (cr0_orig & !(1 << 16)), options(nomem, nostack));
        }
    }

    let cr3 = read_cr3();
    // Use identity mapping (bootloader maps low memory phys=virt)
    let pml4_virt = cr3 as *mut PageTable;
    let pml4 = unsafe { &mut *pml4_virt };

    // PML4 index for PHYS_MAP_OFFSET (0xFFFF_8000_0000_0000)
    // (0xFFFF_8000_0000_0000 >> 39) & 0x1FF = 256
    let pml4_idx = ((PHYS_MAP_OFFSET >> 39) & 0x1FF) as usize;

    // Get or create PDPT
    let pml4e = pml4.entry(pml4_idx);
    let pdpt_phys = if pml4e & PageFlags::Present as u64 == 0 {
        // Allocate new PDPT
        let pdpt_frame = alloc_frame().expect("Failed to allocate PDPT for direct map");
        // Use identity mapping for access during init
        let pdpt_virt = pdpt_frame as *mut u8;

        // Zero the PDPT
        unsafe {
            core::ptr::write_bytes(pdpt_virt, 0, PAGE_SIZE);
        }

        // Set PML4 entry (Present | Writable)
        pml4.set_entry(pml4_idx, pdpt_frame | (PageFlags::Present as u64) | (PageFlags::Writable as u64));

        pdpt_frame
    } else {
        pml4e & ENTRY_ADDR_MASK
    };

    // Use identity mapping for PDPT access during init
    let pdpt_virt = pdpt_phys as *mut PageTable;
    let pdpt = unsafe { &mut *pdpt_virt };

    let num_huge_pages = direct_map_size / huge_page_size;
    let entries_per_pd = 512;
    let num_pds = (num_huge_pages + entries_per_pd - 1) / entries_per_pd;

    // Allocate PDs and map physical memory
    for pd_idx in 0..num_pds {
        let pdpte = pdpt.entry(pd_idx);

        let pd_phys = if pdpte & PageFlags::Present as u64 == 0 {
            // Allocate new PD
            let pd_frame = alloc_frame().expect("Failed to allocate PD for direct map");
            // Use identity mapping for access during init
            let pd_virt = pd_frame as *mut u8;

            // Zero the PD
            unsafe {
                core::ptr::write_bytes(pd_virt, 0, PAGE_SIZE);
            }

            // Set PDPT entry (Present | Writable)
            pdpt.set_entry(pd_idx, pd_frame | (PageFlags::Present as u64) | (PageFlags::Writable as u64));

            pd_frame
        } else {
            pdpte & ENTRY_ADDR_MASK
        };

        // Use identity mapping for PD access during init
        let pd_virt = pd_phys as *mut PageTable;
        let pd = unsafe { &mut *pd_virt };

        // Fill PD with 2MB huge page mappings
        for pd_entry_idx in 0..entries_per_pd {
            let phys_addr = ((pd_idx * entries_per_pd + pd_entry_idx) * huge_page_size) as u64;

            // Don't map beyond direct_map_size
            if phys_addr >= direct_map_size as u64 {
                break;
            }

            // Create 2MB huge page entry (Present | Writable | Huge | NoExecute)
            // NX prevents code execution from the direct physical map.
            // Kernel code runs from PIE virtual addresses, not through this map.
            let entry = phys_addr
                | (PageFlags::Present as u64)
                | (PageFlags::Writable as u64)
                | (PageFlags::HugePage as u64)
                | (PageFlags::NoExecute as u64);
            pd.set_entry(pd_entry_idx, entry);
        }
    }

    // Flush TLB by reloading CR3
    // SAFETY: cr3 is the current valid page table address
    unsafe {
        write_cr3(cr3);
    }

    unsafe {
        if cr0_orig & (1 << 16) != 0 {
            core::arch::asm!("mov cr0, {}", in(reg) cr0_orig, options(nomem, nostack));
        }
    }
}

/// Program IA32_PAT MSR to enable Write-Combining.
///
/// Replaces the default PAT1 entry (Write-Through) with Write-Combining (WC).
/// PAT1 is selected by PTE flags PWT=1, PCD=0, PAT=0, which corresponds to the
/// existing `PageFlags::WriteThrough` bit. After this, setting WriteThrough on
/// a PTE gives WC caching instead of WT.
///
/// Default PAT: 0x00070406_00070406 (PAT0=WB, PAT1=WT, PAT2=UC-, PAT3=UC, ...)
/// New PAT:     0x00070406_00070401 (PAT0=WB, PAT1=WC, PAT2=UC-, PAT3=UC, ...)
///
/// # Safety
/// Must be called during single-threaded boot, before any mapping uses PAT1.
unsafe fn init_pat() {
    const IA32_PAT: u32 = 0x277;
    let new_pat: u64 = 0x00070406_00070401; // PAT1 = WC (0x01)
    let lo = new_pat as u32;
    let hi = (new_pat >> 32) as u32;
    // SAFETY: IA32_PAT is a valid MSR; single-threaded boot context.
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") IA32_PAT,
            in("eax") lo,
            in("edx") hi,
            options(nomem, nostack),
        );
    }
}

/// Initialize paging (kernel page tables set up by bootloader)
pub fn init() {
    // Program PAT MSR for Write-Combining support (PAT1 = WC)
    // SAFETY: Single-threaded boot context, before any WC mappings
    unsafe {
        init_pat();
    }

    // Set up direct physical mapping sized to actual RAM
    let max_phys = crate::mm::max_phys();
    // SAFETY: Single-threaded boot context, frame allocator initialized
    unsafe {
        init_direct_map(max_phys);
    }

    // Initialize kernel VSpace tracking (needed before any VSpace::new() calls)
    crate::mm::vspace::init_kernel_vspace(read_cr3());
}

/// Remove bootloader identity mapping (PML4[0]).
///
/// Must be called AFTER all APs have booted. The AP trampoline executes
/// in low physical memory and needs the identity mapping during its
/// real-mode → long-mode transition. Once all APs are in higher-half
/// kernel code, PML4[0] can be safely cleared.
///
/// This prevents stale bootloader page table frames (with supervisor-only
/// 2MB entries) from being visible through the old PML4[0] reference
/// after their physical memory is reclaimed by the frame allocator.
pub fn clear_boot_identity_map() {
    let cr3 = read_cr3();
    let pml4 = unsafe { &mut *(crate::mm::phys_to_virt(cr3) as *mut PageTable) };
    pml4.set_entry(0, 0);

    // Flush local TLB
    unsafe {
        write_cr3(cr3);
    }
}
