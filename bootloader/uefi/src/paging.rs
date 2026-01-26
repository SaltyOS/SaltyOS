//! Page table setup for higher-half kernel loading
//!
//! Sets up minimal page tables to map:
//! - 0x0000000000000000 -> 0x0 (identity map for low memory)
//! - 0xffffffff80000000 -> KERNEL_PHYS_BASE (higher half kernel map)

use core::ptr;
use x86_64::{
    structures::paging::{PageTable, PageTableFlags, PhysFrame, Size4KiB},
    PhysAddr,
};
use saltyos_bootloader_common::layout::{KERNEL_VIRT_BASE, USER_CODE_BASE, USER_STACK_BASE};

/// Page table indices for P4, P3, P2, P1
const P4_INDEX: usize = 511;  // Last entry in P4 for higher half
const KERNEL_PDP_INDEX: usize = 510; // PDP index for 0xffff_ffff_8000_0000

/// Higher half kernel base address
pub const KERNEL_HIGHER_HALF_BASE: u64 = KERNEL_VIRT_BASE;

/// Create page tables for higher-half kernel
///
/// Returns the physical address of the PML4 (level 4 page table)
pub unsafe fn create_page_tables(
    kernel_phys_base: u64,
    identity_map_gib: usize,
    user_image_phys: u64,
    user_image_pages: usize,
    user_stack_phys: u64,
    user_stack_pages: usize,
) -> u64 {
    // Allocate page tables (all 4KB aligned)
    let pml4_addr = allocate_page_table();
    let pdpt_low_addr = allocate_page_table();
    let pdpt_high_addr = allocate_page_table();

    let pml4 = &mut *(pml4_addr as *mut PageTable);
    let pdpt_low = &mut *(pdpt_low_addr as *mut PageTable);
    let pdpt_high = &mut *(pdpt_high_addr as *mut PageTable);

    // Identity mapping: 0x0 -> 0x0 (first N GiB using huge pages)
    // P4[0] -> PDPT (low)
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
    pml4[0].set_addr(PhysAddr::new(pdpt_low_addr), flags);

    // Higher half mapping: 0xffffffff80000000 -> KERNEL_PHYS_BASE
    // P4[511] -> PDPT (high)
    pml4[P4_INDEX].set_addr(PhysAddr::new(pdpt_high_addr), flags);

    let map_gib = core::cmp::max(identity_map_gib, 1);

    // PDPT (low): map first N GiB using 2MB huge pages
    for gi in 0..map_gib {
        let pd_addr = allocate_page_table();
        let pd = &mut *(pd_addr as *mut PageTable);

        pdpt_low[gi].set_addr(PhysAddr::new(pd_addr), flags);

        for i in 0..512 {
            let phys_addr = ((gi as u64) * 1024 * 1024 * 1024) + (i as u64 * 2048 * 1024);
            let huge_flags = PageTableFlags::PRESENT
                | PageTableFlags::WRITABLE
                | PageTableFlags::HUGE_PAGE;
            pd[i].set_addr(PhysAddr::new(phys_addr), huge_flags);
        }
    }

    // PDPT (high): map first 1 GiB starting at kernel_phys_base
    let pd_high_addr = allocate_page_table();
    let pd_high = &mut *(pd_high_addr as *mut PageTable);
    pdpt_high[KERNEL_PDP_INDEX].set_addr(PhysAddr::new(pd_high_addr), flags);

    for i in 0..512 {
        let phys_addr = kernel_phys_base + (i as u64 * 2048 * 1024);
        let huge_flags = PageTableFlags::PRESENT
            | PageTableFlags::WRITABLE
            | PageTableFlags::HUGE_PAGE;
        pd_high[i].set_addr(PhysAddr::new(phys_addr), huge_flags);
    }

    // User mappings: separate user code + stack in lower canonical half
    let user_pml4_idx = ((USER_CODE_BASE >> 39) & 0x1ff) as usize;
    let user_pdpt_idx = ((USER_CODE_BASE >> 30) & 0x1ff) as usize;
    let user_pd_idx = ((USER_CODE_BASE >> 21) & 0x1ff) as usize;
    let user_stack_pt_idx = ((USER_STACK_BASE >> 12) & 0x1ff) as usize;

    let pdpt_user_addr = allocate_page_table();
    let pd_user_addr = allocate_page_table();
    let pt_user_addr = allocate_page_table();
    let pdpt_user = &mut *(pdpt_user_addr as *mut PageTable);
    let pd_user = &mut *(pd_user_addr as *mut PageTable);
    let pt_user = &mut *(pt_user_addr as *mut PageTable);

    let user_flags = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::USER_ACCESSIBLE;
    pml4[user_pml4_idx].set_addr(PhysAddr::new(pdpt_user_addr), user_flags);
    pdpt_user[user_pdpt_idx].set_addr(PhysAddr::new(pd_user_addr), user_flags);
    pd_user[user_pd_idx].set_addr(PhysAddr::new(pt_user_addr), user_flags);

    let image_flags = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::USER_ACCESSIBLE;
    for i in 0..user_image_pages {
        pt_user[i].set_addr(
            PhysAddr::new(user_image_phys + (i as u64 * 4096)),
            image_flags,
        );
    }

    let stack_flags = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::USER_ACCESSIBLE;
    for i in 0..user_stack_pages {
        let idx = user_stack_pt_idx + i;
        pt_user[idx].set_addr(
            PhysAddr::new(user_stack_phys + (i as u64 * 4096)),
            stack_flags,
        );
    }

    pml4_addr
}

/// Allocate a 4KB aligned page for page table use
fn allocate_page_table() -> u64 {
    // Use a static allocation for the bootloader
    // In a real bootloader, this would be allocated from UEFI memory
    use core::sync::atomic::{AtomicU64, Ordering};

    // Simple bump allocator starting at a fixed address
    // This is a hack - in production, use proper memory allocation
    static PAGE_TABLE_ALLOCATOR: AtomicU64 = AtomicU64::new(0x10000);  // Start at 64KB

    let addr = PAGE_TABLE_ALLOCATOR.fetch_add(4096, Ordering::SeqCst);
    if addr >= 0x100000 {
        panic!("Page table space exhausted - would overlap kernel at 1MB");
    }

    // Zero the page table
    unsafe {
        ptr::write_bytes(addr as *mut u8, 0, 4096);
    }

    addr
}

/// Enable paging and load page tables
///
/// # Safety
/// Caller must ensure page tables are valid and memory is mapped correctly
pub unsafe fn enable_paging(pml4_phys_addr: u64) {
    use x86_64::registers::control::Cr3;

    // Load CR3 with PML4 physical address
    // Note: On x86_64, paging is always enabled in long mode
    // We just need to load CR3. The UEFI firmware should have already enabled long mode.
    let frame = PhysFrame::<Size4KiB>::from_start_address(PhysAddr::new(pml4_phys_addr))
        .expect("Invalid CR3 address - not aligned");
    unsafe {
        Cr3::write(frame, x86_64::registers::control::Cr3Flags::empty());
    }
}

/// Convert a higher-half virtual address to physical address
/// using our mapping (0xffff800000000000 + X -> X)
pub fn virt_to_phys(virt: u64) -> u64 {
    if virt >= KERNEL_VIRT_BASE {
        virt - KERNEL_VIRT_BASE
    } else {
        virt  // Identity mapped
    }
}

/// Convert a physical address to higher-half virtual address
pub fn phys_to_virt(phys: u64) -> u64 {
    phys + KERNEL_VIRT_BASE
}

/// Get the actual entry point to jump to
///
/// For PIE kernel with higher-half addressing:
/// - e_entry contains the higher-half VMA (e.g., 0xffff800000001000)
/// - We need page tables to access this address
/// - After enabling paging, we can jump directly to e_entry
pub fn get_kernel_entry(e_entry: u64) -> u64 {
    // The e_entry should be the higher-half address
    // After we enable paging with our mapping, we can jump directly to it
    e_entry
}
