//! Framebuffer Physical-to-Virtual Mapping
//!
//! Maps the framebuffer physical address into kernel virtual address space
//! at a dedicated PML4 slot (PML4[257] = 0xFFFF_8080_0000_0000).
//!
//! SPDX-License-Identifier: GPL-2.0-only

use crate::arch::x86_64::paging::{read_cr3, write_cr3, PageFlags, PageTable};
use crate::mm::{alloc_frame, phys_to_virt, PAGE_SIZE};
use crate::FramebufferInfo;

/// Kernel VA for framebuffer mapping (PML4[257])
const FB_KERNEL_VA: u64 = 0xFFFF_8080_0000_0000;

/// Map the framebuffer into kernel address space.
///
/// Creates page table entries at PML4[257] to map the framebuffer's
/// physical pages with write-through, cache-disable flags.
///
/// # Safety
/// - Must be called after paging::init() and frame allocator init.
/// - Must be called before init_smp() so APs inherit the mapping.
/// - Must only be called once during boot (single-threaded).
pub unsafe fn map_framebuffer(fb_info: &FramebufferInfo) -> Option<*mut u8> {
    // Validate framebuffer parameters
    if fb_info.addr == 0 || fb_info.bpp != 32 || fb_info.width == 0 || fb_info.height == 0 {
        return None;
    }

    let fb_size = fb_info.height as u64 * fb_info.pitch as u64;
    let num_pages = ((fb_size + PAGE_SIZE as u64 - 1) / PAGE_SIZE as u64) as usize;

    let cr3 = read_cr3();
    let pml4 = unsafe { &mut *(phys_to_virt(cr3) as *mut PageTable) };

    // PML4 index 257 for 0xFFFF_8080_0000_0000
    let pml4_idx = ((FB_KERNEL_VA >> 39) & 0x1FF) as usize;

    // Allocate and install PDPT at PML4[257]
    let pdpt_phys = alloc_frame()?;
    unsafe {
        core::ptr::write_bytes(phys_to_virt(pdpt_phys) as *mut u8, 0, PAGE_SIZE);
    }
    let flags_rw = PageFlags::Present as u64 | PageFlags::Writable as u64;
    pml4.set_entry(pml4_idx, pdpt_phys | flags_rw);

    let pdpt = unsafe { &mut *(phys_to_virt(pdpt_phys) as *mut PageTable) };

    // PDPT index 0 (we only need the first GB entry)
    let pd_phys = alloc_frame()?;
    unsafe {
        core::ptr::write_bytes(phys_to_virt(pd_phys) as *mut u8, 0, PAGE_SIZE);
    }
    pdpt.set_entry(0, pd_phys | flags_rw);

    let pd = unsafe { &mut *(phys_to_virt(pd_phys) as *mut PageTable) };

    // Map pages using 4KB page tables
    // Calculate how many PTs we need (each PT covers 512 * 4KB = 2MB)
    let num_pts = (num_pages + 511) / 512;

    // Use Write-Combining (WC) caching via PAT1. After init_pat() programs
    // the PAT MSR, PAT1 (PWT=1, PCD=0) = WC. This allows the CPU to
    // coalesce sequential VRAM writes into burst transactions, which is
    // 6-10x faster than UC on real hardware.
    let pt_flags = PageFlags::Present as u64
        | PageFlags::Writable as u64
        | PageFlags::WriteThrough as u64; // PAT1 = WC after init_pat()

    let mut pages_mapped = 0;
    for pt_idx in 0..num_pts {
        let pt_phys = alloc_frame()?;
        unsafe {
            core::ptr::write_bytes(phys_to_virt(pt_phys) as *mut u8, 0, PAGE_SIZE);
        }
        pd.set_entry(pt_idx, pt_phys | flags_rw);

        let pt = unsafe { &mut *(phys_to_virt(pt_phys) as *mut PageTable) };

        for pte_idx in 0..512 {
            if pages_mapped >= num_pages {
                break;
            }
            let page_phys = fb_info.addr + (pages_mapped as u64 * PAGE_SIZE as u64);
            pt.set_entry(pte_idx, page_phys | pt_flags);
            pages_mapped += 1;
        }
    }

    // Flush TLB
    unsafe {
        write_cr3(cr3);
    }

    Some(FB_KERNEL_VA as *mut u8)
}
