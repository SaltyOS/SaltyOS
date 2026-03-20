//! AArch64 page table management (stub for Phase 1)
//!
//! Provides the same public interface as x86_64::paging so that shared
//! kernel code (vspace.rs, init.rs, etc.) can reference `crate::arch::paging::*`.
//!
//! SPDX-License-Identifier: GPL-2.0-only

/// Page table structure (4KB granule, 512 entries per level)
#[repr(C, align(4096))]
pub struct PageTable {
    pub entries: [u64; 512],
}

/// Page flags (aarch64 equivalents of x86 PTE bits)
pub struct PageFlags;

impl PageFlags {
    pub const PRESENT: u64 = 1 << 0;
    pub const WRITABLE: u64 = 1 << 6;  // AP[1] = 0 for RW
    pub const USER: u64 = 1 << 6;      // AP[1]
    pub const NO_EXECUTE: u64 = 1 << 54; // UXN
}

/// Read the current page table root (TTBR0_EL1)
pub fn read_cr3() -> u64 {
    let val: u64;
    // SAFETY: Reading TTBR0_EL1 is always safe from EL1
    unsafe {
        core::arch::asm!("mrs {}, TTBR0_EL1", out(reg) val, options(nomem, nostack));
    }
    val
}

/// Write the page table root (TTBR0_EL1)
pub fn write_cr3(val: u64) {
    // SAFETY: Caller must ensure val points to a valid page table
    unsafe {
        core::arch::asm!("msr TTBR0_EL1, {}", in(reg) val, options(nomem, nostack));
        core::arch::asm!("isb", options(nomem, nostack));
    }
}

/// Invalidate a single page in the TLB
pub fn invlpg(virt: u64) {
    // SAFETY: TLBI is always safe
    unsafe {
        // TLBI VAE1IS: TLB Invalidate by VA, EL1, Inner Shareable
        // The VA is shifted right by 12 (page-aligned)
        let va_shifted = virt >> 12;
        core::arch::asm!(
            "tlbi vae1is, {}",
            "dsb ish",
            "isb",
            in(reg) va_shifted,
            options(nomem, nostack),
        );
    }
}

/// Flush entire TLB
pub fn flush_tlb_all() {
    // SAFETY: Full TLB flush is always safe
    unsafe {
        core::arch::asm!(
            "tlbi vmalle1is",
            "dsb ish",
            "isb",
            options(nomem, nostack),
        );
    }
}

/// Clear bootloader identity mapping (stub)
pub fn clear_boot_identity_map() {
    // TODO: Phase 2 — clear TTBR0_EL1 identity map after all APs boot
}

/// Initialize kernel page tables (stub)
pub fn init(_boot_info: Option<&crate::ParsedBootInfo>) {
    // TODO: Phase 2 — set up TTBR1_EL1 with direct physical map
}
