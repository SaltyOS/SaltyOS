//! x86_64 Paging
//!
//! SPDX-License-Identifier: GPL-2.0-only

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
        self.entries[index]
    }

    pub fn set_entry(&mut self, index: usize, entry: u64) {
        self.entries[index] = entry;
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
        core::arch::asm!("mov cr3, {}", in(reg) value, options(nomem, nostack));
    }
}

/// Flush TLB for a single page
pub fn invlpg(addr: u64) {
    unsafe {
        core::arch::asm!("invlpg [{}]", in(reg) addr, options(nomem, nostack));
    }
}

/// Initialize paging (kernel page tables set up by bootloader)
pub fn init() {
    // Page tables are already set up by bootloader
    // Just verify we're in long mode with paging enabled
}
