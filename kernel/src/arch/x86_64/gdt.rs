//! Global Descriptor Table (GDT)
//!
//! SPDX-License-Identifier: GPL-2.0-only

use core::mem::size_of;

/// GDT entry
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct GdtEntry {
    limit_low: u16,
    base_low: u16,
    base_mid: u8,
    access: u8,
    granularity: u8,
    base_high: u8,
}

impl GdtEntry {
    pub const fn null() -> Self {
        Self {
            limit_low: 0,
            base_low: 0,
            base_mid: 0,
            access: 0,
            granularity: 0,
            base_high: 0,
        }
    }

    pub const fn kernel_code() -> Self {
        Self {
            limit_low: 0xFFFF,
            base_low: 0,
            base_mid: 0,
            access: 0x9A,      // Present, Ring 0, Code, Executable, Readable
            granularity: 0xAF, // 4KB granularity, 64-bit mode
            base_high: 0,
        }
    }

    pub const fn kernel_data() -> Self {
        Self {
            limit_low: 0xFFFF,
            base_low: 0,
            base_mid: 0,
            access: 0x92,      // Present, Ring 0, Data, Writable
            granularity: 0xCF, // 4KB granularity, 32-bit size
            base_high: 0,
        }
    }

    pub const fn user_code() -> Self {
        Self {
            limit_low: 0xFFFF,
            base_low: 0,
            base_mid: 0,
            access: 0xFA,      // Present, Ring 3, Code, Executable, Readable
            granularity: 0xAF, // 4KB granularity, 64-bit mode
            base_high: 0,
        }
    }

    pub const fn user_data() -> Self {
        Self {
            limit_low: 0xFFFF,
            base_low: 0,
            base_mid: 0,
            access: 0xF2,      // Present, Ring 3, Data, Writable
            granularity: 0xCF, // 4KB granularity, 32-bit size
            base_high: 0,
        }
    }
}

/// Task State Segment entry (16 bytes)
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct TssEntry {
    limit_low: u16,
    base_low: u16,
    base_mid: u8,
    access: u8,
    granularity: u8,
    base_high: u8,
    base_upper: u32,
    reserved: u32,
}

/// GDT structure
#[repr(C, packed)]
pub struct Gdt {
    null: GdtEntry,
    kernel_code: GdtEntry,
    kernel_data: GdtEntry,
    user_code: GdtEntry,
    user_data: GdtEntry,
    tss: TssEntry,
}

/// GDT pointer
#[repr(C, packed)]
struct GdtPtr {
    limit: u16,
    base: u64,
}

static mut GDT: Gdt = Gdt {
    null: GdtEntry::null(),
    kernel_code: GdtEntry::kernel_code(),
    kernel_data: GdtEntry::kernel_data(),
    user_code: GdtEntry::user_code(),
    user_data: GdtEntry::user_data(),
    tss: TssEntry {
        limit_low: 0,
        base_low: 0,
        base_mid: 0,
        access: 0,
        granularity: 0,
        base_high: 0,
        base_upper: 0,
        reserved: 0,
    },
};

/// Initialize GDT
pub fn init() {
    // SAFETY: Single-threaded initialization, GDT is properly structured
    unsafe {
        let gdt_ptr = GdtPtr {
            limit: (size_of::<Gdt>() - 1) as u16,
            base: (&raw const GDT) as u64,
        };

        core::arch::asm!(
            "lgdt [{}]",
            in(reg) &gdt_ptr,
            options(nostack)
        );

        // Reload segment registers
        reload_segments();
    }
}

unsafe fn reload_segments() {
    // SAFETY: Called after GDT is loaded with valid segments
    unsafe {
        core::arch::asm!(
            // Reload CS via far return
            "push 0x08", // Kernel code segment
            "lea rax, [rip + 2f]",
            "push rax",
            "retfq",
            "2:",
            // Reload data segments
            "mov ax, 0x10", // Kernel data segment
            "mov ds, ax",
            "mov es, ax",
            "mov fs, ax",
            "mov gs, ax",
            "mov ss, ax",
            options(nostack)
        );
    }
}
