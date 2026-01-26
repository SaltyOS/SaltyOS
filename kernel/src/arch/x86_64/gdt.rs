//! Global Descriptor Table for x86_64
//!
//! Defines kernel/user code and data segments for long mode.

#![no_std]

use core::arch::asm;
use core::fmt;
use crate::arch::x86_64::tss::Tss;

/// GDT Pointer for lgdt instruction
#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct GdtPointer {
    pub limit: u16,
    pub base: u64,
}

impl GdtPointer {
    /// Get the limit value
    pub const fn limit(&self) -> u16 {
        self.limit
    }

    /// Get the base value
    pub const fn base(&self) -> u64 {
        self.base
    }
}

impl fmt::Debug for GdtPointer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Copy packed fields to avoid unaligned reference
        let base = self.base;
        let limit = self.limit;
        write!(f, "GdtPointer {{ base: {:#x}, limit: {} }}", base, limit)
    }
}

/// GDT with 7 entries:
/// 0: Null
/// 1: Kernel code (0x08)
/// 2: Kernel data (0x10)
/// 3: User data (0x18)
/// 4: User code (0x20)
/// 5: TSS low (0x28)
/// 6: TSS high (0x30)
#[repr(C, align(16))]
pub struct Gdt {
    entries: [u64; 8],
}

impl Gdt {
    /// Create a new GDT with standard entries
    pub const fn new() -> Self {
        Self {
            entries: [
                // Null selector
                0,
                // Kernel code (0x08): executable, 64-bit, present, DPL=0
                // Type=0xA (code), S=1 (code/data), DPL=00, P=1, L=1 (64-bit), D=0
                0x00af9b000000ffff,
                // Kernel data (0x10): writable, present, DPL=0
                // Type=0x2 (data), S=1, DPL=00, P=1
                0x00cf93000000ffff,
                // User data (0x18): writable, present, DPL=3
                // Type=0x2, S=1, DPL=11, P=1
                0x00cff3000000ffff,
                // User code (0x20): executable, 64-bit, present, DPL=3
                // Type=0xA, S=1, DPL=11, P=1, L=1
                0x00affb000000ffff,
                // TSS low (0x28) - placeholder, not used yet
                0,
                // TSS high (0x30) - placeholder, not used yet
                0,
                // Spare
                0,
            ],
        }
    }

    /// Install a TSS descriptor into the GDT
    pub fn set_tss(&mut self, tss: &Tss) {
        let base = tss as *const _ as u64;
        let limit = (core::mem::size_of::<Tss>() - 1) as u64;

        let low = (limit & 0xFFFF)
            | ((base & 0xFFFFFF) << 16)
            | (0x89u64 << 40)
            | ((limit & 0xF0000) << 32)
            | ((base & 0xFF000000) << 32);

        let high = base >> 32;

        self.entries[5] = low;
        self.entries[6] = high;
    }

    /// Load the GDT using lgdt instruction
    pub fn load(&'static self) {
        let pointer = GdtPointer {
            limit: (core::mem::size_of::<Gdt>() - 1) as u16,
            base: self as *const _ as u64,
        };
        unsafe {
            asm!("lgdt [{}]", in(reg) &pointer, options(nostack));
        }
    }

    /// Load GDT and reload data segment registers
    pub unsafe fn load_and_set_segments(&'static self) {
        let pointer = GdtPointer {
            limit: (core::mem::size_of::<Gdt>() - 1) as u16,
            base: self as *const _ as u64,
        };

        asm!(
            "lgdt [{0}]",
            "mov ax, 0x10",
            "mov ds, ax",
            "mov es, ax",
            "mov ss, ax",
            "mov fs, ax",
            "mov gs, ax",
            "push 0x08",
            "lea rax, [rip + 2f]",
            "push rax",
            "retfq",
            "2:",
            in(reg) &pointer,
            options(preserves_flags),
        );
    }

    /// Load TSS selector into TR
    pub unsafe fn load_tss() {
        asm!(
            "mov ax, 0x28",
            "ltr ax",
            options(nostack, preserves_flags),
        );
    }

    /// Get the base address of the GDT
    pub fn base(&self) -> u64 {
        self as *const _ as u64
    }
}

impl fmt::Debug for Gdt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Gdt")
            .field("entries", &self.entries)
            .finish()
    }
}
