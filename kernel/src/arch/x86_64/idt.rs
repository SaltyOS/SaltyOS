//! Interrupt Descriptor Table for x86_64

#![no_std]

use core::arch::asm;
use core::fmt;

/// IDT Entry (16 bytes)
#[derive(Clone, Copy)]
#[repr(C)]
pub struct IdtEntry {
    offset_low: u16,
    selector: u16,
    ist: u8,
    type_attr: u8,
    offset_mid: u16,
    offset_high: u32,
    reserved: u32,
}

impl IdtEntry {
    /// Create a missing (uninitialized) entry
    pub const fn missing() -> Self {
        Self {
            offset_low: 0,
            selector: 0,
            ist: 0,
            type_attr: 0,
            offset_mid: 0,
            offset_high: 0,
            reserved: 0,
        }
    }

    /// Set handler for this IDT entry
    pub fn set_handler(&mut self, addr: u64, selector: u16, type_attr: u8) {
        self.offset_low = (addr & 0xffff) as u16;
        self.selector = selector;
        self.ist = 0;
        self.type_attr = type_attr;
        self.offset_mid = ((addr >> 16) & 0xffff) as u16;
        self.offset_high = ((addr >> 32) & 0xffffffff) as u32;
        self.reserved = 0;
    }

    /// Set handler with an IST index (1-7)
    pub fn set_handler_with_ist(&mut self, addr: u64, selector: u16, type_attr: u8, ist: u8) {
        self.offset_low = (addr & 0xffff) as u16;
        self.selector = selector;
        self.ist = ist & 0x7;
        self.type_attr = type_attr;
        self.offset_mid = ((addr >> 16) & 0xffff) as u16;
        self.offset_high = ((addr >> 32) & 0xffffffff) as u32;
        self.reserved = 0;
    }
}

impl fmt::Debug for IdtEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let offset = (self.offset_high as u64) << 32
            | (self.offset_mid as u64) << 16
            | (self.offset_low as u64);
        write!(
            f,
            "IdtEntry {{ offset: {:#x}, selector: {:#x}, type_attr: {:#x} }}",
            offset, self.selector, self.type_attr
        )
    }
}

/// IDT with 256 entries
#[repr(C, align(16))]
pub struct Idt {
    pub entries: [IdtEntry; 256],
}

impl Idt {
    /// Create a new IDT with all entries missing
    pub const fn new() -> Self {
        Self {
            entries: [IdtEntry::missing(); 256],
        }
    }

    /// Load the IDT using lidt instruction
    pub fn load(&'static self) {
        let pointer = IdtPointer {
            limit: (core::mem::size_of::<Idt>() - 1) as u16,
            base: self as *const _ as u64,
        };
        unsafe {
            asm!("lidt [{}]", in(reg) &pointer, options(nostack));
        }
    }
}

impl fmt::Debug for Idt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Idt")
            .field("entries", &self.entries)
            .finish()
    }
}

/// IDT Pointer for lidt instruction
#[repr(C, packed)]
pub struct IdtPointer {
    pub limit: u16,
    pub base: u64,
}

/// Normalized interrupt frame passed to Rust handlers
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct InterruptFrame {
    pub vector: u64,
    pub error_code: u64,
    pub instruction_pointer: u64,
    pub code_segment: u64,
    pub cpu_flags: u64,
    pub stack_pointer: u64,
    pub stack_segment: u64,
}

impl InterruptFrame {
    /// Returns true if the interrupt came from ring 3
    pub fn from_user(&self) -> bool {
        (self.code_segment & 0x3) == 0x3
    }
}
