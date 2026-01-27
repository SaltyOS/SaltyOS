//! Interrupt Descriptor Table (IDT)
//!
//! SPDX-License-Identifier: GPL-2.0-only

use core::mem::size_of;

/// IDT entry (16 bytes)
#[repr(C, packed)]
#[derive(Clone, Copy)]
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
    pub const fn null() -> Self {
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

    pub fn set_handler(&mut self, handler: u64) {
        self.offset_low = handler as u16;
        self.offset_mid = (handler >> 16) as u16;
        self.offset_high = (handler >> 32) as u32;
        self.selector = 0x08; // Kernel code segment
        self.ist = 0;
        self.type_attr = 0x8E; // Present, Ring 0, Interrupt Gate
    }

    pub fn set_trap(&mut self, handler: u64) {
        self.set_handler(handler);
        self.type_attr = 0x8F; // Trap gate (no interrupt disable)
    }
}

/// IDT structure
#[repr(C, align(16))]
pub struct Idt {
    entries: [IdtEntry; 256],
}

impl Idt {
    pub const fn new() -> Self {
        Self {
            entries: [IdtEntry::null(); 256],
        }
    }
}

/// IDT pointer
#[repr(C, packed)]
struct IdtPtr {
    limit: u16,
    base: u64,
}

/// Interrupt stack frame pushed by x86_64 on interrupt/exception
#[repr(C)]
#[derive(Clone, Copy)]
pub struct InterruptStackFrame {
    /// This value is always pushed by the CPU
    pub rip: u64,
    /// Code segment selector
    pub cs: u64,
    /// CPU flags (RFLAGS register)
    pub rflags: u64,
    /// Stack pointer before interrupt
    pub rsp: u64,
    /// Stack segment selector
    pub ss: u64,
}

static mut IDT: Idt = Idt::new();

/// Initialize IDT
pub fn init() {
    // SAFETY: Single-threaded initialization, IDT is properly structured
    unsafe {
        // Set up exception handlers (vectors 0-31)
        (*(&raw mut IDT)).entries[0].set_handler(exception_divide_error as u64);
        (*(&raw mut IDT)).entries[1].set_handler(exception_debug as u64);
        (*(&raw mut IDT)).entries[2].set_handler(exception_nmi as u64);
        (*(&raw mut IDT)).entries[3].set_trap(exception_breakpoint as u64);
        (*(&raw mut IDT)).entries[4].set_handler(exception_overflow as u64);
        (*(&raw mut IDT)).entries[6].set_handler(exception_invalid_opcode as u64);
        (*(&raw mut IDT)).entries[8].set_handler(exception_double_fault as u64);
        (*(&raw mut IDT)).entries[13].set_handler(exception_gpf as u64);
        (*(&raw mut IDT)).entries[14].set_handler(exception_page_fault as u64);

        // Set up IRQ handlers (vectors 32+)
        // Vector 32: APIC Timer
        (*(&raw mut IDT)).entries[32].set_handler(irq_timer as u64);

        let idt_ptr = IdtPtr {
            limit: (size_of::<Idt>() - 1) as u16,
            base: (&raw const IDT) as u64,
        };

        core::arch::asm!(
            "lidt [{}]",
            in(reg) &idt_ptr,
            options(nostack)
        );
    }
}

// Exception handlers (stubs)
extern "C" fn exception_divide_error() {
    loop {
        super::halt();
    }
}

extern "C" fn exception_debug() {
    loop {
        super::halt();
    }
}

extern "C" fn exception_nmi() {
    loop {
        super::halt();
    }
}

extern "C" fn exception_breakpoint() {
    // Continue execution for breakpoints
}

extern "C" fn exception_overflow() {
    loop {
        super::halt();
    }
}

extern "C" fn exception_invalid_opcode() {
    loop {
        super::halt();
    }
}

extern "C" fn exception_double_fault() {
    loop {
        super::halt();
    }
}

extern "C" fn exception_gpf() {
    loop {
        super::halt();
    }
}

extern "C" fn exception_page_fault() {
    loop {
        super::halt();
    }
}

/// APIC Timer interrupt handler
///
/// Vector 32 - called every 1ms by the APIC timer.
/// This is the primary scheduler tick interrupt.
extern "C" fn irq_timer() {
    // Delegate to the APIC timer handler
    // SAFETY: Interrupt context, timer handler is designed for this
    super::apic::timer_handler();
}
