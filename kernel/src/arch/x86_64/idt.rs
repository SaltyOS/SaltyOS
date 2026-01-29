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

/// Serial port (COM1) for debug output
const SERIAL_PORT: u16 = 0x3F8;

/// Write a byte to serial port
unsafe fn serial_putc(c: u8) {
    // SAFETY: COM1 is a standard x86 serial port
    unsafe {
        while (super::inb(SERIAL_PORT + 5) & 0x20) == 0 {}
        super::outb(SERIAL_PORT, c);
    }
}

/// Write a string to serial port
unsafe fn serial_puts(s: &str) {
    for byte in s.bytes() {
        // SAFETY: COM1 is a standard x86 serial port
        unsafe {
            serial_putc(byte);
        }
    }
}

/// Write a hexadecimal number to serial port
unsafe fn serial_hex(mut val: u64) {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    // SAFETY: COM1 is a standard x86 serial port
    unsafe {
        serial_puts("0x");
    }
    if val == 0 {
        // SAFETY: COM1 is a standard x86 serial port
        unsafe {
            serial_putc(b'0');
        }
        return;
    }
    let mut buf = [0u8; 16];
    let mut pos = 15;
    while val > 0 {
        buf[pos] = HEX_CHARS[(val & 0xF) as usize];
        val >>= 4;
        pos -= 1;
    }
    for &c in &buf[(pos + 1)..] {
        // SAFETY: COM1 is a standard x86 serial port
        unsafe {
            serial_putc(c);
        }
    }
}

/// Initialize IDT
pub fn init() {
    // SAFETY: Single-threaded initialization, IDT is properly structured
    unsafe {
        serial_puts("\n[IDT] Starting init\n");

        // Print IDT address
        serial_puts("[IDT] IDT addr: ");
        serial_hex((&raw const IDT) as u64);
        serial_putc(b'\n');

        // Set up exception handlers (vectors 0-31)
        serial_puts("[IDT] Setting exception handlers\n");

        (*(&raw mut IDT)).entries[0].set_handler(exception_divide_error as *const () as u64);
        serial_puts("[IDT]   divide_error handler: ");
        serial_hex(exception_divide_error as *const () as u64);
        serial_putc(b'\n');

        (*(&raw mut IDT)).entries[1].set_handler(exception_debug as *const () as u64);
        (*(&raw mut IDT)).entries[2].set_handler(exception_nmi as *const () as u64);
        (*(&raw mut IDT)).entries[3].set_trap(exception_breakpoint as *const () as u64);
        (*(&raw mut IDT)).entries[4].set_handler(exception_overflow as *const () as u64);
        (*(&raw mut IDT)).entries[6].set_handler(exception_invalid_opcode as *const () as u64);
        (*(&raw mut IDT)).entries[8].set_handler(exception_double_fault as *const () as u64);
        (*(&raw mut IDT)).entries[13].set_handler(exception_gpf as *const () as u64);
        (*(&raw mut IDT)).entries[14].set_handler(exception_page_fault as *const () as u64);

        serial_puts("[IDT] Exception handlers set\n");

        // Set up IRQ handlers (vectors 32+)
        // Vector 32: APIC Timer
        serial_puts("[IDT] Setting IRQ handlers\n");
        (*(&raw mut IDT)).entries[32].set_handler(irq_timer as *const () as u64);
        serial_puts("[IDT]   timer handler: ");
        serial_hex(irq_timer as *const () as u64);
        serial_putc(b'\n');

        // Prepare IDT pointer
        serial_puts("[IDT] Preparing IDT pointer\n");
        let idt_ptr = IdtPtr {
            limit: (size_of::<Idt>() - 1) as u16,
            base: (&raw const IDT) as u64,
        };

        serial_puts("[IDT]   limit: ");
        serial_hex(idt_ptr.limit as u64);
        serial_puts("\n[IDT]   base: ");
        serial_hex(idt_ptr.base);
        serial_putc(b'\n');

        // Load IDT
        serial_puts("[IDT] Calling lidt\n");
        core::arch::asm!(
            "lidt [{}]",
            in(reg) &idt_ptr,
            options(nostack)
        );

        // Verify with sidt - CRITICAL: must use same packed struct
        serial_puts("[IDT] Verifying with sidt...\n");
        let mut idt_read_back: IdtPtr = IdtPtr { limit: 0, base: 0 };
        core::arch::asm!(
            "sidt [{}]",
            in(reg) &mut idt_read_back,
            options(nostack)
        );
        serial_puts("[IDT] sidt result: limit=");
        serial_hex(idt_read_back.limit as u64);
        serial_puts(" base=");
        serial_hex(idt_read_back.base);
        serial_putc(b'\n');

        // CRITICAL: Verify struct sizes
        serial_puts("[IDT] Struct sizes:\n");
        serial_puts("  size_of::<IdtEntry>() = ");
        serial_hex(size_of::<IdtEntry>() as u64);
        serial_putc(b'\n');
        serial_puts("  size_of::<IdtPtr>() = ");
        serial_hex(size_of::<IdtPtr>() as u64);
        serial_putc(b'\n');
        serial_puts("  size_of::<Idt>() = ");
        serial_hex(size_of::<Idt>() as u64);
        serial_putc(b'\n');

        // Panic if sizes are wrong
        assert!(size_of::<IdtEntry>() == 16, "IdtEntry must be 16 bytes!");
        assert!(size_of::<IdtPtr>() == 10, "IdtPtr must be 10 bytes (packed)!");

        serial_puts("[IDT] IDT loaded and verified successfully\n");
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
