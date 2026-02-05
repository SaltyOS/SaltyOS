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

/// Task State Segment (x86_64)
///
/// In 64-bit mode, TSS is only used for:
/// - IST (Interrupt Stack Table) pointers for exception handling
/// - IOPB (I/O Permission Bitmap) - optional, not used in kernel
/// - The actual task switching mechanism is NOT used in x86_64
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct TaskStateSegment {
    pub reserved0: u32,
    pub rsp0: u64,     // Stack pointer for CPL=0
    pub rsp1: u64,     // Stack pointer for CPL=1
    pub rsp2: u64,     // Stack pointer for CPL=2
    pub reserved1: u64,
    pub ist1: u64,     // IST1 stack pointer
    pub ist2: u64,     // IST2 stack pointer
    pub ist3: u64,     // IST3 stack pointer
    pub ist4: u64,     // IST4 stack pointer
    pub ist5: u64,     // IST5 stack pointer
    pub ist6: u64,     // IST6 stack pointer
    pub ist7: u64,     // IST7 stack pointer
    pub reserved2: u64,
    pub reserved3: u16,
    pub iomap_base: u16, // I/O permission bitmap base (0xFFFF if none)
}

impl TaskStateSegment {
    pub const fn new() -> Self {
        Self {
            reserved0: 0,
            rsp0: 0,
            rsp1: 0,
            rsp2: 0,
            reserved1: 0,
            ist1: 0,
            ist2: 0,
            ist3: 0,
            ist4: 0,
            ist5: 0,
            ist6: 0,
            ist7: 0,
            reserved2: 0,
            reserved3: 0,
            iomap_base: 0xFFFF, // No I/O bitmap
        }
    }
}

/// GDT structure
#[repr(C, align(16))]
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

/// The kernel TSS
static mut TSS: TaskStateSegment = TaskStateSegment::new();

/// Set the kernel stack pointer in TSS (rsp0)
///
/// This is the stack that will be used when interrupts occur from user mode.
/// The CPU switches to this stack automatically based on CPL.
///
/// # Safety
/// Must be called with a valid kernel stack pointer.
pub unsafe fn set_tss_rsp0(stack_top: u64) {
    unsafe {
        TSS.rsp0 = stack_top;
    }
}

/// Get the current TSS stack pointer
pub fn get_tss_rsp0() -> u64 {
    unsafe { TSS.rsp0 }
}

/// Set an IST (Interrupt Stack Table) entry in the TSS
///
/// IST entries provide dedicated stacks for critical exceptions (e.g., double fault)
/// so they can be handled even if the current kernel stack is corrupted.
///
/// # Safety
/// `stack_top` must be a valid virtual address pointing to the top of an allocated stack.
pub unsafe fn set_tss_ist(ist_index: u8, stack_top: u64) {
    unsafe {
        match ist_index {
            1 => TSS.ist1 = stack_top,
            2 => TSS.ist2 = stack_top,
            3 => TSS.ist3 = stack_top,
            4 => TSS.ist4 = stack_top,
            5 => TSS.ist5 = stack_top,
            6 => TSS.ist6 = stack_top,
            7 => TSS.ist7 = stack_top,
            _ => {}
        }
    }
}

/// Serial port (COM1) for debug output
const SERIAL_PORT: u16 = 0x3F8;

/// Write a byte to serial port (inline for debugging)
///
/// # Safety
/// Serial port I/O is safe as long as the port exists.
unsafe fn serial_putc(c: u8) {
    // Wait for transmit buffer empty
    loop {
        // SAFETY: Reading serial port status is safe for standard COM1 port
        let status = unsafe { inb(SERIAL_PORT + 5) };
        if status & 0x20 != 0 {
            break;
        }
    }
    // SAFETY: Serial port I/O is safe for standard COM1 port
    unsafe {
        outb(SERIAL_PORT, c);
    }
}

/// Write a string to serial port
unsafe fn serial_puts(s: &str) {
    for byte in s.bytes() {
        // SAFETY: Serial port I/O is safe for standard COM1 port
        unsafe {
            serial_putc(byte);
        }
    }
}

/// Write a hexadecimal number to serial port
unsafe fn serial_hex(mut val: u64) {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

    // SAFETY: Serial port I/O is safe
    unsafe {
        serial_puts("0x");
    }

    if val == 0 {
        // SAFETY: Serial port I/O is safe
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
        // SAFETY: Serial port I/O is safe
        unsafe {
            serial_putc(c);
        }
    }
}

/// Read byte from I/O port
unsafe fn inb(port: u16) -> u8 {
    let result: u8;
    // SAFETY: I/O port read is safe for standard ports
    unsafe {
        core::arch::asm!(
            "in al, dx",
            out("al") result,
            in("dx") port,
            options(nomem, nostack)
        );
    }
    result
}

/// Write byte to I/O port
unsafe fn outb(port: u16, value: u8) {
    // SAFETY: I/O port write is safe for standard ports
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") port,
            in("al") value,
            options(nomem, nostack)
        );
    }
}

impl TssEntry {
    /// Create a TSS entry pointing to a TSS structure
    pub fn from_tss(tss: *const TaskStateSegment) -> Self {
        let tss_addr = tss as u64;
        let limit = size_of::<TaskStateSegment>() as u16 - 1;

        Self {
            limit_low: limit,
            base_low: (tss_addr & 0xFFFF) as u16,
            base_mid: ((tss_addr >> 16) & 0xFF) as u8,
            access: 0x89,      // Present, Ring 0, TSS (busy bit will be set by ltr)
            granularity: 0x00, // 16-bit limit for TSS in 64-bit mode
            base_high: ((tss_addr >> 24) & 0xFF) as u8,
            base_upper: (tss_addr >> 32) as u32,
            reserved: 0,
        }
    }
}

/// Initialize GDT
pub fn init() {
    // SAFETY: Single-threaded initialization, GDT is properly structured
    unsafe {
        // Set up TSS entry in GDT to point to TSS
        (*(&raw mut GDT)).tss = TssEntry::from_tss(&raw const TSS);

        let gdt_ptr = GdtPtr {
            limit: (size_of::<Gdt>() - 1) as u16,
            base: (&raw const GDT) as u64,
        };

        // DEBUG: Print what we're about to load
        serial_puts("\n[GDT] Before lgdt:\n");
        serial_puts("  base: ");
        serial_hex(gdt_ptr.base);
        serial_puts("\n  limit: ");
        serial_hex(gdt_ptr.limit as u64);
        serial_puts("\n  GDT addr: ");
        serial_hex((&raw const GDT) as u64);
        serial_puts("\n  TSS addr: ");
        serial_hex((&raw const TSS) as u64);
        serial_putc(b'\n');

        core::arch::asm!(
            "lgdt [{}]",
            in(reg) &gdt_ptr,
            options(nostack)
        );

        // DEBUG: Read back GDTR to verify
        let read_back_base: u64;
        let read_back_limit: u16;
        core::arch::asm!(
            "sgdt [{}]",
            in(reg) &gdt_ptr,
            options(nostack)
        );
        read_back_base = gdt_ptr.base;
        read_back_limit = gdt_ptr.limit;

        serial_puts("[GDT] After lgdt (read back):\n");
        serial_puts("  base: ");
        serial_hex(read_back_base);
        serial_puts("\n  limit: ");
        serial_hex(read_back_limit as u64);
        serial_putc(b'\n');

        // Reload segment registers (including CS via far return)
        reload_segments();
        serial_puts("[GDT] Segments reloaded successfully\n");

        // Load TSS (must be AFTER GDT is loaded and segments are reloaded)
        // TSS selector is 0x28 (5th GDT entry, first is null)
        core::arch::asm!(
            "ltr {0:x}",
            in(reg) 0x28u16,
            options(nostack)
        );
        serial_puts("[GDT] TSS loaded successfully\n");
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
