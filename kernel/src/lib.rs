//! SaltyOS Microkernel
//!
//! A capability-based microkernel with EDF scheduling and synchronous IPC.
//!
//! SPDX-License-Identifier: GPL-2.0-only

#![no_std]
#![no_main]
#![allow(dead_code)]

mod arch;
mod builtins;
mod cap;
mod ipc;
mod mm;
mod sched;
mod syscall;

use core::panic::PanicInfo;

/// Serial port (COM1) for debug output
const SERIAL_PORT: u16 = 0x3F8;

/// Write a byte to serial port
///
/// # Safety
/// Serial port I/O is safe as long as the port exists.
#[inline]
fn serial_putc(c: u8) {
    // SAFETY: COM1 is a standard x86 serial port
    unsafe {
        // Wait for transmit buffer empty
        while (arch::inb(SERIAL_PORT + 5) & 0x20) == 0 {}
        arch::outb(SERIAL_PORT, c);
    }
}

/// Write a string to serial port
fn serial_puts(s: &str) {
    for byte in s.bytes() {
        serial_putc(byte);
    }
}

/// Write a hexadecimal number to serial port
fn serial_hex(mut val: u64) {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

    serial_puts("0x");

    if val == 0 {
        serial_putc(b'0');
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
        serial_putc(c);
    }
}

/// Write a decimal number to serial port
fn serial_dec(mut val: u64) {
    if val == 0 {
        serial_putc(b'0');
        return;
    }

    let mut buf = [0u8; 20];
    let mut pos = 19;

    while val > 0 {
        buf[pos] = b'0' + ((val % 10) as u8);
        val /= 10;
        pos -= 1;
    }

    for &c in &buf[(pos + 1)..] {
        serial_putc(c);
    }
}

/// Kernel entry point (called from bootloader)
///
/// # Safety
/// This function is called directly from assembly with a specific ABI.
#[unsafe(no_mangle)]
pub extern "C" fn kmain(boot_info: *const BootInfo) -> ! {
    // Immediate confirmation we're in kernel (before anything else)
    // SAFETY: Serial port 0x3F8 is standard COM1
    unsafe {
        for byte in b"[ENTRY] " {
            while (arch::inb(0x3F8 + 5) & 0x20) == 0 {}
            arch::outb(0x3F8, *byte);
        }
    }

    // Output to serial to confirm kernel is running
    // SAFETY: Serial port 0x3F8 is standard COM1
    unsafe {
        for byte in b"\nSaltyOS Kernel loaded\n" {
            // Wait for transmit buffer empty
            while (arch::inb(0x3F8 + 5) & 0x20) == 0 {}
            arch::outb(0x3F8, *byte);
        }

        // Debug: Print kernel entry address and kmain address
        for byte in b"[KMAIN] Entry addr: " {
            while (arch::inb(0x3F8 + 5) & 0x20) == 0 {}
            arch::outb(0x3F8, *byte);
        }
        serial_hex(kmain as *const () as u64);
        for byte in b"\n[KMAIN] Boot info: " {
            while (arch::inb(0x3F8 + 5) & 0x20) == 0 {}
            arch::outb(0x3F8, *byte);
        }
        serial_hex(boot_info as u64);
        for byte in b"\n" {
            while (arch::inb(0x3F8 + 5) & 0x20) == 0 {}
            arch::outb(0x3F8, *byte);
        }
    }

    // Initialize architecture-specific subsystems
    // (includes memory management, which is needed before paging setup)
    let boot_info_ref = if !boot_info.is_null() {
        // SAFETY: Caller guarantees boot_info is valid when non-null
        Some(unsafe { &*boot_info })
    } else {
        None
    };
    arch::init(boot_info_ref);

    // Initialize capability system
    cap::init();

    // Initialize IPC subsystem
    ipc::init();

    // Initialize scheduler
    sched::init();

    // Start timer interrupts (scheduler must be ready first)
    arch::start_timer();

    // TODO: Load init process from initrd
    // TODO: Switch to userspace

    // For now, halt
    loop {
        arch::halt();
    }
}

/// Boot information passed from bootloader
#[repr(C)]
pub struct BootInfo {
    /// Magic number for validation
    pub magic: u64,
    /// Memory map entries
    pub memory_map: *const MemoryMapEntry,
    /// Number of memory map entries
    pub memory_map_len: usize,
    /// Kernel physical base address
    pub kernel_phys_base: u64,
    /// Kernel virtual base address
    pub kernel_virt_base: u64,
    /// Initrd physical address
    pub initrd_addr: u64,
    /// Initrd size in bytes
    pub initrd_size: u64,
    /// Kernel command line
    pub cmdline: *const u8,
    /// ACPI RSDP address
    pub rsdp_addr: u64,
    /// Framebuffer info (if available)
    pub framebuffer: FramebufferInfo,
}

/// Memory map entry from bootloader
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MemoryMapEntry {
    pub base: u64,
    pub length: u64,
    pub kind: MemoryKind,
}

/// Memory region type
#[repr(u32)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum MemoryKind {
    Usable = 1,
    Reserved = 2,
    AcpiReclaimable = 3,
    AcpiNvs = 4,
    BadMemory = 5,
    Bootloader = 6,
    Kernel = 7,
}

/// Framebuffer information
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FramebufferInfo {
    pub addr: u64,
    pub width: u32,
    pub height: u32,
    pub pitch: u32,
    pub bpp: u8,
}

/// Panic handler
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_puts("\n!!! KERNEL PANIC !!!\n");

    if let Some(location) = info.location() {
        serial_puts("  Location: ");
        serial_puts(location.file());
        serial_putc(b':');
        serial_dec(location.line() as u64);
        serial_putc(b'\n');
    }

    // message() returns PanicMessage which can be converted to Option<&str>
    if let Some(msg) = info.message().as_str() {
        serial_puts("  Message: ");
        serial_puts(msg);
        serial_putc(b'\n');
    }

    loop {
        arch::halt();
    }
}
