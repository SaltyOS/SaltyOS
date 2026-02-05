//! SaltyOS Microkernel
//!
//! A capability-based microkernel with EDF scheduling and synchronous IPC.
//!
//! SPDX-License-Identifier: GPL-2.0-only

#![no_std]
#![no_main]
#![allow(dead_code)]

mod arch;
mod bootinfo;
mod builtins;
mod cap;
mod ipc;
mod mm;
mod sched;
mod syscall;

pub use bootinfo::{FramebufferInfo, MemoryKind, MemoryMapEntry, ParsedBootInfo};

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
/// The bootloader passes a pointer to a TLV-encoded BootInfo structure via RDI.
///
/// # Safety
/// This function is called directly from assembly with a specific ABI.
#[unsafe(no_mangle)]
pub extern "C" fn kmain(raw_boot_info: *const u8) -> ! {
    // Immediate confirmation we're in kernel (before anything else)
    unsafe {
        for byte in b"[ENTRY] " {
            while (arch::inb(0x3F8 + 5) & 0x20) == 0 {}
            arch::outb(0x3F8, *byte);
        }
    }

    unsafe {
        for byte in b"\nSaltyOS Kernel loaded\n" {
            while (arch::inb(0x3F8 + 5) & 0x20) == 0 {}
            arch::outb(0x3F8, *byte);
        }

        for byte in b"[KMAIN] Entry addr: " {
            while (arch::inb(0x3F8 + 5) & 0x20) == 0 {}
            arch::outb(0x3F8, *byte);
        }
        serial_hex(kmain as *const () as u64);
        for byte in b"\n[KMAIN] Boot info ptr: " {
            while (arch::inb(0x3F8 + 5) & 0x20) == 0 {}
            arch::outb(0x3F8, *byte);
        }
        serial_hex(raw_boot_info as u64);
        for byte in b"\n" {
            while (arch::inb(0x3F8 + 5) & 0x20) == 0 {}
            arch::outb(0x3F8, *byte);
        }
    }

    // Parse TLV-encoded BootInfo from bootloader
    let boot_info = unsafe { bootinfo::parse(raw_boot_info) };

    if let Some(info) = boot_info {
        serial_puts("[KMAIN] BootInfo parsed: ");
        serial_dec(info.memory_map_len as u64);
        serial_puts(" memory map entries\n");
    } else {
        serial_puts("[KMAIN] WARNING: Failed to parse BootInfo!\n");
    }

    // Initialize architecture-specific subsystems
    arch::init(boot_info);

    // Initialize capability system
    cap::init();

    // Initialize IPC subsystem
    ipc::init();

    // Initialize scheduler
    sched::init();

    // Start timer interrupts (scheduler must be ready first)
    arch::start_timer();

    // For now, halt
    loop {
        arch::halt();
    }
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
