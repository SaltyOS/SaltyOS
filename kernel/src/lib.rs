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

/// Kernel entry point (called from bootloader)
///
/// # Safety
/// This function is called directly from assembly with a specific ABI.
#[unsafe(no_mangle)]
pub extern "C" fn kmain(boot_info: *const BootInfo) -> ! {
    // Output to serial to confirm kernel is running
    // SAFETY: Serial port 0x3F8 is standard COM1
    unsafe {
        for byte in b"\nSaltyOS Kernel loaded\n" {
            // Wait for transmit buffer empty
            while (arch::inb(0x3F8 + 5) & 0x20) == 0 {}
            arch::outb(0x3F8, *byte);
        }
    }

    // Initialize architecture-specific subsystems
    arch::init();

    // Initialize memory management
    if !boot_info.is_null() {
        // SAFETY: Caller guarantees boot_info is valid when non-null
        unsafe { mm::init(&*boot_info) };
    }

    // Initialize capability system
    cap::init();

    // Initialize IPC subsystem
    ipc::init();

    // Initialize scheduler
    sched::init();

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
fn panic(_info: &PanicInfo) -> ! {
    // TODO: Print panic info to serial
    loop {
        arch::halt();
    }
}
