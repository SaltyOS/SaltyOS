//! x86_64 boot and entry point
//!
//! SPDX-License-Identifier: GPL-2.0-only

use core::arch::naked_asm;

/// Kernel entry point from bootloader
///
/// Sets up initial stack and jumps to kmain
#[unsafe(naked)]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.boot")]
pub extern "C" fn _start() -> ! {
    naked_asm!(
        // Set up kernel stack (stack grows down, so we want end of array)
        "lea rsp, [rip + KERNEL_STACK + 16384]",
        // Clear RFLAGS
        "push 0",
        "popfq",
        // RDI already contains boot_info pointer from bootloader
        // Call kmain
        "call kmain",
        // Should never return, but halt if it does
        "2:",
        "hlt",
        "jmp 2b",
    )
}

// Kernel stack (16KB, 16-byte aligned)
#[repr(C, align(16))]
struct KernelStack([u8; 16384]);

#[unsafe(link_section = ".bss")]
#[unsafe(no_mangle)]
static mut KERNEL_STACK: KernelStack = KernelStack([0; 16384]);
