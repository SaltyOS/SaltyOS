//! x86_64 boot and entry point
//!
//! SPDX-License-Identifier: GPL-2.0-only

// Kernel stack (16KB, 16-byte aligned)
#[repr(C, align(16))]
struct KernelStack([u8; 16384]);

#[unsafe(link_section = ".bss")]
#[unsafe(no_mangle)]
static mut KERNEL_STACK: KernelStack = KernelStack([0; 16384]);
