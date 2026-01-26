//! Syscall handling for x86_64

#![no_std]

use core::arch::asm;

// Syscal entry point is defined in syscall.S
unsafe extern "C" {
    /// Syscal entry point (defined in syscall.S)
    fn syscall_entry();
    fn syscall_entry_addr_asm() -> u64;
    fn user_test_entry();
    fn user_test_entry_addr_asm() -> u64;
}

const IA32_EFER: u32 = 0xC000_0080;
const IA32_STAR: u32 = 0xC000_0081;
const IA32_LSTAR: u32 = 0xC000_0082;
const IA32_FMASK: u32 = 0xC000_0084;
const IA32_KERNEL_GS_BASE: u32 = 0xC000_0102;
const IA32_GS_BASE: u32 = 0xC000_0101;

/// Initialize syscall handling
pub fn init() {
    unsafe {
        let entry = syscall_entry_addr();
        let kernel_cs: u64 = 0x08;
        let user_cs: u64 = 0x20 | 0x3;
        let user_star = user_cs - 16;

        let star = (user_star << 48) | (kernel_cs << 32);

        wrmsr(IA32_LSTAR, entry);
        wrmsr(IA32_STAR, star);
        wrmsr(IA32_FMASK, 0x200); // Clear IF on syscall
        wrmsr(IA32_GS_BASE, 0);
        wrmsr(IA32_KERNEL_GS_BASE, 0);

        let mut efer = rdmsr(IA32_EFER);
        efer |= 1; // SCE
        wrmsr(IA32_EFER, efer);
    }
}

/// Get the syscall entry point address
///
/// This can be used to set up MSR registers if needed
/// (currently not required as syscall uses a fixed entry point)
pub fn entry_point() -> u64 {
    syscall_entry_addr()
}

pub fn user_test_entry_low(kernel_virt_base: u64, kernel_phys_base: u64) -> u64 {
    let virt = unsafe { user_test_entry_addr_asm() };
    kernel_phys_base.wrapping_add(virt.wrapping_sub(kernel_virt_base))
}

pub fn syscall_entry_addr() -> u64 {
    unsafe { syscall_entry_addr_asm() }
}

pub fn user_test_entry_addr() -> u64 {
    unsafe { user_test_entry_addr_asm() }
}

unsafe fn rdmsr(msr: u32) -> u64 {
    let low: u32;
    let high: u32;
    asm!(
        "rdmsr",
        in("ecx") msr,
        out("eax") low,
        out("edx") high,
        options(nostack, preserves_flags),
    );
    ((high as u64) << 32) | (low as u64)
}

unsafe fn wrmsr(msr: u32, val: u64) {
    let low = val as u32;
    let high = (val >> 32) as u32;
    asm!(
        "wrmsr",
        in("ecx") msr,
        in("eax") low,
        in("edx") high,
        options(nostack, preserves_flags),
    );
}
