//! Bootcore binary entry for BIOS path.

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use saltyos_bootloader_core::{bootcore_enter, BootHandoff};

#[unsafe(no_mangle)]
pub unsafe extern "sysv64" fn _start(handoff: *const BootHandoff) -> ! {
    bootcore_enter(handoff)
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        unsafe { core::arch::asm!("hlt", options(nomem, nostack)); }
    }
}

// Minimal C runtime shims for bare-metal bootcore (BIOS path).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcpy(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    core::arch::asm!(
        "rep movsb",
        inout("rdi") dst => _,
        inout("rsi") src => _,
        inout("rcx") n => _,
        options(nostack, preserves_flags)
    );
    dst
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memmove(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    if (dst as usize) < (src as usize) {
        core::arch::asm!(
            "rep movsb",
            inout("rdi") dst => _,
            inout("rsi") src => _,
            inout("rcx") n => _,
            options(nostack, preserves_flags)
        );
    } else if n != 0 {
        let dst_end = dst.add(n - 1);
        let src_end = src.add(n - 1);
        core::arch::asm!(
            "std",
            "rep movsb",
            "cld",
            inout("rdi") dst_end => _,
            inout("rsi") src_end => _,
            inout("rcx") n => _,
            options(nostack, preserves_flags)
        );
    }
    dst
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memset(dst: *mut u8, value: i32, n: usize) -> *mut u8 {
    core::arch::asm!(
        "rep stosb",
        inout("rdi") dst => _,
        in("al") value as u8,
        inout("rcx") n => _,
        options(nostack, preserves_flags)
    );
    dst
}
