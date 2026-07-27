// SPDX-License-Identifier: GPL-2.0-only
//! Build identity embedded by the Meson kernel link.

use crate::kernel::printk::{serial_dec_raw, serial_putc_hw, serial_puts_raw};

unsafe extern "C" {
    static __kernite_build_git: u8;
    static __kernite_build_config_hash: u8;
    static __kernite_build_arch: u8;
    static __kernite_build_rustc: u8;
    static __kernite_build_profile: u8;
    static __kernite_build_kernel_stack_size: u8;
    static __kernite_build_config_summary: u8;
}

const MAX_BUILD_STRING: usize = 8192;

#[derive(Clone, Copy)]
pub(crate) struct BuildInfo {
    pub git: *const u8,
    pub config_hash: *const u8,
    pub arch: *const u8,
    pub rustc: *const u8,
    pub profile: *const u8,
    pub kernel_stack_size: *const u8,
    pub config_summary: *const u8,
}

pub(crate) fn current() -> BuildInfo {
    BuildInfo {
        git: core::ptr::addr_of!(__kernite_build_git),
        config_hash: core::ptr::addr_of!(__kernite_build_config_hash),
        arch: core::ptr::addr_of!(__kernite_build_arch),
        rustc: core::ptr::addr_of!(__kernite_build_rustc),
        profile: core::ptr::addr_of!(__kernite_build_profile),
        kernel_stack_size: core::ptr::addr_of!(__kernite_build_kernel_stack_size),
        config_summary: core::ptr::addr_of!(__kernite_build_config_summary),
    }
}

pub(crate) fn kernel_stack_size() -> u64 {
    parse_decimal_cstr(current().kernel_stack_size).unwrap_or(16 * 1024)
}

pub(crate) fn print_identity_line() {
    let info = current();
    serial_puts_raw("kernel: kernite git=");
    print_cstr(info.git, None);
    serial_puts_raw(" config=");
    print_cstr(info.config_hash, Some(12));
    serial_puts_raw(" arch=");
    print_cstr(info.arch, None);
    serial_puts_raw(" rustc=");
    print_cstr(info.rustc, None);
    serial_puts_raw(" profile=");
    print_cstr(info.profile, None);
    serial_putc_hw(b'\n');
}

pub(crate) fn print_full_config() {
    let info = current();
    serial_puts_raw("build_config_hash: ");
    print_cstr(info.config_hash, None);
    serial_putc_hw(b'\n');
    serial_puts_raw("build_config_summary:\n");
    print_cstr(info.config_summary, None);
    if !cstr_ends_with_newline(info.config_summary) {
        serial_putc_hw(b'\n');
    }
    serial_puts_raw("kernel_stack_size: ");
    serial_dec_raw(kernel_stack_size());
    serial_putc_hw(b'\n');
}

pub(crate) fn print_cstr(ptr: *const u8, max: Option<usize>) {
    if ptr.is_null() {
        serial_puts_raw("<null>");
        return;
    }
    let limit = max.unwrap_or(MAX_BUILD_STRING).min(MAX_BUILD_STRING);
    let mut i = 0usize;
    while i < limit {
        let b = unsafe { core::ptr::read_volatile(ptr.add(i)) };
        if b == 0 {
            return;
        }
        serial_putc_hw(b);
        i += 1;
    }
}

fn cstr_ends_with_newline(ptr: *const u8) -> bool {
    if ptr.is_null() {
        return false;
    }
    let mut i = 0usize;
    let mut last = 0u8;
    while i < MAX_BUILD_STRING {
        let b = unsafe { core::ptr::read_volatile(ptr.add(i)) };
        if b == 0 {
            return last == b'\n';
        }
        last = b;
        i += 1;
    }
    false
}

fn parse_decimal_cstr(ptr: *const u8) -> Option<u64> {
    if ptr.is_null() {
        return None;
    }
    let mut i = 0usize;
    let mut value = 0u64;
    let mut any = false;
    while i < 32 {
        let b = unsafe { core::ptr::read_volatile(ptr.add(i)) };
        if b == 0 {
            return any.then_some(value);
        }
        if !b.is_ascii_digit() {
            return None;
        }
        value = value.saturating_mul(10).saturating_add((b - b'0') as u64);
        any = true;
        i += 1;
    }
    None
}
