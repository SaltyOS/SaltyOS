// SPDX-License-Identifier: GPL-2.0-only
//! Kernel console and serial logging.

use crate::{arch, console, mm};

/// Serial port (COM1) for debug output.
#[cfg(target_arch = "x86_64")]
const SERIAL_PORT: u16 = 0x3F8;

/// Leaf-level spinlock protecting all serial and framebuffer console output.
///
/// Lock ordering:
/// CAP_LOCK -> IRQ_LOCK -> per-object locks -> scheduler locks -> VSpace/MM
/// locks -> FRAME_LOCK -> SERIAL_LOCK.
pub(crate) static SERIAL_LOCK: mm::SpinLock = mm::SpinLock::new();

#[inline]
fn serial_putc_device(c: u8) {
    #[cfg(no_serial_output)]
    {
        let _ = c;
        return;
    }

    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: COM1 is the kernel's early debug UART on x86_64.
        unsafe {
            while (arch::inb(SERIAL_PORT + 5) & 0x20) == 0 {}
            arch::outb(SERIAL_PORT, c);
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        arch::aarch64::pl011::putc(c);
    }
}

#[inline]
fn serial_write_device(buf: &[u8]) {
    #[cfg(no_serial_output)]
    {
        let _ = buf;
        return;
    }

    for &c in buf {
        serial_putc_device(c);
    }
}

/// Write a single byte to serial hardware and mirror it to framebuffer. No locking.
#[inline]
pub(crate) fn serial_putc_hw(c: u8) {
    if crate::kernel::panic::suppress_non_panic_cpu_output() {
        return;
    }
    serial_putc_device(c);
    console::putc(c);
}

/// Write a byte slice to serial hardware and mirror it to framebuffer.
#[inline]
pub(crate) fn serial_write_hw(buf: &[u8]) {
    if buf.is_empty() {
        return;
    }
    if crate::kernel::panic::suppress_non_panic_cpu_output() {
        return;
    }
    serial_write_device(buf);
    console::write(buf);
}

/// Write a byte to the early serial device only. No lock, no framebuffer mirror.
#[inline]
pub(crate) fn serial_putc_early(c: u8) {
    if crate::kernel::panic::suppress_non_panic_cpu_output() {
        return;
    }
    serial_putc_device(c);
}

/// Write a byte slice to the early serial device only. No lock, no framebuffer mirror.
#[inline]
pub(crate) fn serial_write_early(buf: &[u8]) {
    if buf.is_empty() {
        return;
    }
    if crate::kernel::panic::suppress_non_panic_cpu_output() {
        return;
    }
    serial_write_device(buf);
}

/// Write a string to the early serial device only. Boot/probe path only.
#[inline]
pub(crate) fn serial_puts_early(s: &str) {
    serial_write_early(s.as_bytes());
}

/// Write a hexadecimal number to the early serial device only.
#[inline]
pub(crate) fn serial_hex_early(val: u64) {
    serial_hex_early_impl(val);
}

/// Write a decimal number to the early serial device only.
#[inline]
pub(crate) fn serial_dec_early(val: u64) {
    serial_dec_early_impl(val);
}

/// Write a string without taking SERIAL_LOCK. Panic/crash path only.
#[inline]
pub(crate) fn serial_puts_raw(s: &str) {
    serial_write_hw(s.as_bytes());
}

/// Write a hexadecimal number without taking SERIAL_LOCK.
#[inline]
pub(crate) fn serial_hex_raw(val: u64) {
    serial_hex_impl(val);
}

/// Write a decimal number without taking SERIAL_LOCK.
#[inline]
pub(crate) fn serial_dec_raw(val: u64) {
    serial_dec_impl(val);
}

/// Write a byte under SERIAL_LOCK.
pub(crate) fn serial_putc(c: u8) {
    #[cfg(no_serial_output)]
    {
        let _ = c;
        return;
    }
    let irq = unsafe { mm::save_irq_disable() };
    SERIAL_LOCK.lock();
    serial_putc_hw(c);
    console::flush_pending();
    SERIAL_LOCK.unlock();
    unsafe { mm::restore_irq(irq) };
}

/// Write a string under SERIAL_LOCK.
pub(crate) fn serial_puts(s: &str) {
    #[cfg(no_serial_output)]
    {
        let _ = s;
        return;
    }
    let irq = unsafe { mm::save_irq_disable() };
    SERIAL_LOCK.lock();
    serial_write_hw(s.as_bytes());
    SERIAL_LOCK.unlock();
    unsafe { mm::restore_irq(irq) };
}

fn serial_hex_impl(mut val: u64) {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    if val == 0 {
        serial_write_hw(b"0x0");
        return;
    }
    let mut buf = [0u8; 18];
    buf[0] = b'0';
    buf[1] = b'x';
    let mut pos = 17;
    while val > 0 {
        buf[pos] = HEX_CHARS[(val & 0xF) as usize];
        val >>= 4;
        pos -= 1;
    }
    let digit_start = pos + 1;
    let digit_count = 18 - digit_start;
    buf.copy_within(digit_start..18, 2);
    serial_write_hw(&buf[..2 + digit_count]);
}

fn serial_hex_early_impl(mut val: u64) {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    if val == 0 {
        serial_write_early(b"0x0");
        return;
    }
    let mut buf = [0u8; 18];
    buf[0] = b'0';
    buf[1] = b'x';
    let mut pos = 17;
    while val > 0 {
        buf[pos] = HEX_CHARS[(val & 0xF) as usize];
        val >>= 4;
        pos -= 1;
    }
    let digit_start = pos + 1;
    let digit_count = 18 - digit_start;
    buf.copy_within(digit_start..18, 2);
    serial_write_early(&buf[..2 + digit_count]);
}

fn serial_dec_impl(mut val: u64) {
    if val == 0 {
        serial_write_hw(b"0");
        return;
    }
    let mut buf = [0u8; 20];
    let mut pos = 19;
    while val > 0 {
        buf[pos] = b'0' + ((val % 10) as u8);
        val /= 10;
        pos -= 1;
    }
    serial_write_hw(&buf[(pos + 1)..]);
}

fn serial_dec_early_impl(mut val: u64) {
    if val == 0 {
        serial_write_early(b"0");
        return;
    }
    let mut buf = [0u8; 20];
    let mut pos = 19;
    while val > 0 {
        buf[pos] = b'0' + ((val % 10) as u8);
        val /= 10;
        pos -= 1;
    }
    serial_write_early(&buf[(pos + 1)..]);
}

/// RAII guard for atomic multi-part console output.
pub(crate) struct SerialGuard {
    irq: u64,
    active: bool,
}

impl SerialGuard {
    pub fn acquire() -> Self {
        if crate::kernel::panic::suppress_non_panic_cpu_output() {
            return Self {
                irq: 0,
                active: false,
            };
        }

        #[cfg(no_serial_output)]
        {
            return Self {
                irq: 0,
                active: false,
            };
        }

        #[cfg(not(no_serial_output))]
        {
            let irq = unsafe { mm::save_irq_disable() };
            SERIAL_LOCK.lock();
            Self { irq, active: true }
        }
    }

    pub fn puts(&self, s: &str) {
        if !self.active {
            return;
        }
        #[cfg(no_serial_output)]
        {
            let _ = s;
            return;
        }
        #[cfg(not(no_serial_output))]
        serial_write_hw(s.as_bytes());
    }

    pub fn hex(&self, val: u64) {
        if !self.active {
            return;
        }
        #[cfg(no_serial_output)]
        {
            let _ = val;
            return;
        }
        #[cfg(not(no_serial_output))]
        serial_hex_impl(val);
    }

    pub fn dec(&self, val: u64) {
        if !self.active {
            return;
        }
        #[cfg(no_serial_output)]
        {
            let _ = val;
            return;
        }
        #[cfg(not(no_serial_output))]
        serial_dec_impl(val);
    }

    pub fn putc(&self, c: u8) {
        if !self.active {
            return;
        }
        #[cfg(no_serial_output)]
        {
            let _ = c;
            return;
        }
        #[cfg(not(no_serial_output))]
        serial_putc_hw(c);
    }
}

impl Drop for SerialGuard {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        #[cfg(no_serial_output)]
        return;

        #[cfg(not(no_serial_output))]
        {
            console::flush_pending();
            SERIAL_LOCK.unlock();
            unsafe { mm::restore_irq(self.irq) };
        }
    }
}

#[allow(unused_macros)]
macro_rules! ktrace {
    (mm, |$g:ident| { $($body:tt)* }) => { #[cfg(any(klog_trace, klog_mod_mm))] { let $g = $crate::kernel::printk::SerialGuard::acquire(); $($body)* } };
    (ipc, |$g:ident| { $($body:tt)* }) => { #[cfg(any(klog_trace, klog_mod_ipc))] { let $g = $crate::kernel::printk::SerialGuard::acquire(); $($body)* } };
    (sched, |$g:ident| { $($body:tt)* }) => { #[cfg(any(klog_trace, klog_mod_sched))] { let $g = $crate::kernel::printk::SerialGuard::acquire(); $($body)* } };
    (cap, |$g:ident| { $($body:tt)* }) => { #[cfg(any(klog_trace, klog_mod_cap))] { let $g = $crate::kernel::printk::SerialGuard::acquire(); $($body)* } };
    (syscall, |$g:ident| { $($body:tt)* }) => { #[cfg(any(klog_trace, klog_mod_syscall))] { let $g = $crate::kernel::printk::SerialGuard::acquire(); $($body)* } };
    (init, |$g:ident| { $($body:tt)* }) => { #[cfg(any(klog_trace, klog_mod_init))] { let $g = $crate::kernel::printk::SerialGuard::acquire(); $($body)* } };
    (arch, |$g:ident| { $($body:tt)* }) => { #[cfg(any(klog_trace, klog_mod_arch))] { let $g = $crate::kernel::printk::SerialGuard::acquire(); $($body)* } };
    (console, |$g:ident| { $($body:tt)* }) => { #[cfg(any(klog_trace, klog_mod_console))] { let $g = $crate::kernel::printk::SerialGuard::acquire(); $($body)* } };
    (|$g:ident| { $($body:tt)* }) => {
        #[cfg(klog_trace)]
        {
            let $g = $crate::kernel::printk::SerialGuard::acquire();
            $($body)*
        }
    };
}

#[allow(unused_macros)]
macro_rules! kdebug {
    (mm, |$g:ident| { $($body:tt)* }) => { #[cfg(any(klog_debug, klog_mod_mm))] { let $g = $crate::kernel::printk::SerialGuard::acquire(); $($body)* } };
    (ipc, |$g:ident| { $($body:tt)* }) => { #[cfg(any(klog_debug, klog_mod_ipc))] { let $g = $crate::kernel::printk::SerialGuard::acquire(); $($body)* } };
    (sched, |$g:ident| { $($body:tt)* }) => { #[cfg(any(klog_debug, klog_mod_sched))] { let $g = $crate::kernel::printk::SerialGuard::acquire(); $($body)* } };
    (cap, |$g:ident| { $($body:tt)* }) => { #[cfg(any(klog_debug, klog_mod_cap))] { let $g = $crate::kernel::printk::SerialGuard::acquire(); $($body)* } };
    (syscall, |$g:ident| { $($body:tt)* }) => { #[cfg(any(klog_debug, klog_mod_syscall))] { let $g = $crate::kernel::printk::SerialGuard::acquire(); $($body)* } };
    (init, |$g:ident| { $($body:tt)* }) => { #[cfg(any(klog_debug, klog_mod_init))] { let $g = $crate::kernel::printk::SerialGuard::acquire(); $($body)* } };
    (arch, |$g:ident| { $($body:tt)* }) => { #[cfg(any(klog_debug, klog_mod_arch))] { let $g = $crate::kernel::printk::SerialGuard::acquire(); $($body)* } };
    (console, |$g:ident| { $($body:tt)* }) => { #[cfg(any(klog_debug, klog_mod_console))] { let $g = $crate::kernel::printk::SerialGuard::acquire(); $($body)* } };
    (|$g:ident| { $($body:tt)* }) => {
        #[cfg(klog_debug)]
        {
            let $g = $crate::kernel::printk::SerialGuard::acquire();
            $($body)*
        }
    };
}

#[allow(unused_macros)]
macro_rules! kinfo {
    (|$g:ident| { $($body:tt)* }) => {
        #[cfg(klog_info)]
        {
            let $g = $crate::kernel::printk::SerialGuard::acquire();
            $($body)*
        }
    };
}

#[allow(unused_macros)]
macro_rules! kwarn {
    (|$g:ident| { $($body:tt)* }) => {
        #[cfg(klog_warn)]
        {
            let $g = $crate::kernel::printk::SerialGuard::acquire();
            $($body)*
        }
    };
}

#[allow(unused_macros)]
macro_rules! kerror {
    (|$g:ident| { $($body:tt)* }) => {
        {
            let $g = $crate::kernel::printk::SerialGuard::acquire();
            $($body)*
        }
    };
}

pub(crate) use kdebug;
pub(crate) use kerror;
pub(crate) use kinfo;
pub(crate) use ktrace;
pub(crate) use kwarn;
