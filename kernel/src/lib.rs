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
mod console;
mod cpio;
mod elf;
mod init;
mod ipc;
mod mm;
mod sched;
mod syscall;

pub use bootinfo::{FramebufferInfo, MemoryKind, MemoryMapEntry, ParsedBootInfo};

use core::panic::PanicInfo;

/// Acquire SCHED_IPC_LOCK. Does `cli` first to prevent same-CPU deadlock.
/// Called from assembly (timer/reschedule/exception stubs).
#[unsafe(no_mangle)]
pub extern "C" fn sched_ipc_lock() {
    unsafe { core::arch::asm!("cli", options(nomem, nostack)); }
    mm::SCHED_IPC_LOCK.lock();
}

/// Release SCHED_IPC_LOCK. Does NOT re-enable interrupts.
/// Called from assembly (timer/reschedule/exception stubs).
#[unsafe(no_mangle)]
pub extern "C" fn sched_ipc_unlock() {
    mm::SCHED_IPC_LOCK.unlock();
}

/// Serial port (COM1) for debug output
const SERIAL_PORT: u16 = 0x3F8;

/// Leaf-level spinlock protecting all COM1 serial output.
///
/// Lock ordering (outermost → innermost):
///   CAP_LOCK → SCHED_IPC_LOCK → scheduler.lock_state → VSpace.lock → MM_LOCK → SERIAL_LOCK
pub(crate) static SERIAL_LOCK: mm::SpinLock = mm::SpinLock::new();

// ---------------------------------------------------------------------------
// Raw serial output (no lock) — for panic/deadlock/crash paths only
// ---------------------------------------------------------------------------

/// Write a single byte to COM1 hardware. No locking.
/// Also mirrors output to the framebuffer console (if initialized).
#[inline]
pub(crate) fn serial_putc_hw(c: u8) {
    // SAFETY: COM1 is a standard x86 serial port
    unsafe {
        while (arch::inb(SERIAL_PORT + 5) & 0x20) == 0 {}
        arch::outb(SERIAL_PORT, c);
    }
    console::putc(c);
}

/// Write a byte slice to COM1 hardware and mirror it to framebuffer.
#[inline]
pub(crate) fn serial_write_hw(buf: &[u8]) {
    if buf.is_empty() {
        return;
    }
    for &c in buf {
        // SAFETY: COM1 is a standard x86 serial port
        unsafe {
            while (arch::inb(SERIAL_PORT + 5) & 0x20) == 0 {}
            arch::outb(SERIAL_PORT, c);
        }
    }
    console::write(buf);
}

/// Write a string to COM1 without any locking. Panic/crash path only.
pub(crate) fn serial_puts_raw(s: &str) {
    serial_write_hw(s.as_bytes());
}

/// Write a hexadecimal number to COM1 without any locking. Panic/crash path only.
pub(crate) fn serial_hex_raw(mut val: u64) {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    if val == 0 {
        serial_write_hw(b"0x0");
        return;
    }
    let mut buf = [0u8; 18]; // "0x" + max 16 hex digits
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

/// Write a decimal number to COM1 without any locking. Panic/crash path only.
pub(crate) fn serial_dec_raw(mut val: u64) {
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

// ---------------------------------------------------------------------------
// Locked serial output — IRQ-safe, SMP-safe
// ---------------------------------------------------------------------------

/// Write a single byte to COM1 under SERIAL_LOCK.
pub(crate) fn serial_putc(c: u8) {
    // SAFETY: save/restore IRQ flags around spinlock to prevent deadlock
    let irq = unsafe { mm::save_irq_disable() };
    SERIAL_LOCK.lock();
    serial_putc_hw(c);
    console::flush_pending();
    SERIAL_LOCK.unlock();
    unsafe { mm::restore_irq(irq) };
}

/// Write a string to COM1 under SERIAL_LOCK.
pub(crate) fn serial_puts(s: &str) {
    // SAFETY: save/restore IRQ flags around spinlock to prevent deadlock
    let irq = unsafe { mm::save_irq_disable() };
    SERIAL_LOCK.lock();
    serial_write_hw(s.as_bytes());
    SERIAL_LOCK.unlock();
    unsafe { mm::restore_irq(irq) };
}

/// Write a hexadecimal number to COM1 under SERIAL_LOCK.
pub(crate) fn serial_hex(val: u64) {
    // SAFETY: save/restore IRQ flags around spinlock to prevent deadlock
    let irq = unsafe { mm::save_irq_disable() };
    SERIAL_LOCK.lock();
    serial_hex_impl(val);
    SERIAL_LOCK.unlock();
    unsafe { mm::restore_irq(irq) };
}

/// Write a decimal number to COM1 under SERIAL_LOCK.
pub(crate) fn serial_dec(val: u64) {
    // SAFETY: save/restore IRQ flags around spinlock to prevent deadlock
    let irq = unsafe { mm::save_irq_disable() };
    SERIAL_LOCK.lock();
    serial_dec_impl(val);
    SERIAL_LOCK.unlock();
    unsafe { mm::restore_irq(irq) };
}

/// Hex formatting without lock (used by SerialGuard and locked wrappers)
fn serial_hex_impl(mut val: u64) {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    if val == 0 {
        serial_write_hw(b"0x0");
        return;
    }
    let mut buf = [0u8; 18]; // "0x" + max 16 hex digits
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

/// Decimal formatting without lock (used by SerialGuard and locked wrappers)
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

// ---------------------------------------------------------------------------
// SerialGuard — RAII guard for compound serial output atomicity
// ---------------------------------------------------------------------------

/// RAII guard that holds SERIAL_LOCK for the duration of a compound output.
///
/// Use when multiple serial_puts/hex/dec calls form a single logical message
/// that must not be interleaved with output from other CPUs/threads.
///
/// ```rust
/// {
///     let s = SerialGuard::acquire();
///     s.puts("[AP] CPU ");
///     s.dec(cpu_id as u64);
///     s.puts(" online\n");
/// } // Drop → unlock + restore_irq
/// ```
pub(crate) struct SerialGuard {
    irq: u64,
}

impl SerialGuard {
    pub fn acquire() -> Self {
        // SAFETY: save IRQ flags and disable interrupts to prevent deadlock
        let irq = unsafe { mm::save_irq_disable() };
        SERIAL_LOCK.lock();
        Self { irq }
    }

    pub fn puts(&self, s: &str) {
        serial_write_hw(s.as_bytes());
    }

    pub fn hex(&self, val: u64) {
        serial_hex_impl(val);
    }

    pub fn dec(&self, val: u64) {
        serial_dec_impl(val);
    }

    pub fn putc(&self, c: u8) {
        serial_putc_hw(c);
    }
}

impl Drop for SerialGuard {
    fn drop(&mut self) {
        // Flush all pending console output accumulated during this guard's scope
        // into a single VRAM update, before releasing the lock.
        console::flush_pending();
        SERIAL_LOCK.unlock();
        // SAFETY: restoring previously saved IRQ flags
        unsafe { mm::restore_irq(self.irq) };
    }
}

// ---------------------------------------------------------------------------
// Compile-time-gated kernel log macros
// ---------------------------------------------------------------------------

/// Trace-level log. Compiled out unless `klog_trace` cfg is set.
///
/// The body receives a reference to a `SerialGuard` named `_g`. Use it to
/// emit output with `_g.puts(...)`, `_g.hex(...)`, `_g.dec(...)`, etc.
/// The guard (and its lock) is released when the block exits.
///
/// Example:
/// ```rust
/// ktrace!({
///     _g.puts("[RETYPE] seq=");
///     _g.hex(crate::arch::current_invoke_seq());
///     _g.putc(b'\n');
/// });
/// ```
#[allow(unused_macros)]
macro_rules! ktrace {
    ($body:block) => {
        #[cfg(klog_trace)]
        {
            let _g = $crate::SerialGuard::acquire();
            $body
        }
    };
}

/// Debug-level log. Compiled out unless `klog_debug` (or `klog_trace`) cfg is set.
///
/// Same usage as `ktrace!`.
#[allow(unused_macros)]
macro_rules! kdebug {
    ($body:block) => {
        #[cfg(klog_debug)]
        {
            let _g = $crate::SerialGuard::acquire();
            $body
        }
    };
}

pub(crate) use ktrace;
pub(crate) use kdebug;

/// Kernel entry point (called from bootloader)
///
/// The bootloader passes a pointer to a TLV-encoded BootInfo structure via RDI.
///
/// # Safety
/// This function is called directly from assembly with a specific ABI.
#[unsafe(no_mangle)]
pub extern "C" fn kmain(raw_boot_info: *const u8) -> ! {
    // Immediate confirmation we're in kernel (before anything else)
    // Note: raw output OK here — single CPU, before SMP init
    serial_puts_raw("[ENTRY] ");
    serial_puts_raw("\nSaltyOS Kernel loaded\n");
    {
        let s = SerialGuard::acquire();
        s.puts("[KMAIN] Entry addr: ");
        s.hex(kmain as *const () as u64);
        s.puts("\n[KMAIN] Boot info ptr: ");
        s.hex(raw_boot_info as u64);
        s.puts("\n");
    }

    // Parse TLV-encoded BootInfo from bootloader
    let boot_info = unsafe { bootinfo::parse(raw_boot_info) };

    if let Some(info) = boot_info {
        let s = SerialGuard::acquire();
        s.puts("[KMAIN] BootInfo parsed: ");
        s.dec(info.memory_map_len as u64);
        s.puts(" memory map entries\n");
    } else {
        serial_puts("[KMAIN] WARNING: Failed to parse BootInfo!\n");
    }

    // Initialize architecture-specific subsystems
    arch::init(boot_info);

    // Initialize framebuffer text console (mirrors serial to screen).
    // Must be after arch::init() (paging + frame allocator) and before
    // init_smp() so APs inherit the PML4[257] mapping.
    if let Some(info) = boot_info {
        console::init(&info.framebuffer);
    }

    // Initialize capability system
    cap::init();

    // Initialize IPC subsystem
    ipc::init();

    // Initialize scheduler
    sched::init();

    // Start timer interrupts (scheduler must be ready first)
    arch::start_timer();

    // Initialize SMP (start Application Processors)
    arch::init_smp(boot_info);

    // Remove bootloader identity mapping (PML4[0]) now that all APs
    // have booted and are running in higher-half kernel code.
    arch::clear_boot_identity_map();

    // Bootstrap the first user-mode init task
    init::bootstrap(boot_info);

    // Dispatch the init task (context_switch to it).
    // SCHED_IPC_LOCK must be held: do_context_switch releases/reacquires it.
    mm::SCHED_IPC_LOCK.lock();
    sched::scheduler::scheduler().reschedule();
    mm::SCHED_IPC_LOCK.unlock();

    // Fallback (should never reach here once init task is dispatched)
    loop {
        arch::halt();
    }
}

/// Panic handler
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    // Re-enable framebuffer console so crash output is visible on screen
    // even if the display server had taken over
    console::enable();

    // Use raw output — another CPU might hold SERIAL_LOCK
    serial_puts_raw("\n!!! KERNEL PANIC !!!\n");

    if let Some(location) = info.location() {
        serial_puts_raw("  Location: ");
        serial_puts_raw(location.file());
        serial_putc_hw(b':');
        serial_dec_raw(location.line() as u64);
        serial_putc_hw(b'\n');
    }

    if let Some(msg) = info.message().as_str() {
        serial_puts_raw("  Message: ");
        serial_puts_raw(msg);
        serial_putc_hw(b'\n');
    }

    loop {
        arch::halt();
    }
}
