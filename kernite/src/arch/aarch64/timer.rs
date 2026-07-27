// SPDX-License-Identifier: GPL-2.0-only
//! ARM Generic Timer driver.
//!
//! Uses the EL1 Virtual Timer (CNTV).
//!
//! ## Registers used
//!
//! - `CNTFRQ_EL0`  — counter frequency (set by firmware, read-only)
//! - `CNTVCT_EL0`  — virtual counter value (monotonic, read-only)
//! - `CNTV_CVAL_EL0` — EL1 virtual timer compare value
//! - `CNTV_CTL_EL0`  — EL1 virtual timer control (bit 0 = ENABLE, bit 1 = IMASK)

use core::ptr;

unsafe extern "C" {
    fn aarch64_timer_read_cntfrq_el0() -> u64;
    fn aarch64_timer_read_cntvct_el0() -> u64;
    fn aarch64_timer_write_cntv_cval_el0(cval: u64);
    fn aarch64_timer_write_cntv_ctl_el0(ctl: u64);
    fn aarch64_timer_read_cntkctl_el1() -> u64;
    fn aarch64_timer_write_cntkctl_el1(value: u64);
}

/// EL1 virtual timer PPI interrupt ID.
const VIRT_TIMER_PPI_INTID: u32 = 27;
/// Timer control bit: enable timer output/comparison.
const TIMER_CTL_ENABLE: u64 = 1 << 0;
/// Timer control bit: mask timer interrupt delivery.
const TIMER_CTL_IMASK: u64 = 1 << 1;

/// Timer tick interval: 1 ms (1000 Hz).
const TICK_HZ: u64 = 1000;

/// Cached counter frequency (set once during `init()`).
static mut COUNTER_FREQ: u64 = 0;

// ---------------------------------------------------------------------------
// Register accessors
// ---------------------------------------------------------------------------

/// Read the counter frequency from CNTFRQ_EL0.
#[inline(always)]
fn read_cntfrq() -> u64 {
    // SAFETY: Reading CNTFRQ_EL0 is always safe.
    unsafe { aarch64_timer_read_cntfrq_el0() }
}

/// Read the active counter value used by the virtual timer.
#[inline(always)]
fn read_timer_count() -> u64 {
    // SAFETY: Reading CNTVCT_EL0 is always safe from EL1 kernel context.
    unsafe { aarch64_timer_read_cntvct_el0() }
}

/// Write the virtual timer compare value.
#[inline(always)]
fn write_timer_cval(cval: u64) {
    // SAFETY: Writing CNTV_CVAL_EL0 is safe from EL1 kernel context.
    unsafe {
        aarch64_timer_write_cntv_cval_el0(cval);
    }
}

/// Write the virtual timer control register.
#[inline(always)]
fn write_timer_ctl(ctl: u64) {
    // SAFETY: Writing CNTV_CTL_EL0 is safe from EL1 kernel context.
    unsafe {
        aarch64_timer_write_cntv_ctl_el0(ctl);
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Initialize the timer subsystem.
///
/// Reads and caches the counter frequency, then disables the timer
/// (it will be started later by `start()`).
pub fn init() {
    let freq = read_cntfrq();
    if freq == 0 {
        crate::kernel::printk::serial_puts(
            "[TIMER] WARNING: CNTFRQ_EL0 is 0 — timer will not function\n",
        );
        return;
    }

    // SAFETY: Single-threaded boot context. COUNTER_FREQ is written once
    // and only read afterwards.
    unsafe {
        ptr::write_volatile(ptr::addr_of_mut!(COUNTER_FREQ), freq);
    }

    // Disable the timer while we configure.
    write_timer_ctl(0);

    crate::kernel::printk::kinfo!(|_g| {
        _g.puts("[TIMER] Counter frequency: ");
        _g.hex(freq);
        _g.puts(" Hz\n");
    });
}

/// Start periodic timer interrupts.
///
/// Programs the active timer in a masked state first, enables delivery in the
/// GIC, then unmasks the timer as the final step. This mirrors the x86 LAPIC
/// pattern where the timer is fully configured before the first interrupt can
/// be delivered.
pub fn start() {
    let freq = get_frequency();
    if freq == 0 {
        return;
    }

    // Per-CPU: allow EL0 to read CNTVCT_EL0 (virtual counter).
    let mut cntkctl = unsafe { aarch64_timer_read_cntkctl_el1() };
    cntkctl |= 1 << 1; // EL0VCTEN
    cntkctl &= !(1 << 0); // clear EL0PCTEN
    unsafe {
        aarch64_timer_write_cntkctl_el1(cntkctl);
    }

    let ticks = freq / TICK_HZ;

    // Quiesce the timer while programming it.
    write_timer_ctl(0);

    // Arm the countdown but keep interrupt delivery masked.
    write_timer_cval(read_timer_count().wrapping_add(ticks));
    write_timer_ctl(TIMER_CTL_ENABLE | TIMER_CTL_IMASK);

    // Enable the timer PPI in the GIC while the timer is still masked.
    super::gic::enable_irq(irq_intid());

    // Refresh the countdown so the first visible tick starts from a clean
    // interval after the GIC path is ready.
    write_timer_cval(read_timer_count().wrapping_add(ticks));

    // Finally unmask timer interrupt delivery.
    write_timer_ctl(TIMER_CTL_ENABLE);

    crate::kernel::printk::serial_puts("[TIMER] Started (1 ms tick)\n");
}

/// Stop the local timer and mask further timer interrupt delivery.
pub fn stop() {
    write_timer_ctl(0);
}

/// Return the active timer interrupt ID for the current exception level.
pub fn irq_intid() -> u32 {
    VIRT_TIMER_PPI_INTID
}

/// Return the cached counter frequency.
pub fn get_frequency() -> u64 {
    // SAFETY: COUNTER_FREQ is written once during init() and only read
    // afterwards.
    unsafe { ptr::read_volatile(ptr::addr_of!(COUNTER_FREQ)) }
}

/// Re-arm the timer for the next tick.
///
/// Called from the IRQ handler after acknowledging the active timer PPI.
/// Writing a future timer CVAL clears ISTATUS and arms the next deadline.
pub fn rearm() {
    let freq = get_frequency();
    if freq == 0 {
        return;
    }
    let ticks = freq / TICK_HZ;
    write_timer_cval(read_timer_count().wrapping_add(ticks));
}
