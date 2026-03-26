// SPDX-License-Identifier: GPL-2.0-only
//! ARM Generic Timer driver.
//!
//! Uses the EL1 Physical Timer (CNTP) to generate periodic 1 ms interrupts
//! via PPI 30 (INTID 30) on the GICv3.
//!
//! ## Registers used
//!
//! - `CNTFRQ_EL0`  — counter frequency (set by firmware, read-only)
//! - `CNTPCT_EL0`  — physical counter value (monotonic, read-only)
//! - `CNTP_TVAL_EL0` — timer countdown value (write to arm, auto-decrements)
//! - `CNTP_CTL_EL0`  — timer control (bit 0 = ENABLE, bit 1 = IMASK)

use core::ptr;

/// Physical timer PPI interrupt ID.
const TIMER_PPI_INTID: u32 = 30;

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
    let val: u64;
    // SAFETY: Reading CNTFRQ_EL0 is always safe.
    unsafe {
        core::arch::asm!("mrs {}, CNTFRQ_EL0", out(reg) val, options(nomem, nostack));
    }
    val
}

/// Write the timer countdown value (CNTP_TVAL_EL0).
#[inline(always)]
fn write_cntp_tval(tval: u64) {
    // SAFETY: Writing CNTP_TVAL_EL0 is safe from EL1.
    unsafe {
        core::arch::asm!("msr CNTP_TVAL_EL0, {}", in(reg) tval, options(nomem, nostack));
    }
}

/// Write the timer control register (CNTP_CTL_EL0).
#[inline(always)]
fn write_cntp_ctl(ctl: u64) {
    // SAFETY: Writing CNTP_CTL_EL0 is safe from EL1.
    unsafe {
        core::arch::asm!("msr CNTP_CTL_EL0, {}", in(reg) ctl, options(nomem, nostack));
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
        crate::serial_puts("[TIMER] WARNING: CNTFRQ_EL0 is 0 — timer will not function\n");
        return;
    }

    // SAFETY: Single-threaded boot context. COUNTER_FREQ is written once
    // and only read afterwards.
    unsafe {
        ptr::write_volatile(ptr::addr_of_mut!(COUNTER_FREQ), freq);
    }

    // Disable the timer while we configure.
    write_cntp_ctl(0);

    crate::kinfo!(|_g| {
        _g.puts("[TIMER] Counter frequency: ");
        _g.hex(freq);
        _g.puts(" Hz\n");
    });
}

/// Start periodic timer interrupts.
///
/// Arms the countdown with a 1 ms interval, enables the timer (IMASK
/// cleared), and enables PPI 30 in the GIC redistributor.
pub fn start() {
    let freq = get_frequency();
    if freq == 0 {
        return;
    }

    // Per-CPU: allow EL0 to read CNTVCT_EL0 (virtual counter).
    // CNTKCTL_EL1 is banked per CPU, so this must run on each core.
    // SAFETY: Writing CNTKCTL_EL1 is safe from EL1.
    unsafe {
        let mut cntkctl: u64;
        core::arch::asm!("mrs {}, CNTKCTL_EL1", out(reg) cntkctl, options(nomem, nostack));
        cntkctl |= 1 << 1; // EL0VCTEN
        cntkctl &= !(1 << 0); // clear EL0PCTEN
        core::arch::asm!("msr CNTKCTL_EL1, {}", in(reg) cntkctl, options(nomem, nostack));
    }

    let tval = freq / TICK_HZ;

    // Set the countdown value.
    write_cntp_tval(tval);

    // Enable the timer: ENABLE=1 (bit 0), IMASK=0 (bit 1 clear).
    write_cntp_ctl(1);

    // Enable PPI 30 in the GIC so the interrupt is delivered.
    super::gic::enable_irq(TIMER_PPI_INTID);

    crate::serial_puts("[TIMER] Started (1 ms tick)\n");
}

/// Return the cached counter frequency.
pub fn get_frequency() -> u64 {
    // SAFETY: COUNTER_FREQ is written once during init() and only read
    // afterwards.
    unsafe { ptr::read_volatile(ptr::addr_of!(COUNTER_FREQ)) }
}

/// Re-arm the timer for the next tick.
///
/// Called from the IRQ handler after acknowledging PPI 30. Writing
/// CNTP_TVAL_EL0 clears the ISTATUS condition and starts a new countdown.
pub fn rearm() {
    let freq = get_frequency();
    if freq == 0 {
        return;
    }
    let tval = freq / TICK_HZ;
    write_cntp_tval(tval);
}
