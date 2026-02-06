//! Programmable Interval Timer (8253/8254)
//!
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! # PIT (Programmable Interval Timer)
//!
//! The legacy PIT is used for:
//! - Time calibration for the APIC timer
//! - Fallback timing if APIC is unavailable
//! - System-wide time reference
//!
//! The PIT has three channels:
//! - Channel 0: System timer (used by us)
//! - Channel 1: (historically) DRAM refresh
//! - Channel 2: PC speaker
//!
//! # Configuration
//!
//! We configure channel 0 for:
//! - Mode 3 (square wave) - periodic interrupts
//! - 16-bit binary counting
//! - LSB + MSB access mode
//! - 1ms interrupt period (1000 Hz)

use super::{inb, outb};
use core::sync::atomic::{AtomicU64, Ordering};

/// PIT I/O ports
const PIT_COMMAND: u16 = 0x43;
const PIT_CHANNEL0: u16 = 0x40;

/// PIT base frequency (Hz)
/// The classic PC PIT runs at 1.193182 MHz
pub const PIT_FREQUENCY: u32 = 1193182;

/// Target tick frequency (1000 Hz = 1ms per tick)
const TARGET_FREQUENCY: u32 = 1000;

/// Divisor for 1ms ticks
const DIVISOR: u16 = (PIT_FREQUENCY / TARGET_FREQUENCY) as u16;

/// Global tick counter
static TICK_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Initialize PIT for 1ms ticks
///
/// Configures channel 0 for periodic interrupts at 1000 Hz (1ms period).
pub fn init() {
    unsafe {
        // Configure channel 0:
        // - Channel 0 (bits 6-7 = 00)
        // - Access mode: lobyte/hibyte (bits 4-5 = 11)
        // - Operating mode: mode 3 square wave (bits 1-3 = 011)
        // - Binary mode (bit 0 = 0)
        let command: u8 = 0b00110110; // 0x36
        outb(PIT_COMMAND, command);

        // Set divisor (LSB first, then MSB)
        outb(PIT_CHANNEL0, (DIVISOR & 0xFF) as u8);
        outb(PIT_CHANNEL0, ((DIVISOR >> 8) & 0xFF) as u8);
    }
}

/// Read current PIT counter value
///
/// Returns the current count value from channel 0.
/// This decreases from DIVISOR to 0, then wraps around.
pub fn read_counter() -> u16 {
    unsafe {
        // Latch the count value
        outb(PIT_COMMAND, 0x00);

        // Read LSB then MSB
        let lsb = inb(PIT_CHANNEL0);
        let msb = inb(PIT_CHANNEL0);

        ((msb as u16) << 8) | (lsb as u16)
    }
}

/// Get the current tick count
///
/// Returns the number of PIT ticks since boot.
pub fn get_ticks() -> u64 {
    TICK_COUNTER.load(Ordering::Relaxed)
}

/// Get elapsed time in microseconds
///
/// Returns the number of microseconds since boot.
/// This is an approximation based on the tick counter (1000 ticks/sec).
pub fn now_us() -> u64 {
    get_ticks() * 1000
}

/// PIT interrupt handler
///
/// Called by the IRQ0 handler when using the PIT as the primary timer.
/// Note: We primarily use the APIC timer, so this may not be used.
pub fn timer_handler() {
    TICK_COUNTER.fetch_add(1, Ordering::Relaxed);
}

/// Calibrate using PIT
///
/// Uses the PIT to measure time for calibrating other timers.
/// This is a busy-wait calibration that uses the PIT counter.
pub fn calibrate_sleep_us(microseconds: u32) {
    // Calculate how many PIT ticks to wait
    // PIT ticks per microsecond = PIT_FREQUENCY / 1_000_000
    // For X microseconds: X * PIT_FREQUENCY / 1_000_000
    let pit_ticks = ((microseconds as u64) * (PIT_FREQUENCY as u64)) / 1_000_000;
    let initial = read_counter() as u64;

    loop {
        let current = read_counter() as u64;
        // Counter counts down, so we calculate elapsed ticks
        let elapsed = if current <= initial {
            initial - current
        } else {
            // Wrapped around
            initial + (DIVISOR as u64) - current
        };

        if elapsed >= pit_ticks {
            break;
        }
    }
}

/// Precise delay using PIT
///
/// Provides a busy-wait delay with microsecond precision.
/// This is useful for short delays where interrupt overhead is unacceptable.
pub fn delay_us(microseconds: u32) {
    if microseconds == 0 {
        return;
    }

    // For very short delays (< 10us), just use a few cycles
    if microseconds < 10 {
        let iterations = microseconds * 30;
        for _ in 0..iterations {
            unsafe { core::arch::asm!("nop") };
        }
        return;
    }

    // The PIT counter wraps every ~1ms (DIVISOR ticks).
    // For delays > ~500us, break into smaller chunks to avoid
    // wrap-around issues in the counter tracking.
    // Each chunk is at most 500us (about half a PIT cycle).
    let chunk_us = 500u32;
    let mut remaining = microseconds;
    while remaining > chunk_us {
        calibrate_sleep_us(chunk_us);
        remaining -= chunk_us;
    }
    if remaining > 0 {
        calibrate_sleep_us(remaining);
    }
}

/// Get approximate time since boot in milliseconds
///
/// Uses the tick counter (1000 ticks = 1 second).
pub fn uptime_ms() -> u64 {
    get_ticks()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_divisor_calculation() {
        // Verify our divisor gives us approximately 1ms ticks
        let actual_frequency = PIT_FREQUENCY / (DIVISOR as u32);
        assert!((actual_frequency - TARGET_FREQUENCY).abs() < 10);
    }

    #[test]
    fn test_divisor_value() {
        // Divisor should be 1193 for ~1000 Hz
        assert_eq!(DIVISOR, 1193);
    }
}
