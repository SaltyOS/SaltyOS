//! Local APIC and Timer Support
//!
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! # Local APIC (Advanced Programmable Interrupt Controller)
//!
//! The Local APIC is integrated into each CPU core and provides:
//! - Local timer for per-CPU scheduling
//! - Inter-Processor Interrupts (IPIs) for SMP coordination
//! - Local interrupt handling
//!
//! # Memory Mapped I/O
//!
//! The LAPIC is accessed via MMIO at a fixed physical address.
//! We map it into the kernel's virtual address space using the
//! direct physical mapping.

use super::outb;
use crate::mm::PHYS_MAP_OFFSET;
use core::sync::atomic::{AtomicU32, Ordering};

/// Local APIC base address (physical)
pub const LAPIC_BASE: u64 = 0xFEE0_0000;

/// Local APIC register offsets (from base)
pub const LAPIC_ID: u32 = 0x020;
pub const LAPIC_VER: u32 = 0x030;
pub const LAPIC_TPR: u32 = 0x080;
pub const LAPIC_APR: u32 = 0x090;
pub const LAPIC_PPR: u32 = 0x0A0;
pub const LAPIC_EOI: u32 = 0x0B0;
pub const LAPIC_RRR: u32 = 0x0C0;
pub const LAPIC_LDR: u32 = 0x0D0;
pub const LAPIC_DFR: u32 = 0x0E0;
pub const LAPIC_SVR: u32 = 0x0F0;
pub const LAPIC_ISR0: u32 = 0x100;
pub const LAPIC_ISR1: u32 = 0x110;
pub const LAPIC_ISR2: u32 = 0x120;
pub const LAPIC_ISR3: u32 = 0x130;
pub const LAPIC_TMR0: u32 = 0x180;
pub const LAPIC_TMR1: u32 = 0x190;
pub const LAPIC_TMR2: u32 = 0x1A0;
pub const LAPIC_TMR3: u32 = 0x1B0;
pub const LAPIC_IRR0: u32 = 0x200;
pub const LAPIC_IRR1: u32 = 0x210;
pub const LAPIC_IRR2: u32 = 0x220;
pub const LAPIC_IRR3: u32 = 0x230;
pub const LAPIC_ESR: u32 = 0x280;
pub const LAPIC_LVT_TIMER: u32 = 0x320;
pub const LAPIC_LVT_THERMAL: u32 = 0x330;
pub const LAPIC_LVT_PERF: u32 = 0x340;
pub const LAPIC_LVT_LINT0: u32 = 0x350;
pub const LAPIC_LVT_LINT1: u32 = 0x360;
pub const LAPIC_LVT_ERROR: u32 = 0x370;
pub const LAPIC_TIMER_INITIAL: u32 = 0x380;
pub const LAPIC_TIMER_CURRENT: u32 = 0x390;
pub const LAPIC_TIMER_DIVIDE: u32 = 0x3E0;

/// IA32_APIC_BASE MSR address
const IA32_APIC_BASE_MSR: u32 = 0x1B;

/// APIC enabled bit in MSR
const APIC_BASE_ENABLED: u64 = 1 << 11;

/// APIC global enable bit in SVR
const SVR_ENABLE: u32 = 1 << 8;

/// Spurious interrupt vector
const SVR_VECTOR: u32 = 0xFF;

/// Timer interrupt vector (32 = IRQ0 after exceptions)
pub const LAPIC_TIMER_VECTOR: u8 = 32;

/// Timer mode: one-shot
const TIMER_MODE_ONE_SHOT: u32 = 0 << 17;

/// Timer mode: periodic
const TIMER_MODE_PERIODIC: u32 = 1 << 17;

/// Timer mask
const TIMER_MASK: u32 = 1 << 16;

/// Timer divide value (divide by 16)
const TIMER_DIVIDE_16: u32 = 0x3;

/// Timer ticks per millisecond (for 1ms tick period)
/// This assumes APIC runs at bus frequency (typically 100-200 MHz)
/// We'll calibrate this later using the PIT
const TIMER_TICKS_PER_MS: u32 = 10000;

/// Tick counter for timekeeping
static TICK_COUNTER: AtomicU32 = AtomicU32::new(0);

/// Local APIC base address (virtual)
static mut LAPIC_VIRTUAL_BASE: u64 = 0;

/// Check if APIC is available via CPUID
///
/// Returns true if the CPU supports local APIC.
pub fn is_available() -> bool {
    let mut eax: u32 = 1;
    let mut edx: u32;
    unsafe {
        core::arch::asm!(
            "cpuid",
            inout("eax") eax,
            lateout("edx") edx,
            lateout("ecx") _,
        );
    }
    // Check bit 9 of EDX (APIC on CPU)
    edx & (1 << 9) != 0
}

/// Enable Local APIC via MSR
///
/// # Safety
/// Must be called only once per CPU during initialization.
unsafe fn enable_apic() {
    unsafe {
        let mut eax: u32;
        let mut edx: u32;

        // Read current APIC base MSR
        core::arch::asm!(
            "rdmsr",
            in("ecx") IA32_APIC_BASE_MSR,
            out("eax") eax,
            out("edx") edx,
        );

        let apic_base = ((edx as u64) << 32) | (eax as u64);

        // Enable APIC if not already enabled
        if apic_base & APIC_BASE_ENABLED == 0 {
            let new_base = apic_base | APIC_BASE_ENABLED;

            core::arch::asm!(
                "wrmsr",
                in("ecx") IA32_APIC_BASE_MSR,
                in("eax") (new_base as u32),
                in("edx") ((new_base >> 32) as u32),
            );
        }
    }
}

/// Map LAPIC MMIO region to virtual address
///
/// # Safety
/// Must be called after paging is initialized.
/// Assumes direct physical mapping is available.
unsafe fn map_lapic() {
    unsafe {
        LAPIC_VIRTUAL_BASE = LAPIC_BASE + PHYS_MAP_OFFSET;
    }
}

/// Read from LAPIC register
///
/// # Safety
/// The LAPIC must be initialized and mapped before calling this.
#[inline(always)]
unsafe fn lapic_read(offset: u32) -> u32 {
    unsafe {
        let addr = LAPIC_VIRTUAL_BASE + offset as u64;
        let ptr = addr as *const u32;
        ptr.read_volatile()
    }
}

/// Write to LAPIC register
///
/// # Safety
/// The LAPIC must be initialized and mapped before calling this.
#[inline(always)]
unsafe fn lapic_write(offset: u32, value: u32) {
    unsafe {
        let addr = LAPIC_VIRTUAL_BASE + offset as u64;
        let ptr = addr as *mut u32;
        ptr.write_volatile(value);
    }
}

/// Disable legacy 8259 PIC
///
/// The 8259 PIC must be disabled when using APIC to avoid interrupt conflicts.
/// We mask all IRQs on both PICs.
fn disable_8259_pic() {
    unsafe {
        // ICW1: Initialize, ICW4 needed
        outb(0x20, 0x11);
        outb(0xA0, 0x11);

        // ICW2: Vector base (unused since we're masking)
        outb(0x21, 0x08);
        outb(0xA1, 0x70);

        // ICW3: Cascade (unused)
        outb(0x21, 0x04);
        outb(0xA1, 0x02);

        // ICW4: 8086 mode
        outb(0x21, 0x01);
        outb(0xA1, 0x01);

        // OCW1: Mask all IRQs
        outb(0x21, 0xFF);
        outb(0xA1, 0xFF);
    }
}

/// Initialize Local APIC for BSP
///
/// This function:
/// 1. Verifies APIC is available via CPUID
/// 2. Enables APIC in MSR
/// 3. Maps LAPIC MMIO region
/// 4. Configures spurious interrupt vector
/// 5. Initializes and starts the timer
/// 6. Disables legacy 8259 PIC
pub fn init() {
    if !is_available() {
        // APIC not available - this is a critical error
        // TODO: Fall back to PIT-only mode
        loop {
            unsafe { core::arch::asm!("hlt") };
        }
    }

    unsafe {
        // Enable APIC in MSR
        enable_apic();

        // Map LAPIC MMIO region
        map_lapic();

        // Read APIC ID to verify it's working
        let apic_id = lapic_read(LAPIC_ID);
        let _ = apic_id; // Suppress unused warning for now

        // Set Spurious Interrupt Vector register
        // Enable APIC and set spurious vector
        lapic_write(LAPIC_SVR, SVR_ENABLE | SVR_VECTOR);

        // Initialize timer
        init_timer();

        // Initialize LVT interrupts (mask them for now)
        lapic_write(LAPIC_LVT_THERMAL, TIMER_MASK);
        lapic_write(LAPIC_LVT_PERF, TIMER_MASK);
        lapic_write(LAPIC_LVT_LINT0, TIMER_MASK);
        lapic_write(LAPIC_LVT_LINT1, TIMER_MASK);
        lapic_write(LAPIC_LVT_ERROR, TIMER_MASK);
    }

    // Disable legacy 8259 PIC
    disable_8259_pic();
}

/// Initialize and start the APIC timer
///
/// Configures the timer for periodic interrupts at 1ms intervals.
unsafe fn init_timer() {
    unsafe {
        // Set timer divide configuration (divide by 16)
        lapic_write(LAPIC_TIMER_DIVIDE, TIMER_DIVIDE_16);

        // Configure timer for periodic mode
        // Vector 32, periodic, unmasked
        let timer_config = (LAPIC_TIMER_VECTOR as u32) | TIMER_MODE_PERIODIC;
        lapic_write(LAPIC_LVT_TIMER, timer_config);

        // Set initial count for 1ms ticks
        // This will need calibration using PIT for accurate timing
        lapic_write(LAPIC_TIMER_INITIAL, TIMER_TICKS_PER_MS);
    }
}

/// Send End of Interrupt to LAPIC
///
/// Must be called at the end of interrupt handlers to acknowledge
/// interrupt processing and allow further interrupts.
#[inline]
pub fn eoi() {
    unsafe {
        lapic_write(LAPIC_EOI, 0);
    }
}

/// Get the current tick count
///
/// Returns the number of timer ticks since boot.
/// This increments by 1000 per second (1ms tick period).
pub fn get_ticks() -> u32 {
    TICK_COUNTER.load(Ordering::Relaxed)
}

/// Get elapsed time in microseconds
///
/// Returns the number of microseconds since boot.
/// This is an approximation based on tick count.
pub fn now_us() -> u64 {
    get_ticks() as u64 * 1000
}

/// Calibrate APIC timer using PIT
///
/// Uses the PIT to measure the actual APIC timer frequency
/// and adjust the tick count for accurate 1ms intervals.
///
/// This is called during initialization to get accurate timing.
pub fn calibrate_timer() {
    // TODO: Implement PIT-based calibration
    // For now, use the hardcoded value
}

/// APIC Timer interrupt handler
///
/// Called by the IDT handler when the timer interrupt fires.
/// Increments the tick counter and notifies the scheduler.
pub fn timer_handler() {
    // Increment tick counter
    TICK_COUNTER.fetch_add(1, Ordering::Relaxed);

    // Notify scheduler
    crate::sched::timer_tick();

    // Send EOI
    eoi();
}
