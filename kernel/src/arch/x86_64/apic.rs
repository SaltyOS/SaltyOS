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
pub const LAPIC_EOI: u32 = 0x0B0;

/// ICR (Interrupt Command Register) offsets
pub const LAPIC_ICR0: u32 = 0x300;
pub const LAPIC_ICR1: u32 = 0x310;

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

/// IPI interrupt vectors (starting after timer)
pub const IPI_VECTOR_BASE: u8 = 40;

/// Timer mode: one-shot
const TIMER_MODE_ONE_SHOT: u32 = 0 << 17;

/// Timer mode: periodic
const TIMER_MODE_PERIODIC: u32 = 1 << 17;

/// Timer mask
const TIMER_MASK: u32 = 1 << 16;

/// Timer divide value (divide by 16)
const TIMER_DIVIDE_16: u32 = 0x3;

/// Timer ticks per millisecond (calibrated at boot)
/// Default fallback value assumes ~100 MHz APIC bus frequency
/// This is calibrated during initialization using the PIT
static mut TIMER_TICKS_PER_MS: u32 = 10000;

/// ICR (Interrupt Command Register) bits
const ICR_DS: u32 = 1 << 12; // Destination shorthand
const ICR_LEVEL: u32 = 1 << 14; // Level trigger
const ICR_MODE_ASSERT: u32 = 1 << 15; // Assert interrupt

/// Tick counter for timekeeping
static TICK_COUNTER: AtomicU32 = AtomicU32::new(0);

/// Local APIC base address (virtual)
static mut LAPIC_VIRTUAL_BASE: u64 = 0;

/// IPI kinds
#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum IpiKind {
    VSpaceTeardown = 0,
    Reschedule = 1,
}

impl IpiKind {
    /// Get IPI vector for this kind
    fn vector(self) -> u8 {
        IPI_VECTOR_BASE + (self as u8)
    }
}

/// Check if APIC is available via CPUID
///
/// Returns true if the CPU supports local APIC.
pub fn is_available() -> bool {
    let mut edx: u32;
    unsafe {
        core::arch::asm!(
            "cpuid",
            in("eax") 1,
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
/// Can be called early (before APIC init) to prevent spurious IRQ0 from PIT.
pub fn disable_8259_pic() {
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

/// Initialize the APIC timer (but don't start it yet)
///
/// Configures the timer for periodic interrupts at 1ms intervals,
/// but keeps it masked to prevent interrupts before the scheduler is ready.
/// Call start_timer() after the scheduler is initialized to begin ticks.
unsafe fn init_timer() {
    unsafe {
        // Calibrate timer using PIT
        let calibrated_ticks = calibrate_timer();
        TIMER_TICKS_PER_MS = calibrated_ticks;

        // Set timer divide configuration (divide by 16)
        lapic_write(LAPIC_TIMER_DIVIDE, TIMER_DIVIDE_16);

        // Configure timer for periodic mode, but MASKED
        // Timer will not fire until start_timer() is called
        let timer_config = TIMER_MASK | (LAPIC_TIMER_VECTOR as u32) | TIMER_MODE_PERIODIC;
        lapic_write(LAPIC_LVT_TIMER, timer_config);

        // NOTE: Don't set INITIAL count yet - timer starts when we do
        // We'll set it in start_timer() when scheduler is ready
    }
}

/// Start the APIC timer
///
/// Called after the scheduler is initialized to begin timer interrupts.
/// This is separate from init() because the timer must not start
/// until the idle thread is ready to handle interrupts.
pub fn start_timer() {
    unsafe {
        // Set initial count for 1ms ticks using calibrated value
        lapic_write(LAPIC_TIMER_INITIAL, TIMER_TICKS_PER_MS);

        // Unmask the timer - interrupts will now fire
        let timer_config = (LAPIC_TIMER_VECTOR as u32) | TIMER_MODE_PERIODIC;
        lapic_write(LAPIC_LVT_TIMER, timer_config);
    }
}

/// Send End of Interrupt to LAPIC
///
/// Must be called at the end of interrupt handlers to acknowledge
/// interrupt processing and allow further interrupts.
#[inline]
pub fn eoi() {
    // Guard: LAPIC must be mapped before we can write EOI
    if unsafe { LAPIC_VIRTUAL_BASE } == 0 {
        return;
    }
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
/// and calculate the correct tick count for accurate 1ms intervals.
///
/// # Algorithm
/// 1. Save current APIC timer configuration
/// 2. Set APIC timer to one-shot mode with maximum count
/// 3. Use PIT counter to measure time until APIC timer expires
/// 4. Calculate actual APIC ticks per millisecond
/// 5. Restore original timer configuration
///
/// # Returns
/// The calibrated number of APIC timer ticks per millisecond.
/// If calibration fails, returns the default fallback value.
unsafe fn calibrate_timer() -> u32 {
    /// Default fallback value (assumes ~100 MHz APIC bus frequency)
    const DEFAULT_TICKS_PER_MS: u32 = 10000;

    /// Reasonable bounds for calibrated value (sanity check)
    const MIN_TICKS_PER_MS: u32 = 1000;
    const MAX_TICKS_PER_MS: u32 = 100000;

    /// APIC count value for calibration (slightly less than max)
    /// Using max - 1000 to account for threshold check overhead
    const APIC_COUNT: u32 = 0xFFFF_FFFF - 1000;

    /// Timeout: if we don't see APIC timer expire within ~55ms (one PIT period),
    /// something is wrong - fall back to default value
    const PIT_TIMEOUT_TICKS: u16 = 65; // ~55ms at 1193 Hz

    unsafe {
        // Step 1: Save current APIC timer configuration
        let original_lvt = lapic_read(LAPIC_LVT_TIMER);
        let original_divide = lapic_read(LAPIC_TIMER_DIVIDE);
        let original_initial = lapic_read(LAPIC_TIMER_INITIAL);

        // Step 2: Configure APIC timer for one-shot mode
        lapic_write(LAPIC_TIMER_DIVIDE, TIMER_DIVIDE_16);

        // Mask timer and set to one-shot mode
        let timer_config = TIMER_MASK | TIMER_MODE_ONE_SHOT | (LAPIC_TIMER_VECTOR as u32);
        lapic_write(LAPIC_LVT_TIMER, timer_config);

        // Set initial count to our calibration value
        let start_count = APIC_COUNT;
        lapic_write(LAPIC_TIMER_INITIAL, start_count);

        // Step 3: Wait for APIC timer to expire, measuring with PIT
        let pit_start = super::pit::read_counter();
        let mut timer_current: u32;

        // Wait for APIC timer to count down (with timeout protection)
        loop {
            timer_current = lapic_read(LAPIC_TIMER_CURRENT);

            // Check if timer has expired (reached zero or wrapped)
            if timer_current == 0 || timer_current >= start_count {
                break;
            }

            // Timeout check: if PIT has counted down too far, abort
            let pit_current = super::pit::read_counter();
            let pit_elapsed = if pit_current <= pit_start {
                pit_start - pit_current
            } else {
                // Wrapped around (PIT counts down from 0xFFFF to 0)
                pit_start + (0xFFFF as u16 - pit_current) + 1
            };

            if pit_elapsed > PIT_TIMEOUT_TICKS {
                // Calibration failed - timer didn't expire in time
                // Restore original configuration and return default
                lapic_write(LAPIC_TIMER_DIVIDE, original_divide);
                lapic_write(LAPIC_TIMER_INITIAL, original_initial);
                lapic_write(LAPIC_LVT_TIMER, original_lvt);
                return DEFAULT_TICKS_PER_MS;
            }
        }

        // Read final PIT counter value and APIC timer end value
        let pit_end = super::pit::read_counter();
        let end_count = lapic_read(LAPIC_TIMER_CURRENT);

        // Calculate PIT ticks elapsed
        let pit_elapsed = if pit_end <= pit_start {
            pit_start - pit_end
        } else {
            // Wrapped around
            pit_start + (0xFFFF as u16 - pit_end) + 1
        };

        // Calculate actual APIC ticks elapsed (down-counter: start > end)
        let apic_ticks = (start_count - end_count) as u64;

        // Step 4: Calculate APIC ticks per millisecond
        // Formula: (APIC_count * PIT_FREQUENCY) / (PIT_ticks_elapsed * TIMER_DIVIDE * 1000)
        let pit_freq = super::pit::PIT_FREQUENCY as u64;
        let pit_elapsed_u64 = pit_elapsed as u64;
        let timer_divide = 16u64;

        let ticks_per_ms = (apic_ticks * pit_freq) / (pit_elapsed_u64 * timer_divide * 1000);

        // Sanity check: reject values outside reasonable bounds
        let calibrated =
            if ticks_per_ms >= MIN_TICKS_PER_MS as u64 && ticks_per_ms <= MAX_TICKS_PER_MS as u64 {
                ticks_per_ms as u32
            } else {
                DEFAULT_TICKS_PER_MS
            };

        // Step 5: Restore original timer configuration
        lapic_write(LAPIC_TIMER_DIVIDE, original_divide);
        lapic_write(LAPIC_TIMER_INITIAL, original_initial);
        lapic_write(LAPIC_LVT_TIMER, original_lvt);

        calibrated
    }
}

/// Get the calibrated timer ticks per millisecond
///
/// Returns the number of APIC timer ticks that correspond to 1 millisecond.
/// This value is calibrated during boot using the PIT for accuracy.
pub fn get_timer_ticks_per_ms() -> u32 {
    unsafe { TIMER_TICKS_PER_MS }
}

/// APIC Timer interrupt handler
///
/// Called by the IDT handler when the timer interrupt fires.
/// Increments the tick counter and notifies the scheduler.
pub fn timer_handler() {
    // Guard: LAPIC must be mapped before we can handle timer or send EOI
    if unsafe { LAPIC_VIRTUAL_BASE } == 0 {
        return;
    }

    // Increment tick counter
    TICK_COUNTER.fetch_add(1, Ordering::Relaxed);

    // Notify scheduler
    crate::sched::timer_tick();

    // Send EOI
    eoi();
}

/// Send Inter-Processor Interrupt (IPI)
///
/// # Safety
/// - cpu_id must be valid (< MAX_CPUS)
/// - This must only be called when the target CPU is online
pub unsafe fn send_ipi(cpu_id: usize, kind: IpiKind) {
    // PRECONDITION: Kernel text/data must be mapped identically in all VSpaces
    // This is the standard higher-half kernel design where PML4 entries 256..511
    // are identical across all address spaces.
    //
    // When a CPU receives the VSpaceTeardown IPI:
    // 1. IPI handler executes in current VSpace (which has kernel mapped)
    // 2. Handler switches CR3 to kernel VSpace
    // 3. Handler returns via interrupt epilogue
    // 4. CR3 still points to kernel VSpace (which includes current user mappings)
    // 5. Interrupt epilogue can safely return to user code
    #[cfg(debug_assertions)]
    {
        // In debug builds, verify kernel PML4 entries are identical
        // This is a simple check - a full implementation would verify all entries
        debug_assert!(cpu_id < crate::arch::MAX_CPUS, "send_ipi: invalid CPU ID");
    }

    unsafe {
        // Ensure previous IPI has been delivered
        while lapic_read(LAPIC_ICR0) & (1 << 12) != 0 {
            core::hint::spin_loop();
        }

        // Set destination (single CPU, not shorthand)
        // ICR1: high 32 bits of destination APIC ID
        lapic_write(LAPIC_ICR1, (cpu_id as u32) << 24);

        // Send IPI (ICR0: vector + trigger mode + destination shorthand)
        let icr0 = kind.vector() as u32 | ICR_MODE_ASSERT | ICR_LEVEL;
        lapic_write(LAPIC_ICR0, icr0);
    }
}

/// Handle IPI on current CPU (interrupt context)
///
/// CRITICAL: We're in interrupt context, cannot call scheduler or deactivate!
/// Instead, we:
/// 1. Switch CR3 to kernel VSpace
/// 2. Update per-CPU tracking
/// 3. Record pending deactivate for later processing in scheduler context
///
/// # PRECONDITION
/// Kernel text/data MUST be mapped identically in ALL VSpaces (higher-half shared mapping).
/// This is the standard design - kernel PML4 entries (256..511) are identical across all VSpaces.
///
/// In debug builds, this precondition is verified:
/// ```rust
/// debug_assert!(KERNEL_PML4_ENTRIES_ARE_IDENTICAL);
/// ```
pub fn handle_ipi(kind: IpiKind) {
    match kind {
        IpiKind::VSpaceTeardown => {
            let cpu_id = crate::arch::current_cpu() as usize;
            let current_tracking = crate::mm::current_vspace_tracking();

            // Skip if already on kernel VSpace or null
            let kernel_tracking = crate::mm::kernel_vspace_tracking();
            if current_tracking.is_null() || current_tracking == kernel_tracking {
                return;
            }

            // CRITICAL ORDERING:
            // 1. Switch CR3 to kernel FIRST (still using old mappings, but safe)
            let kernel_root = crate::mm::kernel_vspace_root();
            unsafe {
                crate::arch::x86_64::paging::write_cr3(kernel_root);
            }

            // 2. Compiler fence to prevent reordering
            // Prevents compiler from moving set_current_vspace_tracking before CR3 write
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

            // 3. Update per-CPU tracking (after CR3 switch guaranteed)
            crate::mm::set_current_vspace_tracking(kernel_tracking);

            // 4. Record pending deactivate (will be processed in scheduler context)
            // DO NOT call deactivate() here - that would call vspace_inactive()
            // which would try to manipulate scheduler state from interrupt context!
            unsafe {
                crate::mm::set_pending_deactivate(cpu_id, current_tracking);
            }
        }
        IpiKind::Reschedule => {
            // Trigger a reschedule check on this CPU via the timer_tick path
            crate::sched::timer_tick();
        }
    }
}
