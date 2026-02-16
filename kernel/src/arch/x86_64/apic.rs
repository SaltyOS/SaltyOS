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
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicBool, Ordering};

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
static TIMER_TICKS_PER_MS: AtomicU32 = AtomicU32::new(10000);

/// ICR (Interrupt Command Register) bits
const ICR_DS: u32 = 1 << 12; // Destination shorthand
const ICR_LEVEL: u32 = 1 << 14; // Level trigger
const ICR_MODE_ASSERT: u32 = 1 << 15; // Assert interrupt

/// Tick counter for timekeeping (incremented by BSP only)
static TICK_COUNTER: AtomicU64 = AtomicU64::new(0);

/// TSC value at boot (set after calibration)
static TSC_BOOT: AtomicU64 = AtomicU64::new(0);

/// TSC ticks per microsecond (calibrated via PIT)
static TSC_PER_US: AtomicU32 = AtomicU32::new(0);

/// Per-CPU TSC boot value (calibrated during init for each CPU)
static PER_CPU_TSC_BOOT: [AtomicU64; super::cpu::MAX_CPUS] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; super::cpu::MAX_CPUS]
};

/// Last returned timestamp for global monotonicity (all CPUs)
static LAST_NS: AtomicU64 = AtomicU64::new(0);

/// Read the x86 Time Stamp Counter
#[inline]
fn rdtsc() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack));
    }
    (hi as u64) << 32 | lo as u64
}

/// Local APIC base address (virtual)
static LAPIC_VIRTUAL_BASE: AtomicU64 = AtomicU64::new(0);

/// Per-CPU TLB shootdown target address
///
/// When a VSpace modifies a page table entry, it stores the target virtual address
/// here and sends a TlbShootdown IPI. The handler reads the address and does `invlpg`.
static TLB_SHOOTDOWN_ADDR: [AtomicU64; super::cpu::MAX_CPUS] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; super::cpu::MAX_CPUS]
};

/// Set TLB shootdown target address for a CPU (called by sender before IPI)
pub fn set_tlb_shootdown_addr(cpu_id: usize, addr: u64) {
    TLB_SHOOTDOWN_ADDR[cpu_id].store(addr, Ordering::Release);
}

/// Read TLB shootdown target address for a CPU (called by handler on target)
pub fn tlb_shootdown_addr(cpu_id: usize) -> u64 {
    TLB_SHOOTDOWN_ADDR[cpu_id].load(Ordering::Acquire)
}

/// IPI kinds
#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum IpiKind {
    VSpaceTeardown = 0,
    Reschedule = 1,
    TlbShootdown = 8,     // vector 48 (single-page inval)
    TlbShootdownAll = 9,  // vector 49 (full TLB flush)
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
    LAPIC_VIRTUAL_BASE.store(LAPIC_BASE + PHYS_MAP_OFFSET, Ordering::Release);
}

/// Read from LAPIC register
///
/// # Safety
/// The LAPIC must be initialized and mapped before calling this.
#[inline(always)]
unsafe fn lapic_read(offset: u32) -> u32 {
    unsafe {
        let addr = LAPIC_VIRTUAL_BASE.load(Ordering::Acquire) + offset as u64;
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
        let addr = LAPIC_VIRTUAL_BASE.load(Ordering::Acquire) + offset as u64;
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
        panic!("apic::init() called but APIC not available");
    }

    unsafe {
        // Enable APIC in MSR
        enable_apic();

        // Map LAPIC MMIO region
        map_lapic();

        // Read APIC ID to verify it's working and store BSP mapping
        let apic_id = lapic_read(LAPIC_ID) >> 24;
        super::cpu::set_cpu_apic_id(0, apic_id);

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
        // Calibrate timer using PIT (also calibrates TSC_PER_US)
        let calibrated_ticks = calibrate_timer();
        TIMER_TICKS_PER_MS.store(calibrated_ticks, Ordering::Release);

        // Record boot TSC after calibration completes
        TSC_BOOT.store(rdtsc(), Ordering::Release);

        // Also set BSP's per-CPU TSC boot value
        PER_CPU_TSC_BOOT[0].store(TSC_BOOT.load(Ordering::Relaxed), Ordering::Release);

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
        lapic_write(LAPIC_TIMER_INITIAL, TIMER_TICKS_PER_MS.load(Ordering::Acquire));

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
    if LAPIC_VIRTUAL_BASE.load(Ordering::Relaxed) == 0 {
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
pub fn get_ticks() -> u64 {
    TICK_COUNTER.load(Ordering::Relaxed)
}

/// Get elapsed time in microseconds
///
/// Returns the number of microseconds since boot.
/// Uses TSC for nanosecond precision when calibrated.
pub fn now_us() -> u64 {
    now_ns() / 1000
}

/// Get elapsed time in nanoseconds
///
/// Uses per-CPU TSC for sub-microsecond precision when calibrated.
/// Falls back to tick-based timing before calibration completes.
/// A global monotonicity guard ensures time never goes backwards,
/// even when threads migrate between CPUs with different TSC origins.
pub fn now_ns() -> u64 {
    let tsc_per_us = TSC_PER_US.load(Ordering::Acquire);
    let tick_ns = TICK_COUNTER.load(Ordering::Relaxed) * 1_000_000;

    let raw_ns = if tsc_per_us == 0 {
        tick_ns
    } else {
        let cpu = crate::arch::current_cpu() as usize;
        let boot = PER_CPU_TSC_BOOT[cpu].load(Ordering::Relaxed);
        if boot == 0 {
            tick_ns
        } else {
            let delta = rdtsc().wrapping_sub(boot);
            let tsc_ns = (delta * 1000) / tsc_per_us as u64;
            // Floor at TICK_COUNTER time to prevent large drift
            tsc_ns.max(tick_ns)
        }
    };

    // Global monotonicity guard: never return less than previous value
    loop {
        let last = LAST_NS.load(Ordering::Acquire);
        if raw_ns > last {
            match LAST_NS.compare_exchange_weak(
                last,
                raw_ns,
                Ordering::Release,
                Ordering::Acquire,
            ) {
                Ok(_) => return raw_ns,
                Err(_) => continue,
            }
        } else {
            // Time would go backwards — return last seen value + 1ns
            // to maintain strict monotonicity
            let bumped = last + 1;
            match LAST_NS.compare_exchange_weak(
                last,
                bumped,
                Ordering::Release,
                Ordering::Acquire,
            ) {
                Ok(_) => return bumped,
                Err(_) => continue,
            }
        }
    }
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

        // Step 3: Wait for APIC timer to expire, measuring with PIT and TSC
        let tsc_start = rdtsc();
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

        // Read TSC at end of calibration
        let tsc_end = rdtsc();

        // Calculate actual APIC ticks elapsed (down-counter: start > end)
        let apic_ticks = (start_count - end_count) as u64;

        // Calibrate TSC frequency from the same PIT-measured interval
        let tsc_elapsed = tsc_end.wrapping_sub(tsc_start);

        // Step 4: Calculate APIC ticks per millisecond
        // Formula: (APIC_count * PIT_FREQUENCY) / (PIT_ticks_elapsed * TIMER_DIVIDE * 1000)
        let pit_freq = super::pit::PIT_FREQUENCY as u64;
        let pit_elapsed_u64 = pit_elapsed as u64;
        let timer_divide = 16u64;

        let ticks_per_ms = (apic_ticks * pit_freq) / (pit_elapsed_u64 * timer_divide * 1000);

        // Compute TSC ticks per microsecond:
        // time_us = (pit_elapsed * 1_000_000) / pit_freq
        // tsc_per_us = tsc_elapsed / time_us
        //            = (tsc_elapsed * pit_freq) / (pit_elapsed * 1_000_000)
        let tsc_per_us_val = (tsc_elapsed * pit_freq) / (pit_elapsed_u64 * 1_000_000);
        if tsc_per_us_val > 0 && tsc_per_us_val <= u32::MAX as u64 {
            TSC_PER_US.store(tsc_per_us_val as u32, Ordering::Release);
        }

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
    TIMER_TICKS_PER_MS.load(Ordering::Relaxed)
}

/// APIC Timer interrupt handler
///
/// Called by the IDT handler when the timer interrupt fires.
/// Increments the tick counter and notifies the scheduler.
pub fn timer_handler() {
    // Guard: LAPIC must be mapped before we can handle timer or send EOI
    if LAPIC_VIRTUAL_BASE.load(Ordering::Relaxed) == 0 {
        return;
    }

    // Only BSP increments tick counter so ticks represent wall-clock time
    if crate::arch::current_cpu() == 0 {
        TICK_COUNTER.fetch_add(1, Ordering::Relaxed);
    }

    // Send EOI BEFORE timer_tick: if budget exhaustion triggers a context switch,
    // timer_tick() never returns (context_switch jumps to another thread).
    // Without early EOI, the APIC blocks all further timer interrupts.
    eoi();

    // Notify scheduler (may context-switch and never return)
    crate::sched::timer_tick();
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

        // Look up the real hardware APIC ID for this logical CPU index.
        // On hardware where APIC IDs differ from sequential indices
        // (multi-socket, non-sequential), using cpu_id directly would
        // send the IPI to the wrong processor.
        let apic_id = super::cpu::get_apic_id_for_cpu(cpu_id);

        // Set destination (single CPU, not shorthand)
        // ICR1: high 32 bits of destination APIC ID
        lapic_write(LAPIC_ICR1, apic_id << 24);

        // Send IPI (ICR0: vector + trigger mode + destination shorthand)
        let icr0 = kind.vector() as u32 | ICR_MODE_ASSERT | ICR_LEVEL;
        lapic_write(LAPIC_ICR0, icr0);
    }
}

/// Number of APs that have successfully booted
static AP_BOOT_COUNT: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Flag set by each AP when it finishes initialization
static AP_READY: [core::sync::atomic::AtomicBool; super::cpu::MAX_CPUS] = {
    const INIT: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
    [INIT; super::cpu::MAX_CPUS]
};

/// Get AP boot count
pub fn ap_boot_count() -> usize {
    AP_BOOT_COUNT.load(core::sync::atomic::Ordering::SeqCst)
}

/// Signal that an AP has finished initialization
pub fn signal_ap_ready(cpu_id: usize) {
    AP_READY[cpu_id].store(true, core::sync::atomic::Ordering::SeqCst);
    AP_BOOT_COUNT.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
}

/// Trampoline communication area addresses (physical)
const TRAMPOLINE_BASE: u64 = 0x8000;
const TRAMPOLINE_PML4: u64 = 0x8FF0;
const TRAMPOLINE_STACK: u64 = 0x8FF8;
const TRAMPOLINE_CPU_ID: u64 = 0x8FE8;
const TRAMPOLINE_ENTRY: u64 = 0x8FE0;

/// SIPI vector (physical page number: 0x8000 / 0x1000 = 0x08)
const SIPI_VECTOR: u32 = 0x08;

/// ICR delivery mode bits
const ICR_INIT: u32 = 0x500;
const ICR_STARTUP: u32 = 0x600;
const ICR_LEVEL_ASSERT: u32 = 0x4000;
const ICR_LEVEL_DEASSERT: u32 = 0x0000;

// Assembly symbols for trampoline code bounds
unsafe extern "C" {
    static ap_trampoline_start: u8;
    static ap_trampoline_end: u8;
}

/// Start Application Processors
///
/// Copies the AP trampoline to physical 0x8000, then sends INIT+SIPI
/// to each non-BSP CPU discovered by the ACPI parser.
///
/// # Safety
/// Must be called from the BSP after ACPI parsing and memory init.
pub unsafe fn start_aps(cpu_descriptors: &[super::acpi::CpuDescriptor], cpu_count: usize) {
    use crate::mm::PHYS_MAP_OFFSET;

    unsafe {
        // Serial debug
        let serial = |s: &str| {
            for byte in s.bytes() {
                while (super::inb(0x3F8 + 5) & 0x20) == 0 {}
                super::outb(0x3F8, byte);
            }
        };

        serial("\n[SMP] Starting Application Processors\n");

        // Copy trampoline code to physical 0x8000
        let tramp_src = &raw const ap_trampoline_start as *const u8;
        let tramp_end = &raw const ap_trampoline_end as *const u8;
        let tramp_size = tramp_end as usize - tramp_src as usize;
        let tramp_dst = (TRAMPOLINE_BASE + PHYS_MAP_OFFSET) as *mut u8;

        core::ptr::copy_nonoverlapping(tramp_src, tramp_dst, tramp_size);

        serial("[SMP] Trampoline copied to 0x8000 (");
        // Print size
        let mut buf = [0u8; 8];
        let mut n = tramp_size;
        let mut pos = 7;
        if n == 0 {
            buf[pos] = b'0';
        } else {
            while n > 0 {
                buf[pos] = b'0' + (n % 10) as u8;
                n /= 10;
                if pos == 0 { break; }
                pos -= 1;
            }
        }
        for &c in &buf[(pos)..] {
            if c != 0 {
                while (super::inb(0x3F8 + 5) & 0x20) == 0 {}
                super::outb(0x3F8, c);
            }
        }
        serial(" bytes)\n");

        // Store PML4 physical address (current CR3)
        let pml4_phys = super::paging::read_cr3();
        let pml4_ptr = (TRAMPOLINE_PML4 + PHYS_MAP_OFFSET) as *mut u64;
        pml4_ptr.write_volatile(pml4_phys);

        // Store ap_entry function pointer
        let entry_fn = super::ap_boot::ap_entry as *const () as u64;
        let entry_ptr = (TRAMPOLINE_ENTRY + PHYS_MAP_OFFSET) as *mut u64;
        entry_ptr.write_volatile(entry_fn);

        // Send INIT+SIPI to each AP
        for i in 0..cpu_count {
            let desc = &cpu_descriptors[i];
            if desc.is_bsp || !desc.enabled {
                continue;
            }

            let apic_id = desc.apic_id;

            serial("[SMP] Starting AP APIC_ID=");
            let digit = b'0' + apic_id;
            while (super::inb(0x3F8 + 5) & 0x20) == 0 {}
            super::outb(0x3F8, digit);
            serial("\n");

            // Allocate per-CPU kernel stack (16KB = 4 pages)
            const STACK_PAGES: usize = 4;
            const STACK_SIZE: u64 = STACK_PAGES as u64 * 4096;

            let stack_phys = crate::mm::alloc_contiguous_frames(STACK_PAGES)
                .expect("[SMP] Failed to allocate AP kernel stack");
            let stack_top = crate::mm::phys_to_virt(stack_phys) + STACK_SIZE;

            // Write per-CPU communication data
            let stack_ptr = (TRAMPOLINE_STACK + PHYS_MAP_OFFSET) as *mut u64;
            stack_ptr.write_volatile(stack_top);

            // CPU ID = array index (we need a logical cpu_id, not APIC ID)
            let cpu_id = i as u32;
            let cpuid_ptr = (TRAMPOLINE_CPU_ID + PHYS_MAP_OFFSET) as *mut u32;
            cpuid_ptr.write_volatile(cpu_id);

            // Store the mapping from logical CPU ID to hardware APIC ID
            super::cpu::set_cpu_apic_id(cpu_id as usize, apic_id as u32);

            // Set up per-CPU GS data before the AP boots
            let per_cpu = super::cpu::per_cpu_mut(cpu_id);
            per_cpu.cpu_id = cpu_id;
            per_cpu.kernel_stack = stack_top;

            // Clear magic check area (trampoline writes 0xCAFE here)
            let magic_ptr = (0x8F00u64 + PHYS_MAP_OFFSET) as *mut u16;
            magic_ptr.write_volatile(0);

            // Verify trampoline code was copied by reading first bytes
            let verify_ptr = (TRAMPOLINE_BASE + PHYS_MAP_OFFSET) as *const u8;
            let byte0 = verify_ptr.read_volatile();
            let byte1 = verify_ptr.add(1).read_volatile();
            serial("[SMP]   Trampoline verify: first bytes = ");
            let hex = b"0123456789abcdef";
            while (super::inb(0x3F8 + 5) & 0x20) == 0 {}
            super::outb(0x3F8, hex[((byte0 >> 4) & 0xF) as usize]);
            while (super::inb(0x3F8 + 5) & 0x20) == 0 {}
            super::outb(0x3F8, hex[(byte0 & 0xF) as usize]);
            while (super::inb(0x3F8 + 5) & 0x20) == 0 {}
            super::outb(0x3F8, b' ');
            while (super::inb(0x3F8 + 5) & 0x20) == 0 {}
            super::outb(0x3F8, hex[((byte1 >> 4) & 0xF) as usize]);
            while (super::inb(0x3F8 + 5) & 0x20) == 0 {}
            super::outb(0x3F8, hex[(byte1 & 0xF) as usize]);
            serial(" (expect: fa fc)\n");

            // Verify PML4 was stored
            let pml4_verify = (TRAMPOLINE_PML4 + PHYS_MAP_OFFSET) as *const u64;
            serial("[SMP]   PML4 at 0x8FF0 = ");
            crate::serial_hex_raw(pml4_verify.read_volatile());
            serial("\n");

            // Set warm-reset vector (BIOS data area at 0x467)
            // This tells the BIOS where to jump after INIT reset.
            // Write the trampoline address as segment:offset (real mode far pointer).
            let warm_reset_ptr = (0x467u64 + PHYS_MAP_OFFSET) as *mut u32;
            warm_reset_ptr.write_volatile(0x0800_0000); // segment 0x0800, offset 0x0000

            // Set CMOS shutdown status to 0x0A (jump via warm-reset vector)
            super::outb(0x70, 0x0F); // select CMOS register 0x0F
            super::outb(0x71, 0x0A); // shutdown status = warm reset

            // Memory fence to ensure all writes are ordered
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

            // Send INIT IPI (level assert)
            send_init_ipi(apic_id);

            // Wait 10ms for INIT to be received and processed
            super::pit::delay_us(10_000);

            // Send SIPI (twice per Intel spec)
            // SIPI vector = physical page number of trampoline code
            send_sipi(apic_id, SIPI_VECTOR);
            super::pit::delay_us(200);
            send_sipi(apic_id, SIPI_VECTOR);

            // Wait for AP to signal ready (timeout after 500ms)
            let mut timeout = 500;
            while !AP_READY[cpu_id as usize].load(core::sync::atomic::Ordering::SeqCst) {
                super::pit::delay_us(1_000);
                timeout -= 1;
                if timeout == 0 {
                    serial("[SMP] WARNING: AP did not respond\n");
                    // Check if trampoline was even reached
                    let magic = magic_ptr.read_volatile();
                    if magic == 0xCAFE {
                        serial("[SMP]   Trampoline WAS reached (magic=0xCAFE)\n");
                    } else {
                        serial("[SMP]   Trampoline NOT reached (magic=0x");
                        let digits = [
                            b"0123456789abcdef"[((magic >> 12) & 0xF) as usize],
                            b"0123456789abcdef"[((magic >> 8) & 0xF) as usize],
                            b"0123456789abcdef"[((magic >> 4) & 0xF) as usize],
                            b"0123456789abcdef"[(magic & 0xF) as usize],
                        ];
                        for &d in &digits {
                            while (super::inb(0x3F8 + 5) & 0x20) == 0 {}
                            super::outb(0x3F8, d);
                        }
                        serial(")\n");
                    }
                    break;
                }
            }

            if AP_READY[cpu_id as usize].load(core::sync::atomic::Ordering::SeqCst) {
                serial("[SMP] AP is online\n");
            }
        }

        serial("[SMP] AP startup complete. Online CPUs: ");
        let total = ap_boot_count() + 1; // +1 for BSP
        let digit = b'0' + (total as u8);
        while (super::inb(0x3F8 + 5) & 0x20) == 0 {}
        super::outb(0x3F8, digit);
        serial("\n");
    }
}

/// Send INIT IPI to a specific APIC ID
unsafe fn send_init_ipi(apic_id: u8) {
    unsafe {
        // Wait for ICR to be idle
        while lapic_read(LAPIC_ICR0) & (1 << 12) != 0 {
            core::hint::spin_loop();
        }

        // Set destination APIC ID
        lapic_write(LAPIC_ICR1, (apic_id as u32) << 24);

        // Send INIT IPI: delivery mode = INIT, level = assert, trigger = level
        lapic_write(LAPIC_ICR0, ICR_INIT | ICR_LEVEL_ASSERT | (1 << 15));

        // Wait for delivery
        while lapic_read(LAPIC_ICR0) & (1 << 12) != 0 {
            core::hint::spin_loop();
        }
    }
}

/// Send INIT IPI (level de-assert) broadcast
///
/// This is required by the Intel MP specification after the INIT assert.
/// It is a broadcast de-assert (all CPUs), not targeted.
unsafe fn send_init_deassert() {
    unsafe {
        // Wait for ICR to be idle
        while lapic_read(LAPIC_ICR0) & (1 << 12) != 0 {
            core::hint::spin_loop();
        }

        // Broadcast INIT de-assert (all including self)
        // Delivery mode = INIT, Level = de-assert, Trigger = level
        // Destination shorthand = All Including Self (bits 19:18 = 10)
        lapic_write(LAPIC_ICR0, ICR_INIT | (1 << 15) | (0b10 << 18));

        // Wait for delivery
        while lapic_read(LAPIC_ICR0) & (1 << 12) != 0 {
            core::hint::spin_loop();
        }
    }
}

/// Send Startup IPI (SIPI) to a specific APIC ID
unsafe fn send_sipi(apic_id: u8, vector: u32) {
    unsafe {
        // Wait for ICR to be idle
        while lapic_read(LAPIC_ICR0) & (1 << 12) != 0 {
            core::hint::spin_loop();
        }

        // Set destination APIC ID
        lapic_write(LAPIC_ICR1, (apic_id as u32) << 24);

        // Send SIPI with startup vector
        lapic_write(LAPIC_ICR0, ICR_STARTUP | vector);

        // Wait for delivery
        while lapic_read(LAPIC_ICR0) & (1 << 12) != 0 {
            core::hint::spin_loop();
        }
    }
}

/// Initialize Local APIC for an Application Processor
///
/// This is a minimal APIC init for APs - the APIC is already enabled
/// in hardware, we just need to configure the SVR and timer.
pub fn init_ap() {
    unsafe {
        // Map LAPIC (reuse same virtual base as BSP)
        map_lapic();

        // Set Spurious Interrupt Vector register (enable APIC)
        lapic_write(LAPIC_SVR, SVR_ENABLE | SVR_VECTOR);

        // Configure timer for this AP (same settings as BSP)
        lapic_write(LAPIC_TIMER_DIVIDE, TIMER_DIVIDE_16);

        // Set initial count for 1ms ticks
        lapic_write(LAPIC_TIMER_INITIAL, TIMER_TICKS_PER_MS.load(Ordering::Acquire));

        // Unmask timer - periodic mode
        let timer_config = (LAPIC_TIMER_VECTOR as u32) | TIMER_MODE_PERIODIC;
        lapic_write(LAPIC_LVT_TIMER, timer_config);

        // Mask other LVT entries
        lapic_write(LAPIC_LVT_THERMAL, TIMER_MASK);
        lapic_write(LAPIC_LVT_PERF, TIMER_MASK);
        lapic_write(LAPIC_LVT_LINT0, TIMER_MASK);
        lapic_write(LAPIC_LVT_LINT1, TIMER_MASK);
        lapic_write(LAPIC_LVT_ERROR, TIMER_MASK);

        // Calibrate per-CPU TSC boot value using TICK_COUNTER as reference.
        // TICK_COUNTER (BSP-only, 1ms resolution) gives approximate elapsed time.
        // We compute what this CPU's rdtsc() "would have been" at time=0.
        let cpu_id = crate::arch::current_cpu() as usize;
        let tsc_per_us = TSC_PER_US.load(Ordering::Acquire);
        if tsc_per_us > 0 {
            let ticks = TICK_COUNTER.load(Ordering::Acquire);
            let my_tsc = rdtsc();
            // elapsed_tsc = ticks_ms * 1000_us/ms * tsc_per_us
            let elapsed_tsc = ticks * 1000 * tsc_per_us as u64;
            PER_CPU_TSC_BOOT[cpu_id].store(
                my_tsc.wrapping_sub(elapsed_tsc),
                Ordering::Release,
            );
        }
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

            // Only switch CR3 if our current VSpace is actually dying.
            // switch_to() activates the new VSpace before deactivating the old one,
            // so an IPI for the OLD VSpace can arrive while this CPU already runs
            // a different (Active) VSpace. Switching CR3 in that case would corrupt
            // the active thread's address space.
            unsafe {
                if (*current_tracking).state() == crate::mm::vspace::VSpaceState::Active {
                    return;
                }
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
            crate::sched::handle_reschedule_ipi();
        }
        IpiKind::TlbShootdown => {
            // Handled by irq_handler_ipi_tlb_shootdown (own assembly stub),
            // not through handle_ipi. This arm should never be reached.
        }
        IpiKind::TlbShootdownAll => {
            // Handled by irq_handler_ipi_tlb_shootdown_all (own assembly stub),
            // not through handle_ipi. This arm should never be reached.
        }
    }
}

// ======================================================================
// I/O APIC support
// ======================================================================

/// IOAPIC virtual base address (set during init_ioapic)
static IOAPIC_BASE: AtomicU64 = AtomicU64::new(0);

/// Whether IOAPIC has been initialized
static IOAPIC_READY: AtomicBool = AtomicBool::new(false);

/// IOAPIC MMIO register offsets
const IOREGSEL: u64 = 0x00;
const IOWIN: u64 = 0x10;

/// IOAPIC registers
const IOAPIC_REG_ID: u32 = 0x00;
const IOAPIC_REG_VER: u32 = 0x01;

/// Redirection entry flags
const IOAPIC_MASKED: u32 = 1 << 16;

/// Read an IOAPIC register via indirect MMIO access.
///
/// # Safety
/// IOAPIC must be mapped and `IOAPIC_BASE` must be valid.
unsafe fn ioapic_read(reg: u32) -> u32 {
    unsafe {
        let base = IOAPIC_BASE.load(Ordering::Acquire);
        let sel = base as *mut u32;
        let win = (base + IOWIN) as *const u32;
        sel.write_volatile(reg);
        win.read_volatile()
    }
}

/// Write an IOAPIC register via indirect MMIO access.
///
/// # Safety
/// IOAPIC must be mapped and `IOAPIC_BASE` must be valid.
unsafe fn ioapic_write(reg: u32, val: u32) {
    unsafe {
        let base = IOAPIC_BASE.load(Ordering::Acquire);
        let sel = base as *mut u32;
        let win = (base + IOWIN) as *mut u32;
        sel.write_volatile(reg);
        win.write_volatile(val);
    }
}

/// Initialize the I/O APIC and configure redirection entries for
/// ISA IRQs that the kernel needs (IRQ1 = keyboard, IRQ4 = COM1).
///
/// Maps the IOAPIC MMIO region using the direct physical mapping,
/// masks all redirection entries, then unmasks IRQ1 and IRQ4 routed
/// to the BSP's Local APIC.
///
/// # Arguments
/// * `ioapic_phys` - Physical address of the IOAPIC (from MADT)
/// * `bsp_apic_id` - APIC ID of the BSP (destination for routed IRQs)
pub fn init_ioapic(ioapic_phys: u32, bsp_apic_id: u8) {
    // Map IOAPIC MMIO via the direct physical mapping (same approach as LAPIC)
    let virt = ioapic_phys as u64 + PHYS_MAP_OFFSET;
    IOAPIC_BASE.store(virt, Ordering::Release);

    {
        let s = crate::SerialGuard::acquire();
        s.puts("[IOAPIC] phys=");
        s.hex(ioapic_phys as u64);
        s.puts(" virt=");
        s.hex(virt);
        s.putc(b'\n');
    }

    unsafe {
        // Read version register to get max redirection entries
        let ver = ioapic_read(IOAPIC_REG_VER);
        let max_entry = ((ver >> 16) & 0xFF) as u32;

        {
            let s = crate::SerialGuard::acquire();
            s.puts("[IOAPIC] version=");
            s.hex(ver as u64);
            s.puts(" max_entry=");
            s.dec(max_entry as u64);
            s.putc(b'\n');
        }

        // Mask all redirection entries first
        for i in 0..=max_entry {
            let reg_lo = 0x10 + 2 * i;
            let reg_hi = 0x10 + 2 * i + 1;
            // Low 32 bits: masked, vector = i+32
            ioapic_write(reg_lo, IOAPIC_MASKED | ((i + 32) & 0xFF));
            // High 32 bits: destination = 0 (doesn't matter, entry is masked)
            ioapic_write(reg_hi, 0);
        }

        // Enable IRQ1 (keyboard) → vector 33, routed to BSP
        // Low: vector=33, delivery=Fixed(0), destmode=Physical(0),
        //      polarity=ActiveHigh(0), trigger=Edge(0), mask=0
        let irq1_lo: u32 = 33; // vector 33, all other bits 0 = fixed, physical, active-high, edge, unmasked
        let irq1_hi: u32 = (bsp_apic_id as u32) << 24;
        ioapic_write(0x10 + 2 * 1, irq1_lo);
        ioapic_write(0x10 + 2 * 1 + 1, irq1_hi);

        // Enable IRQ4 (COM1) → vector 36, routed to BSP
        let irq4_lo: u32 = 36; // vector 36
        let irq4_hi: u32 = (bsp_apic_id as u32) << 24;
        ioapic_write(0x10 + 2 * 4, irq4_lo);
        ioapic_write(0x10 + 2 * 4 + 1, irq4_hi);
    }

    IOAPIC_READY.store(true, Ordering::Release);

    {
        let s = crate::SerialGuard::acquire();
        s.puts("[IOAPIC] IRQ1 (keyboard) → vec 33, IRQ4 (COM1) → vec 36, dest APIC ");
        s.dec(bsp_apic_id as u64);
        s.putc(b'\n');
    }
}
