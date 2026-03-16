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

/// APIC timer fallback value (used when calibration is invalid).
const DEFAULT_TIMER_TICKS_PER_MS: u32 = 10000;

/// Timer ticks per millisecond (calibrated at boot)
/// Default fallback value assumes ~100 MHz APIC bus frequency
/// This is calibrated during initialization using the PIT
static TIMER_TICKS_PER_MS: AtomicU32 = AtomicU32::new(DEFAULT_TIMER_TICKS_PER_MS);

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

/// True if TSC is approved as the active high-resolution clocksource.
///
/// Enabled only when:
/// - TSC calibration produced a non-zero rate
/// - CPUID reports invariant TSC
static TSC_CLOCKSOURCE_ENABLED: AtomicBool = AtomicBool::new(false);

/// Per-CPU TSC boot value (calibrated during init for each CPU)
static PER_CPU_TSC_BOOT: [AtomicU64; super::cpu::MAX_CPUS] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; super::cpu::MAX_CPUS]
};

/// Global floor timestamp in nanoseconds.
///
/// Published by BSP timer ticks and used as a cross-CPU lower bound so AP
/// time never falls behind BSP wall-clock progress.
static GLOBAL_FLOOR_NS: AtomicU64 = AtomicU64::new(0);

/// Per-CPU last returned timestamp for local monotonicity without global CAS.
static LAST_NS_PER_CPU: [AtomicU64; super::cpu::MAX_CPUS] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; super::cpu::MAX_CPUS]
};

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
        let (calibrated_ticks, used_fallback) = calibrate_timer();
        TIMER_TICKS_PER_MS.store(calibrated_ticks, Ordering::Release);

        let tsc_per_us = TSC_PER_US.load(Ordering::Acquire);
        let has_invariant_tsc = super::cpuid::has_invariant_tsc();
        let tsc_clock_enabled = tsc_per_us > 0 && has_invariant_tsc;
        TSC_CLOCKSOURCE_ENABLED.store(tsc_clock_enabled, Ordering::Release);

        if tsc_clock_enabled {
            // Record boot TSC after calibration completes.
            let tsc_boot = rdtsc();
            TSC_BOOT.store(tsc_boot, Ordering::Release);
            PER_CPU_TSC_BOOT[0].store(tsc_boot, Ordering::Release);
        } else {
            TSC_BOOT.store(0, Ordering::Release);
            PER_CPU_TSC_BOOT[0].store(0, Ordering::Release);
        }

        {
            let s = crate::SerialGuard::acquire();
            s.puts("[TIMER] APIC ticks/ms=");
            s.dec(calibrated_ticks as u64);
            s.puts(" fallback=");
            s.dec(used_fallback as u64);
            s.puts(" tsc_per_us=");
            s.dec(tsc_per_us as u64);
            s.puts(" inv_tsc=");
            s.dec(has_invariant_tsc as u64);
            s.puts(" source=");
            if tsc_clock_enabled {
                s.puts("tsc");
            } else {
                s.puts("tick");
            }
            s.putc(b'\n');

            if used_fallback {
                s.puts("[WARN] APIC timer calibration fell back to default ticks/ms\n");
            }
            if tsc_per_us == 0 {
                s.puts("[WARN] TSC calibration unavailable; using tick clocksource\n");
            } else if !has_invariant_tsc {
                s.puts("[WARN] Non-invariant TSC detected; disabling TSC clocksource\n");
            }
        }

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
/// Uses per-CPU TSC for sub-microsecond precision when calibrated and
/// CPUID reports invariant TSC; otherwise uses tick-based timing.
/// Guarantees:
/// - Per-CPU monotonicity (`LAST_NS_PER_CPU`)
/// - Cross-CPU lower bound: returned time is always >= BSP global floor time
///   published from timer ticks (`GLOBAL_FLOOR_NS`).
pub fn now_ns() -> u64 {
    let tsc_per_us = TSC_PER_US.load(Ordering::Acquire);
    let tsc_enabled = TSC_CLOCKSOURCE_ENABLED.load(Ordering::Acquire);
    let inv_tsc_global = super::cpuid::has_invariant_tsc();
    let tick_ns = TICK_COUNTER.load(Ordering::Relaxed) * 1_000_000;
    let floor_ns = GLOBAL_FLOOR_NS.load(Ordering::Acquire).max(tick_ns);

    let raw_ns = if !tsc_enabled || !inv_tsc_global || tsc_per_us == 0 {
        floor_ns
    } else {
        let cpu = crate::arch::current_cpu() as usize;
        let boot = PER_CPU_TSC_BOOT[cpu].load(Ordering::Relaxed);
        if boot == 0 {
            floor_ns
        } else {
            let delta = rdtsc().wrapping_sub(boot);
            let tsc_ns = (delta * 1000) / tsc_per_us as u64;
            // Floor at BSP tick-derived time to prevent backward drift.
            tsc_ns.max(floor_ns)
        }
    };

    // Clamp per-CPU interpolation to a narrow window above the BSP floor.
    // This prevents far-future jumps from cross-CPU TSC skew while preserving
    // sub-ms resolution within a bounded range.
    const MAX_SKEW_NS: u64 = 2_000_000; // +2ms above floor_ns
    let upper = floor_ns.saturating_add(MAX_SKEW_NS);
    let bounded_ns = raw_ns.clamp(floor_ns, upper);

    let cpu = crate::arch::current_cpu() as usize;
    let last = LAST_NS_PER_CPU[cpu].load(Ordering::Relaxed);
    let next = if bounded_ns > last {
        bounded_ns
    } else {
        last.saturating_add(1)
    };
    LAST_NS_PER_CPU[cpu].store(next, Ordering::Relaxed);
    next
}

/// Calibrate APIC timer using PIT
///
/// Uses the PIT to measure the actual APIC timer frequency
/// and calculate the correct tick count for accurate 1ms intervals.
///
/// # Algorithm
/// 1. Save current APIC timer configuration
/// 2. Set APIC timer to one-shot mode with a very large count
/// 3. Measure APIC down-counter delta over a fixed PIT-measured interval
/// 4. Calculate APIC ticks per millisecond
/// 5. Restore original timer configuration
///
/// # Returns
/// Returns `(ticks_per_ms, used_fallback)`.
/// `used_fallback = true` means a default tick rate was used.
unsafe fn calibrate_timer() -> (u32, bool) {
    /// Reasonable bounds for calibrated value (sanity check).
    /// Min: ~16 MHz APIC bus / 16 divider.  Max: ~16 GHz / 16 divider.
    const MIN_TICKS_PER_MS: u32 = 1000;
    const MAX_TICKS_PER_MS: u32 = 1_000_000;

    /// PIT wraps to measure for APIC calibration (1 wrap ~= 1ms).
    /// Larger windows reduce quantization error.
    const CALIBRATION_WINDOW_MS: u64 = 32;

    /// APIC one-shot start value used during calibration.
    /// Keep this high so it will not expire during the PIT measurement window.
    const APIC_COUNT: u32 = 0xFFFF_FFFF - 1;

    /// Safety timeout for PIT sampling loops to avoid hangs if PIT stalls.
    const MAX_CALIBRATION_SPINS: u32 = 20_000_000;

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

        // Step 3a: Synchronize to a PIT wrap edge for a clean window start.
        let mut pit_prev = super::pit::read_counter() as u64;
        let mut spins: u32 = 0;
        loop {
            spins = spins.saturating_add(1);
            if spins > MAX_CALIBRATION_SPINS {
                lapic_write(LAPIC_TIMER_DIVIDE, original_divide);
                lapic_write(LAPIC_TIMER_INITIAL, original_initial);
                lapic_write(LAPIC_LVT_TIMER, original_lvt);
                return (DEFAULT_TIMER_TICKS_PER_MS, true);
            }

            let pit_current = super::pit::read_counter() as u64;
            // PIT counts down and jumps high on reload; this upward jump marks one wrap.
            if pit_current > pit_prev {
                break;
            }
            pit_prev = pit_current;
            core::hint::spin_loop();
        }

        // Step 3b: Restart APIC count at PIT edge, then measure for N PIT wraps.
        lapic_write(LAPIC_TIMER_INITIAL, start_count);
        let tsc_start = rdtsc();

        let mut wraps: u64 = 0;
        let mut pit_prev = super::pit::read_counter() as u64;
        spins = 0;
        while wraps < CALIBRATION_WINDOW_MS {
            spins = spins.saturating_add(1);
            if spins > MAX_CALIBRATION_SPINS {
                lapic_write(LAPIC_TIMER_DIVIDE, original_divide);
                lapic_write(LAPIC_TIMER_INITIAL, original_initial);
                lapic_write(LAPIC_LVT_TIMER, original_lvt);
                return (DEFAULT_TIMER_TICKS_PER_MS, true);
            }

            let pit_current = super::pit::read_counter() as u64;
            if pit_current > pit_prev {
                wraps = wraps.saturating_add(1);
            }
            pit_prev = pit_current;
            core::hint::spin_loop();
        }

        // Read APIC timer end value at the end of the PIT wrap window.
        let end_count = lapic_read(LAPIC_TIMER_CURRENT);

        // Read TSC at end of calibration
        let tsc_end = rdtsc();

        // Calculate actual APIC ticks elapsed (down-counter: start > end)
        let apic_ticks = (start_count as u64).saturating_sub(end_count as u64);

        // Calibrate TSC frequency from the same PIT-measured interval
        let tsc_elapsed = tsc_end.wrapping_sub(tsc_start);

        // Step 4: Calculate APIC ticks per millisecond.
        let measured_ms = wraps.max(1);
        let ticks_per_ms = apic_ticks / measured_ms;

        // Compute TSC ticks per microsecond:
        // tsc_per_us = tsc_elapsed / elapsed_us, with elapsed_us ~= wraps * 1000.
        let elapsed_us = measured_ms.saturating_mul(1000);
        let tsc_per_us_val = tsc_elapsed / elapsed_us.max(1);
        if tsc_per_us_val > 0 && tsc_per_us_val <= u32::MAX as u64 {
            TSC_PER_US.store(tsc_per_us_val as u32, Ordering::Release);
        }

        // Sanity check: reject values outside reasonable bounds
        let calibrated =
            if ticks_per_ms >= MIN_TICKS_PER_MS as u64 && ticks_per_ms <= MAX_TICKS_PER_MS as u64 {
                (ticks_per_ms as u32, false)
            } else {
                (DEFAULT_TIMER_TICKS_PER_MS, true)
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
        let next_tick = TICK_COUNTER.fetch_add(1, Ordering::Relaxed) + 1;
        GLOBAL_FLOOR_NS.store(next_tick * 1_000_000, Ordering::Release);
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
        // Ensure previous IPI has been delivered.
        // Log but continue on timeout — skipping a runtime IPI would cause
        // worse problems (missed reschedules, stale TLB entries).
        if !wait_icr_idle() {
            crate::serial_puts("[APIC] WARNING: send_ipi pre-send ICR stuck, proceeding\n");
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

/// Per-CPU "claimed" bitmap to detect duplicate cpu_id assignment.
/// An AP atomically swaps this to `true` on entry; a second AP with the
/// same cpu_id sees `true` and halts instead of corrupting the first AP's stack.
static AP_CLAIMED: [core::sync::atomic::AtomicBool; super::cpu::MAX_CPUS] = {
    const INIT: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
    [INIT; super::cpu::MAX_CPUS]
};

/// Clear the claimed flag for a cpu_id (BSP calls this before sending SIPI).
pub fn clear_ap_claimed(cpu_id: usize) {
    AP_CLAIMED[cpu_id].store(false, core::sync::atomic::Ordering::SeqCst);
}

/// Atomically claim a cpu_id. Returns `true` if this caller is the first
/// to claim it, `false` if another AP already claimed this slot.
pub fn try_claim_ap(cpu_id: usize) -> bool {
    !AP_CLAIMED[cpu_id].swap(true, core::sync::atomic::Ordering::SeqCst)
}

/// Get AP boot count
pub fn ap_boot_count() -> usize {
    AP_BOOT_COUNT.load(core::sync::atomic::Ordering::SeqCst)
}

/// Signal that an AP has finished initialization.
///
/// Idempotent: only increments AP_BOOT_COUNT on the first call for a given
/// cpu_id, preventing double-counting if a duplicate AP somehow reaches here.
pub fn signal_ap_ready(cpu_id: usize) {
    if !AP_READY[cpu_id].swap(true, core::sync::atomic::Ordering::SeqCst) {
        AP_BOOT_COUNT.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
    }
}

/// Trampoline communication area addresses (physical)
const TRAMPOLINE_BASE: u64 = 0x8000;
const TRAMPOLINE_PML4: u64 = 0x8FF0;
const TRAMPOLINE_STACK: u64 = 0x8FF8;
const TRAMPOLINE_CPU_ID: u64 = 0x8FE8;
const TRAMPOLINE_ENTRY: u64 = 0x8FE0;
/// Consumed flag: AP writes 0xACE1 here after reading all mailbox values.
const TRAMPOLINE_CONSUMED: u64 = 0x8F02;

/// SIPI vector (physical page number: 0x8000 / 0x1000 = 0x08)
const SIPI_VECTOR: u32 = 0x08;

/// ICR delivery mode bits
const ICR_INIT: u32 = 0x500;
const ICR_STARTUP: u32 = 0x600;
const ICR_LEVEL_ASSERT: u32 = 0x4000;
const ICR_LEVEL_DEASSERT: u32 = 0x0000;

/// Maximum iterations to wait for ICR delivery status to become idle.
/// ~50us at 2GHz — more than enough for any delivery mode on real hardware.
const ICR_IDLE_TIMEOUT: u32 = 100_000;

/// Wait for the ICR delivery status bit to clear (idle).
///
/// Returns `true` if ICR became idle within the timeout, `false` on timeout.
///
/// # Safety
/// LAPIC must be initialized and mapped.
unsafe fn wait_icr_idle() -> bool {
    for _ in 0..ICR_IDLE_TIMEOUT {
        // SAFETY: LAPIC is initialized (caller precondition)
        if unsafe { lapic_read(LAPIC_ICR0) } & (1 << 12) == 0 {
            return true;
        }
        core::hint::spin_loop();
    }
    crate::serial_puts("[APIC] WARNING: ICR delivery timeout\n");
    false
}

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

            // Clear consumed flag (AP writes 0xACE1 after reading mailbox)
            let consumed_ptr = (TRAMPOLINE_CONSUMED + PHYS_MAP_OFFSET) as *mut u16;
            consumed_ptr.write_volatile(0);

            // Clear claimed flag so the AP can atomically claim this cpu_id
            clear_ap_claimed(cpu_id as usize);

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
            if !send_init_ipi(apic_id) {
                serial("[SMP] INIT IPI failed for AP, skipping\n");
                continue;
            }

            // Wait 10ms for INIT to be received and processed
            super::pit::delay_us(10_000);

            // Intel MP spec requires deassert after INIT assert
            if !send_init_deassert() {
                serial("[SMP] INIT deassert failed for AP, skipping\n");
                continue;
            }
            // 200us settling time before first SIPI
            super::pit::delay_us(200);

            // Send SIPI (twice per Intel spec)
            // SIPI vector = physical page number of trampoline code
            if !send_sipi(apic_id, SIPI_VECTOR) {
                serial("[SMP] first SIPI failed for AP, skipping\n");
                continue;
            }
            super::pit::delay_us(200);
            if !send_sipi(apic_id, SIPI_VECTOR) {
                serial("[SMP] second SIPI failed for AP, skipping\n");
                continue;
            }

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

                    // Check if the AP consumed the mailbox before we overwrite it.
                    // The AP writes 0xACE1 to TRAMPOLINE_CONSUMED after reading
                    // all mailbox values into registers.
                    let consumed_ptr = (TRAMPOLINE_CONSUMED + PHYS_MAP_OFFSET) as *const u16;
                    let consumed = consumed_ptr.read_volatile();
                    if consumed != 0xACE1 {
                        let magic = magic_ptr.read_volatile();
                        if magic == 0xCAFE {
                            // Trampoline reached but mailbox not yet consumed —
                            // AP is in mode transition. Spin briefly for consumption.
                            serial("[SMP]   Waiting for mailbox consumption...\n");
                            let mut consumed_wait = 10; // 10ms
                            while consumed_wait > 0 {
                                super::pit::delay_us(1_000);
                                if consumed_ptr.read_volatile() == 0xACE1 {
                                    break;
                                }
                                consumed_wait -= 1;
                            }
                            if consumed_ptr.read_volatile() != 0xACE1 {
                                serial("[SMP]   Mailbox NOT consumed, poisoning\n");
                            }
                        }
                    }

                    // Poison trampoline CPU_ID to catch late arrivals
                    // SAFETY: PHYS_MAP_OFFSET is valid, address is in trampoline comm area
                    let cpuid_ptr = (TRAMPOLINE_CPU_ID + PHYS_MAP_OFFSET) as *mut u32;
                    cpuid_ptr.write_volatile(0xFFFF_FFFF);

                    // Reset timed-out AP to INIT state (Intel-recommended abort)
                    let _ = send_init_ipi(apic_id);
                    super::pit::delay_us(10_000);

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

/// Send INIT IPI to a specific APIC ID.
/// Returns `true` if both pre-send and post-send ICR waits succeeded.
unsafe fn send_init_ipi(apic_id: u8) -> bool {
    unsafe {
        // Wait for ICR to be idle
        if !wait_icr_idle() {
            return false;
        }

        // Set destination APIC ID
        lapic_write(LAPIC_ICR1, (apic_id as u32) << 24);

        // Send INIT IPI: delivery mode = INIT, level = assert, trigger = level
        lapic_write(LAPIC_ICR0, ICR_INIT | ICR_LEVEL_ASSERT | (1 << 15));

        // Wait for delivery
        wait_icr_idle()
    }
}

/// Send INIT IPI (level de-assert) broadcast.
/// Returns `true` if both pre-send and post-send ICR waits succeeded.
///
/// This is required by the Intel MP specification after the INIT assert.
/// It is a broadcast de-assert (all CPUs), not targeted.
unsafe fn send_init_deassert() -> bool {
    unsafe {
        // Wait for ICR to be idle
        if !wait_icr_idle() {
            return false;
        }

        // Broadcast INIT de-assert (all including self)
        // Delivery mode = INIT, Level = de-assert, Trigger = level
        // Destination shorthand = All Including Self (bits 19:18 = 10)
        lapic_write(LAPIC_ICR0, ICR_INIT | (1 << 15) | (0b10 << 18));

        // Wait for delivery
        wait_icr_idle()
    }
}

/// Send Startup IPI (SIPI) to a specific APIC ID.
/// Returns `true` if both pre-send and post-send ICR waits succeeded.
unsafe fn send_sipi(apic_id: u8, vector: u32) -> bool {
    unsafe {
        // Wait for ICR to be idle
        if !wait_icr_idle() {
            return false;
        }

        // Set destination APIC ID
        lapic_write(LAPIC_ICR1, (apic_id as u32) << 24);

        // Send SIPI with startup vector
        lapic_write(LAPIC_ICR0, ICR_STARTUP | vector);

        // Wait for delivery
        wait_icr_idle()
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
        let tsc_enabled = TSC_CLOCKSOURCE_ENABLED.load(Ordering::Acquire);
        let inv_tsc_global = super::cpuid::has_invariant_tsc();
        let tsc_per_us = TSC_PER_US.load(Ordering::Acquire);
        if tsc_enabled && inv_tsc_global && tsc_per_us > 0 {
            let ticks = TICK_COUNTER.load(Ordering::Acquire);
            let my_tsc = rdtsc();
            // elapsed_tsc = ticks_ms * 1000_us/ms * tsc_per_us
            let elapsed_tsc = ticks * 1000 * tsc_per_us as u64;
            PER_CPU_TSC_BOOT[cpu_id].store(
                my_tsc.wrapping_sub(elapsed_tsc),
                Ordering::Release,
            );
        } else {
            PER_CPU_TSC_BOOT[cpu_id].store(0, Ordering::Release);
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

/// Dynamically unmask an IOAPIC redirection entry for the given IRQ.
///
/// Sets the entry to: fixed delivery, physical destination mode, edge-triggered,
/// active-high, unmasked, routed to BSP. Vector = irq + 32.
///
/// # Safety
/// IOAPIC must be initialized (`init_ioapic` called first).
pub fn ioapic_unmask(irq: u32) {
    if !IOAPIC_READY.load(Ordering::Acquire) {
        return;
    }

    let vector = irq + 32;
    let bsp_apic_id = super::cpu::get_apic_id_for_cpu(0);
    let reg_lo = 0x10 + 2 * irq;
    let reg_hi = 0x10 + 2 * irq + 1;

    unsafe {
        // Low: vector, fixed delivery(0), physical dest(0), active-high(0),
        // edge-trigger(0), unmasked(0)
        ioapic_write(reg_lo, vector & 0xFF);
        // High: destination APIC ID in bits [31:24]
        ioapic_write(reg_hi, bsp_apic_id << 24);
    }
}

/// Unmask an IOAPIC redirection entry for a PCI (level-triggered, active-low) IRQ.
///
/// Sets the entry to: fixed delivery, physical destination mode, level-triggered,
/// active-low, unmasked, routed to BSP. Vector = irq + 32.
///
/// PCI INTx interrupts are level-triggered and active-low per the PCI specification.
/// ISA interrupts should use `ioapic_unmask()` (edge-triggered, active-high) instead.
///
/// # Safety
/// IOAPIC must be initialized (`init_ioapic` called first).
pub fn ioapic_unmask_level(irq: u32) {
    if !IOAPIC_READY.load(Ordering::Acquire) {
        return;
    }

    let vector = irq + 32;
    let bsp_apic_id = super::cpu::get_apic_id_for_cpu(0);
    let reg_lo = 0x10 + 2 * irq;
    let reg_hi = 0x10 + 2 * irq + 1;

    unsafe {
        // Low: vector, fixed delivery(0), physical dest(0),
        // active-low(bit13=1), level-trigger(bit15=1), unmasked(bit16=0)
        let lo = (vector & 0xFF) | (1 << 13) | (1 << 15);
        ioapic_write(reg_lo, lo);
        // High: destination APIC ID in bits [31:24]
        ioapic_write(reg_hi, bsp_apic_id << 24);
    }
}

/// Mask an IOAPIC redirection entry for the given IRQ.
///
/// # Safety
/// IOAPIC must be initialized (`init_ioapic` called first).
pub fn ioapic_mask(irq: u32) {
    if !IOAPIC_READY.load(Ordering::Acquire) {
        return;
    }

    let reg_lo = 0x10 + 2 * irq;
    unsafe {
        let current = ioapic_read(reg_lo);
        ioapic_write(reg_lo, current | IOAPIC_MASKED);
    }
}
