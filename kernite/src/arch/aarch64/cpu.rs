//! AArch64 per-CPU data management
//!
//! Uses TPIDR_EL1 to store a pointer to the current CPU's `PerCpuData`
//! entry in a static array. The register is inaccessible from EL0, so
//! userspace cannot tamper with it.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use core::sync::atomic::{AtomicBool, Ordering};

unsafe extern "C" {
    fn aarch64_cpu_write_tpidr_el1(value: u64);
    fn aarch64_cpu_read_tpidr_el1() -> u64;
}

/// Per-CPU data structure.
///
/// Accessed via the active host TPIDR register → pointer → field offset.
/// Layout must be `#[repr(C)]` for stable offsets used by explicit assembly.
#[repr(C)]
pub struct PerCpuData {
    /// Logical CPU index (0 = BSP).
    pub cpu_id: u32,
    _pad0: u32,
    /// Top of kernel stack for this CPU (used by exception entry).
    pub kernel_stack_top: u64,
    /// Stack canary value for overflow detection.
    pub canary: u64,
    /// Monotonically increasing invocation sequence number.
    pub invoke_seq: u64,
    /// Reserved for future per-CPU state.
    _reserved: [u64; 12],
}

impl PerCpuData {
    const fn zeroed() -> Self {
        Self {
            cpu_id: 0,
            _pad0: 0,
            kernel_stack_top: 0,
            canary: 0,
            invoke_seq: 0,
            _reserved: [0; 12],
        }
    }
}

/// Static per-CPU data array (one entry per logical CPU).
static mut PER_CPU_DATA: [PerCpuData; super::MAX_CPUS] =
    [const { PerCpuData::zeroed() }; super::MAX_CPUS];

/// Atomic claim flags to detect duplicate AP arrival.
static AP_CLAIMED: [AtomicBool; super::MAX_CPUS] =
    [const { AtomicBool::new(false) }; super::MAX_CPUS];

// ---------------------------------------------------------------------------
// Host TPIDR helpers
// ---------------------------------------------------------------------------

/// Write a pointer to TPIDR_EL1 (per-CPU data base).
#[inline(always)]
fn write_host_tpidr(val: u64) {
    // SAFETY: Writing TPIDR_EL1 is safe from EL1 kernel context.
    unsafe {
        aarch64_cpu_write_tpidr_el1(val);
    }
}

/// Read TPIDR_EL1 (per-CPU data base pointer).
#[inline(always)]
fn read_host_tpidr() -> u64 {
    // SAFETY: Reading TPIDR_EL1 is always safe from EL1 kernel context.
    unsafe { aarch64_cpu_read_tpidr_el1() }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Initialize per-CPU data for the boot CPU (CPU 0).
///
/// Sets `PER_CPU_DATA[0].cpu_id = 0` and writes the active host TPIDR to point at it.
/// Must be called early during BSP init before any per-CPU field access.
pub fn init_bsp() {
    // SAFETY: Single-threaded boot context; no other CPU is running.
    unsafe {
        let per_cpu = &raw mut PER_CPU_DATA[0];
        (*per_cpu).cpu_id = 0;
        write_host_tpidr(per_cpu as u64);
    }
    AP_CLAIMED[0].store(true, Ordering::Release);
}

/// Initialize per-CPU data for an application processor.
///
/// Sets `PER_CPU_DATA[cpu_id]` fields and writes the active host TPIDR.
/// Called from `ap_entry()` during AP startup.
pub fn init_ap(cpu_id: u32) {
    let idx = cpu_id as usize;
    if idx >= super::MAX_CPUS {
        return;
    }
    // SAFETY: Each AP writes only its own PER_CPU_DATA slot. No other CPU
    // accesses PER_CPU_DATA[cpu_id] until the AP signals ready.
    unsafe {
        let per_cpu = &raw mut PER_CPU_DATA[idx];
        (*per_cpu).cpu_id = cpu_id;
        write_host_tpidr(per_cpu as u64);
    }
}

/// Generate and store a stack canary for an AP.
pub fn init_ap_canary(cpu_id: usize) {
    if cpu_id >= super::MAX_CPUS {
        return;
    }
    let canary = super::generate_stack_canary();
    // SAFETY: Only the owning AP writes its own slot during init.
    unsafe {
        (*(&raw mut PER_CPU_DATA[cpu_id])).canary = canary;
    }
}

/// Atomically claim an AP slot.  Returns `true` if this CPU successfully
/// claimed the slot, `false` if another AP already claimed it.
pub fn try_claim_ap(cpu_id: usize) -> bool {
    if cpu_id >= super::MAX_CPUS {
        return false;
    }
    !AP_CLAIMED[cpu_id].swap(true, Ordering::AcqRel)
}

/// Clear the AP claim flag (called by BSP before starting an AP).
pub fn clear_ap_claimed(cpu_id: usize) {
    if cpu_id < super::MAX_CPUS {
        AP_CLAIMED[cpu_id].store(false, Ordering::Release);
    }
}

/// Return a mutable reference to a CPU's `PerCpuData`.
///
/// # Safety
/// The caller must ensure exclusive access to the target CPU's data
/// (either single-threaded boot context or called from the owning CPU).
pub unsafe fn per_cpu_mut(cpu_id: u32) -> &'static mut PerCpuData {
    // SAFETY: Caller guarantees exclusive access.
    unsafe { &mut *(&raw mut PER_CPU_DATA[cpu_id as usize]) }
}

// ---------------------------------------------------------------------------
// Field accessors (used by mod.rs wrappers)
// ---------------------------------------------------------------------------

/// Set the kernel stack top for the current CPU.
pub fn set_kernel_stack(stack_top: u64) {
    let base = read_host_tpidr();
    if base == 0 {
        return;
    }
    // SAFETY: The active host TPIDR points to a valid PerCpuData; kernel_stack_top is
    // at offset 8 (after cpu_id u32 + _pad0 u32).
    unsafe {
        let ptr = (base + 8) as *mut u64;
        core::ptr::write_volatile(ptr, stack_top);
    }
}

/// Return the kernel stack top for the current CPU.
pub fn get_kernel_stack() -> u64 {
    let base = read_host_tpidr();
    if base == 0 {
        return 0;
    }
    // SAFETY: The active host TPIDR points to a valid PerCpuData;
    // kernel_stack_top is at offset 8.
    unsafe {
        let ptr = (base + 8) as *const u64;
        core::ptr::read_volatile(ptr)
    }
}

/// Set the stack canary for the current CPU.
pub fn set_per_cpu_canary(canary: u64) {
    let base = read_host_tpidr();
    if base == 0 {
        return;
    }
    // SAFETY: The active host TPIDR points to a valid PerCpuData; canary is at offset 16.
    unsafe {
        let ptr = (base + 16) as *mut u64;
        core::ptr::write_volatile(ptr, canary);
    }
}

/// Increment and return the invocation sequence number for the current CPU.
pub fn next_invoke_seq() -> u64 {
    let base = read_host_tpidr();
    if base == 0 {
        return 0;
    }
    // SAFETY: The active host TPIDR points to a valid PerCpuData; invoke_seq is at offset 24.
    // Only the current CPU accesses its own invoke_seq, so no races.
    unsafe {
        let ptr = (base + 24) as *mut u64;
        let val = core::ptr::read_volatile(ptr);
        let next = val.wrapping_add(1);
        core::ptr::write_volatile(ptr, next);
        next
    }
}

/// Return the current invocation sequence number for the current CPU.
pub fn current_invoke_seq() -> u64 {
    let base = read_host_tpidr();
    if base == 0 {
        return 0;
    }
    // SAFETY: The active host TPIDR points to a valid PerCpuData; invoke_seq at offset 24.
    unsafe {
        let ptr = (base + 24) as *const u64;
        core::ptr::read_volatile(ptr)
    }
}
