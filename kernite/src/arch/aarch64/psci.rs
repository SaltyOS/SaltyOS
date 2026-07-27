//! Power State Coordination Interface (PSCI) for SMP and power management
//!
//! Uses the HVC conduit for PSCI calls. The host kernel runs at EL1 with no
//! EL3 secure monitor (QEMU `virt` default), so the HVC conduit — serviced by
//! QEMU's emulated EL2 trap — is the correct transport. An SMC from EL1 with
//! no EL3 is UNDEFINED and raises a synchronous exception (EC=0x00).
//!
//! SPDX-License-Identifier: GPL-2.0-only

/// PSCI function IDs (32-bit calling convention).
pub const PSCI_VERSION: u32 = 0x8400_0000;
pub const PSCI_CPU_OFF: u32 = 0x8400_0002;
pub const PSCI_SYSTEM_OFF: u32 = 0x8400_0008;
pub const PSCI_SYSTEM_RESET: u32 = 0x8400_0009;

/// PSCI function IDs (64-bit calling convention).
pub const PSCI_CPU_ON_64: u64 = 0xC400_0003;

/// PSCI return values
pub const PSCI_SUCCESS: i64 = 0;
pub const PSCI_NOT_SUPPORTED: i64 = -1;
pub const PSCI_INVALID_PARAMETERS: i64 = -2;
pub const PSCI_DENIED: i64 = -3;
pub const PSCI_ALREADY_ON: i64 = -4;
pub const PSCI_ON_PENDING: i64 = -5;
pub const PSCI_INTERNAL_FAILURE: i64 = -6;

unsafe extern "C" {
    fn aarch64_psci_call0(fn_id: u64) -> i64;
    fn aarch64_psci_call3(fn_id: u64, x1: u64, x2: u64, x3: u64) -> i64;
    fn aarch64_psci_system_off() -> !;
    fn aarch64_psci_system_reset() -> !;
}

/// Query PSCI version.
///
/// Returns the version as a 32-bit value (major in bits 31:16, minor in 15:0),
/// or a negative error code.
pub fn version() -> i64 {
    unsafe { aarch64_psci_call0(PSCI_VERSION as u64) }
}

/// Start an application processor via PSCI CPU_ON.
///
/// `target_cpu` is the MPIDR affinity value of the target core.
/// `entry_point` is the physical address where the core begins execution.
/// `context_id` is passed to the target core in x0 on entry.
///
/// Returns `PSCI_SUCCESS` (0) on success, or a negative error code.
pub fn cpu_on(target_cpu: u64, entry_point: u64, context_id: u64) -> i64 {
    unsafe { aarch64_psci_call3(PSCI_CPU_ON_64, target_cpu, entry_point, context_id) }
}

/// Turn off the calling CPU. Does not return on success.
///
/// Returns a negative error code only on failure.
pub fn cpu_off() -> i64 {
    unsafe { aarch64_psci_call0(PSCI_CPU_OFF as u64) }
}

/// Shut down the entire system. Does not return.
pub fn system_off() -> ! {
    // SAFETY: PSCI SYSTEM_OFF powers down the entire system and never returns.
    unsafe {
        aarch64_psci_system_off();
    }
}

/// Reset the entire system. Does not return.
pub fn system_reset() -> ! {
    // SAFETY: PSCI SYSTEM_RESET resets the system and never returns.
    unsafe {
        aarch64_psci_system_reset();
    }
}

/// Return a human-readable name for a PSCI error code.
pub fn error_name(code: i64) -> &'static str {
    match code {
        0 => "SUCCESS",
        -1 => "NOT_SUPPORTED",
        -2 => "INVALID_PARAMETERS",
        -3 => "DENIED",
        -4 => "ALREADY_ON",
        -5 => "ON_PENDING",
        -6 => "INTERNAL_FAILURE",
        _ => "UNKNOWN",
    }
}
