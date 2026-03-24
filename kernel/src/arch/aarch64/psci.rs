//! Power State Coordination Interface (PSCI) for SMP and power management
//!
//! Implements PSCI calls via HVC (for QEMU virt platform). The conduit
//! can be changed to SMC for bare-metal platforms via ACPI FADT in the future.
//!
//! SPDX-License-Identifier: GPL-2.0-only

/// PSCI function IDs (SMC32 convention for 32-bit functions)
pub const PSCI_VERSION: u32 = 0x8400_0000;
pub const PSCI_CPU_OFF: u32 = 0x8400_0002;
pub const PSCI_SYSTEM_OFF: u32 = 0x8400_0008;
pub const PSCI_SYSTEM_RESET: u32 = 0x8400_0009;

/// PSCI function IDs (SMC64 convention for 64-bit functions)
pub const PSCI_CPU_ON_64: u64 = 0xC400_0003;

/// PSCI return values
pub const PSCI_SUCCESS: i64 = 0;
pub const PSCI_NOT_SUPPORTED: i64 = -1;
pub const PSCI_INVALID_PARAMETERS: i64 = -2;
pub const PSCI_DENIED: i64 = -3;
pub const PSCI_ALREADY_ON: i64 = -4;
pub const PSCI_ON_PENDING: i64 = -5;
pub const PSCI_INTERNAL_FAILURE: i64 = -6;

/// Query PSCI version.
///
/// Returns the version as a 32-bit value (major in bits 31:16, minor in 15:0),
/// or a negative error code.
pub fn version() -> i64 {
    let result: i64;
    // SAFETY: HVC with PSCI_VERSION is a read-only query with no side effects.
    unsafe {
        core::arch::asm!(
            "hvc #0",
            inlateout("x0") PSCI_VERSION as u64 => result,
            options(nomem, nostack),
        );
    }
    result
}

/// Start an application processor via PSCI CPU_ON (SMC64).
///
/// `target_cpu` is the MPIDR affinity value of the target core.
/// `entry_point` is the physical address where the core begins execution.
/// `context_id` is passed to the target core in x0 on entry.
///
/// Returns `PSCI_SUCCESS` (0) on success, or a negative error code.
pub fn cpu_on(target_cpu: u64, entry_point: u64, context_id: u64) -> i64 {
    let result: i64;
    // SAFETY: PSCI CPU_ON is the standard mechanism for bringing up
    // secondary cores. The entry_point must be a valid physical address
    // with executable code. The caller is responsible for ensuring this.
    unsafe {
        core::arch::asm!(
            "hvc #0",
            inlateout("x0") PSCI_CPU_ON_64 as u64 => result,
            in("x1") target_cpu,
            in("x2") entry_point,
            in("x3") context_id,
            options(nomem, nostack),
        );
    }
    result
}

/// Turn off the calling CPU. Does not return on success.
///
/// Returns a negative error code only on failure.
pub fn cpu_off() -> i64 {
    let result: i64;
    // SAFETY: PSCI CPU_OFF powers down the calling core. On success it
    // never returns. On failure, the return value indicates the error.
    unsafe {
        core::arch::asm!(
            "hvc #0",
            inlateout("x0") PSCI_CPU_OFF as u64 => result,
            options(nomem, nostack),
        );
    }
    result
}

/// Shut down the entire system. Does not return.
pub fn system_off() -> ! {
    // SAFETY: PSCI SYSTEM_OFF powers down the entire system and never returns.
    unsafe {
        core::arch::asm!(
            "hvc #0",
            in("x0") PSCI_SYSTEM_OFF as u64,
            options(noreturn, nomem, nostack),
        );
    }
}

/// Reset the entire system. Does not return.
pub fn system_reset() -> ! {
    // SAFETY: PSCI SYSTEM_RESET resets the system and never returns.
    unsafe {
        core::arch::asm!(
            "hvc #0",
            in("x0") PSCI_SYSTEM_RESET as u64,
            options(noreturn, nomem, nostack),
        );
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
