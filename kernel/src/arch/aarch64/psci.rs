//! Power State Coordination Interface (PSCI) for SMP and power management
//!
//! Uses SMC for PSCI calls.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use core::sync::atomic::{AtomicU8, Ordering};

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

const PSCI_CONDUIT_UNKNOWN: u8 = 0;
const PSCI_CONDUIT_SMC: u8 = 1;

static PSCI_CONDUIT: AtomicU8 = AtomicU8::new(PSCI_CONDUIT_UNKNOWN);

/// Initialize PSCI conduit selection from boot handoff and ACPI FADT.
pub fn init_from_firmware(rsdp_phys: u64, boot_flags: u32) {
    let _ = boot_flags;

    if rsdp_phys == 0 {
        PSCI_CONDUIT.store(PSCI_CONDUIT_SMC, Ordering::Relaxed);
        return;
    }

    let conduit = unsafe { crate::acpi::parse_psci_conduit(rsdp_phys) };
    let conduit = match conduit {
        Some(crate::acpi::PsciConduit::Smc) => PSCI_CONDUIT_SMC,
        Some(crate::acpi::PsciConduit::Hvc) => PSCI_CONDUIT_SMC,
        None => PSCI_CONDUIT_SMC,
    };

    PSCI_CONDUIT.store(conduit, Ordering::Relaxed);
}

/// Issue a PSCI call with 0 extra arguments (x0 = function ID).
macro_rules! psci_call0 {
    ($fn_id:expr) => {{
        let result: i64;
        // SAFETY: PSCI calls are the standard firmware interface for power
        // management. The host kernel always uses the SMC conduit here.
        unsafe {
            core::arch::asm!(
                ".inst 0xD4000003", // smc #0
                inlateout("x0") $fn_id as u64 => result,
                options(nomem, nostack),
            );
        }
        result
    }};
}

/// Issue a PSCI call with 3 extra arguments (x0-x3).
macro_rules! psci_call3 {
    ($fn_id:expr, $x1:expr, $x2:expr, $x3:expr) => {{
        let result: i64;
        // SAFETY: PSCI calls are the standard firmware interface. Arguments
        // in x0-x3 follow the SMC calling convention.
        unsafe {
            core::arch::asm!(
                ".inst 0xD4000003", // smc #0
                inlateout("x0") $fn_id as u64 => result,
                in("x1") $x1, in("x2") $x2, in("x3") $x3,
                options(nomem, nostack),
            );
        }
        result
    }};
}

/// Query PSCI version.
///
/// Returns the version as a 32-bit value (major in bits 31:16, minor in 15:0),
/// or a negative error code.
pub fn version() -> i64 {
    psci_call0!(PSCI_VERSION)
}

/// Start an application processor via PSCI CPU_ON (SMC64).
///
/// `target_cpu` is the MPIDR affinity value of the target core.
/// `entry_point` is the physical address where the core begins execution.
/// `context_id` is passed to the target core in x0 on entry.
///
/// Returns `PSCI_SUCCESS` (0) on success, or a negative error code.
pub fn cpu_on(target_cpu: u64, entry_point: u64, context_id: u64) -> i64 {
    psci_call3!(PSCI_CPU_ON_64, target_cpu, entry_point, context_id)
}

/// Turn off the calling CPU. Does not return on success.
///
/// Returns a negative error code only on failure.
pub fn cpu_off() -> i64 {
    psci_call0!(PSCI_CPU_OFF)
}

/// Shut down the entire system. Does not return.
pub fn system_off() -> ! {
    // SAFETY: PSCI SYSTEM_OFF powers down the entire system and never returns.
    unsafe {
        core::arch::asm!(
            ".inst 0xD4000003", // smc #0
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
            ".inst 0xD4000003", // smc #0
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
