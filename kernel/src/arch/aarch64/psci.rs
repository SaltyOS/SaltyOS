//! Power State Coordination Interface (PSCI) for SMP and power management
//!
//! SPDX-License-Identifier: GPL-2.0-only

/// PSCI function IDs
pub const PSCI_CPU_ON_64: u64 = 0xC400_0003;
pub const PSCI_SYSTEM_OFF: u64 = 0x8400_0008;
pub const PSCI_SYSTEM_RESET: u64 = 0x8400_0009;

/// Start an application processor via PSCI CPU_ON
pub fn cpu_on(_target_cpu: u64, _entry_point: u64, _context_id: u64) -> i64 {
    // TODO: Phase 4 — SMC/HVC call
    -1 // Not implemented
}
