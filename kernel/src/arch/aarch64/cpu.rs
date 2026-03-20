//! AArch64 per-CPU data management
//!
//! Uses TPIDR_EL1 to store per-CPU data pointer.
//!
//! SPDX-License-Identifier: GPL-2.0-only

/// Per-CPU data structure
#[repr(C)]
pub struct PerCpuData {
    pub cpu_id: u32,
    pub kernel_stack_top: u64,
    pub canary: u64,
}

/// Initialize per-CPU data for the boot CPU
pub fn init_bsp() {
    // TODO: Phase 3 — allocate PerCpuData, store in TPIDR_EL1
}

/// Initialize per-CPU data for an application processor
pub fn init_ap(_cpu_id: u32) {
    // TODO: Phase 4 — SMP per-CPU init
}
