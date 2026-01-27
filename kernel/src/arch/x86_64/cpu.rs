//! x86_64 CPU support
//!
//! SPDX-License-Identifier: GPL-2.0-only

/// IA32_GS_BASE MSR address
const IA32_GS_BASE_MSR: u32 = 0xC000_0101;

/// Maximum number of CPUs supported
pub const MAX_CPUS: usize = 16;

/// Per-CPU data structure
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PerCpuData {
    /// CPU ID (0 for BSP, 1+ for APs)
    pub cpu_id: u32,
    /// Reserved for future use
    _reserved: [u64; 15],
}

/// Per-CPU data for each CPU
static mut PER_CPU_DATA: [PerCpuData; MAX_CPUS] = {
    const INIT: PerCpuData = PerCpuData {
        cpu_id: 0,
        _reserved: [0; 15],
    };
    [INIT; MAX_CPUS]
};

/// Initialize per-CPU data for the BSP (Boot Processor)
pub fn init_bsp() {
    unsafe {
        PER_CPU_DATA[0].cpu_id = 0;
        // Set GS base to point to this CPU's data
        write_gs_base_msr(&PER_CPU_DATA[0] as *const _ as u64);
    }
}

/// Get the current CPU ID
///
/// Uses the GS base register to access per-CPU data.
/// The GS base is set by init_bsp() (for BSP) or during AP startup.
#[inline(always)]
pub fn current_cpu() -> u32 {
    unsafe {
        let ptr: *const PerCpuData;
        core::arch::asm!(
            "mov {}, gs:[0]",
            out(reg) ptr,
            options(nostack, pure, readonly)
        );
        (*ptr).cpu_id
    }
}

/// Write to GS base using MSR (more compatible than wrgsbase)
///
/// # Safety
/// The address must be valid.
fn write_gs_base_msr(base: u64) {
    // SAFETY: MSR address is valid, caller ensures base is valid
    unsafe {
        let low = base as u32;
        let high = (base >> 32) as u32;

        core::arch::asm!(
            "wrmsr",
            in("ecx") IA32_GS_BASE_MSR,
            in("eax") low,
            in("edx") high,
            options(nostack, nomem)
        );
    }
}

/// Get per-CPU data pointer for a specific CPU
///
/// # Safety
/// The CPU ID must be valid and less than MAX_CPUS.
pub unsafe fn per_cpu_mut(cpu_id: u32) -> &'static mut PerCpuData {
    // SAFETY: Caller ensures CPU ID is valid
    unsafe {
        &mut PER_CPU_DATA[cpu_id as usize]
    }
}
