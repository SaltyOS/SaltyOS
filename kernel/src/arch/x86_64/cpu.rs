//! x86_64 CPU support
//!
//! SPDX-License-Identifier: GPL-2.0-only

/// IA32_GS_BASE MSR address
const IA32_GS_BASE_MSR: u32 = 0xC000_0101;
/// IA32_KERNEL_GS_BASE MSR address
const IA32_KERNEL_GS_BASE_MSR: u32 = 0xC000_0102;

/// Maximum number of CPUs supported
pub const MAX_CPUS: usize = 16;

/// Per-CPU data structure
///
/// Layout is fixed with #[repr(C)] to ensure assembly compatibility.
/// Offset 0: cpu_id (u32)
/// Offset 4: padding (u32)
/// Offset 8: kernel_stack (u64)
/// Offset 16: saved_rsp (u64)
/// Offset 24: fpu_owner (u64) — pointer to TCB that owns FPU state in hardware
///
/// Assembly accesses GS:0, GS:8, GS:16 only — offset 24+ is safe for Rust.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PerCpuData {
    /// CPU ID (0 for BSP, 1+ for APs)
    pub cpu_id: u32,
    /// Kernel stack pointer for syscall entry
    pub kernel_stack: u64,
    /// Saved user RSP during syscall
    pub saved_rsp: u64,
    /// Pointer to TCB that owns the current FPU/SSE state in hardware registers
    pub fpu_owner: u64,
    /// Reserved for future use
    _reserved: [u64; 12],
}

/// Per-CPU data for each CPU
static mut PER_CPU_DATA: [PerCpuData; MAX_CPUS] = {
    const INIT: PerCpuData = PerCpuData {
        cpu_id: 0,
        kernel_stack: 0,
        saved_rsp: 0,
        fpu_owner: 0,
        _reserved: [0; 12],
    };
    [INIT; MAX_CPUS]
};

/// APIC ID mapping table: logical CPU index → hardware APIC ID
///
/// Separate from PerCpuData to avoid disturbing the assembly-accessed
/// layout (GS:[0], GS:[8], GS:[16]).
static mut CPU_APIC_IDS: [u32; MAX_CPUS] = [0; MAX_CPUS];

/// Initialize per-CPU data for the BSP (Boot Processor)
pub fn init_bsp() {
    unsafe {
        crate::serial_puts("\n[CPU] init_bsp() called\n");

        PER_CPU_DATA[0].cpu_id = 0;

        {
            let s = crate::SerialGuard::acquire();
            s.puts("[CPU] PER_CPU_DATA addr: ");
            s.hex((&raw const PER_CPU_DATA) as u64);
            s.puts("\n[CPU] Setting GS base\n");
        }

        // Keep kernel GS pointing at PerCpuData. User GS starts at 0 and is
        // swapped in/out by swapgs on user<->kernel transitions.
        let per_cpu_base = &PER_CPU_DATA[0] as *const _ as u64;
        write_gs_base_msr(per_cpu_base);
        write_kernel_gs_base_msr(0);

        crate::serial_puts("[CPU] GS base set successfully\n");
    }
}

/// Get the current CPU ID
#[inline(always)]
pub fn current_cpu() -> u32 {
    let cpu_id: u32;
    unsafe {
        // Read value directly from GS:[0], not as a pointer
        core::arch::asm!(
            "mov {0:e}, gs:[0]",
            out(reg) cpu_id,
            options(nostack, pure, readonly)
        );
    }
    cpu_id
}

/// Set GS base for a specific CPU by index
///
/// Used during AP init before GS is functional.
pub fn write_gs_base_for_cpu(cpu_id: usize) {
    let base = unsafe { &PER_CPU_DATA[cpu_id] as *const _ as u64 };
    write_gs_base_msr(base);
    write_kernel_gs_base_msr(0);
}

/// Write to GS base using MSR
fn write_gs_base_msr(base: u64) {
    unsafe {
        let low = base as u32;
        let high = (base >> 32) as u32;

        core::arch::asm!(
            "wrmsr",
            in("ecx") IA32_GS_BASE_MSR,
            in("eax") low,
            in("edx") high,
            options(nostack)
        );
    }
}

/// Write to KERNEL_GS_BASE using MSR
fn write_kernel_gs_base_msr(base: u64) {
    unsafe {
        let low = base as u32;
        let high = (base >> 32) as u32;

        core::arch::asm!(
            "wrmsr",
            in("ecx") IA32_KERNEL_GS_BASE_MSR,
            in("eax") low,
            in("edx") high,
            options(nostack)
        );
    }
}

/// Get per-CPU data pointer for a specific CPU
pub unsafe fn per_cpu_mut(cpu_id: u32) -> &'static mut PerCpuData {
    unsafe { &mut PER_CPU_DATA[cpu_id as usize] }
}

/// Store the hardware APIC ID for a logical CPU index
///
/// # Safety
/// Must be called during boot before IPIs are sent.
pub unsafe fn set_cpu_apic_id(cpu_id: usize, apic_id: u32) {
    unsafe { CPU_APIC_IDS[cpu_id] = apic_id; }
}

/// Get the hardware APIC ID for a logical CPU index
pub fn get_apic_id_for_cpu(cpu_id: usize) -> u32 {
    unsafe { CPU_APIC_IDS[cpu_id] }
}

/// Set kernel stack for the current CPU
///
/// # Safety
/// Must be called with a valid kernel stack pointer.
pub unsafe fn set_kernel_stack(stack_top: u64) {
    // SAFETY: We access GS:[8] which corresponds to `kernel_stack` field.
    // Offset calculation: cpu_id(4) + padding(4) = 8
    unsafe {
        core::arch::asm!(
            "mov gs:[8], {}",
            in(reg) stack_top,
            options(nostack)
        );
    }
}

/// Get kernel stack pointer for the current CPU
pub fn get_kernel_stack() -> u64 {
    let stack_top: u64;
    unsafe {
        // Read value directly from GS:[8]
        core::arch::asm!(
            "mov {}, gs:[8]",
            out(reg) stack_top,
            options(nostack, pure, readonly)
        );
    }
    stack_top
}

/// Get the FPU owner pointer for the current CPU
///
/// Returns the raw TCB pointer (as *mut u8) of the thread whose FPU state
/// is currently in the hardware registers. Null if no thread owns FPU.
#[inline]
pub fn get_fpu_owner() -> *mut u8 {
    let owner: u64;
    unsafe {
        // SAFETY: GS:24 corresponds to fpu_owner field in PerCpuData
        core::arch::asm!(
            "mov {}, gs:[24]",
            out(reg) owner,
            options(nostack, pure, readonly)
        );
    }
    owner as *mut u8
}

/// Set the FPU owner pointer for the current CPU
///
/// # Safety
/// Must be called with interrupts disabled or from interrupt context.
#[inline]
pub unsafe fn set_fpu_owner(ptr: *mut u8) {
    // SAFETY: GS:24 corresponds to fpu_owner field in PerCpuData
    unsafe {
        core::arch::asm!(
            "mov gs:[24], {}",
            in(reg) ptr as u64,
            options(nostack)
        );
    }
}
