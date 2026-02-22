//! x86_64 CPU support
//!
//! SPDX-License-Identifier: GPL-2.0-only

/// IA32_FS_BASE MSR address
const IA32_FS_BASE_MSR: u32 = 0xC000_0100;
/// IA32_GS_BASE MSR address
const IA32_GS_BASE_MSR: u32 = 0xC000_0101;
/// IA32_KERNEL_GS_BASE MSR address
const IA32_KERNEL_GS_BASE_MSR: u32 = 0xC000_0102;

/// Maximum number of CPUs supported
pub const MAX_CPUS: usize = 16;

/// Per-CPU data structure
///
/// Layout is fixed with #[repr(C)] to ensure assembly compatibility.
/// Offset 0:  cpu_id (u32)
/// Offset 4:  padding (u32)  [implicit]
/// Offset 8:  kernel_stack (u64)
/// Offset 16: saved_rsp (u64)
/// Offset 24: fpu_owner (u64) — pointer to TCB that owns FPU state in hardware
/// Offset 32: invoke_seq (u64) — per-CPU monotonic invoke counter for diagnostics
/// Offset 40: stack_canary (u64) — per-CPU canary for syscall stack corruption detection
///
/// Assembly accesses GS:0, GS:8, GS:16, GS:40 — offset 24+ is safe for Rust.
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
    /// Per-CPU monotonic sequence number incremented at every capability invocation.
    /// Used as a diagnostic correlation ID in kernel trace logs.
    pub invoke_seq: u64,
    /// Per-CPU stack canary value for syscall stack overflow detection.
    /// Seeded from RDSEED/RDRAND during BSP/AP init.
    pub stack_canary: u64,
    /// Reserved for future use
    _reserved: [u64; 10],
}

/// Per-CPU data for each CPU
static mut PER_CPU_DATA: [PerCpuData; MAX_CPUS] = {
    const INIT: PerCpuData = PerCpuData {
        cpu_id: 0,
        kernel_stack: 0,
        saved_rsp: 0,
        fpu_owner: 0,
        invoke_seq: 0,
        stack_canary: 0,
        _reserved: [0; 10],
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

        // Seed per-CPU stack canary from hardware RNG (RDSEED/RDRAND)
        PER_CPU_DATA[0].stack_canary = init_stack_canary();

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

/// Initialize stack canary for an AP (Application Processor).
///
/// # Safety
/// Must be called after GS base is set for this CPU.
pub fn init_ap_canary(cpu_id: usize) {
    unsafe {
        PER_CPU_DATA[cpu_id].stack_canary = init_stack_canary();
    }
}

/// Generate a per-CPU stack canary seed.
/// Uses RDSEED (best), falls back to RDRAND, then TSC.
fn init_stack_canary() -> u64 {
    if let Some(val) = crate::rng::rdseed64() {
        return val;
    }
    // Fallback: read TSC and mix with a constant
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nostack));
    }
    (((hi as u64) << 32) | (lo as u64)) ^ 0xDEAD_BEEF_CAFE_BABE
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

/// Increment and return the per-CPU invoke sequence counter.
///
/// Used to stamp capability invocations with a monotonic correlation ID
/// for diagnostic trace logs. Not visible to userspace.
#[inline]
pub fn next_invoke_seq() -> u64 {
    let seq: u64;
    unsafe {
        // SAFETY: GS:32 corresponds to invoke_seq field in PerCpuData.
        // This is a simple RMW on a per-CPU field; no other CPU touches it.
        core::arch::asm!(
            "add qword ptr gs:[32], 1",
            "mov {}, gs:[32]",
            out(reg) seq,
            options(nostack)
        );
    }
    seq
}

/// Read the current per-CPU invoke sequence counter (without incrementing).
#[inline]
pub fn current_invoke_seq() -> u64 {
    let seq: u64;
    unsafe {
        // SAFETY: GS:32 corresponds to invoke_seq field in PerCpuData.
        core::arch::asm!(
            "mov {}, gs:[32]",
            out(reg) seq,
            options(nostack, pure, readonly)
        );
    }
    seq
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

/// Read the current FS_BASE MSR value (user TLS base pointer).
#[inline]
pub fn read_fs_base() -> u64 {
    let low: u32;
    let high: u32;
    unsafe {
        // SAFETY: Reading IA32_FS_BASE is a non-destructive MSR read.
        core::arch::asm!(
            "rdmsr",
            in("ecx") IA32_FS_BASE_MSR,
            out("eax") low,
            out("edx") high,
            options(nostack)
        );
    }
    (high as u64) << 32 | (low as u64)
}

/// Write the FS_BASE MSR (user TLS base pointer).
///
/// # Safety
/// Must be called with interrupts disabled. The base address must be a
/// valid user-mode TLS pointer (or 0 to clear).
#[inline]
pub unsafe fn write_fs_base(base: u64) {
    let low = base as u32;
    let high = (base >> 32) as u32;
    unsafe {
        // SAFETY: Writing IA32_FS_BASE sets the user-visible FS segment base.
        core::arch::asm!(
            "wrmsr",
            in("ecx") IA32_FS_BASE_MSR,
            in("eax") low,
            in("edx") high,
            options(nostack)
        );
    }
}
