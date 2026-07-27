//! x86_64 CPU support
//!
//! SPDX-License-Identifier: GPL-2.0-only

/// IA32_FS_BASE MSR address
const IA32_FS_BASE_MSR: u32 = 0xC000_0100;
/// IA32_GS_BASE MSR address
const IA32_GS_BASE_MSR: u32 = 0xC000_0101;
/// IA32_KERNEL_GS_BASE MSR address
const IA32_KERNEL_GS_BASE_MSR: u32 = 0xC000_0102;

unsafe extern "C" {
    fn x86_cpu_rdtsc() -> u64;
    fn x86_cpu_rdmsr(msr: u32) -> u64;
    fn x86_cpu_wrmsr(msr: u32, value: u64);
    fn x86_cpu_set_per_cpu_canary(canary: u64);
    fn x86_cpu_current_cpu() -> u32;
    fn x86_cpu_next_invoke_seq() -> u64;
    fn x86_cpu_current_invoke_seq() -> u64;
    fn x86_cpu_set_kernel_stack(stack_top: u64);
    fn x86_cpu_get_kernel_stack() -> u64;
}

/// Maximum number of CPUs supported
pub const MAX_CPUS: usize = 16;

/// Per-CPU data structure
///
/// Layout is fixed with #[repr(C)] to ensure assembly compatibility.
/// Offset 0:  cpu_id (u32)
/// Offset 4:  padding (u32)  [implicit]
/// Offset 8:  kernel_stack (u64)
/// Offset 16: saved_rsp (u64)
/// Offset 24: invoke_seq (u64) — per-CPU monotonic invoke counter for diagnostics
/// Offset 32: stack_canary (u64) — per-CPU canary for syscall stack corruption detection
///
/// Assembly accesses GS:0, GS:8, GS:16, GS:32. Keep the layout in sync
/// with `kernite/src/arch/x86_64/syscall.S`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PerCpuData {
    /// CPU ID (0 for BSP, 1+ for APs)
    pub cpu_id: u32,
    /// Kernel stack pointer for syscall entry
    pub kernel_stack: u64,
    /// Saved user RSP during syscall
    pub saved_rsp: u64,
    /// Per-CPU monotonic sequence number incremented at every capability invocation.
    /// Used as a diagnostic correlation ID in kernel trace logs.
    pub invoke_seq: u64,
    /// Per-CPU stack canary value for syscall stack overflow detection.
    /// Seeded from RDSEED/RDRAND during BSP/AP init.
    pub stack_canary: u64,
    /// Reserved for future use
    _reserved: [u64; 11],
}

/// Per-CPU data for each CPU
static mut PER_CPU_DATA: [PerCpuData; MAX_CPUS] = {
    const INIT: PerCpuData = PerCpuData {
        cpu_id: 0,
        kernel_stack: 0,
        saved_rsp: 0,
        invoke_seq: 0,
        stack_canary: 0,
        _reserved: [0; 11],
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
        crate::kernel::printk::kdebug!(arch, |_g| {
            _g.puts("\n[CPU] init_bsp() called\n");
        });

        PER_CPU_DATA[0].cpu_id = 0;

        // Seed per-CPU stack canary from hardware RNG (RDSEED/RDRAND)
        PER_CPU_DATA[0].stack_canary = generate_stack_canary();

        crate::kernel::printk::kdebug!(arch, |_g| {
            _g.puts("[CPU] PER_CPU_DATA addr: ");
            _g.hex((&raw const PER_CPU_DATA) as u64);
            _g.puts("\n[CPU] Setting GS base\n");
        });

        // Keep kernel GS pointing at PerCpuData. User GS starts at 0 and is
        // swapped in/out by swapgs on user<->kernel transitions.
        let per_cpu_base = &PER_CPU_DATA[0] as *const _ as u64;
        write_gs_base_msr(per_cpu_base);
        write_kernel_gs_base_msr(0);

        crate::kernel::printk::kdebug!(arch, |_g| {
            _g.puts("[CPU] GS base set successfully\n");
        });
    }
}

/// Initialize stack canary for an AP (Application Processor).
///
/// # Safety
/// Must be called after GS base is set for this CPU.
pub fn init_ap_canary(cpu_id: usize) {
    unsafe {
        PER_CPU_DATA[cpu_id].stack_canary = generate_stack_canary();
    }
}

/// Generate a random stack canary value.
/// Uses RDSEED (best), falls back to RDRAND, then TSC.
pub fn generate_stack_canary() -> u64 {
    if let Some(val) = crate::kernel::random::rdseed64() {
        return val;
    }
    // Fallback: read TSC and mix with a constant
    unsafe { x86_cpu_rdtsc() ^ 0xDEAD_BEEF_CAFE_BABE }
}

/// Update the per-CPU canary cache at %gs:32 to the given thread's canary.
///
/// Called during context switch so that the assembly canary check at
/// syscall exit matches even if the thread migrated from a different CPU.
#[inline(always)]
pub fn set_per_cpu_canary(canary: u64) {
    unsafe {
        // SAFETY: GS:32 corresponds to stack_canary field in PerCpuData.
        x86_cpu_set_per_cpu_canary(canary);
    }
}

/// Get the current CPU ID
#[inline(always)]
pub fn current_cpu() -> u32 {
    unsafe {
        // Read value directly from GS:[0], not as a pointer
        x86_cpu_current_cpu()
    }
}

#[inline(always)]
pub fn per_cpu_ready() -> bool {
    let gs_base = read_gs_base_msr();
    let start = (&raw const PER_CPU_DATA) as *const PerCpuData as u64;
    let stride = core::mem::size_of::<PerCpuData>() as u64;
    let end = start + stride * MAX_CPUS as u64;

    gs_base >= start && gs_base < end && (gs_base - start) % stride == 0
}

#[inline(always)]
pub fn diagnostic_current_cpu() -> usize {
    if per_cpu_ready() {
        (current_cpu() as usize).min(MAX_CPUS - 1)
    } else {
        0
    }
}

/// Set GS base for a specific CPU by index
///
/// Used during AP init before GS is functional.
pub fn write_gs_base_for_cpu(cpu_id: usize) {
    let base = unsafe { (&raw const PER_CPU_DATA[cpu_id]) as u64 };
    write_gs_base_msr(base);
    write_kernel_gs_base_msr(0);
}

/// Read the current GS base using MSR.
fn read_gs_base_msr() -> u64 {
    unsafe { x86_cpu_rdmsr(IA32_GS_BASE_MSR) }
}

/// Write to GS base using MSR
fn write_gs_base_msr(base: u64) {
    unsafe {
        x86_cpu_wrmsr(IA32_GS_BASE_MSR, base);
    }
}

/// Write to KERNEL_GS_BASE using MSR
fn write_kernel_gs_base_msr(base: u64) {
    unsafe {
        x86_cpu_wrmsr(IA32_KERNEL_GS_BASE_MSR, base);
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
    unsafe {
        CPU_APIC_IDS[cpu_id] = apic_id;
    }
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
    unsafe {
        // SAFETY: GS:24 corresponds to invoke_seq field in PerCpuData.
        // This is a simple RMW on a per-CPU field; no other CPU touches it.
        x86_cpu_next_invoke_seq()
    }
}

/// Read the current per-CPU invoke sequence counter (without incrementing).
#[inline]
pub fn current_invoke_seq() -> u64 {
    unsafe {
        // SAFETY: GS:24 corresponds to invoke_seq field in PerCpuData.
        x86_cpu_current_invoke_seq()
    }
}

/// Set kernel stack for the current CPU
///
/// # Safety
/// Must be called with a valid kernel stack pointer.
pub unsafe fn set_kernel_stack(stack_top: u64) {
    // SAFETY: We access GS:[8] which corresponds to `kernel_stack` field.
    // Offset calculation: cpu_id(4) + padding(4) = 8
    unsafe {
        x86_cpu_set_kernel_stack(stack_top);
    }
}

/// Get kernel stack pointer for the current CPU
pub fn get_kernel_stack() -> u64 {
    unsafe {
        // Read value directly from GS:[8]
        x86_cpu_get_kernel_stack()
    }
}

/// Read the current FS_BASE MSR value (user TLS base pointer).
#[inline]
pub fn read_fs_base() -> u64 {
    // SAFETY: Reading IA32_FS_BASE is a non-destructive MSR read.
    unsafe { x86_cpu_rdmsr(IA32_FS_BASE_MSR) }
}

/// Write the FS_BASE MSR (user TLS base pointer).
///
/// # Safety
/// Must be called with interrupts disabled. The base address must be a
/// valid user-mode TLS pointer (or 0 to clear).
#[inline]
pub unsafe fn write_fs_base(base: u64) {
    unsafe {
        // SAFETY: Writing IA32_FS_BASE sets the user-visible FS segment base.
        x86_cpu_wrmsr(IA32_FS_BASE_MSR, base);
    }
}

/// Write the architecture ABI thread pointer restored by `swapgs` on user
/// return. This is the user GS base while kernel GS continues to point at
/// `PerCpuData`.
#[inline]
pub fn write_abi_tp_base(base: u64) {
    write_kernel_gs_base_msr(base);
}
