//! x86_64 CPU support
//!
//! SPDX-License-Identifier: GPL-2.0-only

/// IA32_GS_BASE MSR address
const IA32_GS_BASE_MSR: u32 = 0xC000_0101;

/// Maximum number of CPUs supported
pub const MAX_CPUS: usize = 16;

/// Per-CPU data structure
///
/// Layout is fixed with #[repr(C)] to ensure assembly compatibility.
/// Offset 0: cpu_id (u32)
/// Offset 4: padding (u32)
/// Offset 8: kernel_stack (u64)
/// Offset 16: saved_rsp (u64)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PerCpuData {
    /// CPU ID (0 for BSP, 1+ for APs)
    pub cpu_id: u32,
    /// Kernel stack pointer for syscall entry
    pub kernel_stack: u64,
    /// Saved user RSP during syscall
    pub saved_rsp: u64,
    /// Reserved for future use
    _reserved: [u64; 13],
}

/// Per-CPU data for each CPU
static mut PER_CPU_DATA: [PerCpuData; MAX_CPUS] = {
    const INIT: PerCpuData = PerCpuData {
        cpu_id: 0,
        kernel_stack: 0,
        saved_rsp: 0,
        _reserved: [0; 13],
    };
    [INIT; MAX_CPUS]
};

/// Serial port (COM1) for debug output
const SERIAL_PORT: u16 = 0x3F8;

/// Write a byte to serial port
unsafe fn serial_putc(c: u8) {
    unsafe {
        while (super::inb(SERIAL_PORT + 5) & 0x20) == 0 {}
        super::outb(SERIAL_PORT, c);
    }
}

/// Write a string to serial port
unsafe fn serial_puts(s: &str) {
    for byte in s.bytes() {
        unsafe { serial_putc(byte); }
    }
}

/// Write a hexadecimal number to serial port
unsafe fn serial_hex(mut val: u64) {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    unsafe { serial_puts("0x"); }
    if val == 0 {
        unsafe { serial_putc(b'0'); }
        return;
    }
    let mut buf = [0u8; 16];
    let mut pos = 15;
    while val > 0 {
        buf[pos] = HEX_CHARS[(val & 0xF) as usize];
        val >>= 4;
        pos -= 1;
    }
    for &c in &buf[(pos + 1)..] {
        unsafe { serial_putc(c); }
    }
}

/// Initialize per-CPU data for the BSP (Boot Processor)
pub fn init_bsp() {
    unsafe {
        serial_puts("\n[CPU] init_bsp() called\n");

        PER_CPU_DATA[0].cpu_id = 0;

        serial_puts("[CPU] PER_CPU_DATA addr: ");
        serial_hex((&raw const PER_CPU_DATA) as u64);
        serial_puts("\n[CPU] Setting GS base\n");

        // Set GS base to point to this CPU's data
        write_gs_base_msr(&PER_CPU_DATA[0] as *const _ as u64);

        serial_puts("[CPU] GS base set successfully\n");
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
            options(nostack, nomem)
        );
    }
}

/// Get per-CPU data pointer for a specific CPU
pub unsafe fn per_cpu_mut(cpu_id: u32) -> &'static mut PerCpuData {
    unsafe { &mut PER_CPU_DATA[cpu_id as usize] }
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