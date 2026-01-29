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

/// Serial port (COM1) for debug output
const SERIAL_PORT: u16 = 0x3F8;

/// Write a byte to serial port
unsafe fn serial_putc(c: u8) {
    // SAFETY: COM1 is a standard x86 serial port
    unsafe {
        while (super::inb(SERIAL_PORT + 5) & 0x20) == 0 {}
        super::outb(SERIAL_PORT, c);
    }
}

/// Write a string to serial port
unsafe fn serial_puts(s: &str) {
    for byte in s.bytes() {
        // SAFETY: COM1 is a standard x86 serial port
        unsafe {
            serial_putc(byte);
        }
    }
}

/// Write a hexadecimal number to serial port
unsafe fn serial_hex(mut val: u64) {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    // SAFETY: COM1 is a standard x86 serial port
    unsafe {
        serial_puts("0x");
    }
    if val == 0 {
        // SAFETY: COM1 is a standard x86 serial port
        unsafe {
            serial_putc(b'0');
        }
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
        // SAFETY: COM1 is a standard x86 serial port
        unsafe {
            serial_putc(c);
        }
    }
}

/// Initialize per-CPU data for the BSP (Boot Processor)
pub fn init_bsp() {
    // SAFETY: Single-threaded initialization, PER_CPU_DATA is valid
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
    unsafe { &mut PER_CPU_DATA[cpu_id as usize] }
}
