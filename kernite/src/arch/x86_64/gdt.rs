//! Global Descriptor Table (GDT)
//!
//! SPDX-License-Identifier: GPL-2.0-only

use super::cpu::MAX_CPUS;
use core::mem::size_of;

unsafe extern "C" {
    fn x86_gdt_lgdt(ptr: *const GdtPtr);
    fn x86_gdt_sgdt(ptr: *mut GdtPtr);
    fn x86_gdt_ltr(selector: u16);
    fn x86_gdt_reload_segments();
}

/// GDT entry
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct GdtEntry {
    limit_low: u16,
    base_low: u16,
    base_mid: u8,
    access: u8,
    granularity: u8,
    base_high: u8,
}

impl GdtEntry {
    pub const fn null() -> Self {
        Self {
            limit_low: 0,
            base_low: 0,
            base_mid: 0,
            access: 0,
            granularity: 0,
            base_high: 0,
        }
    }

    pub const fn kernel_code() -> Self {
        Self {
            limit_low: 0xFFFF,
            base_low: 0,
            base_mid: 0,
            access: 0x9A,      // Present, Ring 0, Code, Executable, Readable
            granularity: 0xAF, // 4KB granularity, 64-bit mode
            base_high: 0,
        }
    }

    pub const fn kernel_data() -> Self {
        Self {
            limit_low: 0xFFFF,
            base_low: 0,
            base_mid: 0,
            access: 0x92,      // Present, Ring 0, Data, Writable
            granularity: 0xCF, // 4KB granularity, 32-bit size
            base_high: 0,
        }
    }

    pub const fn user_code() -> Self {
        Self {
            limit_low: 0xFFFF,
            base_low: 0,
            base_mid: 0,
            access: 0xFA,      // Present, Ring 3, Code, Executable, Readable
            granularity: 0xAF, // 4KB granularity, 64-bit mode
            base_high: 0,
        }
    }

    pub const fn user_data() -> Self {
        Self {
            limit_low: 0xFFFF,
            base_low: 0,
            base_mid: 0,
            access: 0xF2,      // Present, Ring 3, Data, Writable
            granularity: 0xCF, // 4KB granularity, 32-bit size
            base_high: 0,
        }
    }
}

/// Task State Segment entry (16 bytes)
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct TssEntry {
    limit_low: u16,
    base_low: u16,
    base_mid: u8,
    access: u8,
    granularity: u8,
    base_high: u8,
    base_upper: u32,
    reserved: u32,
}

/// Task State Segment (x86_64)
///
/// In 64-bit mode, TSS is only used for:
/// - IST (Interrupt Stack Table) pointers for exception handling
/// - IOPB (I/O Permission Bitmap) - optional, not used in kernel
/// - The actual task switching mechanism is NOT used in x86_64
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct TaskStateSegment {
    pub reserved0: u32,
    pub rsp0: u64, // Stack pointer for CPL=0
    pub rsp1: u64, // Stack pointer for CPL=1
    pub rsp2: u64, // Stack pointer for CPL=2
    pub reserved1: u64,
    pub ist1: u64, // IST1 stack pointer
    pub ist2: u64, // IST2 stack pointer
    pub ist3: u64, // IST3 stack pointer
    pub ist4: u64, // IST4 stack pointer
    pub ist5: u64, // IST5 stack pointer
    pub ist6: u64, // IST6 stack pointer
    pub ist7: u64, // IST7 stack pointer
    pub reserved2: u64,
    pub reserved3: u16,
    pub iomap_base: u16, // I/O permission bitmap base (0xFFFF if none)
}

impl TaskStateSegment {
    pub const fn new() -> Self {
        Self {
            reserved0: 0,
            rsp0: 0,
            rsp1: 0,
            rsp2: 0,
            reserved1: 0,
            ist1: 0,
            ist2: 0,
            ist3: 0,
            ist4: 0,
            ist5: 0,
            ist6: 0,
            ist7: 0,
            reserved2: 0,
            reserved3: 0,
            iomap_base: 0xFFFF, // No I/O bitmap
        }
    }
}

/// GDT structure
#[repr(C, align(16))]
pub struct Gdt {
    null: GdtEntry,
    kernel_code: GdtEntry,
    kernel_data: GdtEntry,
    user_data: GdtEntry, // 0x18: must be before user_code for sysretq
    user_code: GdtEntry, // 0x20: sysretq computes CS = STAR[63:48]+16
    tss: TssEntry,
}

/// GDT pointer
#[repr(C, packed)]
struct GdtPtr {
    limit: u16,
    base: u64,
}

static mut GDT: Gdt = Gdt {
    null: GdtEntry::null(),
    kernel_code: GdtEntry::kernel_code(),
    kernel_data: GdtEntry::kernel_data(),
    user_data: GdtEntry::user_data(), // 0x18
    user_code: GdtEntry::user_code(), // 0x20
    tss: TssEntry {
        limit_low: 0,
        base_low: 0,
        base_mid: 0,
        access: 0,
        granularity: 0,
        base_high: 0,
        base_upper: 0,
        reserved: 0,
    },
};

/// The BSP TSS (CPU 0)
static mut TSS: TaskStateSegment = TaskStateSegment::new();

/// Per-CPU TSS array (for APs; index 0 is unused since BSP uses the original TSS)
static mut PER_CPU_TSS: [TaskStateSegment; MAX_CPUS] =
    [const { TaskStateSegment::new() }; MAX_CPUS];

/// Per-CPU GDT array (for APs; index 0 is unused since BSP uses the original GDT)
static mut PER_CPU_GDT: [Gdt; MAX_CPUS] = [const {
    Gdt {
        null: GdtEntry::null(),
        kernel_code: GdtEntry::kernel_code(),
        kernel_data: GdtEntry::kernel_data(),
        user_data: GdtEntry::user_data(),
        user_code: GdtEntry::user_code(),
        tss: TssEntry {
            limit_low: 0,
            base_low: 0,
            base_mid: 0,
            access: 0,
            granularity: 0,
            base_high: 0,
            base_upper: 0,
            reserved: 0,
        },
    }
}; MAX_CPUS];

/// Set the kernel stack pointer in TSS (rsp0) for the current CPU
pub unsafe fn set_tss_rsp0(stack_top: u64) {
    let cpu_id = super::cpu::current_cpu() as usize;
    unsafe {
        set_tss_rsp0_cpu(cpu_id, stack_top);
    }
}

/// Set the kernel stack pointer in TSS (rsp0) for a specific CPU.
pub unsafe fn set_tss_rsp0_cpu(cpu_id: usize, stack_top: u64) {
    unsafe {
        if cpu_id == 0 {
            TSS.rsp0 = stack_top;
        } else {
            PER_CPU_TSS[cpu_id].rsp0 = stack_top;
        }
    }
}

/// Get the current TSS stack pointer
pub fn get_tss_rsp0() -> u64 {
    let cpu_id = super::cpu::current_cpu() as usize;
    unsafe {
        if cpu_id == 0 {
            TSS.rsp0
        } else {
            PER_CPU_TSS[cpu_id].rsp0
        }
    }
}

/// Set an IST (Interrupt Stack Table) entry in the TSS
pub unsafe fn set_tss_ist(ist_index: u8, stack_top: u64) {
    let cpu_id = super::cpu::current_cpu() as usize;
    unsafe {
        let tss = if cpu_id == 0 {
            &raw mut TSS
        } else {
            &raw mut PER_CPU_TSS[cpu_id]
        };
        match ist_index {
            1 => (*tss).ist1 = stack_top,
            2 => (*tss).ist2 = stack_top,
            3 => (*tss).ist3 = stack_top,
            4 => (*tss).ist4 = stack_top,
            5 => (*tss).ist5 = stack_top,
            6 => (*tss).ist6 = stack_top,
            7 => (*tss).ist7 = stack_top,
            _ => {}
        }
    }
}

/// Set an IST entry for a specific CPU's TSS (used during AP init before GS is set)
pub unsafe fn set_tss_ist_cpu(cpu_id: usize, ist_index: u8, stack_top: u64) {
    unsafe {
        let tss = if cpu_id == 0 {
            &raw mut TSS
        } else {
            &raw mut PER_CPU_TSS[cpu_id]
        };
        match ist_index {
            1 => (*tss).ist1 = stack_top,
            2 => (*tss).ist2 = stack_top,
            3 => (*tss).ist3 = stack_top,
            4 => (*tss).ist4 = stack_top,
            5 => (*tss).ist5 = stack_top,
            6 => (*tss).ist6 = stack_top,
            7 => (*tss).ist7 = stack_top,
            _ => {}
        }
    }
}

/// Load per-CPU GDT and TSS for an Application Processor
pub unsafe fn load_per_cpu(cpu_id: usize) {
    unsafe {
        // Set up per-CPU TSS entry in per-CPU GDT
        let tss_ptr = &raw const PER_CPU_TSS[cpu_id];
        PER_CPU_GDT[cpu_id].tss = TssEntry::from_tss(tss_ptr);

        let gdt_ptr = GdtPtr {
            limit: (size_of::<Gdt>() - 1) as u16,
            base: (&raw const PER_CPU_GDT[cpu_id]) as u64,
        };

        // Load GDTR
        x86_gdt_lgdt(&gdt_ptr);

        // Reload segment registers
        reload_segments();

        // Load TSS (selector 0x28 = 5th entry)
        x86_gdt_ltr(0x28u16);
    }
}

impl TssEntry {
    /// Create a TSS entry pointing to a TSS structure
    pub fn from_tss(tss: *const TaskStateSegment) -> Self {
        let tss_addr = tss as u64;
        let limit = size_of::<TaskStateSegment>() as u16 - 1;

        Self {
            limit_low: limit,
            base_low: (tss_addr & 0xFFFF) as u16,
            base_mid: ((tss_addr >> 16) & 0xFF) as u8,
            access: 0x89,      // Present, Ring 0, TSS (busy bit will be set by ltr)
            granularity: 0x00, // 16-bit limit for TSS in 64-bit mode
            base_high: ((tss_addr >> 24) & 0xFF) as u8,
            base_upper: (tss_addr >> 32) as u32,
            reserved: 0,
        }
    }
}

/// Initialize GDT
pub fn init() {
    // SAFETY: Single-threaded initialization, GDT is properly structured
    unsafe {
        // Set up TSS entry in GDT to point to TSS
        (*(&raw mut GDT)).tss = TssEntry::from_tss(&raw const TSS);

        let mut gdt_ptr = GdtPtr {
            limit: (size_of::<Gdt>() - 1) as u16,
            base: (&raw const GDT) as u64,
        };

        // DEBUG: Print what we're about to load
        crate::kernel::printk::kdebug!(arch, |_g| {
            _g.puts("\n[GDT] Before lgdt:\n");
            _g.puts("  base: ");
            _g.hex(gdt_ptr.base);
            _g.puts("\n  limit: ");
            _g.hex(gdt_ptr.limit as u64);
            _g.puts("\n  GDT addr: ");
            _g.hex((&raw const GDT) as u64);
            _g.puts("\n  TSS addr: ");
            _g.hex((&raw const TSS) as u64);
            _g.putc(b'\n');
        });

        x86_gdt_lgdt(&gdt_ptr);

        // DEBUG: Read back GDTR to verify
        x86_gdt_sgdt(&mut gdt_ptr);
        let _read_back_base: u64;
        let _read_back_limit: u16;
        _read_back_base = gdt_ptr.base;
        _read_back_limit = gdt_ptr.limit;

        crate::kernel::printk::kdebug!(arch, |_g| {
            _g.puts("[GDT] After lgdt (read back):\n");
            _g.puts("  base: ");
            _g.hex(_read_back_base);
            _g.puts("\n  limit: ");
            _g.hex(_read_back_limit as u64);
            _g.putc(b'\n');
        });

        // Reload segment registers (including CS via far return)
        reload_segments();
        crate::kernel::printk::kdebug!(arch, |_g| {
            _g.puts("[GDT] Segments reloaded successfully\n");
        });

        // Load TSS (must be AFTER GDT is loaded and segments are reloaded)
        // TSS selector is 0x28 (5th GDT entry, first is null)
        x86_gdt_ltr(0x28u16);
        crate::kernel::printk::kdebug!(arch, |_g| {
            _g.puts("[GDT] TSS loaded successfully\n");
        });
    }
}

unsafe fn reload_segments() {
    // SAFETY: Called after GDT is loaded with valid segments.
    unsafe {
        x86_gdt_reload_segments();
    }
}
