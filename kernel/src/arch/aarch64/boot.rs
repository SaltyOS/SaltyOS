//! AArch64 boot entry point and AP trampoline
//!
//! SPDX-License-Identifier: GPL-2.0-only

use core::arch::global_asm;

// ---------------------------------------------------------------------------
// BSP boot entry point
// ---------------------------------------------------------------------------

// Boot entry point: set SP, zero BSS, call kmain with x0 (BootInfo ptr)
global_asm!(
    r#"
    .section .text.boot, "ax"
    .global _start
    .type _start, @function
_start:
    // x0 = pointer to BootInfo (passed by bootloader)

    // Mask all exceptions during early boot
    msr     DAIFSet, #0xF

    // Set up kernel stack (use a static boot stack)
    adrp    x1, _boot_stack_top
    add     x1, x1, :lo12:_boot_stack_top
    mov     sp, x1

    // Zero BSS section
    adrp    x1, _bss_start
    add     x1, x1, :lo12:_bss_start
    adrp    x2, _bss_end
    add     x2, x2, :lo12:_bss_end
1:
    cmp     x1, x2
    b.ge    2f
    str     xzr, [x1], #8
    b       1b
2:
    // x0 still holds BootInfo pointer from bootloader
    bl      kmain

    // kmain should never return
3:
    wfi
    b       3b

    .section .bss
    .align 16
_boot_stack_bottom:
    .space  16384       // 16 KiB boot stack
    .global _boot_stack_top
_boot_stack_top:
"#,
);

// ---------------------------------------------------------------------------
// AP trampoline mailbox
// ---------------------------------------------------------------------------

/// Mailbox structure written by the BSP before calling PSCI CPU_ON.
/// The AP trampoline assembly reads this via ADRP (PC-relative) to
/// configure system registers and enable the MMU.
#[repr(C)]
pub struct ApMailbox {
    /// Kernel stack top for this AP.
    pub stack_top: u64,
    /// MAIR_EL1 value (copied from BSP).
    pub mair: u64,
    /// TCR_EL1 value (copied from BSP).
    pub tcr: u64,
    /// SCTLR_EL1 value (copied from BSP, includes M=1 to enable MMU).
    pub sctlr: u64,
    /// TTBR0_EL1 value (boot identity map root).
    pub ttbr0: u64,
    /// TTBR1_EL1 value (kernel higher-half root).
    pub ttbr1: u64,
    /// Virtual address of the Rust AP entry function (`ap_entry`).
    pub entry_virt: u64,
}

/// Global AP mailbox — written by BSP, read by AP trampoline assembly.
/// Only one AP is started at a time, so a single mailbox suffices.
#[unsafe(no_mangle)]
pub static mut AP_MAILBOX: ApMailbox = ApMailbox {
    stack_top: 0,
    mair: 0,
    tcr: 0,
    sctlr: 0,
    ttbr0: 0,
    ttbr1: 0,
    entry_virt: 0,
};

// ---------------------------------------------------------------------------
// AP trampoline assembly
// ---------------------------------------------------------------------------
//
// PSCI CPU_ON starts the AP at the physical address of `_ap_trampoline_start`
// with x0 = context_id (we pass cpu_id).  The AP enters in EL1 with MMU off,
// caches off, and all exceptions masked.
//
// The trampoline:
//   1. Loads system register values from AP_MAILBOX (ADRP is PC-relative,
//      producing the correct physical address because the offset between
//      the trampoline and the mailbox is fixed in the kernel image).
//   2. Configures MAIR, TCR, TTBR0, TTBR1, then enables MMU via SCTLR.
//   3. Loads the kernel-virtual entry address and stack from the mailbox,
//      then branches to the Rust AP entry at the higher-half address.
//
// x0 is preserved throughout (carries cpu_id for ap_entry).

global_asm!(
    r#"
    .section .text
    .balign 4096
    .global _ap_trampoline_start
    .type _ap_trampoline_start, @function
_ap_trampoline_start:
    // x0 = cpu_id (context_id from PSCI CPU_ON)

    // 1. Mask all exceptions
    msr     DAIFSet, #0xF

    // 2. Locate AP_MAILBOX via PC-relative addressing.
    //    ADRP + ADD produces the physical address of the mailbox because
    //    the kernel image is contiguous and ADRP offsets are preserved
    //    regardless of load address.
    adrp    x1, AP_MAILBOX
    add     x1, x1, :lo12:AP_MAILBOX

    // 3. Load and set MAIR_EL1
    ldr     x2, [x1, #8]
    msr     MAIR_EL1, x2

    // 4. Load and set TCR_EL1
    ldr     x2, [x1, #16]
    msr     TCR_EL1, x2

    // 5. Load and set TTBR0_EL1 (identity map root)
    ldr     x2, [x1, #32]
    msr     TTBR0_EL1, x2

    // 6. Load and set TTBR1_EL1 (kernel root)
    ldr     x2, [x1, #40]
    msr     TTBR1_EL1, x2

    // 7. Barrier: ensure all system register writes are visible,
    //    then invalidate any stale TLB entries from firmware.
    isb
    tlbi    vmalle1
    dsb     ish
    isb

    // 8. Enable MMU by writing BSP's SCTLR_EL1 value (M=1, C=1, I=1, etc.)
    ldr     x2, [x1, #24]
    msr     SCTLR_EL1, x2
    isb

    // --- MMU is now ON; identity map covers current PC ---

    // 9. Enable FP/NEON access from EL1 before entering Rust code.
    //    PSCI CPU_ON leaves CPACR_EL1 = 0 (all FP/NEON trapped).
    //    Rust emits NEON instructions for memcpy/memset/struct ops,
    //    so any Rust code will immediately fault without this.
    //    Set CPACR_EL1.FPEN = 0b11 (bits 21:20) to allow EL1+EL0.
    //    fpu::init() will refine this later for lazy EL0 trapping.
    mov     x4, #(3 << 20)
    msr     CPACR_EL1, x4
    isb

    // 10. Load AP kernel stack and virtual entry point from mailbox.
    //     x1 still points to AP_MAILBOX at the physical/identity address;
    //     the identity map is still active so loads from x1 remain valid.
    ldr     x2, [x1, #0]       // stack_top
    ldr     x3, [x1, #48]      // entry_virt (kernel higher-half VA)

    // 11. Set up stack
    mov     sp, x2

    // 12. Jump to kernel virtual address.
    //     x0 still holds cpu_id for ap_entry(cpu_id).
    br      x3

    .global _ap_trampoline_end
_ap_trampoline_end:
.size _ap_trampoline_start, . - _ap_trampoline_start
"#,
);
