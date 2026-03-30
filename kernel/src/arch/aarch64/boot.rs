//! AArch64 boot entry point and AP trampoline
//!
//! SPDX-License-Identifier: GPL-2.0-only

use core::arch::global_asm;

// ---------------------------------------------------------------------------
// BSP boot entry point
// ---------------------------------------------------------------------------

// Boot entry point: the AArch64 host kernel runs at EL1. If firmware or the
// bootloader leaves us at EL2, drop to EL1 before entering the normal kernel
// bootstrap so the higher-half EL1 memory model remains the single host path.
global_asm!(
    r#"
    .section .text.boot, "ax"
    .global _start
    .type _start, @function
_start:
    // x0 = pointer to BootInfo (passed by bootloader) — preserve throughout

    // Mask all exceptions during early boot
    msr     DAIFSet, #0xF

    // If we somehow arrive in EL2, switch to EL1h before touching the host
    // kernel path. Stage 3 should already do this for the BSP, but keep the
    // fallback here so the kernel has one host execution model.
    mrs     x9, CurrentEL
    lsr     x9, x9, #2
    cmp     x9, #2
    b.ne    .Lbsp_el1_entry

    msr     CNTHP_CTL_EL2, xzr
    msr     CNTP_CTL_EL0, xzr
    msr     CNTV_CTL_EL0, xzr
    mov     x9, #3
    msr     CNTHCTL_EL2, x9
    msr     CNTVOFF_EL2, xzr
    movz    x9, #0x8000, lsl #16   // HCR_EL2.RW=1, no E2H/TGE
    msr     HCR_EL2, x9
    adrp    x1, _boot_stack_top
    add     x1, x1, :lo12:_boot_stack_top
    msr     SP_EL1, x1
    adrp    x1, exception_vectors
    add     x1, x1, :lo12:exception_vectors
    msr     VBAR_EL1, x1
    adrp    x9, .Lbsp_el1_entry
    add     x9, x9, :lo12:.Lbsp_el1_entry
    msr     ELR_EL2, x9
    mov     x9, #0x3C5            // EL1h, DAIF masked
    msr     SPSR_EL2, x9
    isb
    eret

.Lbsp_el1_entry:
    // Set up kernel stack (use a static boot stack)
    adrp    x1, _boot_stack_top
    add     x1, x1, :lo12:_boot_stack_top
    mov     sp, x1

    // Replace Stage 3's temporary vectors immediately. Any fault taken while
    // zeroing .bss or entering Rust must land in the kernel vector table.
    adrp    x1, exception_vectors
    add     x1, x1, :lo12:exception_vectors
    msr     VBAR_EL1, x1
    isb

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
4:
    wfi
    b       4b

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
    /// Active host MAIR value copied from the BSP.
    pub mair: u64,
    /// Active host TCR value copied from the BSP.
    pub tcr: u64,
    /// Active host SCTLR value copied from the BSP (includes M=1 to enable MMU).
    pub sctlr: u64,
    /// Shared bootstrap/full root loaded into the active host TTBR0.
    pub host_ttbr0: u64,
    /// Kernel root template loaded into TTBR1_EL1.
    pub compat_ttbr1: u64,
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
    host_ttbr0: 0,
    compat_ttbr1: 0,
    entry_virt: 0,
};

// ---------------------------------------------------------------------------
// AP trampoline assembly
// ---------------------------------------------------------------------------
//
// PSCI CPU_ON starts the AP at the physical address of `_ap_trampoline_start`
// with x0 = context_id (we pass cpu_id).  The AP may enter at EL1 or EL2
// depending on the platform firmware.
//
// The trampoline:
//   0. Handles EL2 by dropping to EL1 before enabling the host kernel mappings.
//   1. Loads system register values from AP_MAILBOX (ADRP is PC-relative,
//      producing the correct physical address because the offset between
//      the trampoline and the mailbox is fixed in the kernel image).
//   2. Configures MAIR_EL1/TCR_EL1/TTBR0_EL1/TTBR1_EL1 and enables the MMU
//      via SCTLR_EL1.
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

    // PSCI CPU_ON may start APs at EL2 even though the host kernel runs at EL1.
    mrs     x9, CurrentEL
    lsr     x9, x9, #2
    cmp     x9, #2
    b.ne    .Lap_el1_cont

    msr     CNTHP_CTL_EL2, xzr
    msr     CNTP_CTL_EL0, xzr
    msr     CNTV_CTL_EL0, xzr
    mov     x9, #3
    msr     CNTHCTL_EL2, x9
    msr     CNTVOFF_EL2, xzr
    movz    x9, #0x8000, lsl #16   // HCR_EL2.RW=1, no E2H/TGE
    msr     HCR_EL2, x9
    adrp    x9, .Lap_el1_cont
    add     x9, x9, :lo12:.Lap_el1_cont
    msr     ELR_EL2, x9
    mov     x9, #0x3C5
    msr     SPSR_EL2, x9
    isb
    eret

.Lap_el1_cont:
    // --- Continue AP trampoline in EL1 ---

    // 2. Locate AP_MAILBOX via PC-relative addressing.
    //    ADRP + ADD produces the physical address of the mailbox because
    //    the kernel image is contiguous and ADRP offsets are preserved
    //    regardless of load address.
    adrp    x1, AP_MAILBOX
    add     x1, x1, :lo12:AP_MAILBOX

    // 3. Load and set host MAIR.
    ldr     x2, [x1, #8]
    msr     MAIR_EL1, x2

    // 4. Load and set host TCR.
    ldr     x2, [x1, #16]
    msr     TCR_EL1, x2

    // 5. Load and set the active host TTBR0 (shared bootstrap/full root).
    ldr     x2, [x1, #32]
    msr     TTBR0_EL1, x2

    // 6. Load TTBR1_EL1 from the shared kernel root template.
    ldr     x2, [x1, #40]
    msr     TTBR1_EL1, x2

    // 7. Barrier: ensure all system register writes are visible,
    //    then invalidate any stale local TLB entries from firmware.
    isb
    tlbi    vmalle1
    dsb     ish
    isb

    // 8. Enable MMU by writing the BSP's active host SCTLR value.
    ldr     x2, [x1, #24]
    msr     SCTLR_EL1, x2
    isb

.Lap_mmu_ready:

    // --- MMU is now ON; identity map covers current PC ---

    // 9. Enable FP/NEON access before entering Rust code.
    //    Rust emits NEON instructions for memcpy/memset/struct ops,
    //    so any Rust code will immediately fault without this.
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
