/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SaltyOS Bootloader - AArch64 UEFI Stage 3 Entry
 *
 * Entry point for the aarch64 Stage 3 kernel loader.
 * When loaded by Stage 2 (UEFI), we may be in EL1 or EL2 depending on the
 * hypervisor/firmware. EL1 handoff can branch directly into the higher-half
 * kernel image. Native non-VHE EL2 cannot do that with TTBR0_EL2 alone, so
 * Stage 3 drops to EL1 before the final handoff in that case.
 */

    .section .text.boot, "ax"
    .equ BOOTINFO_FLAG_STAGE3_EL2, (1 << 4)
    .global _stage3_entry
    .type _stage3_entry, @function
_stage3_entry:
    /* x0 = pointer to Stage2Info (passed from Stage 2) */

    /* Set up a small stack for Stage 3 */
    adrp    x1, _stage3_stack_top
    add     x1, x1, :lo12:_stage3_stack_top
    mov     sp, x1

    /* Call stage3_entry_64(stage2_info) */
    bl      stage3_entry_64

    /* Should not return */
1:
    wfi
    b       1b

    .global stage3_prepare_handoff_el
    .type stage3_prepare_handoff_el, @function
stage3_prepare_handoff_el:
    /* Install a minimal vector table and return BootInfo flags describing
     * the EL used for the kernel handoff. */
    mrs     x9, CurrentEL
    lsr     x9, x9, #2
    cmp     x9, #2
    b.eq    .Linstall_el2_vectors

.Linstall_el1_vectors:
    msr     DAIFSet, #0xF
    adrp    x9, _stage3_el1_vectors
    add     x9, x9, :lo12:_stage3_el1_vectors
    msr     VBAR_EL1, x9
    isb
    mov     x0, xzr
    ret

.Linstall_el2_vectors:
    msr     DAIFSet, #0xF

    adrp    x9, _stage3_el2_vectors
    add     x9, x9, :lo12:_stage3_el2_vectors
    msr     VBAR_EL2, x9
    isb

    // Quiesce any firmware-programmed local timers before Stage 3 keeps EL2.
    // Otherwise a pending PPI can vector into stale firmware EL2 handlers in
    // the narrow window before the kernel takes over the interrupt path.
    msr     CNTHP_CTL_EL2, xzr
    msr     CNTP_CTL_EL0, xzr
    msr     CNTV_CTL_EL0, xzr
    isb

    movz    x10, #0x33FF
    msr     CPTR_EL2, x10
    isb

    mov     x10, #3
    msr     CNTHCTL_EL2, x10
    msr     CNTVOFF_EL2, xzr
    msr     S3_4_C2_C1_0, xzr       /* VTTBR_EL2 */

    /* AArch64 EL2 without E2H/VHE only has TTBR0_EL2 for host stage-1
     * translation, which limits Stage 3 to the lower VA range. The kernel
     * entry lives in the higher half, so complete the handoff through the
     * EL1 TTBR0/TTBR1 regime instead of branching there from native EL2. */
    movz    x10, #0x8000, lsl #16   /* HCR_EL2.RW=1, no E2H/TGE */
    msr     HCR_EL2, x10
    isb

    adrp    x9, _stage3_el1_vectors
    add     x9, x9, :lo12:_stage3_el1_vectors
    msr     VBAR_EL1, x9
    mov     x10, sp
    msr     SP_EL1, x10

    adrp    x10, .Lresume_in_el1
    add     x10, x10, :lo12:.Lresume_in_el1
    msr     ELR_EL2, x10
    mov     x10, #0x3C5            /* EL1h, DAIF masked */
    msr     SPSR_EL2, x10
    isb
    eret

.Lresume_in_el1:
    msr     DAIFSet, #0xF
    isb
    mov     x0, #BOOTINFO_FLAG_STAGE3_EL2
    ret

    .balign 2048
    .global _stage3_el1_vectors
_stage3_el1_vectors:
    b       .
    .space  0x80 - 4
    b       .
    .space  0x80 - 4
    b       .
    .space  0x80 - 4
    b       .
    .space  0x80 - 4
    b       .
    .space  0x80 - 4
    b       _stage3_el1_irq_spx
    .space  0x80 - 4
    b       .
    .space  0x80 - 4
    b       .

    .balign 2048
    .global _stage3_el2_vectors
_stage3_el2_vectors:
    b       .
    .space  0x80 - 4
    b       .
    .space  0x80 - 4
    b       .
    .space  0x80 - 4
    b       .
    .space  0x80 - 4
    b       .
    .space  0x80 - 4
    b       _stage3_el2_irq_spx
    .space  0x80 - 4
    b       .
    .space  0x80 - 4
    b       .

_stage3_el1_irq_spx:
    mrs     x9, SPSR_EL1
    orr     x9, x9, #(1 << 7)     /* Keep IRQ masked after return */
    msr     SPSR_EL1, x9
    eret

_stage3_el2_irq_spx:
    mrs     x9, SPSR_EL2
    orr     x9, x9, #(1 << 7)     /* Keep IRQ masked after return */
    msr     SPSR_EL2, x9
    eret

    .section .bss
    .align 16
_stage3_stack_bottom:
    .space  16384
    .global _stage3_stack_top
_stage3_stack_top:
