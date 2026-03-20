/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SaltyOS Bootloader - AArch64 UEFI Stage 3 Entry
 *
 * Entry point for the aarch64 Stage 3 kernel loader.
 * When loaded by Stage 2 (UEFI), we are already in EL1 64-bit mode.
 */

    .section .text.boot, "ax"
    .global _stage3_entry
    .type _stage3_entry, @function
_stage3_entry:
    /* x0 = pointer to Stage2Info (passed from Stage 2) */

    /* Set up a small stack for Stage 3 */
    adrp    x1, _stage3_stack_top
    add     x1, x1, :lo12:_stage3_stack_top
    mov     sp, x1

    /* Call uefi_stage3_main(stage2_info) */
    bl      uefi_stage3_main

    /* Should not return */
1:
    wfi
    b       1b

    .section .bss
    .align 16
_stage3_stack_bottom:
    .space  16384
    .global _stage3_stack_top
_stage3_stack_top:
