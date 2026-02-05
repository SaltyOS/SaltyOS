/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SaltyOS Bootloader - Stage 3 UEFI Linker Script
 *
 * Stage 3 (UEFI path) is loaded at 0x100000 (1MB) by UEFI Stage 2.
 * It runs in 64-bit long mode (already set up by UEFI firmware).
 */

OUTPUT_FORMAT("elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start_uefi)

SECTIONS
{
    /* Stage 3 UEFI load address (matches UEFI_STAGE3_LOAD_ADDR in stage2) */
    . = 0x100000;

    /* Code section - UEFI entry point must be at the start */
    .text.entry : {
        *(.text.entry)
    }

    .text : {
        *(.text*)
    }

    /* Read-only data */
    .rodata : {
        *(.rodata*)
    }

    /* Data section */
    .data : {
        *(.data*)
    }

    /* BSS section */
    .bss : {
        __bss_start = .;
        *(.bss*)
        *(COMMON)
        __bss_end = .;
    }

    /* End of code/data */
    __stage3_data_end = .;

    /* End marker */
    __stage3_end = .;

    /* Discard unwanted sections */
    /DISCARD/ : {
        *(.comment)
        *(.note*)
        *(.eh_frame*)
    }
}
