/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SaltyOS Bootloader - Stage 2 Linker Script
 *
 * Stage 2 is loaded at 0x8000 by Stage 1 (MBR).
 * It runs in 32-bit protected mode with BTX for BIOS services.
 */

OUTPUT_FORMAT("elf32-i386")
OUTPUT_ARCH(i386)
ENTRY(_start)

SECTIONS
{
    /* Stage 2 load address */
    . = 0x8000;

    /* Entry point must be at the very start */
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

    /* End marker */
    __stage2_end = .;

    /* Discard unwanted sections */
    /DISCARD/ : {
        *(.comment)
        *(.note*)
        *(.eh_frame*)
    }
}

/* Assertions to verify size constraints */
ASSERT(__stage2_end - 0x8000 <= 65536, "Stage 2 exceeds 64KB size limit")
