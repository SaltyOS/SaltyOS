/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SaltyOS Bootloader - Stage 3 Linker Script
 *
 * Stage 3 is loaded at 0x40000 by Stage 2.
 * It runs in 32-bit protected mode and transitions to 64-bit long mode
 * at the end before jumping to the kernel.
 */

OUTPUT_FORMAT("elf32-i386")
OUTPUT_ARCH(i386)
ENTRY(_start)

SECTIONS
{
    /* Stage 3 load address */
    . = 0x40000;

    /* Code section - entry point must be at the start */
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

    /* Stack (16KB) - placed at fixed location to save space in binary */
    . = ALIGN(4096);
    __stack_bottom = .;
    . += 0x4000;
    __stack_top = .;

    /* End marker */
    __stage3_end = .;

    /* Discard unwanted sections */
    /DISCARD/ : {
        *(.comment)
        *(.note*)
        *(.eh_frame*)
    }
}

/* Assertions to verify size constraints */
/* Stage 3 can be up to 128KB (128 sectors at 512 bytes) */
ASSERT(__stage3_end - 0x40000 <= 131072, "Stage 3 exceeds 128KB size limit")
