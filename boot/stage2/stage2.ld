/* Stage 2 Linker Script */
/* SPDX-License-Identifier: GPL-2.0-only */
/* Loaded at 0x7E00 by MBR */

OUTPUT_FORMAT(binary)
OUTPUT_ARCH(i386)

ENTRY(_start)

SECTIONS
{
    . = 0x7E00;

    .text : {
        *(.text)
        *(.text.*)
    }

    .rodata : {
        *(.rodata)
        *(.rodata.*)
    }

    .data : {
        *(.data)
        *(.data.*)
    }

    .bss : {
        *(.bss)
        *(.bss.*)
        *(COMMON)
    }

    /DISCARD/ : {
        *(.comment)
        *(.note.*)
        *(.eh_frame*)
    }
}
