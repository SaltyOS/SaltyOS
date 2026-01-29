/* Stage 2 Linker Script */
/* SPDX-License-Identifier: GPL-2.0-only */
/* Loaded at 0x7E00 by MBR */

OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)

ENTRY(_start)

/* Low memory region for BIOS realmode compatibility */
MEMORY {
    LOWMEM (rwx) : ORIGIN = 0x6000, LENGTH = 8K
    MAIN (rwx)  : ORIGIN = 0x7E00, LENGTH = 512K
}

SECTIONS
{
    /* Main code at 0x7E00 */
    .text : {
        *(.text)
        *(.text.*)
    } > MAIN

    .rodata : {
        *(.rodata)
        *(.rodata.*)
    } > MAIN

    .data : {
        *(.data)
        *(.data.*)
    } > MAIN

    .bss : {
        *(.bss)
        *(.bss.*)
        *(COMMON)
    } > MAIN

    /* Low memory section for BIOS realmode compatibility at 0x6000 */
    .lowmem (NOLOAD) : {
        *(.lowmem)
    } > LOWMEM

    /DISCARD/ : {
        *(.comment)
        *(.note.*)
        *(.eh_frame*)
    }
}
