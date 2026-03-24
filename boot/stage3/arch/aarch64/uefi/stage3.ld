/* SPDX-License-Identifier: GPL-2.0-only */
/* SaltyOS Stage 3 UEFI Kernel Loader (AArch64) */

OUTPUT_FORMAT(elf64-littleaarch64)
OUTPUT_ARCH(aarch64)
ENTRY(_stage3_entry)

SECTIONS
{
    /* Must match UEFI_STAGE3_LOAD_ADDR in Stage 2. */
    . = 0x40200000;

    .text : {
        *(.text.boot)
        *(.text .text.*)
    }

    .rodata ALIGN(4K) : {
        *(.rodata .rodata.*)
    }

    .data ALIGN(4K) : {
        *(.data .data.*)
        *(.got)
        *(.got.plt)
    }

    .dynamic : { *(.dynamic) }
    .rela.dyn : { *(.rela.dyn) *(.rela.plt) }

    .bss ALIGN(0x10000) : {
        *(.bss .bss.*)
        *(COMMON)
    }

    /DISCARD/ : {
        *(.comment)
        *(.note.*)
        *(.eh_frame*)
    }
}
