/* SaltyOS init PIE linker script
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Produces ET_DYN (PIE) ELF with base address 0.
 * Relocated by kernel ELF loader at load time.
 */

OUTPUT_FORMAT(elf64-littleaarch64)
OUTPUT_ARCH(aarch64)
ENTRY(_start)

SECTIONS
{
    . = 0;

    .text ALIGN(4K) : {
        *(.text .text.*)
    }

    .rodata ALIGN(4K) : {
        *(.rodata .rodata.*)
    }

    .data.rel.ro ALIGN(8) : {
        *(.data.rel.ro .data.rel.ro.*)
        *(.got)
        *(.got.plt)
    }

    .dynamic : { *(.dynamic) }
    .rela.dyn : { *(.rela.dyn) *(.rela.plt) }

    . = ALIGN(4K);

    .data : {
        *(.data .data.*)
    }

    .bss ALIGN(4K) : {
        *(.bss .bss.*)
        *(COMMON)
    }

    /DISCARD/ : {
        *(.comment)
        *(.note.*)
        *(.eh_frame*)
    }
}
