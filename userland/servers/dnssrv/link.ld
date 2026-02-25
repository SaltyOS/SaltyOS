/* SaltyOS dnssrv - dynamically linked PIE linker script
 * SPDX-License-Identifier: GPL-2.0-only
 */

OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

SECTIONS
{
    . = SIZEOF_HEADERS;

    .interp       : { *(.interp) }
    .gnu.hash     : { *(.gnu.hash) }
    .dynsym       : { *(.dynsym) }
    .dynstr       : { *(.dynstr) }
    .rela.dyn     : { *(.rela.dyn) }
    .rela.plt     : { *(.rela.plt) }

    .plt ALIGN(16) : { *(.plt .plt.*) }

    .text ALIGN(4K) : {
        *(.text .text.*)
    }

    .rodata ALIGN(4K) : {
        *(.rodata .rodata.*)
    }

    .data ALIGN(4K) : {
        *(.data .data.*)
    }

    .got      : { *(.got) }
    .dynamic  : { *(.dynamic) }
    .got.plt  : { *(.got.plt) }

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
