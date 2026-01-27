/* SaltyOS Stage 1 EFI Linker Script
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Linker script for PE/COFF EFI application (ld.lld -m i386pep)
 */

OUTPUT_FORMAT(pei-x86-64)
ENTRY(efi_main)

SECTIONS {
    . = 0x1000;

    .text : ALIGN(0x20) {
        *(.text .text.*)
    }

    .rodata : ALIGN(0x20) {
        *(.rodata .rodata.*)
    }

    .data : ALIGN(0x20) {
        *(.data .data.*)
        *(.bss .bss.*)
        *(COMMON)
    }

    .reloc : ALIGN(0x20) {
        *(.reloc)
    }

    /DISCARD/ : {
        *(.comment)
        *(.note.*)
        *(.eh_frame*)
        *(.gnu.hash)
        *(.dynsym)
        *(.dynstr)
    }
}
