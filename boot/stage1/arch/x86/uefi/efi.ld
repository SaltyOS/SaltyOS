/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SaltyOS Bootloader - UEFI Stage 1 Linker Script
 *
 * This linker script creates an ELF shared object that can be
 * converted to PE/COFF format using llvm-objcopy.
 *
 * The resulting EFI application is position-independent and
 * uses the standard PE/COFF section layout expected by UEFI.
 */

OUTPUT_FORMAT("elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
ENTRY(efi_main)

SECTIONS
{
    . = 0;

    ImageBase = .;

    /* PE/COFF header info (for objcopy) */
    .hash : {
        *(.hash)
    }

    /* Code section */
    .text : ALIGN(4096) {
        _text = .;
        *(.text)
        *(.text.*)
        _etext = .;
    }

    /* Read-only data */
    .rodata : ALIGN(4096) {
        _rodata = .;
        *(.rodata)
        *(.rodata.*)
        _erodata = .;
    }

    /* Initialized data */
    .data : ALIGN(4096) {
        _data = .;
        *(.data)
        *(.data.*)
        *(.sdata)
        *(.sdata.*)
        *(.got)
        *(.got.plt)
        _edata = .;
    }

    /* Dynamic linking info (needed for PE conversion) */
    .dynamic : ALIGN(4096) {
        *(.dynamic)
    }

    .dynsym : {
        *(.dynsym)
    }

    .dynstr : {
        *(.dynstr)
    }

    /* Relocation sections */
    .rel.dyn : {
        *(.rel.*)
    }

    .rela.dyn : {
        *(.rela.*)
    }

    /* PE relocation section (filled by objcopy) */
    .reloc : {
        *(.reloc)
    }

    /* BSS (uninitialized data) */
    .bss : ALIGN(4096) {
        _bss = .;
        *(.bss)
        *(.bss.*)
        *(COMMON)
        *(.sbss)
        *(.sbss.*)
        . = ALIGN(4096);
        _bss_end = .;
    }

    _end = .;

    /* Discard debug and other unnecessary sections */
    /DISCARD/ : {
        *(.comment)
        *(.comment.*)
        *(.note)
        *(.note.*)
        *(.eh_frame)
        *(.eh_frame_hdr)
        *(.gnu.hash)
    }
}
