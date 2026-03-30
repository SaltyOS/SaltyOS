/* Kernite Linker Script (AArch64) */
/* SPDX-License-Identifier: GPL-2.0-only */

OUTPUT_FORMAT(elf64-littleaarch64)
OUTPUT_ARCH(aarch64)
ENTRY(_start)

SECTIONS
{
    . = 0;

    /* Text section (read + execute) */
    .text ALIGN(4K) :
    {
        _text_start = .;
        *(.text.boot)       /* Boot entry point first */
        *(.text .text.*)
        _text_end = .;
    } :text

    /* Read-only data */
    .rodata ALIGN(4K) :
    {
        _rodata_start = .;
        *(.rodata .rodata.*)
        _rodata_end = .;
    } :rodata

    /* Initialized data (read + write) */
    .data ALIGN(4K) :
    {
        _data_start = .;
        *(.data .data.*)
        *(.got)
        *(.got.plt)
        _data_end = .;
    } :data

    /* Dynamic linking info (for PIE relocations) */
    .dynamic : { *(.dynamic) } :data

    /* Relocation entries */
    .rela.dyn : { *(.rela.dyn) *(.rela.plt) } :data

    /* Uninitialized data */
    .bss ALIGN(4K) :
    {
        _bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        _bss_end = .;
    } :data

    /* Kernel end marker */
    . = ALIGN(4K);
    _kernel_end = .;

    /* Discard unnecessary sections */
    /DISCARD/ :
    {
        *(.comment)
        *(.note.*)
        *(.eh_frame*)
    }
}
