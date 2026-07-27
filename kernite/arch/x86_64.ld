/* Kernite Linker Script */
/* SPDX-License-Identifier: GPL-2.0-only */

OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
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
        . = ALIGN(8);
        __kernite_build_info_section_start = .;
        KEEP(*(.rodata.kernite_build_info))
        __kernite_build_info_section_end = .;
        *(.rodata .rodata.*)
        . = ALIGN(8);
        __kallsyms_section_start = .;
        __kallsyms_start = .;
        KEEP(*(.kallsyms.header))
        . = ALIGN(8);
        __kallsyms_entries = .;
        KEEP(*(.kallsyms.entries))
        . = ALIGN(8);
        __kallsyms_strings = .;
        KEEP(*(.kallsyms.strings))
        KEEP(*(.kallsyms))
        . = ALIGN(8);
        __kallsyms_end = .;
        __kallsyms_section_end = .;
        . = ALIGN(8);
        __kernite_unwind_section_start = .;
        KEEP(*(.kernite_unwind))
        __kernite_unwind_section_end = .;
        _rodata_end = .;
    } :rodata

    /* Compact unwind metadata kept for in-kernel panic tracebacks. */
    .eh_frame ALIGN(8) :
    {
        __eh_frame_start = .;
        KEEP(*(.eh_frame))
        __eh_frame_end = .;
    } :rodata

    .eh_frame_hdr ALIGN(8) :
    {
        __eh_frame_hdr_start = .;
        KEEP(*(.eh_frame_hdr))
        __eh_frame_hdr_end = .;
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
    }
}
