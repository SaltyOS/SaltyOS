/* libc.so (saltyc) linker script
 * SPDX-License-Identifier: GPL-2.0-only
 */

OUTPUT_FORMAT("elf64-x86-64")
SECTIONS {
    . = SIZEOF_HEADERS;
    .gnu.hash : { *(.gnu.hash) }
    .dynsym   : { *(.dynsym) }
    .dynstr   : { *(.dynstr) }
    .rela.dyn : { *(.rela.dyn) *(.rela.plt) }
    .text     : ALIGN(0x1000) { *(.text .text.*) }
    .rodata   : ALIGN(0x1000) { *(.rodata .rodata.*) }
    .data     : ALIGN(0x1000) { *(.data .data.*) }
    .got      : { *(.got) }
    .dynamic  : { *(.dynamic) }
    .got.plt  : { *(.got.plt) }
    .bss      : ALIGN(0x1000) { *(.bss .bss.* COMMON) }
    /DISCARD/ : { *(.comment) *(.note.*) *(.eh_frame*) }
}
