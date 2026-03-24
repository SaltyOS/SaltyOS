/* SaltyOS mmsrv - dynamically linked PIE linker script
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Produces ET_DYN (PIE) ELF with base address 0.
 * Includes PLT/GOT sections for dynamic linking via ld-besalt.so.
 *
 * SIZEOF_HEADERS ensures the ELF header and program headers are placed
 * inside the first PT_LOAD segment, making them accessible at runtime
 * for the dynamic linker (ld-besalt.so) to parse PT_DYNAMIC, PT_PHDR, etc.
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
