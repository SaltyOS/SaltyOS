/* SaltyOS Kernel Linker Script - PIE (ET_DYN), low VMA */

OUTPUT_FORMAT(elf64-x86-64)
ENTRY(_start)

/* Define Program Headers for proper ELF loading */
PHDRS
{
    text    PT_LOAD    FLAGS(0x5);  /* PF_X | PF_R */
    rodata  PT_LOAD    FLAGS(0x4);  /* PF_R */
    data    PT_LOAD    FLAGS(0x6);  /* PF_R | PF_W */
    dynamic PT_DYNAMIC FLAGS(0x4);  /* PF_R */
}

SECTIONS
{
    /* Place everything at a low virtual address so the bootloader can slide
     * the image to KERNEL_VIRT_BASE dynamically. */
    . = 0;

    /* Text */
    .text :
    {
        /* Keep _start first - it's the entry point */
        KEEP(*(.text._start))
        *(.text .text.*)
    } :text

    /* Read-only data */
    . = ALIGN(0x1000);
    .rodata :
    {
        *(.rodata .rodata.*)
    } :rodata

    .dynsym :
    {
        *(.dynsym)
    } :rodata

    .dynstr :
    {
        *(.dynstr)
    } :rodata

    /* Data section - read-write */
    . = ALIGN(0x1000);
    .data :
    {
        *(.data .data.*)
        *(.got .got.*)
        *(.got.plt .got.plt.*)
    } :data

    /* Dynamic linking/relocation sections for PIE */
    . = ALIGN(0x1000);
    .dynamic :
    {
        *(.dynamic)
    } :data :dynamic

    .rela.dyn :
    {
        *(.rela.dyn .rela.dyn.*)
        *(.rela.plt .rela.plt.*)
    } :rodata

    /* BSS section */
    . = ALIGN(0x1000);
    .bss :
    {
        *(COMMON)
        *(.bss .bss.*)
    } :data

    /* Discard unwind info and other sections we don't need */
    /DISCARD/ :
    {
        *(.eh_frame*)
        *(.eh_frame_hdr*)
        *(.note*)
        *(.note.GNU-stack)
        *(.note.gnu.build-id)
        *(.gnu_debuglink)
        *(.interp)
        *(.hash)
        *(.gnu.hash)
        *(.comment)
    }
}
