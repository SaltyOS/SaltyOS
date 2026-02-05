/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SaltyOS Bootloader - GDT Setup (C implementation)
 *
 * Note: The primary GDT setup is in entry.asm.
 * This C implementation provides helpers for Stage 3.
 */

#include "gdt.h"

/* GDT entries (5 entries: null, code32, data32, code64, data64) */
static struct GDTEntry gdt[5] ALIGNED(16);
static struct GDTPointer gdtr;

static void gdt_set_entry(int index, uint32_t base, uint32_t limit,
                          uint8_t access, uint8_t granularity)
{
    gdt[index].limit_low    = limit & 0xFFFF;
    gdt[index].base_low     = base & 0xFFFF;
    gdt[index].base_middle  = (base >> 16) & 0xFF;
    gdt[index].access       = access;
    gdt[index].granularity  = ((limit >> 16) & 0x0F) | (granularity & 0xF0);
    gdt[index].base_high    = (base >> 24) & 0xFF;
}

void gdt_init(void)
{
    /* Null descriptor */
    gdt_set_entry(0, 0, 0, 0, 0);

    /* 32-bit code segment */
    gdt_set_entry(1, 0, 0xFFFFF,
                  GDT_ACCESS_PRESENT | GDT_ACCESS_RING0 | GDT_ACCESS_CODEDATA |
                  GDT_ACCESS_EXECUTABLE | GDT_ACCESS_RW,
                  GDT_GRAN_4K | GDT_GRAN_32BIT);

    /* 32-bit data segment */
    gdt_set_entry(2, 0, 0xFFFFF,
                  GDT_ACCESS_PRESENT | GDT_ACCESS_RING0 | GDT_ACCESS_CODEDATA |
                  GDT_ACCESS_RW,
                  GDT_GRAN_4K | GDT_GRAN_32BIT);

    /* 64-bit code segment */
    gdt_set_entry(3, 0, 0,
                  GDT_ACCESS_PRESENT | GDT_ACCESS_RING0 | GDT_ACCESS_CODEDATA |
                  GDT_ACCESS_EXECUTABLE | GDT_ACCESS_RW,
                  GDT_GRAN_64BIT);

    /* 64-bit data segment */
    gdt_set_entry(4, 0, 0,
                  GDT_ACCESS_PRESENT | GDT_ACCESS_RING0 | GDT_ACCESS_CODEDATA |
                  GDT_ACCESS_RW,
                  0);

    /* Set up GDTR */
    gdtr.limit = sizeof(gdt) - 1;
    gdtr.base = (uint64_t)&gdt;

    gdt_load(&gdtr);
}

void gdt_load(struct GDTPointer *gdtr_ptr)
{
    __asm__ volatile("lgdt %0" : : "m"(*gdtr_ptr));
}
