/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SaltyOS Bootloader - GDT Setup
 *
 * Global Descriptor Table configuration for x86/x86_64.
 * The GDT is set up in entry.asm for the boot process.
 */

#ifndef BOOT_STAGE2_BIOS_GDT_H
#define BOOT_STAGE2_BIOS_GDT_H

#include "../../../../common/types.h"

/* GDT segment selectors */
#define GDT_NULL 0x00
#define GDT_CODE32 0x08
#define GDT_DATA32 0x10
#define GDT_CODE64 0x18
#define GDT_DATA64 0x20

/* GDT entry structure */
struct GDTEntry {
  uint16_t limit_low;
  uint16_t base_low;
  uint8_t base_middle;
  uint8_t access;
  uint8_t granularity;
  uint8_t base_high;
} PACKED;

/* GDT pointer structure */
struct GDTPointer {
  uint16_t limit;
  uint64_t base;
} PACKED;

/* Access byte flags */
#define GDT_ACCESS_PRESENT (1 << 7)
#define GDT_ACCESS_RING0 (0 << 5)
#define GDT_ACCESS_RING3 (3 << 5)
#define GDT_ACCESS_SYSTEM (0 << 4)
#define GDT_ACCESS_CODEDATA (1 << 4)
#define GDT_ACCESS_EXECUTABLE (1 << 3)
#define GDT_ACCESS_DC (1 << 2) /* Direction/Conforming */
#define GDT_ACCESS_RW (1 << 1) /* Readable/Writable */
#define GDT_ACCESS_ACCESSED (1 << 0)

/* Granularity byte flags */
#define GDT_GRAN_4K (1 << 7)
#define GDT_GRAN_32BIT (1 << 6)
#define GDT_GRAN_64BIT (1 << 5)

/* Initialize GDT with standard entries */
void gdt_init(void);

/* Load GDT */
void gdt_load(struct GDTPointer *gdtr);

#endif /* BOOT_STAGE2_BIOS_GDT_H */
