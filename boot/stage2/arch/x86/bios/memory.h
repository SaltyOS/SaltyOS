/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SaltyOS Bootloader - Memory Map Collection (E820)
 *
 * Collects memory map via BIOS INT 15h, E820h.
 * The primary collection is done in entry.asm.
 */

#ifndef BOOT_STAGE2_BIOS_MEMORY_H
#define BOOT_STAGE2_BIOS_MEMORY_H

#include "../../../../common/types.h"
#include "../../../../common/stage2_info.h"

/* E820 memory types */
#define E820_USABLE     1
#define E820_RESERVED   2
#define E820_ACPI_RECL  3
#define E820_ACPI_NVS   4
#define E820_BAD        5

/*
 * Get memory map entry count
 * Returns: Number of E820 entries collected
 */
uint32_t memory_get_entry_count(void);

/*
 * Get pointer to memory map entries
 * Returns: Pointer to array of E820Entry structures
 */
struct E820Entry *memory_get_entries(void);

/*
 * Find a usable memory region of at least 'size' bytes
 * aligned to 'align' boundary, starting at or after 'min_addr'.
 *
 * Returns: Physical address of region, or 0 if not found
 */
uint64_t memory_find_usable(uint64_t min_addr, uint64_t size, uint64_t align);

/*
 * Print memory map (for debugging)
 */
void memory_print_map(void);

#endif /* BOOT_STAGE2_BIOS_MEMORY_H */
