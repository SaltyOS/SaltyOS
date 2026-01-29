/* SaltyOS Stage 2 BIOS Memory Map
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * E820 memory map retrieval for BIOS
 */

#include "../common/stage2.h"
#include "../../common/types.h"

/* External assembly helper for E820 call */
extern uint64_t bios_get_e820_map(struct e820_entry *buf, uint64_t max_entries);

/* E820 entry structure (matching BIOS format) */
struct e820_entry {
    uint64_t base;
    uint64_t length;
    uint32_t type;
    uint32_t acpi_attrs;
};

/* E820 memory types */
#define E820_TYPE_USABLE        1
#define E820_TYPE_RESERVED      2
#define E820_TYPE_ACPI_RECLAIM  3
#define E820_TYPE_ACPI_NVS      4
#define E820_TYPE_BAD           5

/* Static buffer for memory map (max 256 entries) */
static struct e820_entry e820_buffer[256];
static struct memory_map_entry mmap_buffer[256];
static size_t mmap_count = 0;

/* Convert E820 type to MemoryKind */
static uint32_t e820_to_memory_kind(uint32_t e820_type) {
    switch (e820_type) {
        case E820_TYPE_USABLE:       return MEMORY_USABLE;
        case E820_TYPE_RESERVED:     return MEMORY_RESERVED;
        case E820_TYPE_ACPI_RECLAIM: return MEMORY_ACPI_RECLAIMABLE;
        case E820_TYPE_ACPI_NVS:     return MEMORY_ACPI_NVS;
        case E820_TYPE_BAD:          return MEMORY_BAD;
        default:                     return MEMORY_RESERVED;
    }
}

/* Get memory map using E820 BIOS interrupt via assembly helper */
int bios_get_memory_map(struct memory_map_entry **map, size_t *count) {
    /* Call assembly helper to get E820 entries */
    uint64_t entries = bios_get_e820_map(e820_buffer, 256);

    /* Convert E820 entries to memory_map_entry format */
    for (size_t i = 0; i < entries; i++) {
        mmap_buffer[i].base = e820_buffer[i].base;
        mmap_buffer[i].length = e820_buffer[i].length;
        mmap_buffer[i].kind = e820_to_memory_kind(e820_buffer[i].type);
        mmap_buffer[i].reserved = 0;
    }

    mmap_count = entries;
    *map = mmap_buffer;
    *count = mmap_count;

    return 0;
}
