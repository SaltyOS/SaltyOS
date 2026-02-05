/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SaltyOS Bootloader - Memory Map Collection (C implementation)
 *
 * Note: E820 collection is done in entry.asm (real mode).
 * This provides helpers for accessing the collected map in long mode.
 */

#include "memory.h"
#include "../../../../common/print.h"

/* Memory map buffer address (set by entry.asm) */
#define MEMMAP_BUFFER_ADDR  0x30000

/* Memory map structure in buffer:
 * uint32_t count;
 * E820Entry entries[count];
 */

uint32_t memory_get_entry_count(void)
{
    uint32_t *count = (uint32_t *)MEMMAP_BUFFER_ADDR;
    return *count;
}

struct E820Entry *memory_get_entries(void)
{
    return (struct E820Entry *)(MEMMAP_BUFFER_ADDR + 4);
}

uint64_t memory_find_usable(uint64_t min_addr, uint64_t size, uint64_t align)
{
    uint32_t count = memory_get_entry_count();
    struct E820Entry *entries = memory_get_entries();

    for (uint32_t i = 0; i < count; i++) {
        if (entries[i].type != E820_USABLE)
            continue;

        uint64_t base = entries[i].base;
        uint64_t end = base + entries[i].length;

        /* Skip if entirely below min_addr */
        if (end <= min_addr)
            continue;

        /* Adjust base to min_addr if needed */
        if (base < min_addr)
            base = min_addr;

        /* Align base */
        base = ALIGN_UP(base, align);

        /* Check if region is large enough */
        if (base + size <= end)
            return base;
    }

    return 0;
}

void memory_print_map(void)
{
    uint32_t count = memory_get_entry_count();
    struct E820Entry *entries = memory_get_entries();

    print_str("Memory Map (");
    print_dec(count);
    print_line(" entries):");

    for (uint32_t i = 0; i < count; i++) {
        print_str("  ");
        print_hex(entries[i].base, 16);
        print_str(" - ");
        print_hex(entries[i].base + entries[i].length - 1, 16);
        print_str(" (");

        switch (entries[i].type) {
        case E820_USABLE:
            print_str("Usable");
            break;
        case E820_RESERVED:
            print_str("Reserved");
            break;
        case E820_ACPI_RECL:
            print_str("ACPI Reclaim");
            break;
        case E820_ACPI_NVS:
            print_str("ACPI NVS");
            break;
        case E820_BAD:
            print_str("Bad");
            break;
        default:
            print_str("Unknown");
            break;
        }

        print_line(")");
    }
}
