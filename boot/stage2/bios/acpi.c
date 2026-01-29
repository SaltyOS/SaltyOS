/* SaltyOS Stage 2 BIOS ACPI
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * RSDP (Root System Description Pointer) search for BIOS
 */

#include "../common/stage2.h"
#include "../../common/types.h"

/* RSDP signature */
#define RSDP_SIGNATURE 0x2052545020445352ULL  /* "RSD PTR " */

/* RSDP structure (version 1.0) */
struct rsdp {
    uint64_t signature;     /* "RSD PTR " */
    uint8_t  checksum;
    uint8_t  oem_id[6];
    uint8_t  revision;
    uint32_t rsdt_addr;
    /* Version 2.0+ fields follow */
} __attribute__((packed));

/* Checksum memory range */
static uint8_t checksum_memory(const uint8_t *start, size_t len) {
    uint8_t sum = 0;
    for (size_t i = 0; i < len; i++) {
        sum += start[i];
    }
    return sum;
}

/* Search for RSDP in a given memory range */
static uint64_t search_rsdp_range(uint64_t start, uint64_t end) {
    /* RSDP is aligned on 16-byte boundary */
    for (uint64_t addr = start; addr < end; addr += 16) {
        struct rsdp *rsdp = (struct rsdp *)addr;

        /* Check signature */
        if (rsdp->signature != RSDP_SIGNATURE) {
            continue;
        }

        /* Verify checksum (first 20 bytes for v1.0) */
        if (checksum_memory((uint8_t *)rsdp, 20) != 0) {
            continue;
        }

        /* Found valid RSDP */
        return addr;
    }

    return 0;
}

/* Get RSDP address */
uint64_t bios_get_rsdp(void) {
    uint64_t rsdp_addr = 0;

    /* Search EBDA (Extended BIOS Data Area) first */
    /* EBDA address is stored at 0x40E */
    uint16_t ebda_seg = *(uint16_t *)0x40E;
    uint64_t ebda_base = ebda_seg * 16;
    uint64_t ebda_end = ebda_base + 1024;

    rsdp_addr = search_rsdp_range(ebda_base, ebda_end);
    if (rsdp_addr != 0) {
        return rsdp_addr;
    }

    /* Search main BIOS area (0xE0000..0xFFFFF) */
    rsdp_addr = search_rsdp_range(0xE0000, 0xFFFFF);
    if (rsdp_addr != 0) {
        return rsdp_addr;
    }

    /* Not found */
    return 0;
}
