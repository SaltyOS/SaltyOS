/* SaltyOS Stage 2 EFI Memory Map
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * EFI memory map handling
 */

#include "efi.h"
#include "../common/stage2.h"

/* EFI system table pointer (set by entry point) */
static EFI_SYSTEM_TABLE *g_st = NULL;

/* Convert EFI memory type to SaltyOS memory kind */
static uint32_t efi_to_memory_kind(uint32_t efi_type) {
    switch (efi_type) {
        case EFI_CONVENTIONAL_MEMORY:
            return MEMORY_USABLE;
        case EFI_LOADER_CODE:
        case EFI_LOADER_DATA:
        case EFI_BOOT_SERVICES_CODE:
        case EFI_BOOT_SERVICES_DATA:
            return MEMORY_BOOTLOADER;
        case EFI_ACPI_RECLAIM_MEMORY:
            return MEMORY_ACPI_RECLAIMABLE;
        case EFI_ACPI_MEMORY_NVS:
            return MEMORY_ACPI_NVS;
        case EFI_RESERVED_MEMORY_TYPE:
        case EFI_UNUSABLE_MEMORY:
        case EFI_MEMORY_MAPPED_IO:
        case EFI_MEMORY_MAPPED_IO_PORT_SPACE:
            return MEMORY_RESERVED;
        default:
            return MEMORY_RESERVED;
    }
}

/* Boot heap for memory map allocation */
static uint8_t memory_map_buffer[0x10000];  /* 64KB */

/* Get memory map from EFI */
int efi_get_memory_map(struct memory_map_entry **map, size_t *count) {
    EFI_STATUS status;
    uintn_t map_size = sizeof(memory_map_buffer);
    uintn_t map_key;
    uintn_t desc_size;
    uint32_t desc_version;
    EFI_MEMORY_DESCRIPTOR *desc;
    struct memory_map_entry *entry;
    int num_entries = 0;

    /* Get memory map */
    status = g_st->boot_services->get_memory_map(
        &map_size,
        (EFI_MEMORY_DESCRIPTOR *)memory_map_buffer,
        &map_key,
        &desc_size,
        &desc_version
    );
    if (status != EFI_SUCCESS) {
        return -1;
    }

    /* Count entries and convert */
    desc = (EFI_MEMORY_DESCRIPTOR *)memory_map_buffer;
    entry = (struct memory_map_entry *)memory_map_buffer;

    for (uintn_t i = 0; i < map_size / desc_size; i++) {
        entry->base = desc->physical_start;
        entry->length = desc->number_of_pages * 4096;
        entry->kind = efi_to_memory_kind(desc->type);
        entry->reserved = 0;

        entry++;
        desc = (EFI_MEMORY_DESCRIPTOR *)((uint8_t *)desc + desc_size);
        num_entries++;
    }

    *map = (struct memory_map_entry *)memory_map_buffer;
    *count = num_entries;

    return 0;
}

/* Initialize EFI context for memory operations */
void efi_memory_init(EFI_SYSTEM_TABLE *st) {
    g_st = st;
}

/* Get memory map callback for stage2 context */
static int efi_get_memory_map_callback(struct memory_map_entry **map, size_t *count) {
    return efi_get_memory_map(map, count);
}

/* Get memory map callback function */
int (*efi_get_memory_map_fn_ptr)(struct memory_map_entry **, size_t *) = efi_get_memory_map_callback;
