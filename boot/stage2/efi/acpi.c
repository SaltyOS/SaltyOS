/* SaltyOS Stage 2 EFI ACPI
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Find RSDP from EFI configuration tables
 */

#include "efi.h"
#include <types.h>

/* EFI system table pointer (set by entry point) */
static EFI_SYSTEM_TABLE *g_st = NULL;

/* ACPI GUIDs */
static EFI_GUID acpi_20_guid = ACPI_20_TABLE_GUID;
static EFI_GUID acpi_guid = ACPI_TABLE_GUID;

/* Find RSDP in EFI configuration tables */
uint64_t efi_find_rsdp(void) {
    EFI_CONFIGURATION_TABLE *config_table;
    uint64_t n_entries;

    if (!g_st) {
        return 0;
    }

    config_table = (EFI_CONFIGURATION_TABLE *)g_st->configuration_table;
    n_entries = g_st->number_of_table_entries;

    for (uint64_t i = 0; i < n_entries; i++) {
        /* Try ACPI 2.0 GUID first */
        if (config_table[i].vendor_guid.data1 == acpi_20_guid.data1 &&
            config_table[i].vendor_guid.data2 == acpi_20_guid.data2 &&
            config_table[i].vendor_guid.data3 == acpi_20_guid.data3 &&
            config_table[i].vendor_guid.data4[0] == acpi_20_guid.data4[0]) {
            return (uint64_t)config_table[i].vendor_table;
        }

        /* Fallback to ACPI 1.0 GUID */
        if (config_table[i].vendor_guid.data1 == acpi_guid.data1 &&
            config_table[i].vendor_guid.data2 == acpi_guid.data2 &&
            config_table[i].vendor_guid.data3 == acpi_guid.data3 &&
            config_table[i].vendor_guid.data4[0] == acpi_guid.data4[0]) {
            return (uint64_t)config_table[i].vendor_table;
        }
    }

    return 0;
}

/* Initialize EFI context for ACPI operations */
void efi_acpi_init(EFI_SYSTEM_TABLE *st) {
    g_st = st;
}

/* Get RSDP callback for stage2 context */
static uint64_t efi_find_rsdp_callback(void) {
    return efi_find_rsdp();
}

/* Get RSDP callback function */
uint64_t (*efi_find_rsdp_fn_ptr)(void) = efi_find_rsdp_callback;

