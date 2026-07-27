/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SaltyOS Bootloader - UEFI Print Utilities
 *
 * Common print functions for UEFI stages using ConOut.
 * Call efi_print_init() once with the EFI_SYSTEM_TABLE before use.
 */

#ifndef BOOT_COMMON_EFI_PRINT_H
#define BOOT_COMMON_EFI_PRINT_H

#include "efi_protocol.h"
#include "efi_types.h"

/*
 * Initialize the UEFI print subsystem.
 *
 * @param systable: EFI_SYSTEM_TABLE pointer
 */
void efi_print_init(EFI_SYSTEM_TABLE *systable);

/*
 * Print a wide string to the UEFI console.
 */
void efi_print(CHAR16 *str);

/*
 * Print a 64-bit value as 16-digit hex.
 */
void efi_print_hex(uint64_t value);

/*
 * Print a 64-bit value as decimal.
 */
void efi_print_dec(uint64_t value);

/*
 * Print an error message with EFI_STATUS.
 */
void efi_print_error(CHAR16 *msg, EFI_STATUS status);

#endif /* BOOT_COMMON_EFI_PRINT_H */
