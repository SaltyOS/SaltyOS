/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SaltyOS Bootloader - UEFI Print Utilities
 *
 * Common print functions shared across UEFI boot stages.
 */

#include "print.h"

static EFI_SYSTEM_TABLE *g_efi_st;

void efi_print_init(EFI_SYSTEM_TABLE *systable) { g_efi_st = systable; }

void efi_print(CHAR16 *str) {
  if (g_efi_st && g_efi_st->ConOut) {
    g_efi_st->ConOut->OutputString(g_efi_st->ConOut, str);
  }
}

void efi_print_hex(uint64_t value) {
  CHAR16 buf[17];
  static CHAR16 hexchars[] = L"0123456789ABCDEF";

  for (int i = 15; i >= 0; i--) {
    buf[i] = hexchars[value & 0xF];
    value >>= 4;
  }
  buf[16] = 0;
  efi_print(buf);
}

void efi_print_dec(uint64_t value) {
  CHAR16 buf[21];
  int i = 20;
  buf[i] = 0;

  if (value == 0) {
    efi_print(L"0");
    return;
  }

  while (value > 0 && i > 0) {
    buf[--i] = L'0' + (value % 10);
    value /= 10;
  }

  efi_print(&buf[i]);
}

void efi_print_error(CHAR16 *msg, EFI_STATUS status) {
  efi_print(L"Error: ");
  efi_print(msg);
  efi_print(L" (0x");
  efi_print_hex(status);
  efi_print(L")\r\n");
}
