/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SaltyOS Bootloader - Print Functions
 *
 * Simple output functions for debugging.
 * Output goes to serial port (COM1) and/or VGA text mode.
 */

#ifndef BOOT_COMMON_PRINT_H
#define BOOT_COMMON_PRINT_H

#include "types.h"

/* Output targets */
#define PRINT_TARGET_SERIAL  (1 << 0)
#define PRINT_TARGET_VGA     (1 << 1)
#define PRINT_TARGET_ALL     (PRINT_TARGET_SERIAL | PRINT_TARGET_VGA)

/* Initialize print subsystem */
void print_init(uint32_t targets);

/* Output a single character */
void print_char(char c);

/* Output a null-terminated string */
void print_str(const char *s);

/* Output a hexadecimal number */
void print_hex(uint64_t value, int width);

/* Output a full 64-bit hex value with 0x prefix and all 16 digits */
void print_hex64(uint64_t value);

/* Output a decimal number */
void print_dec(uint64_t value);

/* Output with newline */
void print_line(const char *s);

/* Serial port I/O (x86-specific) */
#define COM1_PORT 0x3F8

void serial_init(void);
void serial_putc(char c);

/* VGA text mode (x86-specific) */
#define VGA_TEXT_BASE 0xB8000
#define VGA_WIDTH     80
#define VGA_HEIGHT    25

void vga_init(void);
void vga_putc(char c);
void vga_clear(void);

#endif /* BOOT_COMMON_PRINT_H */
