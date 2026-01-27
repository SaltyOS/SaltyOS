/* SaltyOS Boot Print Header
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef SALTYOS_BOOT_PRINT_H
#define SALTYOS_BOOT_PRINT_H

#include "types.h"

void serial_init(void);
void serial_putc(char c);
void serial_puts(const char *s);
void serial_puthex(uint64_t value);
void print(const char *s);
void println(const char *s);

/* Decls for freestanding libc shims (implemented in memory.c) */
void *memset(void *s, int c, size_t n);
void *memcpy(void *dest, const void *src, size_t n);
void *memmove(void *dest, const void *src, size_t n);
int memcmp(const void *s1, const void *s2, size_t n);
size_t strlen(const char *s);

#endif /* SALTYOS_BOOT_PRINT_H */
