/* SaltyOS Minimal libc
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef SALTYOS_LIBC_H
#define SALTYOS_LIBC_H

#include <stdint.h>
#include <stddef.h>

/* String functions */
size_t strlen(const char *s);
char *strcpy(char *dest, const char *src);
char *strncpy(char *dest, const char *src, size_t n);
int strcmp(const char *s1, const char *s2);
int strncmp(const char *s1, const char *s2, size_t n);
char *strchr(const char *s, int c);

/* Memory functions */
void *memcpy(void *dest, const void *src, size_t n);
void *memset(void *s, int c, size_t n);
void *memmove(void *dest, const void *src, size_t n);
int memcmp(const void *s1, const void *s2, size_t n);

#endif /* SALTYOS_LIBC_H */
