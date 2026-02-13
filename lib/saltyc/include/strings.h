/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __STRINGS_H__
#define __STRINGS_H__

#include <stddef.h>

extern int  strcasecmp(const char *s1, const char *s2);
extern int  strncasecmp(const char *s1, const char *s2, size_t n);
extern void bcopy(const void *src, void *dest, size_t n);
extern void bzero(void *s, size_t n);
extern int  ffs(int i);

#endif /* __STRINGS_H__ */
