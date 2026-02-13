/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __INTTYPES_H__
#define __INTTYPES_H__

#include <stdint.h>

typedef long intmax_t;
typedef unsigned long uintmax_t;

extern intmax_t  strtoimax(const char *nptr, char **endptr, int base);
extern uintmax_t strtoumax(const char *nptr, char **endptr, int base);

/* Format macros for printf */
#define PRId8   "d"
#define PRId16  "d"
#define PRId32  "d"
#define PRId64  "ld"
#define PRIi8   "i"
#define PRIi16  "i"
#define PRIi32  "i"
#define PRIi64  "li"
#define PRIu8   "u"
#define PRIu16  "u"
#define PRIu32  "u"
#define PRIu64  "lu"
#define PRIx8   "x"
#define PRIx16  "x"
#define PRIx32  "x"
#define PRIx64  "lx"
#define PRIX8   "X"
#define PRIX16  "X"
#define PRIX32  "X"
#define PRIX64  "lX"
#define PRIo8   "o"
#define PRIo16  "o"
#define PRIo32  "o"
#define PRIo64  "lo"

#define PRIdMAX "ld"
#define PRIuMAX "lu"
#define PRIxMAX "lx"

/* Format macros for scanf */
#define SCNd8   "hhd"
#define SCNd16  "hd"
#define SCNd32  "d"
#define SCNd64  "ld"
#define SCNu8   "hhu"
#define SCNu16  "hu"
#define SCNu32  "u"
#define SCNu64  "lu"

#endif /* __INTTYPES_H__ */
