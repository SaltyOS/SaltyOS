/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __LIBUTIL_H__
#define __LIBUTIL_H__

#include <stdio.h>
#include <stdint.h>

int   expand_number(const char *buf, int64_t *num);
char *fgetln(FILE *fp, size_t *lenp);
char *getbsize(int *headerlenp, long *blocksizep);

/* humanize_number flags */
#define HN_DECIMAL      0x01
#define HN_NOSPACE      0x02
#define HN_B            0x04
#define HN_DIVISOR_1000 0x08
#define HN_IEC_PREFIXES 0x10

/* humanize_number scale */
#define HN_GETSCALE     0x10
#define HN_AUTOSCALE    0x20

int humanize_number(char *buf, size_t len, int64_t bytes,
                    const char *suffix, int scale, int flags);
int dehumanize_number(const char *str, int64_t *size);

#endif /* __LIBUTIL_H__ */
