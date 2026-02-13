/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __UTIME_H__
#define __UTIME_H__

#include <sys/types.h>

struct utimbuf {
    long actime;
    long modtime;
};

extern int utime(const char *filename, const struct utimbuf *times);

#endif /* __UTIME_H__ */
