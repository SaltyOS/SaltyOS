/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SYS_TIME_H__
#define __SYS_TIME_H__

#include <sys/types.h>

#ifndef __TIMEVAL_DEFINED__
#define __TIMEVAL_DEFINED__
struct timeval {
    long tv_sec;
    long tv_usec;
};
#endif

struct timezone {
    int tz_minuteswest;
    int tz_dsttime;
};

extern int gettimeofday(struct timeval *tv, void *tz);

#endif /* __SYS_TIME_H__ */
