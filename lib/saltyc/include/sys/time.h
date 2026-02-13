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

#define ITIMER_REAL    0
#define ITIMER_VIRTUAL 1
#define ITIMER_PROF    2

struct itimerval {
    struct timeval it_interval;
    struct timeval it_value;
};

extern int setitimer(int which, const struct itimerval *new_value,
                     struct itimerval *old_value);
extern int getitimer(int which, struct itimerval *curr_value);

#endif /* __SYS_TIME_H__ */
