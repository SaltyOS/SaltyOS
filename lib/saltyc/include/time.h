/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __TIME_H__
#define __TIME_H__

#include <stddef.h>
#include <sys/types.h>

#define CLOCK_REALTIME  0
#define CLOCK_MONOTONIC 1

#define CLK_TCK         100
#define CLOCKS_PER_SEC  1000000

struct timespec {
    long tv_sec;
    long tv_nsec;
};

struct tm {
    int tm_sec;
    int tm_min;
    int tm_hour;
    int tm_mday;
    int tm_mon;
    int tm_year;
    int tm_wday;
    int tm_yday;
    int tm_isdst;
};

extern time_t    time(time_t *tloc);
extern clock_t   clock(void);
extern double    difftime(time_t time1, time_t time0);

extern struct tm *gmtime(const time_t *timep);
extern struct tm *gmtime_r(const time_t *timep, struct tm *result);
extern struct tm *localtime(const time_t *timep);
extern struct tm *localtime_r(const time_t *timep, struct tm *result);
extern time_t    mktime(struct tm *tm);

extern char     *asctime(const struct tm *tm);
extern char     *asctime_r(const struct tm *tm, char *buf);
extern char     *ctime(const time_t *timep);
extern char     *ctime_r(const time_t *timep, char *buf);

extern size_t    strftime(char *s, size_t max, const char *format,
                          const struct tm *tm);

extern int       clock_gettime(clockid_t clk_id, struct timespec *tp);
extern int       clock_settime(clockid_t clk_id, const struct timespec *tp);
extern int       nanosleep(const struct timespec *req, struct timespec *rem);
extern void      tzset(void);
extern char     *tzname[2];
extern long      timezone;
extern int       daylight;

extern time_t    timegm(struct tm *tm);
extern char     *strptime(const char *s, const char *format, struct tm *tm);

#endif /* __TIME_H__ */
