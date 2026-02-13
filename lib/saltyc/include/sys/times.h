/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SYS_TIMES_H__
#define __SYS_TIMES_H__

#include <sys/types.h>

struct tms {
    clock_t tms_utime;
    clock_t tms_stime;
    clock_t tms_cutime;
    clock_t tms_cstime;
};

extern clock_t times(struct tms *buf);

#endif /* __SYS_TIMES_H__ */
