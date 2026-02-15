/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SYS_PARAM_H__
#define __SYS_PARAM_H__

#include <limits.h>

#define MAXPATHLEN PATH_MAX
#define MAXHOSTNAMELEN 64
#define MAXNAMLEN       255

#define NBBY            8       /* bits per byte */
#define MAXBSIZE        65536
#define DEV_BSIZE       512
#define MAXLOGNAME      17
#define MAXPHYS         131072

#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#define MAX(a, b) (((a) > (b)) ? (a) : (b))

#define howmany(x, y)   (((x) + ((y) - 1)) / (y))
#define roundup(x, y)   ((((x) + ((y) - 1)) / (y)) * (y))
#define nitems(x)       (sizeof((x)) / sizeof((x)[0]))

#ifndef __unused
#define __unused        __attribute__((unused))
#endif
#ifndef __dead2
#define __dead2         __attribute__((noreturn))
#endif
#ifndef __printf0like
#define __printf0like(a,b) __attribute__((format(printf,a,b)))
#endif

#endif /* __SYS_PARAM_H__ */
