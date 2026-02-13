/* SPDX-License-Identifier: GPL-2.0-only */
/* sysctl compatibility — SaltyOS uses sysconf/uname, not sysctl */
#ifndef __SYS_SYSCTL_H__
#define __SYS_SYSCTL_H__

#include <stddef.h>
#include <errno.h>

/* Top-level identifiers */
#define CTL_KERN        1
#define CTL_HW          6

/* CTL_KERN identifiers */
#define KERN_OSTYPE     1
#define KERN_OSRELEASE  2
#define KERN_OSREV      3
#define KERN_VERSION    4
#define KERN_HOSTNAME   10
#define KERN_OSRELDATE  24

/* CTL_HW identifiers */
#define HW_MACHINE      1
#define HW_MODEL        2
#define HW_NCPU         3
#define HW_PAGESIZE     7
#define HW_PHYSMEM      5
#define HW_USERMEM      6
#define HW_MACHINE_ARCH 11

static inline int
sysctl(const int *name, unsigned int namelen, void *oldp,
       size_t *oldlenp, const void *newp, size_t newlen)
{
    (void)name; (void)namelen; (void)oldp;
    (void)oldlenp; (void)newp; (void)newlen;
    errno = ENOSYS;
    return -1;
}

static inline int
sysctlbyname(const char *name, void *oldp, size_t *oldlenp,
             const void *newp, size_t newlen)
{
    (void)name; (void)oldp; (void)oldlenp;
    (void)newp; (void)newlen;
    errno = ENOSYS;
    return -1;
}

static inline int
sysctlnametomib(const char *name, int *mibp, size_t *sizep)
{
    (void)name; (void)mibp; (void)sizep;
    errno = ENOSYS;
    return -1;
}

#endif /* __SYS_SYSCTL_H__ */
