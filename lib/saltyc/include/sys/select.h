/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SYS_SELECT_H__
#define __SYS_SELECT_H__

#include <sys/types.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>

#define FD_SETSIZE 1024

typedef struct {
    unsigned long fds_bits[FD_SETSIZE / (8 * sizeof(unsigned long))];
} fd_set;

#define FD_ZERO(set) \
    do { \
        unsigned long *_p = (unsigned long *)(set); \
        for (int _i = 0; _i < (int)(sizeof(fd_set) / sizeof(unsigned long)); _i++) \
            _p[_i] = 0; \
    } while (0)

#define FD_SET(fd, set) \
    ((unsigned long *)(set))[(fd) / (8 * sizeof(unsigned long))] |= \
        (1UL << ((fd) % (8 * sizeof(unsigned long))))

#define FD_CLR(fd, set) \
    ((unsigned long *)(set))[(fd) / (8 * sizeof(unsigned long))] &= \
        ~(1UL << ((fd) % (8 * sizeof(unsigned long))))

#define FD_ISSET(fd, set) \
    (((unsigned long *)(set))[(fd) / (8 * sizeof(unsigned long))] & \
        (1UL << ((fd) % (8 * sizeof(unsigned long)))))

extern int select(int nfds, fd_set *readfds, fd_set *writefds,
                  fd_set *exceptfds, struct timeval *timeout);
extern int pselect(int nfds, fd_set *readfds, fd_set *writefds,
                   fd_set *exceptfds, const struct timespec *timeout,
                   const sigset_t *sigmask);

#endif /* __SYS_SELECT_H__ */
