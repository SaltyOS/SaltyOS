/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SYS_MMAN_H__
#define __SYS_MMAN_H__

#include <sys/types.h>

#define PROT_NONE   0x0
#define PROT_READ   0x1
#define PROT_WRITE  0x2
#define PROT_EXEC   0x4

#define MAP_SHARED    0x01
#define MAP_PRIVATE   0x02
#define MAP_FIXED     0x10
#define MAP_ANONYMOUS 0x20
#define MAP_ANON      MAP_ANONYMOUS

#define MAP_FAILED ((void *)-1)

#define MS_ASYNC      1
#define MS_INVALIDATE 2
#define MS_SYNC       4

extern void *mmap(void *addr, size_t length, int prot, int flags,
                  int fd, off_t offset);
extern int   munmap(void *addr, size_t length);
extern int   madvise(void *addr, size_t length, int advice);
extern int   mprotect(void *addr, size_t len, int prot);
extern int   msync(void *addr, size_t length, int flags);
extern int   shm_open(const char *name, int oflag, mode_t mode);
extern int   shm_unlink(const char *name);

#endif /* __SYS_MMAN_H__ */
