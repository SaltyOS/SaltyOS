/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __FCNTL_H__
#define __FCNTL_H__

#include <sys/types.h>

#define O_RDONLY    0x0000
#define O_WRONLY    0x0001
#define O_RDWR      0x0002
#define O_CREAT     0x0100
#define O_TRUNC     0x0200
#define O_APPEND    0x0400
#define O_NONBLOCK  0x0800
#define O_EXCL      0x0080
#define O_NOCTTY    0x0100
#define O_CLOEXEC   0x80000
#define O_DIRECTORY 0x10000
#define O_NOFOLLOW  0x20000

#define O_ACCMODE   (O_RDONLY | O_WRONLY | O_RDWR)

#define F_DUPFD     0
#define F_GETFD     1
#define F_SETFD     2
#define F_GETFL     3
#define F_SETFL     4

#define FD_CLOEXEC  1

#define AT_FDCWD    (-100)

extern int open(const char *pathname, int flags, ...);
extern int fcntl(int fd, int cmd, ...);

#endif /* __FCNTL_H__ */
