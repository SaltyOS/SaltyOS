/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SYS_UIO_H__
#define __SYS_UIO_H__

#include <sys/types.h>

struct iovec {
    void   *iov_base;
    size_t  iov_len;
};

#define IOV_MAX 1024

extern ssize_t readv(int fd, const struct iovec *iov, int iovcnt);
extern ssize_t writev(int fd, const struct iovec *iov, int iovcnt);

#endif /* __SYS_UIO_H__ */
