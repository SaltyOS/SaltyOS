/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __ERRNO_H__
#define __ERRNO_H__

extern int *__errno_location(void);
#define errno (*__errno_location())

#define EPERM           1
#define ENOENT          2
#define ESRCH           3
#define EINTR           4
#define EIO             5
#define ENXIO           6
#define E2BIG           7
#define ENOEXEC         8
#define EBADF           9
#define ECHILD          10
#define EAGAIN          11
#define ENOMEM          12
#define EACCES          13
#define EFAULT          14
#define EBUSY           16
#define EEXIST          17
#define EXDEV           18
#define ENODEV          19
#define ENOTDIR         20
#define EISDIR          21
#define EINVAL          22
#define ENFILE          23
#define EMFILE          24
#define ENOTTY          25
#define EFBIG           27
#define ENOSPC          28
#define ESPIPE          29
#define EROFS           30
#define EMLINK          31
#define EPIPE           32
#define EDOM            33
#define ERANGE          34
#define ENAMETOOLONG    36
#define ENOSYS          38
#define ENOTEMPTY       39
#define ELOOP           40
#define EWOULDBLOCK     EAGAIN
#define EOVERFLOW       75
#define EILSEQ          84
#define ENOTSOCK        88
#define EADDRINUSE      98
#define ECONNREFUSED    111
#define EDEADLK         35
#define ENOLCK          37
#define ENODATA         61
#define ETIME           62
#define EPROTO          71
#define EMULTIHOP       72
#define EBADMSG         74
#define EOPNOTSUPP      95
#define ENOTSUP         EOPNOTSUPP
#define EAFNOSUPPORT    97
#define ECONNRESET      104
#define ENOBUFS         105
#define EISCONN         106
#define ENOTCONN        107
#define ETIMEDOUT       110
#define EALREADY        114
#define EINPROGRESS     115
#define ECANCELED       125
#define EOWNERDEAD      130
#define ENOTRECOVERABLE 131

#endif /* __ERRNO_H__ */
