/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SYS_STATVFS_H__
#define __SYS_STATVFS_H__

#include <sys/types.h>

struct statvfs {
    unsigned long f_bsize;
    unsigned long f_frsize;
    unsigned long f_blocks;
    unsigned long f_bfree;
    unsigned long f_bavail;
    unsigned long f_files;
    unsigned long f_ffree;
    unsigned long f_favail;
    unsigned long f_fsid;
    unsigned long f_flag;
    unsigned long f_namemax;
};

extern int statvfs(const char *path, struct statvfs *buf);
extern int fstatvfs(int fd, struct statvfs *buf);

#endif /* __SYS_STATVFS_H__ */
