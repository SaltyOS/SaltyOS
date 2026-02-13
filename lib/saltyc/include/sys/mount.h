/* SPDX-License-Identifier: GPL-2.0-only */
/* mount/statfs compatibility — VFS doesn't expose filesystem statistics */
#ifndef __SYS_MOUNT_H__
#define __SYS_MOUNT_H__

#include <sys/types.h>
#include <errno.h>

#define MFSNAMELEN  16
#define MNAMELEN    88
#define MAXPATHLEN  4096

#define MNT_RDONLY      0x00000001
#define MNT_NOSUID      0x00000008
#define MNT_NOEXEC      0x00000004
#define MNT_LOCAL       0x00001000

struct statfs {
    unsigned int f_version;
    unsigned int f_type;
    unsigned long f_flags;
    unsigned long f_bsize;
    unsigned long f_iosize;
    unsigned long f_blocks;
    unsigned long f_bfree;
    long          f_bavail;
    unsigned long f_files;
    long          f_ffree;
    unsigned long f_syncwrites;
    unsigned long f_asyncwrites;
    unsigned long f_syncreads;
    unsigned long f_asyncreads;
    unsigned long f_namemax;
    uid_t         f_owner;
    int           f_fsid;        /* simplified */
    char          f_fstypename[MFSNAMELEN];
    char          f_mntfromname[MNAMELEN];
    char          f_mntonname[MNAMELEN];
};

static inline int
statfs(const char *path, struct statfs *buf)
{
    (void)path; (void)buf;
    errno = ENOSYS;
    return -1;
}

static inline int
fstatfs(int fd, struct statfs *buf)
{
    (void)fd; (void)buf;
    errno = ENOSYS;
    return -1;
}

static inline struct statfs *
getmntinfo(struct statfs **mntbufp, int mode)
{
    (void)mntbufp; (void)mode;
    return (struct statfs *)0;
}

#endif /* __SYS_MOUNT_H__ */
