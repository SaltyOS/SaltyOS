/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SYS_STAT_H__
#define __SYS_STAT_H__

#include <sys/types.h>
#include <time.h>

struct stat {
    unsigned long st_dev;
    unsigned long st_ino;
    unsigned long st_nlink;
    mode_t        st_mode;
    short         st_padding0;
    unsigned int  st_uid;
    unsigned int  st_gid;
    int           st_padding1;
    unsigned long st_rdev;
    struct timespec st_atim;
    struct timespec st_mtim;
    struct timespec st_ctim;
    struct timespec st_birthtim;
    long          st_size;
    long          st_blocks;
    int           st_blksize;
    unsigned int  st_flags;
    unsigned long st_gen;
    unsigned long st_spare[10];
};

#define st_atime         st_atim.tv_sec
#define st_atime_nsec    st_atim.tv_nsec
#define st_mtime         st_mtim.tv_sec
#define st_mtime_nsec    st_mtim.tv_nsec
#define st_ctime         st_ctim.tv_sec
#define st_ctime_nsec    st_ctim.tv_nsec
#define st_birthtime     st_birthtim.tv_sec
#define st_birthtime_nsec st_birthtim.tv_nsec
#define st_birthtimespec st_birthtim

/* BSD file flag constants */
#define UF_SETTABLE     0x0000ffff
#define UF_NODUMP       0x00000001
#define UF_IMMUTABLE    0x00000002
#define UF_APPEND       0x00000004
#define UF_NOUNLINK     0x00000010
#define UF_OPAQUE       0x00000008
#define SF_SETTABLE     0xffff0000
#define SF_ARCHIVED     0x00010000
#define SF_IMMUTABLE    0x00020000
#define SF_APPEND       0x00040000
#define SF_NOUNLINK     0x00100000

#define DEFFILEMODE     (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | \
                         S_IROTH | S_IWOTH)
#define ACCESSPERMS     (S_IRWXU | S_IRWXG | S_IRWXO)
#define ALLPERMS        (S_ISUID | S_ISGID | S_ISVTX | S_IRWXU | \
                         S_IRWXG | S_IRWXO)

/* File type bits */
#define S_IFMT   0170000
#define S_IFSOCK 0140000
#define S_IFLNK  0120000
#define S_IFREG  0100000
#define S_IFBLK  0060000
#define S_IFDIR  0040000
#define S_IFCHR  0020000
#define S_IFIFO  0010000
#define S_IFWHT  0160000

/* File type test macros */
#define S_ISREG(m)  (((m) & S_IFMT) == S_IFREG)
#define S_ISDIR(m)  (((m) & S_IFMT) == S_IFDIR)
#define S_ISCHR(m)  (((m) & S_IFMT) == S_IFCHR)
#define S_ISBLK(m)  (((m) & S_IFMT) == S_IFBLK)
#define S_ISFIFO(m) (((m) & S_IFMT) == S_IFIFO)
#define S_ISLNK(m)  (((m) & S_IFMT) == S_IFLNK)
#define S_ISSOCK(m) (((m) & S_IFMT) == S_IFSOCK)

/* Permission bits */
#define S_ISUID  04000
#define S_ISGID  02000
#define S_ISVTX  01000

#define S_IRUSR  0400
#define S_IWUSR  0200
#define S_IXUSR  0100
#define S_IRWXU  0700

#define S_IRGRP  040
#define S_IWGRP  020
#define S_IXGRP  010
#define S_IRWXG  070

#define S_IROTH  04
#define S_IWOTH  02
#define S_IXOTH  01
#define S_IRWXO  07

extern int stat(const char *pathname, struct stat *statbuf);
extern int lstat(const char *pathname, struct stat *statbuf);
extern int fstat(int fd, struct stat *statbuf);
extern mode_t umask(mode_t mask);
extern int chmod(const char *pathname, mode_t mode);
extern int fchmod(int fd, mode_t mode);
extern int mkdir(const char *pathname, mode_t mode);

#define UTIME_NOW   ((1 << 30) - 1)
#define UTIME_OMIT  ((1 << 30) - 2)

extern int fstatat(int dirfd, const char *pathname, struct stat *statbuf,
                   int flags);
extern int mkdirat(int dirfd, const char *pathname, mode_t mode);
extern int mknodat(int dirfd, const char *pathname, mode_t mode, dev_t dev);
extern int fchmodat(int dirfd, const char *pathname, mode_t mode, int flags);
extern int utimensat(int dirfd, const char *pathname,
                     const struct timespec times[2], int flags);
extern int futimens(int fd, const struct timespec times[2]);

#endif /* __SYS_STAT_H__ */
