/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __MNTENT_H__
#define __MNTENT_H__

#include <stdio.h>

#define MOUNTED "/etc/mtab"
#define _PATH_MOUNTED "/etc/mtab"
#define _PATH_MNTTAB  "/etc/fstab"

struct mntent {
    char *mnt_fsname;
    char *mnt_dir;
    char *mnt_type;
    char *mnt_opts;
    int   mnt_freq;
    int   mnt_passno;
};

extern FILE *setmntent(const char *filename, const char *type);
extern struct mntent *getmntent(FILE *stream);
extern int endmntent(FILE *stream);
extern char *hasmntopt(const struct mntent *mnt, const char *opt);

#endif /* __MNTENT_H__ */
