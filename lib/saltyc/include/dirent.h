/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __DIRENT_H__
#define __DIRENT_H__

#include <sys/types.h>

struct dirent {
    unsigned long  d_ino;
    long           d_off;
    unsigned short d_reclen;
    unsigned char  d_type;
    unsigned char  d_pad0;
    unsigned short d_namlen;
    unsigned short d_pad1;
    char           d_name[256];
};

/* File type values for d_type */
#define DT_UNKNOWN  0
#define DT_FIFO     1
#define DT_CHR      2
#define DT_DIR      4
#define DT_BLK      6
#define DT_REG      8
#define DT_LNK      10
#define DT_SOCK     12

typedef struct __DIR DIR;

extern DIR           *opendir(const char *name);
extern struct dirent *readdir(DIR *dirp);
extern int            closedir(DIR *dirp);
extern int            dirfd(DIR *dirp);
extern void           rewinddir(DIR *dirp);

#endif /* __DIRENT_H__ */
