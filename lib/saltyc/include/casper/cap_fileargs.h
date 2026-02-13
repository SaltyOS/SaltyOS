/* SPDX-License-Identifier: GPL-2.0-only */
/* Capsicum fileargs — wraps POSIX open/fopen on SaltyOS */
#ifndef __CASPER_CAP_FILEARGS_H__
#define __CASPER_CAP_FILEARGS_H__

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>

typedef struct fileargs fileargs_t;

#define FA_OPEN     0x0001
#define FA_REALPATH 0x0002
#define FA_LSTAT    0x0004

fileargs_t *fileargs_init(int argc, char *argv[], int flags, mode_t mode, ...);
fileargs_t *fileargs_cinit(void *casper_cap, int argc, char *argv[],
                           int flags, mode_t mode, ...);
int         fileargs_open(fileargs_t *fa, const char *name);
FILE       *fileargs_fopen(fileargs_t *fa, const char *name, const char *mode);
char       *fileargs_realpath(fileargs_t *fa, const char *path, char *resolved);
int         fileargs_lstat(fileargs_t *fa, const char *name, struct stat *sb);
void        fileargs_free(fileargs_t *fa);

#endif /* __CASPER_CAP_FILEARGS_H__ */
