/* FreeBSD compat — Capsicum fileargs wrapper for ported FreeBSD utilities */
/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * cap_fileargs.c — Capsicum fileargs wrapper for SaltyOS
 *
 * Real implementation that wraps POSIX open/fopen. The fileargs_t struct
 * stores the open() flags and mode passed to fileargs_init(), then
 * fileargs_open() calls open() and fileargs_fopen() calls fopen().
 */

#include <casper/cap_fileargs.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

struct fileargs {
    int     flags;
    mode_t  mode;
};

fileargs_t *
fileargs_init(int argc, char *argv[], int flags, mode_t mode, ...)
{
    fileargs_t *fa;

    (void)argc;
    (void)argv;

    fa = (fileargs_t *)malloc(sizeof(*fa));
    if (fa == NULL)
        return NULL;

    fa->flags = flags;
    fa->mode = mode;
    return fa;
}

fileargs_t *
fileargs_cinit(void *casper_cap, int argc, char *argv[], int flags, mode_t mode, ...)
{
    (void)casper_cap;
    (void)argc;
    (void)argv;

    fileargs_t *fa = (fileargs_t *)malloc(sizeof(*fa));
    if (fa == NULL)
        return NULL;

    fa->flags = flags;
    fa->mode = mode;
    return fa;
}

int
fileargs_open(fileargs_t *fa, const char *name)
{
    if (fa == NULL || name == NULL)
        return -1;
    return open(name, fa->flags, fa->mode);
}

FILE *
fileargs_fopen(fileargs_t *fa, const char *name, const char *mode)
{
    (void)fa;
    if (name == NULL || mode == NULL)
        return NULL;
    return fopen(name, mode);
}

char *
fileargs_realpath(fileargs_t *fa, const char *path, char *resolved)
{
    (void)fa;
    return realpath(path, resolved);
}

int
fileargs_lstat(fileargs_t *fa, const char *name, struct stat *sb)
{
    (void)fa;
    return lstat(name, sb);
}

void
fileargs_free(fileargs_t *fa)
{
    free(fa);
}
