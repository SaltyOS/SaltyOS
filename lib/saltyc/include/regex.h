/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __REGEX_H__
#define __REGEX_H__

#include <stddef.h>

/* Compile flags */
#define REG_EXTENDED 1
#define REG_ICASE    2
#define REG_NOSUB    4
#define REG_NEWLINE  8

/* Error codes */
#define REG_NOMATCH   1
#define REG_BADPAT    2
#define REG_ECOLLATE  3
#define REG_ECTYPE    4
#define REG_EESCAPE   5
#define REG_ESUBREG   6
#define REG_EBRACK    7
#define REG_EPAREN    8
#define REG_EBRACE    9
#define REG_BADBR     10
#define REG_ERANGE    11
#define REG_ESPACE    12
#define REG_BADRPT    13

/* Execution flags */
#define REG_NOTBOL    1
#define REG_NOTEOL    2

typedef struct {
    void  *compiled;
    size_t pattern_len;
    int    cflags;
    size_t re_nsub;
} regex_t;

typedef struct {
    int rm_so;
    int rm_eo;
} regmatch_t;

extern int    regcomp(regex_t *preg, const char *pattern, int cflags);
extern int    regexec(const regex_t *preg, const char *string,
                      size_t nmatch, regmatch_t pmatch[], int eflags);
extern void   regfree(regex_t *preg);
extern size_t regerror(int errcode, const regex_t *preg,
                       char *errbuf, size_t errbuf_size);

#endif /* __REGEX_H__ */
