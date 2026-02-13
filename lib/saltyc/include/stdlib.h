/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __STDLIB_H__
#define __STDLIB_H__

#include <stddef.h>
#include <sys/types.h>

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1
#define RAND_MAX     0x7FFFFFFF
#define MB_CUR_MAX   1

typedef struct {
    int quot;
    int rem;
} div_t;

typedef struct {
    long quot;
    long rem;
} ldiv_t;

typedef struct {
    long long quot;
    long long rem;
} lldiv_t;

extern void *malloc(size_t size);
extern void  free(void *ptr);
extern void *realloc(void *ptr, size_t size);
extern void *calloc(size_t nmemb, size_t size);
extern int   posix_memalign(void **memptr, size_t alignment, size_t size);

extern void  exit(int status);
extern void  _exit(int status);
extern void  _Exit(int status);
extern void  abort(void);
extern int   atexit(void (*function)(void));

extern int       atoi(const char *nptr);
extern long      atol(const char *nptr);
extern long long atoll(const char *nptr);

extern long          strtol(const char *nptr, char **endptr, int base);
extern unsigned long strtoul(const char *nptr, char **endptr, int base);
extern long long     strtoll(const char *nptr, char **endptr, int base);
extern unsigned long long strtoull(const char *nptr, char **endptr, int base);
extern double        strtod(const char *nptr, char **endptr);
extern float         strtof(const char *nptr, char **endptr);
extern long double   strtold(const char *nptr, char **endptr);

extern int  abs(int j);
extern long labs(long j);
extern long long llabs(long long j);

extern div_t   div(int numer, int denom);
extern ldiv_t  ldiv(long numer, long denom);
extern lldiv_t lldiv(long long numer, long long denom);

extern int  rand(void);
extern void srand(unsigned int seed);
extern int  rand_r(unsigned int *seedp);
extern long random(void);
extern void srandom(unsigned int seed);

extern char *getenv(const char *name);
extern int   setenv(const char *name, const char *value, int overwrite);
extern int   unsetenv(const char *name);
extern int   putenv(char *string);
extern int   clearenv(void);

extern void  qsort(void *base, size_t nmemb, size_t size,
                    int (*compar)(const void *, const void *));
extern void *bsearch(const void *key, const void *base, size_t nmemb,
                     size_t size,
                     int (*compar)(const void *, const void *));

extern char *mktemp(char *tmpl);
extern char *mkdtemp(char *tmpl);
extern char *realpath(const char *path, char *resolved_path);
extern int   system(const char *command);

extern char **environ;

/* BSD extensions */
extern const char *getprogname(void);
extern void        setprogname(const char *name);
extern void        strmode(int mode, char *bp);
extern void       *setmode(const char *mode_str);
extern mode_t      getmode(const void *set, mode_t omode);

/* BSD file flag stubs */
extern char       *fflagstostr(unsigned long flags);

#endif /* __STDLIB_H__ */
