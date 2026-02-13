/* SPDX-License-Identifier: GPL-2.0-only */
/* Login class compatibility — SaltyOS has no login classes */
#ifndef __LOGIN_CAP_H__
#define __LOGIN_CAP_H__

#include <sys/types.h>

struct passwd;

typedef struct login_cap {
    char *lc_class;
    char *lc_cap;
    char *lc_style;
} login_cap_t;

static inline login_cap_t *
login_getclass(const char *cls)
{ (void)cls; return (login_cap_t *)0; }

static inline login_cap_t *
login_getpwclass(const struct passwd *pwd)
{ (void)pwd; return (login_cap_t *)0; }

static inline login_cap_t *
login_getuserclass(const struct passwd *pwd)
{ (void)pwd; return (login_cap_t *)0; }

static inline void
login_close(login_cap_t *lc)
{ (void)lc; }

static inline void
setclassenvironment(login_cap_t *lc, const struct passwd *pwd, int flags)
{ (void)lc; (void)pwd; (void)flags; }

static inline void
setclassresources(login_cap_t *lc)
{ (void)lc; }

static inline const char *
login_getcapstr(login_cap_t *lc, const char *cap, const char *def,
                const char *err)
{ (void)lc; (void)cap; (void)err; return def; }

static inline int
login_getcapbool(login_cap_t *lc, const char *cap, int def)
{ (void)lc; (void)cap; return def; }

#endif /* __LOGIN_CAP_H__ */
