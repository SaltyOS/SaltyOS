/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __GRP_H__
#define __GRP_H__

#include <sys/types.h>

struct group {
    char        *gr_name;
    char        *gr_passwd;
    gid_t        gr_gid;
    char       **gr_mem;
};

extern struct group *getgrnam(const char *name);
extern struct group *getgrgid(gid_t gid);
extern struct group *getgrent(void);
extern void          setgrent(void);
extern void          endgrent(void);
extern int           getgrgid_r(gid_t gid, struct group *grp,
                                char *buf, size_t buflen,
                                struct group **result);
extern int           getgrnam_r(const char *name, struct group *grp,
                                char *buf, size_t buflen,
                                struct group **result);

#endif /* __GRP_H__ */
