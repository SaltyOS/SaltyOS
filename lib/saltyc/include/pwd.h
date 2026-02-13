/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __PWD_H__
#define __PWD_H__

#include <sys/types.h>

struct passwd {
    char        *pw_name;
    char        *pw_passwd;
    uid_t        pw_uid;
    gid_t        pw_gid;
    char        *pw_gecos;
    char        *pw_dir;
    char        *pw_shell;
};

extern struct passwd *getpwnam(const char *name);
extern struct passwd *getpwuid(uid_t uid);
extern struct passwd *getpwent(void);
extern void           setpwent(void);
extern void           endpwent(void);
extern int            getpwuid_r(uid_t uid, struct passwd *pwd,
                                 char *buf, size_t buflen,
                                 struct passwd **result);
extern int            getpwnam_r(const char *name, struct passwd *pwd,
                                 char *buf, size_t buflen,
                                 struct passwd **result);

#endif /* __PWD_H__ */
