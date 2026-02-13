/* SPDX-License-Identifier: GPL-2.0-only */
/* ACL compatibility — SaltyOS has no ACL subsystem */
#ifndef __SYS_ACL_H__
#define __SYS_ACL_H__

#include <sys/types.h>

typedef void *acl_t;
typedef int   acl_type_t;
typedef int   acl_tag_t;
typedef void *acl_entry_t;
typedef void *acl_permset_t;
typedef int   acl_perm_t;
typedef int   acl_flag_t;
typedef void *acl_flagset_t;
typedef int   acl_entry_type_t;

#define ACL_TYPE_ACCESS         0x0000
#define ACL_TYPE_DEFAULT        0x0001
#define ACL_TYPE_NFS4           0x0002
#define ACL_BRAND_UNKNOWN       0
#define ACL_BRAND_POSIX         1
#define ACL_BRAND_NFS4          2

#include <errno.h>

static inline acl_t acl_get_link_np(const char *path, acl_type_t type)
{ (void)path; (void)type; return (acl_t)0; }

static inline acl_t acl_get_fd(int fd)
{ (void)fd; errno = EOPNOTSUPP; return (acl_t)0; }

static inline acl_t acl_get_fd_np(int fd, acl_type_t type)
{ (void)fd; (void)type; errno = EOPNOTSUPP; return (acl_t)0; }

static inline acl_t acl_get_file(const char *path, acl_type_t type)
{ (void)path; (void)type; errno = EOPNOTSUPP; return (acl_t)0; }

static inline int acl_set_fd(int fd, acl_t acl)
{ (void)fd; (void)acl; errno = EOPNOTSUPP; return -1; }

static inline int acl_set_fd_np(int fd, acl_t acl, acl_type_t type)
{ (void)fd; (void)acl; (void)type; errno = EOPNOTSUPP; return -1; }

static inline int acl_set_file(const char *path, acl_type_t type, acl_t acl)
{ (void)path; (void)type; (void)acl; errno = EOPNOTSUPP; return -1; }

static inline int acl_set_link_np(const char *path, acl_type_t type, acl_t acl)
{ (void)path; (void)type; (void)acl; errno = EOPNOTSUPP; return -1; }

static inline int acl_is_trivial_np(acl_t acl, int *trivialp)
{ (void)acl; if (trivialp) *trivialp = 1; return 0; }

static inline int acl_get_brand_np(acl_t acl, int *brand)
{ (void)acl; if (brand) *brand = ACL_BRAND_UNKNOWN; return 0; }

static inline int acl_get_entry(acl_t acl, int entry_id, acl_entry_t *entry_p)
{ (void)acl; (void)entry_id; (void)entry_p; return 0; /* no entries */ }

static inline void acl_free(void *obj_p)
{ (void)obj_p; }

static inline char *acl_to_text(acl_t acl, ssize_t *len_p)
{ (void)acl; if (len_p) *len_p = 0; return (char *)0; }

static inline char *acl_to_text_np(acl_t acl, ssize_t *len_p, int flags)
{ (void)acl; (void)flags; if (len_p) *len_p = 0; return (char *)0; }

static inline acl_t acl_dup(acl_t acl)
{ (void)acl; return (acl_t)0; }

static inline acl_t acl_from_text(const char *buf)
{ (void)buf; errno = EOPNOTSUPP; return (acl_t)0; }

static inline int acl_strip_np(acl_t acl, int recalculate)
{ (void)acl; (void)recalculate; return 0; }

#endif /* __SYS_ACL_H__ */
