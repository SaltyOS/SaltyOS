/* SPDX-License-Identifier: GPL-2.0-only */
/* MAC compatibility — SaltyOS has no mandatory access control */
#ifndef __SYS_MAC_H__
#define __SYS_MAC_H__

#include <errno.h>

typedef void *mac_t;

static inline int mac_prepare_ifnet_label(mac_t *label)
{ (void)label; errno = ENOSYS; return -1; }

static inline int mac_prepare_file_label(mac_t *label)
{ (void)label; errno = ENOSYS; return -1; }

static inline int mac_prepare_process_label(mac_t *label)
{ (void)label; errno = ENOSYS; return -1; }

static inline int mac_prepare_type(mac_t *label, const char *type)
{ (void)label; (void)type; errno = ENOSYS; return -1; }

static inline int mac_get_file(const char *path, mac_t label)
{ (void)path; (void)label; errno = ENOSYS; return -1; }

static inline int mac_get_link(const char *path, mac_t label)
{ (void)path; (void)label; errno = ENOSYS; return -1; }

static inline int mac_get_fd(int fd, mac_t label)
{ (void)fd; (void)label; errno = ENOSYS; return -1; }

static inline int mac_get_proc(mac_t *label)
{ (void)label; errno = ENOSYS; return -1; }

static inline int mac_get_pid(int pid, mac_t *label)
{ (void)pid; (void)label; errno = ENOSYS; return -1; }

static inline int mac_set_file(const char *path, mac_t label)
{ (void)path; (void)label; errno = ENOSYS; return -1; }

static inline int mac_set_fd(int fd, mac_t label)
{ (void)fd; (void)label; errno = ENOSYS; return -1; }

static inline int mac_set_proc(mac_t label)
{ (void)label; errno = ENOSYS; return -1; }

static inline int mac_to_text(mac_t label, char **text)
{ (void)label; (void)text; errno = ENOSYS; return -1; }

static inline int mac_from_text(mac_t *label, const char *text)
{ (void)label; (void)text; errno = ENOSYS; return -1; }

static inline void mac_free(mac_t label)
{ (void)label; }

static inline int mac_is_present(const char *name)
{ (void)name; return 0; /* MAC not present */ }

#endif /* __SYS_MAC_H__ */
