/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __FNMATCH_H__
#define __FNMATCH_H__

#define FNM_NOMATCH   1
#define FNM_NOESCAPE  (1 << 1)
#define FNM_PATHNAME  (1 << 2)
#define FNM_PERIOD    (1 << 3)
#define FNM_CASEFOLD  (1 << 4)

extern int fnmatch(const char *pattern, const char *string, int flags);

#endif /* __FNMATCH_H__ */
