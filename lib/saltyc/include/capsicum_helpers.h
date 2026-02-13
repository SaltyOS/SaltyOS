/* SPDX-License-Identifier: GPL-2.0-only */
/* Capsicum/Casper stubs — no-op on SaltyOS */
#ifndef __CAPSICUM_HELPERS_H__
#define __CAPSICUM_HELPERS_H__

#define caph_limit_stdio()              0
#define caph_limit_stdin()              0
#define caph_limit_stdout()             0
#define caph_limit_stderr()             0
#define caph_enter()                    0
#define caph_enter_casper()             0
#define caph_rights_limit(fd, rights)   0
#define caph_cache_catpages()           0
#define caph_cache_tzdata()             0
#define caph_fcntls_limit(fd, fcntls)   0
#define caph_ioctls_limit(fd, cmds, n)  0

#endif /* __CAPSICUM_HELPERS_H__ */
