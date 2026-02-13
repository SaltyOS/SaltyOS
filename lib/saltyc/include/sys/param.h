/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SYS_PARAM_H__
#define __SYS_PARAM_H__

#include <limits.h>

#define MAXPATHLEN PATH_MAX
#define MAXHOSTNAMELEN 64

#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#define MAX(a, b) (((a) > (b)) ? (a) : (b))

#endif /* __SYS_PARAM_H__ */
