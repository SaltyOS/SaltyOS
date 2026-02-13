/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __LIMITS_H__
#define __LIMITS_H__

#define CHAR_BIT        8
#define SCHAR_MIN       (-128)
#define SCHAR_MAX       127
#define UCHAR_MAX       255
#define CHAR_MIN        SCHAR_MIN
#define CHAR_MAX        SCHAR_MAX

#define SHRT_MIN        (-32768)
#define SHRT_MAX        32767
#define USHRT_MAX       65535

#define INT_MIN         (-2147483647 - 1)
#define INT_MAX         2147483647
#define UINT_MAX        4294967295U

#define LONG_MIN        (-9223372036854775807L - 1L)
#define LONG_MAX        9223372036854775807L
#define ULONG_MAX       18446744073709551615UL

#define LLONG_MIN       (-9223372036854775807LL - 1LL)
#define LLONG_MAX       9223372036854775807LL
#define ULLONG_MAX      18446744073709551615ULL

#define SSIZE_MAX       LONG_MAX
#define SIZE_MAX        ULONG_MAX

#define PATH_MAX        4096
#define NAME_MAX        255
#define PIPE_BUF        4096
#define ARG_MAX         131072
#define OPEN_MAX        256
#define CHILD_MAX       256
#define LINE_MAX        2048
#define _POSIX_PATH_MAX 4096
#define _POSIX_ARG_MAX  4096
#define NGROUPS_MAX     32
#define LOGIN_NAME_MAX  256
#define HOST_NAME_MAX   64
#define MB_LEN_MAX      4

#endif /* __LIMITS_H__ */
