/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SYS_TYPES_H__
#define __SYS_TYPES_H__

typedef int            pid_t;
typedef unsigned int   uid_t;
typedef unsigned int   gid_t;
typedef unsigned short mode_t;
typedef long           off_t;
typedef unsigned long  size_t;
typedef long           ssize_t;
typedef long           time_t;
typedef long           clock_t;
typedef int            clockid_t;
typedef unsigned long  ino_t;
typedef unsigned long  dev_t;
typedef unsigned long  nlink_t;
typedef int            blksize_t;
typedef long           blkcnt_t;
typedef unsigned long  useconds_t;
typedef long           suseconds_t;
typedef long           intptr_t;
typedef unsigned long  uintptr_t;
typedef long           id_t;

/* BSD compatibility types */
typedef unsigned char  u_char;
typedef unsigned short u_short;
typedef unsigned int   u_int;
typedef unsigned long  u_long;

#endif /* __SYS_TYPES_H__ */
