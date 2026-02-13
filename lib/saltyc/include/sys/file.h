/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SYS_FILE_H__
#define __SYS_FILE_H__

#define LOCK_SH 1
#define LOCK_EX 2
#define LOCK_NB 4
#define LOCK_UN 8

extern int flock(int fd, int operation);

#endif /* __SYS_FILE_H__ */
