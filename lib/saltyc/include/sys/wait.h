/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SYS_WAIT_H__
#define __SYS_WAIT_H__

#include <sys/types.h>

#define WNOHANG   1
#define WUNTRACED 2

#define WIFEXITED(status)   (((status) & 0x7f) == 0)
#define WEXITSTATUS(status) (((status) >> 8) & 0xff)
#define WIFSIGNALED(status) ((((status) & 0x7f) + 1) >> 1 > 0)
#define WTERMSIG(status)    ((status) & 0x7f)
#define WIFSTOPPED(status)  (((status) & 0xff) == 0x7f)
#define WSTOPSIG(status)    (((status) >> 8) & 0xff)
#define WCOREDUMP(status)   ((status) & 0x80)

extern pid_t waitpid(pid_t pid, int *wstatus, int options);
extern pid_t wait(int *wstatus);
extern pid_t wait3(int *wstatus, int options, void *rusage);
extern pid_t wait4(pid_t pid, int *wstatus, int options, void *rusage);

#endif /* __SYS_WAIT_H__ */
