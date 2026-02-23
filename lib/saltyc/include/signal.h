/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SIGNAL_H__
#define __SIGNAL_H__

#include <sys/types.h>

#define SIGHUP      1
#define SIGINT      2
#define SIGQUIT     3
#define SIGILL      4
#define SIGTRAP     5
#define SIGABRT     6
#define SIGBUS      7
#define SIGFPE      8
#define SIGKILL     9
#define SIGUSR1     10
#define SIGSEGV     11
#define SIGUSR2     12
#define SIGPIPE     13
#define SIGALRM     14
#define SIGTERM     15
#define SIGSTKFLT   16
#define SIGCHLD     17
#define SIGCONT     18
#define SIGSTOP     19
#define SIGTSTP     20
#define SIGTTIN     21
#define SIGTTOU     22
#define SIGWINCH    28
#define SIGINFO     29

#define NSIG        32

#define SIG_DFL     ((void (*)(int))0)
#define SIG_IGN     ((void (*)(int))1)
#define SIG_ERR     ((void (*)(int))-1)

#define SA_NOCLDSTOP  0x00000001
#define SA_NOCLDWAIT  0x00000002
#define SA_SIGINFO    0x00000004
#define SA_RESTART    0x10000000
#define SA_RESETHAND  0x80000000

#define SIG_BLOCK     0
#define SIG_UNBLOCK   1
#define SIG_SETMASK   2

typedef int sig_atomic_t;
typedef unsigned int sigset_t;

union sigval {
    int   sival_int;
    void *sival_ptr;
};

typedef struct siginfo {
    int         si_signo;
    int         si_code;
    int         si_errno;
    pid_t       si_pid;
    uid_t       si_uid;
    int         si_status;
    void       *si_addr;
    union sigval si_value;
    long        _pad[4];
} siginfo_t;

struct sigaction {
    union {
        void (*sa_handler)(int);
        void (*sa_sigaction)(int, siginfo_t *, void *);
    };
    sigset_t      sa_mask;
    int           sa_flags;
    unsigned long sa_restorer;
};

typedef void (*sighandler_t)(int);

extern sighandler_t signal(int signum, sighandler_t handler);
extern int   sigaction(int signum, const struct sigaction *act,
                       struct sigaction *oldact);
extern int   sigprocmask(int how, const sigset_t *set, sigset_t *oldset);
extern int   sigsuspend(const sigset_t *mask);
extern int   sigpending(sigset_t *set);

extern int   sigemptyset(sigset_t *set);
extern int   sigfillset(sigset_t *set);
extern int   sigaddset(sigset_t *set, int signum);
extern int   sigdelset(sigset_t *set, int signum);
extern int   sigismember(const sigset_t *set, int signum);
extern int   siginterrupt(int sig, int flag);

extern int   kill(pid_t pid, int sig);
extern int   killpg(pid_t pgrp, int sig);
extern int   raise(int sig);

extern const char * const sys_signame[];
extern char *strsignal(int sig);

#endif /* __SIGNAL_H__ */
