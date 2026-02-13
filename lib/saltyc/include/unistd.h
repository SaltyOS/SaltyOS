/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __UNISTD_H__
#define __UNISTD_H__

#include <sys/types.h>
#include <stddef.h>

#define STDIN_FILENO  0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2

#define R_OK 4
#define W_OK 2
#define X_OK 1
#define F_OK 0

#define _SC_ARG_MAX             0
#define _SC_CHILD_MAX           1
#define _SC_CLK_TCK             2
#define _SC_OPEN_MAX            4
#define _SC_STREAM_MAX          5
#define _SC_PAGESIZE            30
#define _SC_PAGE_SIZE           30
#define _SC_LINE_MAX            43
#define _SC_GETGR_R_SIZE_MAX    69
#define _SC_GETPW_R_SIZE_MAX    70
#define _SC_NPROCESSORS_CONF    83
#define _SC_NPROCESSORS_ONLN    84

#define _PC_LINK_MAX    0
#define _PC_MAX_CANON   1
#define _PC_MAX_INPUT   2
#define _PC_NAME_MAX    3
#define _PC_PATH_MAX    4
#define _PC_PIPE_BUF    5

extern ssize_t read(int fd, void *buf, size_t count);
extern ssize_t write(int fd, const void *buf, size_t count);
extern int     close(int fd);
extern off_t   lseek(int fd, off_t offset, int whence);
extern int     dup(int oldfd);
extern int     dup2(int oldfd, int newfd);
extern int     pipe(int pipefd[2]);
extern int     pipe2(int pipefd[2], int flags);

extern pid_t   fork(void);
extern int     execve(const char *pathname, char *const argv[],
                      char *const envp[]);
extern int     execv(const char *pathname, char *const argv[]);
extern int     execvp(const char *file, char *const argv[]);
extern int     execvpe(const char *file, char *const argv[],
                       char *const envp[]);
extern int     execl(const char *pathname, const char *arg, ...);
extern int     execlp(const char *file, const char *arg, ...);

extern void    _exit(int status);

extern pid_t   getpid(void);
extern pid_t   getppid(void);

extern uid_t   getuid(void);
extern uid_t   geteuid(void);
extern gid_t   getgid(void);
extern gid_t   getegid(void);

extern int     setuid(uid_t uid);
extern int     setgid(gid_t gid);
extern int     seteuid(uid_t euid);
extern int     setegid(gid_t egid);
extern int     setreuid(uid_t ruid, uid_t euid);
extern int     setregid(gid_t rgid, gid_t egid);
extern int     getgroups(int size, gid_t list[]);

extern int     setpgid(pid_t pid, pid_t pgid);
extern pid_t   getpgid(pid_t pid);
extern pid_t   getpgrp(void);
extern int     setpgrp(void);
extern pid_t   setsid(void);
extern pid_t   getsid(pid_t pid);
extern pid_t   tcsetpgrp(int fd, pid_t pgrp);
extern pid_t   tcgetpgrp(int fd);

extern int     chdir(const char *path);
extern int     fchdir(int fd);
extern char   *getcwd(char *buf, size_t size);
extern int     access(const char *pathname, int mode);
extern int     unlink(const char *pathname);
extern int     rmdir(const char *pathname);
extern int     mkdir(const char *pathname, mode_t mode);
extern int     link(const char *oldpath, const char *newpath);
extern int     symlink(const char *target, const char *linkpath);
extern ssize_t readlink(const char *pathname, char *buf, size_t bufsiz);

extern unsigned int sleep(unsigned int seconds);
extern int     usleep(useconds_t usec);
extern unsigned int alarm(unsigned int seconds);
extern int     pause(void);

extern int     isatty(int fd);
extern char   *ttyname(int fd);

extern long    pathconf(const char *path, int name);
extern long    fpathconf(int fd, int name);
extern size_t  confstr(int name, char *buf, size_t len);
extern long    sysconf(int name);

extern int     gethostname(char *name, size_t len);

extern char   *optarg;
extern int     optind, opterr, optopt;

#endif /* __UNISTD_H__ */
