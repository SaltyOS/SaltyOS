/* SaltyOS POSIX Wrapper Library
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Thin POSIX-like API over SaltyOS IPC primitives.
 * Translates standard C-style calls (open/read/write/close/exit/getpid/waitpid)
 * into IPC messages to VFS and procmgr servers.
 *
 * Uses posix_ prefix to avoid conflicts with future musl integration.
 *
 * Requires salty.h to be included first.
 */

#ifndef LIBSALTY_POSIX_H
#define LIBSALTY_POSIX_H

#include <stdint.h>

/* Well-known cap slots for procmgr-spawned children.
 * These must match the layout set up by procmgr's handle_spawn(). */
#define POSIX_CAP_SELF_TCB    0
#define POSIX_CAP_SELF_VSPACE 1
#define POSIX_CAP_SELF_CSPACE 2
#define POSIX_CAP_PROCMGR_EP 3
#define POSIX_CAP_VFS_EP      4
#define POSIX_CAP_NAMESERV_EP 5
#define POSIX_CAP_UNTYPED     7

/* VFS protocol labels (must match userland/vfs/main.c) */
#define POSIX_VFS_OPEN   1
#define POSIX_VFS_READ   2
#define POSIX_VFS_WRITE  3
#define POSIX_VFS_CLOSE  4

/* Procmgr protocol labels (must match userland/procmgr/main.c) */
#define POSIX_PM_SPAWN   1
#define POSIX_PM_EXIT    2
#define POSIX_PM_WAIT    3
#define POSIX_PM_GETPID  4

/* Helper: pack path into IPC message regs starting at regs[offset] */
static inline uint8_t __posix_pack_path(struct salty_msg *msg, int offset,
                                         const char *path);

/* Open a file by path. Returns fd >= 0 on success, -1 on error.
 * Message layout:
 *   regs[0] = reserved (openat dirfd, currently 0)
 *   regs[1] = O_* flags
 *   regs[2] = path length
 *   regs[3..] = packed path bytes (max 64 bytes used by callers)
 */
static inline int posix_open(const char *path, int flags) {
    struct salty_msg msg, reply;
    msg.label = POSIX_VFS_OPEN;
    msg.regs[0] = 0;
    msg.regs[1] = (uint64_t)(uint32_t)flags;
    uint8_t path_len = __posix_pack_path(&msg, 2, path);
    msg.length = 3 + (uint64_t)((path_len + 7) / 8);

    int err = salty_call(POSIX_CAP_VFS_EP, &msg, &reply);
    if (err != 0 || reply.label != SALTY_OK)
        return -1;

    return (int)reply.regs[0];
}

/* Read up to count bytes from fd into buf. Returns bytes read, or -1 on error.
 * VFS returns data in reply.regs[1..19] (up to 152 bytes per call).
 * Loops for larger reads. */
static inline long posix_read(int fd, void *buf, unsigned long count) {
    uint8_t *out = (uint8_t *)buf;
    unsigned long total = 0;

    while (total < count) {
        unsigned long chunk = count - total;
        if (chunk > 152) chunk = 152;

        struct salty_msg msg, reply;
        msg.label = POSIX_VFS_READ;
        msg.length = 2;
        msg.regs[0] = (uint64_t)fd;
        msg.regs[1] = (uint64_t)chunk;
        msg.regs[2] = 0;
        msg.regs[3] = 0;

        int err = salty_call(POSIX_CAP_VFS_EP, &msg, &reply);
        if (err != 0 || reply.label != SALTY_OK)
            return total > 0 ? (long)total : -1;

        uint64_t actual = reply.regs[0];
        if (actual == 0) break; /* EOF */

        /* Copy data from reply registers to user buffer */
        const uint8_t *src = (const uint8_t *)&reply.regs[1];
        for (uint64_t i = 0; i < actual && total + i < count; i++)
            out[total + i] = src[i];

        total += actual;
        if (actual < chunk) break; /* short read */
    }

    return (long)total;
}

/* Write count bytes from buf to fd. Returns bytes written, or -1 on error.
 * Data is packed into msg.regs[2..19] (up to 144 bytes per call).
 * Loops for larger writes. */
static inline long posix_write(int fd, const void *buf, unsigned long count) {
    const uint8_t *src = (const uint8_t *)buf;
    unsigned long total = 0;

    while (total < count) {
        unsigned long chunk = count - total;
        if (chunk > 144) chunk = 144;

        struct salty_msg msg, reply;
        msg.label = POSIX_VFS_WRITE;
        msg.length = 2 + (uint64_t)((chunk + 7) / 8);
        msg.regs[0] = (uint64_t)fd;
        msg.regs[1] = (uint64_t)chunk;

        /* Clear data regs then pack */
        for (int i = 2; i < 20; i++) msg.regs[i] = 0;
        uint8_t *dst = (uint8_t *)&msg.regs[2];
        for (unsigned long i = 0; i < chunk; i++)
            dst[i] = src[total + i];

        int err = salty_call(POSIX_CAP_VFS_EP, &msg, &reply);
        if (err != 0 || reply.label != SALTY_OK)
            return total > 0 ? (long)total : -1;

        uint64_t actual = reply.regs[0];
        total += actual;
        if (actual < chunk) break; /* short write */
    }

    return (long)total;
}

/* Close a file descriptor. Returns 0 on success, -1 on error. */
static inline int posix_close(int fd) {
    struct salty_msg msg, reply;
    msg.label = POSIX_VFS_CLOSE;
    msg.length = 1;
    msg.regs[0] = (uint64_t)fd;
    msg.regs[1] = 0;
    msg.regs[2] = 0;
    msg.regs[3] = 0;

    int err = salty_call(POSIX_CAP_VFS_EP, &msg, &reply);
    if (err != 0 || reply.label != SALTY_OK)
        return -1;

    return 0;
}

/* Exit the current process with the given status code.
 * Sends PM_EXIT to procmgr (one-way, no reply expected). */
static inline void posix_exit(int status) {
    struct salty_msg msg;
    msg.label = POSIX_PM_EXIT;
    msg.length = 1;
    msg.regs[0] = (uint64_t)status;
    msg.regs[1] = 0;
    msg.regs[2] = 0;
    msg.regs[3] = 0;

    salty_send(POSIX_CAP_PROCMGR_EP, &msg);

    /* Never returns - procmgr will suspend our TCB */
    for (;;) { salty_yield(); }
}

/* Get the current process's PID. Returns PID or -1 on error. */
static inline int posix_getpid(void) {
    struct salty_msg msg, reply;
    msg.label = POSIX_PM_GETPID;
    msg.length = 0;
    msg.regs[0] = 0;
    msg.regs[1] = 0;
    msg.regs[2] = 0;
    msg.regs[3] = 0;

    int err = salty_call(POSIX_CAP_PROCMGR_EP, &msg, &reply);
    if (err != 0 || reply.label != SALTY_OK)
        return -1;

    return (int)reply.regs[0];
}

/* Wait for a child process to exit. Returns exit code via *status.
 * This is a blocking call — procmgr saves the reply cap and wakes us
 * when the child exits.
 * Returns child PID on success, -1 on error. */
static inline int posix_waitpid(int pid, int *status) {
    struct salty_msg msg, reply;
    msg.label = POSIX_PM_WAIT;
    msg.length = 1;
    msg.regs[0] = (uint64_t)pid;
    msg.regs[1] = 0;
    msg.regs[2] = 0;
    msg.regs[3] = 0;

    int err = salty_call(POSIX_CAP_PROCMGR_EP, &msg, &reply);
    if (err != 0 || reply.label != SALTY_OK)
        return -1;

    if (status)
        *status = (int)reply.regs[0];
    return pid;
}

/* O_* flags for open() */
#define O_ACCMODE 0x0003
#define O_RDONLY  0x0000
#define O_WRONLY  0x0001
#define O_RDWR    0x0002
#define O_CREAT   0x0040
#define O_EXCL    0x0080
#define O_TRUNC   0x0200
#define O_APPEND  0x0400

/* SEEK_* constants for lseek() */
#define SEEK_SET  0
#define SEEK_CUR  1
#define SEEK_END  2

/* File type constants (used in stat st_mode and dirent d_type) */
#define S_IFMT    0170000
#define S_IFDIR   0040000
#define S_IFCHR   0020000
#define S_IFREG   0100000
#define S_ISDIR(m)  (((m) & S_IFMT) == S_IFDIR)
#define S_ISCHR(m)  (((m) & S_IFMT) == S_IFCHR)
#define S_ISREG(m)  (((m) & S_IFMT) == S_IFREG)

/* Access mode flags */
#define F_OK  0
#define R_OK  4
#define W_OK  2
#define X_OK  1

/* Directory entry type constants */
#define DT_UNKNOWN  0
#define DT_REG      8
#define DT_DIR      4
#define DT_CHR      2

/* stat structure (64 bytes = 8 registers via IPC) */
struct salty_stat {
    uint64_t st_ino;
    uint64_t st_mode;
    uint64_t st_nlink;
    uint64_t st_size;
    uint64_t st_uid;
    uint64_t st_gid;
    uint64_t st_mtime;
    uint64_t st_type;
};

/* Directory entry */
struct salty_dirent {
    uint64_t d_ino;
    uint8_t  d_type;
    uint8_t  d_namlen;
    char     d_name[62];
};

/* VFS extended protocol labels (must match userland/vfs/main.c) */
#define POSIX_VFS_STAT    5
#define POSIX_VFS_LSEEK   6
#define POSIX_VFS_FSTAT   7
#define POSIX_VFS_ACCESS  8
#define POSIX_VFS_UNLINK  9
#define POSIX_VFS_RENAME  10
#define POSIX_VFS_MKDIR   11
#define POSIX_VFS_RMDIR   12
#define POSIX_VFS_OPENDIR 13
#define POSIX_VFS_READDIR 14
#define POSIX_VFS_LSTAT   15

/* Procmgr extended protocol labels */
#define POSIX_PM_FORK    5
#define POSIX_PM_EXEC    6
#define POSIX_PM_GETPPID 7

/* lseek: reposition file offset */
static inline long posix_lseek(int fd, long offset, int whence) {
    struct salty_msg msg, reply;
    msg.label = POSIX_VFS_LSEEK;
    msg.length = 3;
    msg.regs[0] = (uint64_t)fd;
    msg.regs[1] = (uint64_t)offset;
    msg.regs[2] = (uint64_t)whence;
    msg.regs[3] = 0;

    int err = salty_call(POSIX_CAP_VFS_EP, &msg, &reply);
    if (err != 0 || reply.label != SALTY_OK)
        return -1;

    return (long)reply.regs[0];
}

/* fstat: get file status by fd */
static inline int posix_fstat(int fd, struct salty_stat *st) {
    struct salty_msg msg, reply;
    msg.label = POSIX_VFS_FSTAT;
    msg.length = 1;
    msg.regs[0] = (uint64_t)fd;
    msg.regs[1] = 0;
    msg.regs[2] = 0;
    msg.regs[3] = 0;

    int err = salty_call(POSIX_CAP_VFS_EP, &msg, &reply);
    if (err != 0 || reply.label != SALTY_OK)
        return -1;

    if (st) {
        st->st_ino   = reply.regs[0];
        st->st_mode  = reply.regs[1];
        st->st_nlink = reply.regs[2];
        st->st_size  = reply.regs[3];
        st->st_uid   = reply.regs[4];
        st->st_gid   = reply.regs[5];
        st->st_mtime = reply.regs[6];
        st->st_type  = reply.regs[7];
    }
    return 0;
}

/* Helper: pack path into IPC message regs starting at regs[offset] */
static inline uint8_t __posix_pack_path(struct salty_msg *msg, int offset,
                                         const char *path) {
    uint8_t path_len = 0;
    while (path[path_len] && path_len < 64) path_len++;
    msg->regs[offset] = (uint64_t)path_len;
    for (int i = offset + 1; i < 20; i++) msg->regs[i] = 0;
    uint8_t *dst = (uint8_t *)&msg->regs[offset + 1];
    for (uint8_t i = 0; i < path_len; i++)
        dst[i] = (uint8_t)path[i];
    return path_len;
}

/* stat: get file status by path */
static inline int posix_stat(const char *path, struct salty_stat *st) {
    struct salty_msg msg, reply;
    msg.label = POSIX_VFS_STAT;
    uint8_t path_len = __posix_pack_path(&msg, 0, path);
    msg.length = 1 + (uint64_t)((path_len + 7) / 8);

    int err = salty_call(POSIX_CAP_VFS_EP, &msg, &reply);
    if (err != 0 || reply.label != SALTY_OK)
        return -1;

    if (st) {
        st->st_ino   = reply.regs[0];
        st->st_mode  = reply.regs[1];
        st->st_nlink = reply.regs[2];
        st->st_size  = reply.regs[3];
        st->st_uid   = reply.regs[4];
        st->st_gid   = reply.regs[5];
        st->st_mtime = reply.regs[6];
        st->st_type  = reply.regs[7];
    }
    return 0;
}

/* lstat: same as stat (no symlinks yet) */
static inline int posix_lstat(const char *path, struct salty_stat *st) {
    return posix_stat(path, st);
}

/* access: check file access */
static inline int posix_access(const char *path, int mode) {
    struct salty_msg msg, reply;
    msg.label = POSIX_VFS_ACCESS;
    uint8_t path_len = __posix_pack_path(&msg, 1, path);
    msg.regs[0] = (uint64_t)mode;
    msg.length = 2 + (uint64_t)((path_len + 7) / 8);

    int err = salty_call(POSIX_CAP_VFS_EP, &msg, &reply);
    if (err != 0 || reply.label != SALTY_OK)
        return -1;

    return 0;
}

/* unlink: remove a file */
static inline int posix_unlink(const char *path) {
    struct salty_msg msg, reply;
    msg.label = POSIX_VFS_UNLINK;
    uint8_t path_len = __posix_pack_path(&msg, 0, path);
    msg.length = 1 + (uint64_t)((path_len + 7) / 8);

    int err = salty_call(POSIX_CAP_VFS_EP, &msg, &reply);
    if (err != 0 || reply.label != SALTY_OK)
        return -1;

    return 0;
}

/* rename: rename a file */
static inline int posix_rename(const char *old_path, const char *new_path) {
    struct salty_msg msg, reply;
    msg.label = POSIX_VFS_RENAME;

    uint8_t old_len = 0;
    while (old_path[old_len] && old_len < 30) old_len++;
    uint8_t new_len = 0;
    while (new_path[new_len] && new_len < 30) new_len++;

    msg.regs[0] = (uint64_t)old_len;
    msg.regs[1] = (uint64_t)new_len;
    /* Pack old path into regs[2..], new path after old */
    for (int i = 2; i < 20; i++) msg.regs[i] = 0;
    uint8_t *dst = (uint8_t *)&msg.regs[2];
    for (uint8_t i = 0; i < old_len; i++) dst[i] = (uint8_t)old_path[i];
    dst = (uint8_t *)&msg.regs[2 + (old_len + 7) / 8];
    for (uint8_t i = 0; i < new_len; i++) dst[i] = (uint8_t)new_path[i];

    msg.length = 2 + (uint64_t)((old_len + 7) / 8) + (uint64_t)((new_len + 7) / 8);

    int err = salty_call(POSIX_CAP_VFS_EP, &msg, &reply);
    if (err != 0 || reply.label != SALTY_OK)
        return -1;

    return 0;
}

/* mkdir: create a directory */
static inline int posix_mkdir(const char *path, int mode) {
    struct salty_msg msg, reply;
    msg.label = POSIX_VFS_MKDIR;
    uint8_t path_len = __posix_pack_path(&msg, 1, path);
    msg.regs[0] = (uint64_t)mode;
    msg.length = 2 + (uint64_t)((path_len + 7) / 8);

    int err = salty_call(POSIX_CAP_VFS_EP, &msg, &reply);
    if (err != 0 || reply.label != SALTY_OK)
        return -1;

    return 0;
}

/* rmdir: remove a directory */
static inline int posix_rmdir(const char *path) {
    struct salty_msg msg, reply;
    msg.label = POSIX_VFS_RMDIR;
    uint8_t path_len = __posix_pack_path(&msg, 0, path);
    msg.length = 1 + (uint64_t)((path_len + 7) / 8);

    int err = salty_call(POSIX_CAP_VFS_EP, &msg, &reply);
    if (err != 0 || reply.label != SALTY_OK)
        return -1;

    return 0;
}

/* opendir: open a directory for reading. Returns dir_fd or -1 on error. */
static inline int posix_opendir(const char *path) {
    struct salty_msg msg, reply;
    msg.label = POSIX_VFS_OPENDIR;
    uint8_t path_len = __posix_pack_path(&msg, 0, path);
    msg.length = 1 + (uint64_t)((path_len + 7) / 8);

    int err = salty_call(POSIX_CAP_VFS_EP, &msg, &reply);
    if (err != 0 || reply.label != SALTY_OK)
        return -1;

    return (int)reply.regs[0];
}

/* readdir: read next directory entry. Returns 1 if entry found, 0 if done. */
static inline int posix_readdir(int dir_fd, struct salty_dirent *entry) {
    struct salty_msg msg, reply;
    msg.label = POSIX_VFS_READDIR;
    msg.length = 1;
    msg.regs[0] = (uint64_t)dir_fd;
    msg.regs[1] = 0;
    msg.regs[2] = 0;
    msg.regs[3] = 0;

    int err = salty_call(POSIX_CAP_VFS_EP, &msg, &reply);
    if (err != 0 || reply.label != SALTY_OK)
        return 0;

    uint8_t name_len = (uint8_t)reply.regs[0];
    if (name_len == 0)
        return 0; /* end of directory */

    if (entry) {
        entry->d_namlen = name_len;
        entry->d_ino = reply.regs[2];
        entry->d_type = (uint8_t)reply.regs[3];
        /* Unpack name from regs[4..] */
        const uint8_t *src = (const uint8_t *)&reply.regs[4];
        for (uint8_t i = 0; i < name_len && i < 61; i++)
            entry->d_name[i] = (char)src[i];
        entry->d_name[name_len < 61 ? name_len : 61] = '\0';
    }
    return 1;
}

/* closedir: close a directory fd (same as close) */
static inline int posix_closedir(int dir_fd) {
    return posix_close(dir_fd);
}

/* getppid: get parent process ID */
static inline int posix_getppid(void) {
    struct salty_msg msg, reply;
    msg.label = POSIX_PM_GETPPID;
    msg.length = 0;
    msg.regs[0] = 0;
    msg.regs[1] = 0;
    msg.regs[2] = 0;
    msg.regs[3] = 0;

    int err = salty_call(POSIX_CAP_PROCMGR_EP, &msg, &reply);
    if (err != 0 || reply.label != SALTY_OK)
        return -1;

    return (int)reply.regs[0];
}

/* posix_fork: create a child process.
 * Returns child PID to parent, 0 to child, -1 on error.
 * Implemented in fork.S (assembly trampoline) + C helper below. */
extern int posix_fork(void);

/* _posix_fork_impl: C helper called by fork.S trampoline.
 * Sends PM_FORK to procmgr with the caller's saved stack frame metadata. */
static inline int _posix_fork_impl(uint64_t saved_rsp,
                                     uint64_t child_entry) {
    if (saved_rsp == 0 || child_entry == 0)
        return -1;

    /* Stack layout produced by fork.S after pushes:
     *   [0]=r15 [1]=r14 [2]=r13 [3]=r12 [4]=rbx [5]=rbp [6]=return RIP
     */
    const uint64_t *saved = (const uint64_t *)saved_rsp;

    struct salty_msg msg, reply;
    msg.label = POSIX_PM_FORK;
    msg.length = 9;
    msg.regs[0] = saved_rsp;
    msg.regs[1] = child_entry;
    msg.regs[2] = saved[5]; /* rbp */
    msg.regs[3] = saved[4]; /* rbx */
    msg.regs[4] = saved[3]; /* r12 */
    msg.regs[5] = saved[2]; /* r13 */
    msg.regs[6] = saved[1]; /* r14 */
    msg.regs[7] = saved[0]; /* r15 */
    msg.regs[8] = saved[6]; /* return RIP */
    for (int i = 9; i < 20; i++) msg.regs[i] = 0;

    int err = salty_call(POSIX_CAP_PROCMGR_EP, &msg, &reply);
    if (err != 0 || reply.label != SALTY_OK)
        return -1;

    return (int)reply.regs[0]; /* child PID */
}

/* posix_execve: replace process image (declared here, defined in posix.h but
 * implemented via IPC to procmgr). */
static inline int posix_execve(const char *path, char *const argv[],
                                char *const envp[]) {
    (void)envp;

    struct salty_msg msg, reply;
    msg.label = POSIX_PM_EXEC;

    /* Pack path */
    uint8_t path_len = 0;
    while (path[path_len] && path_len < 64) path_len++;

    msg.regs[0] = (uint64_t)path_len;
    for (int i = 1; i < 20; i++) msg.regs[i] = 0;
    uint8_t *dst = (uint8_t *)&msg.regs[1];
    for (uint8_t i = 0; i < path_len; i++)
        dst[i] = (uint8_t)path[i];

    msg.length = 1 + (uint64_t)((path_len + 7) / 8);
    (void)argv;

    int err = salty_call(POSIX_CAP_PROCMGR_EP, &msg, &reply);
    if (err != 0 || reply.label != SALTY_OK)
        return -1;

    /* If exec succeeds, we never return */
    return 0;
}

/* posix_execvp: exec with PATH search (just wraps execve for now) */
static inline int posix_execvp(const char *file, char *const argv[]) {
    return posix_execve(file, argv, (char *const *)0);
}

#endif /* LIBSALTY_POSIX_H */
