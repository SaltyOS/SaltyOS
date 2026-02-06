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

/* Open a file by path. Returns fd >= 0 on success, -1 on error.
 * Path is packed into IPC message registers (max 64 bytes). */
static inline int posix_open(const char *path, int flags) {
    (void)flags;

    /* Compute path length */
    uint8_t path_len = 0;
    while (path[path_len] && path_len < 64) path_len++;

    struct salty_msg msg, reply;
    msg.label = POSIX_VFS_OPEN;
    msg.length = 1 + (uint64_t)((path_len + 7) / 8);
    msg.regs[0] = (uint64_t)path_len;

    /* Pack path bytes into regs[1..] */
    for (int i = 0; i < 19; i++) msg.regs[1 + i] = 0;
    uint8_t *dst = (uint8_t *)&msg.regs[1];
    for (uint8_t i = 0; i < path_len; i++)
        dst[i] = (uint8_t)path[i];

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
 * Polls with yield if process hasn't exited yet.
 * Returns child PID on success, -1 on error. */
static inline int posix_waitpid(int pid, int *status) {
    for (int attempt = 0; attempt < 200; attempt++) {
        struct salty_msg msg, reply;
        msg.label = POSIX_PM_WAIT;
        msg.length = 1;
        msg.regs[0] = (uint64_t)pid;
        msg.regs[1] = 0;
        msg.regs[2] = 0;
        msg.regs[3] = 0;

        int err = salty_call(POSIX_CAP_PROCMGR_EP, &msg, &reply);
        if (err != 0)
            return -1;

        if (reply.label == SALTY_OK) {
            if (status)
                *status = (int)reply.regs[0];
            return pid;
        }

        if (reply.label == SALTY_BUSY) {
            salty_yield();
            continue;
        }

        return -1; /* unexpected error */
    }

    return -1; /* timed out */
}

#endif /* LIBSALTY_POSIX_H */
