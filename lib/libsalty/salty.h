/* libsalty - SaltyOS System Library
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Provides system call wrappers and IPC helpers for userland
 */

#ifndef LIBSALTY_H
#define LIBSALTY_H

#include <stdint.h>

/* System call numbers */
#define SYS_SEND        0
#define SYS_RECV        1
#define SYS_CALL        2
#define SYS_REPLY_RECV  3
#define SYS_SIGNAL      4
#define SYS_WAIT        5
#define SYS_YIELD       6
#define SYS_INVOKE      7

/* Capability handle (index into CSpace) */
typedef uint64_t cap_t;

/* IPC message */
struct salty_msg {
    uint64_t label;
    uint64_t regs[4];
};

/* System call result */
struct salty_result {
    uint64_t error;
    uint64_t value;
};

/* Raw system call */
static inline struct salty_result salty_syscall(
    uint64_t syscall,
    uint64_t arg0,
    uint64_t arg1,
    uint64_t arg2,
    uint64_t arg3,
    uint64_t arg4
) {
    struct salty_result result;
    register uint64_t r8 __asm__("r8") = arg3;
    register uint64_t r9 __asm__("r9") = arg4;

    __asm__ volatile(
        "syscall"
        : "=a"(result.error), "=d"(result.value)
        : "a"(syscall), "D"(arg0), "S"(arg1), "d"(arg2), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory"
    );

    return result;
}

/* IPC operations */
static inline int salty_send(cap_t ep, const struct salty_msg *msg) {
    struct salty_result r = salty_syscall(
        SYS_SEND, ep,
        msg->label, msg->regs[0], msg->regs[1], msg->regs[2]
    );
    return (int)r.error;
}

static inline int salty_recv(cap_t ep, struct salty_msg *msg, uint64_t *badge) {
    struct salty_result r = salty_syscall(SYS_RECV, ep, 0, 0, 0, 0);
    if (r.error == 0) {
        /* TODO: Extract message from registers */
        *badge = r.value;
    }
    return (int)r.error;
}

static inline int salty_call(cap_t ep, const struct salty_msg *msg, struct salty_msg *reply) {
    struct salty_result r = salty_syscall(
        SYS_CALL, ep,
        msg->label, msg->regs[0], msg->regs[1], msg->regs[2]
    );
    if (r.error == 0 && reply) {
        /* TODO: Extract reply from registers */
    }
    return (int)r.error;
}

/* Notification operations */
static inline int salty_signal(cap_t ntfn, uint64_t bits) {
    struct salty_result r = salty_syscall(SYS_SIGNAL, ntfn, bits, 0, 0, 0);
    return (int)r.error;
}

static inline uint64_t salty_wait(cap_t ntfn) {
    struct salty_result r = salty_syscall(SYS_WAIT, ntfn, 0, 0, 0, 0);
    return r.value;
}

/* Yield CPU */
static inline void salty_yield(void) {
    salty_syscall(SYS_YIELD, 0, 0, 0, 0, 0);
}

#endif /* LIBSALTY_H */
