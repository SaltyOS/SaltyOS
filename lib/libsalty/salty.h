/* libsalty - SaltyOS System Library
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Provides system call wrappers and IPC helpers for userland
 */

#ifndef LIBSALTY_H
#define LIBSALTY_H

#include <stdint.h>

/* System call numbers (must match kernel/src/syscall/mod.rs Syscall enum) */
#define SYS_SEND        0
#define SYS_RECV        1
#define SYS_CALL        2
#define SYS_REPLY_RECV  3
#define SYS_NBSEND      4
#define SYS_SIGNAL      5
#define SYS_WAIT        6
#define SYS_POLL        7
#define SYS_YIELD       8
#define SYS_INVOKE      9

/* Capability invoke labels */

/* CNode operations (0x10-0x16) */
#define CNODE_COPY          0x10
#define CNODE_MINT          0x11
#define CNODE_MOVE          0x12
#define CNODE_MUTATE        0x13
#define CNODE_DELETE        0x14
#define CNODE_REVOKE        0x15
#define CNODE_SAVE_CALLER   0x16

/* Untyped operations (0x20) */
#define UNTYPED_RETYPE      0x20

/* SchedContext operations (0x30-0x34) */
#define SC_CONFIGURE        0x30
#define SC_BIND             0x31
#define SC_UNBIND           0x32
#define SC_YIELD_TO         0x33
#define SC_CONSUMED         0x34

/* TCB operations (0x40-0x4A) */
#define TCB_CONFIGURE          0x40
#define TCB_RESUME             0x41
#define TCB_SUSPEND            0x42
#define TCB_SET_SPACE          0x43
#define TCB_SET_AFFINITY       0x44
#define TCB_READ_REGISTERS     0x45
#define TCB_WRITE_REGISTERS    0x46
#define TCB_SET_PRIORITY       0x47
#define TCB_SET_IPC_BUFFER     0x48
#define TCB_BIND_NOTIFICATION  0x49
#define TCB_UNBIND_NOTIFICATION 0x4A

/* VSpace operations (0x50-0x52) */
#define VSPACE_MAP          0x50
#define VSPACE_UNMAP        0x51
#define VSPACE_MAP_PT       0x52

/* IRQ operations (0x60-0x63) */
#define IRQ_CONTROL_GET           0x60
#define IRQ_HANDLER_ACK           0x61
#define IRQ_HANDLER_SET_NOTIFICATION 0x62
#define IRQ_HANDLER_CLEAR         0x63

/* Error codes (positive, returned in RAX) */
#define SALTY_OK                  0
#define SALTY_INVALID_CAPABILITY  1
#define SALTY_INVALID_OPERATION   2
#define SALTY_INSUFFICIENT_RIGHTS 3
#define SALTY_INVALID_ARGUMENT    4
#define SALTY_OUT_OF_MEMORY       5
#define SALTY_NOT_FOUND           6
#define SALTY_BUSY                7
#define SALTY_ALREADY_EXISTS      8
#define SALTY_WOULD_BLOCK         9
#define SALTY_BAD_ADDRESS         10
#define SALTY_OUT_OF_RANGE        11
#define SALTY_CANCELLED           12
#define SALTY_RESTART             13
#define SALTY_DEADLOCK            14

/* VSpace_Map flags */
#define VSPACE_FLAG_WRITABLE      (1 << 0)
#define VSPACE_FLAG_USER          (1 << 1)
#define VSPACE_FLAG_EXECUTABLE    (1 << 2)
#define VSPACE_FLAG_CACHE_DISABLE (1 << 3)
#define VSPACE_FLAG_WRITE_THROUGH (1 << 4)

/* Object types for Untyped_Retype */
#define OBJ_UNTYPED       1
#define OBJ_ENDPOINT       2
#define OBJ_NOTIFICATION   3
#define OBJ_TCB            4
#define OBJ_CNODE          5
#define OBJ_VSPACE         6
#define OBJ_FRAME          7
#define OBJ_IRQ_HANDLER    8
#define OBJ_IO_PORT        9
#define OBJ_SCHED_CONTEXT  10

/* TCB_SetAffinity special value */
#define CPU_AFFINITY_ANY   0xFFFFFFFF

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

/* Raw system call
 *
 * Register convention (matches kernel syscall.S):
 *   RAX = syscall number
 *   RDI = arg0 (capability pointer)
 *   RSI = arg1 (msg_info / label)
 *   RDX = arg2
 *   R10 = arg3 (RCX is clobbered by SYSCALL instruction)
 *   R8  = arg4
 *   R9  = arg5
 *
 * Return: RAX = error, RDX = value
 */
static inline struct salty_result salty_syscall(
    uint64_t syscall,
    uint64_t arg0,
    uint64_t arg1,
    uint64_t arg2,
    uint64_t arg3,
    uint64_t arg4
) {
    struct salty_result result;
    register uint64_t r10 __asm__("r10") = arg3;
    register uint64_t r8  __asm__("r8")  = arg4;

    __asm__ volatile(
        "syscall"
        : "=a"(result.error), "=d"(result.value)
        : "a"(syscall), "D"(arg0), "S"(arg1), "d"(arg2),
          "r"(r10), "r"(r8)
        : "rcx", "r11", "r9", "memory"
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
        *badge = r.value;
    }
    return (int)r.error;
}

static inline int salty_call(cap_t ep, const struct salty_msg *msg, struct salty_msg *reply) {
    struct salty_result r = salty_syscall(
        SYS_CALL, ep,
        msg->label, msg->regs[0], msg->regs[1], msg->regs[2]
    );
    (void)reply;
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

/* Generic capability invocation helper */
static inline struct salty_result salty_invoke(
    cap_t cap,
    uint64_t label,
    uint64_t arg0,
    uint64_t arg1,
    uint64_t arg2
) {
    return salty_syscall(SYS_INVOKE, cap, label, arg0, arg1, arg2);
}

#endif /* LIBSALTY_H */
