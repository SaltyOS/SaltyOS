/* libsalty - SaltyOS System Library
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Provides system call wrappers and IPC helpers for userland.
 *
 * When SALTY_STATIC is defined, all functions are static inline (header-only).
 * When SALTY_STATIC is NOT defined, higher-level wrappers are extern
 * declarations (implemented in salty_impl.c / libsalty.so).
 * Performance-critical primitives (raw syscall, serial, ioport) are always
 * static inline.
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
#define SYS_DEBUG_PUTCHAR   10
#define SYS_DEBUG_DUMP_STATE 11

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
#define TCB_SET_FAULT_HANDLER  0x4B

/* VSpace operations (0x50-0x52) */
#define VSPACE_MAP          0x50
#define VSPACE_UNMAP        0x51
#define VSPACE_MAP_PT       0x52

/* IRQ operations (0x60-0x63) */
#define IRQ_CONTROL_GET           0x60
#define IRQ_HANDLER_ACK           0x61
#define IRQ_HANDLER_SET_NOTIFICATION 0x62
#define IRQ_HANDLER_CLEAR         0x63

/* IoPort operations (0x70-0x73) */
#define IOPORT_IN8                0x70
#define IOPORT_OUT8               0x71
#define IOPORT_IN16               0x72
#define IOPORT_OUT16              0x73

/* Console IPC message labels */
#define CONSOLE_WRITE             1
#define CONSOLE_READ              2

/* Well-known cap slots for init/procmgr */
#define CAP_COM1_IOPORT           8
#define CAP_COM1_IRQ              9
#define CAP_COM1_NTFN             10
#define CAP_CONSOLE_EP            11

/* IPC buffer pointer - set by init to point at mapped IPC buffer page.
 * When SALTY_STATIC: weak hidden definition (each static binary defines its own).
 * When !SALTY_STATIC: extern (defined in libsalty.so).
 */
#ifdef SALTY_STATIC
extern void *__salty_ipc_buffer __attribute__((visibility("hidden")));
#else
extern void *__salty_ipc_buffer;
#endif

/* Initrd mapping address (16 MB) */
#define INITRD_VADDR              0x0000000001000000ULL

/* Scratch address for temporary frame mappings (32 MB) */
#define SCRATCH_VADDR             0x0000000002000000ULL

/* Capability rights bitmask (matches kernel CapRights) */
#define CAP_RIGHTS_ALL            0xFFFFFFFFU

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

/* IPC message
 * The first 5 fields (label + regs[0..3]) are passed in registers.
 * regs[4..19] overflow through the IPC buffer for long messages.
 */
struct salty_msg {
    uint64_t label;
    uint64_t length;
    uint64_t regs[20];
};

/* IPC buffer layout (must match kernel IpcBuffer struct)
 * Mapped at the thread's ipc_buffer address (one 4KB page).
 */
struct salty_ipc_buffer {
    uint64_t msg[20];           /* 0x000: MR0..MR19 */
    uint64_t badge;             /* 0x0A0: received badge */
    uint64_t caps[4];           /* 0x0A8: cap slots to transfer (sender) */
    uint64_t receive_cnode;     /* 0x0C8: CNode for receiving caps */
    uint64_t receive_index;     /* 0x0D0: starting slot index */
    uint64_t receive_depth;     /* 0x0D8: CNode depth */
    uint64_t reserved[480];     /* 0x0E0: future use */
};

/* Pack label, length, and extra_caps into a msg_info word.
 *   Bits  6:0  = length (0-127)
 *   Bits 11:7  = extra_caps (0-31)
 *   Bits 51:12 = label (40 bits)
 */
#define SALTY_MSGINFO(label, length, caps) \
    (((uint64_t)(label) << 12) | ((uint64_t)(caps) << 7) | ((uint64_t)(length) & 0x7F))

/* Extract fields from msg_info */
#define SALTY_MSGINFO_LABEL(info)     (((info) >> 12) & 0xFFFFFFFFFFULL)
#define SALTY_MSGINFO_LENGTH(info)    ((info) & 0x7F)
#define SALTY_MSGINFO_EXTRACAPS(info) (((info) >> 7) & 0x1F)

/* System call result */
struct salty_result {
    uint64_t error;
    uint64_t value;
};

/* ====================================================================
 * Always-inline primitives (performance-critical, single instruction)
 * ==================================================================== */

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
    uint64_t arg4,
    uint64_t arg5
) {
    struct salty_result result;
    register uint64_t r10 __asm__("r10") = arg3;
    register uint64_t r8  __asm__("r8")  = arg4;
    register uint64_t r9  __asm__("r9")  = arg5;

    __asm__ volatile(
        "syscall"
        : "=a"(result.error), "=d"(result.value)
        : "a"(syscall), "D"(arg0), "S"(arg1), "d"(arg2),
          "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory"
    );

    return result;
}

/* Serial output via direct port I/O (always inline for early debugging) */
static inline void salty_serial_putc(char c) {
    uint8_t status;
    do {
        __asm__ volatile("inb %1, %0" : "=a"(status) : "Nd"((uint16_t)0x3FD));
    } while ((status & 0x20) == 0);
    __asm__ volatile("outb %0, %1" :: "a"((uint8_t)c), "Nd"((uint16_t)0x3F8));
}

static inline void salty_serial_puts(const char *s) {
    while (*s) {
        salty_serial_putc(*s++);
    }
}

static inline void salty_serial_hex(uint64_t val) {
    static const char hex[] = "0123456789abcdef";
    salty_serial_putc('0');
    salty_serial_putc('x');
    if (val == 0) {
        salty_serial_putc('0');
        return;
    }
    char buf[16];
    int pos = 15;
    while (val > 0 && pos >= 0) {
        buf[pos--] = hex[val & 0xF];
        val >>= 4;
    }
    for (int i = pos + 1; i < 16; i++) {
        salty_serial_putc(buf[i]);
    }
}

/* IoPort operations (always inline - direct syscall for zero overhead) */
static inline uint8_t salty_ioport_in8(cap_t ioport, uint64_t offset) {
    struct salty_result r = salty_syscall(SYS_INVOKE, ioport, IOPORT_IN8,
                                          offset, 0, 0, 0);
    return (uint8_t)r.value;
}

static inline void salty_ioport_out8(cap_t ioport, uint64_t offset,
                                     uint8_t value) {
    salty_syscall(SYS_INVOKE, ioport, IOPORT_OUT8, offset,
                  (uint64_t)value, 0, 0);
}

static inline uint16_t salty_ioport_in16(cap_t ioport, uint64_t offset) {
    struct salty_result r = salty_syscall(SYS_INVOKE, ioport, IOPORT_IN16,
                                          offset, 0, 0, 0);
    return (uint16_t)r.value;
}

static inline void salty_ioport_out16(cap_t ioport, uint64_t offset,
                                      uint16_t value) {
    salty_syscall(SYS_INVOKE, ioport, IOPORT_OUT16, offset,
                  (uint64_t)value, 0, 0);
}

/* ====================================================================
 * Higher-level wrappers: static inline when SALTY_STATIC, extern otherwise
 * ==================================================================== */

#ifdef SALTY_STATIC

/* Generic capability invocation helper */
static inline struct salty_result salty_invoke(
    cap_t cap,
    uint64_t label,
    uint64_t arg0,
    uint64_t arg1,
    uint64_t arg2,
    uint64_t arg3
) {
    return salty_syscall(SYS_INVOKE, cap, label, arg0, arg1, arg2, arg3);
}

/* IPC operations */
static inline int salty_send(cap_t ep, const struct salty_msg *msg) {
    uint64_t info = SALTY_MSGINFO(msg->label, msg->length, 0);
    struct salty_result r = salty_syscall(
        SYS_SEND, ep,
        info, msg->regs[0], msg->regs[1], msg->regs[2], msg->regs[3]
    );
    return (int)r.error;
}

static inline int salty_recv(cap_t ep, struct salty_msg *msg, uint64_t *badge) {
    struct salty_result r = salty_syscall(SYS_RECV, ep, 0, 0, 0, 0, 0);
    if (r.error == 0) {
        *badge = r.value;
        if (msg && __salty_ipc_buffer) {
            /* Read from IPC buffer (kernel writes Message struct at base) */
            const struct salty_msg *buf = (const struct salty_msg *)__salty_ipc_buffer;
            *msg = *buf;
        }
    }
    return (int)r.error;
}

static inline int salty_call(cap_t ep, const struct salty_msg *msg, struct salty_msg *reply) {
    uint64_t info = SALTY_MSGINFO(msg->label, msg->length, 0);
    struct salty_result r = salty_syscall(
        SYS_CALL, ep,
        info, msg->regs[0], msg->regs[1], msg->regs[2], msg->regs[3]
    );
    if (r.error == 0 && reply && __salty_ipc_buffer) {
        const struct salty_msg *buf = (const struct salty_msg *)__salty_ipc_buffer;
        *reply = *buf;
    }
    return (int)r.error;
}

static inline int salty_reply_recv(cap_t ep, const struct salty_msg *reply,
                                    struct salty_msg *out_msg, uint64_t *badge) {
    uint64_t info = SALTY_MSGINFO(reply->label, reply->length, 0);
    struct salty_result r = salty_syscall(
        SYS_REPLY_RECV, ep,
        info, reply->regs[0], reply->regs[1], reply->regs[2], reply->regs[3]
    );
    if (r.error == 0) {
        if (badge) *badge = r.value;
        if (out_msg && __salty_ipc_buffer) {
            const struct salty_msg *buf = (const struct salty_msg *)__salty_ipc_buffer;
            *out_msg = *buf;
        }
    }
    return (int)r.error;
}

/* Notification operations */
static inline int salty_signal(cap_t ntfn, uint64_t bits) {
    struct salty_result r = salty_syscall(SYS_SIGNAL, ntfn, bits, 0, 0, 0, 0);
    return (int)r.error;
}

static inline uint64_t salty_wait(cap_t ntfn) {
    struct salty_result r = salty_syscall(SYS_WAIT, ntfn, 0, 0, 0, 0, 0);
    return r.value;
}

/* Yield CPU */
static inline void salty_yield(void) {
    salty_syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
}

/* Retype untyped memory into a new object at dest_slot in caller's CSpace */
static inline int salty_untyped_retype(cap_t untyped, uint64_t new_type,
                                       uint64_t size_bits, uint64_t dest_slot) {
    struct salty_result r = salty_invoke(untyped, UNTYPED_RETYPE,
                                        new_type, size_bits, dest_slot, 0);
    return (int)r.error;
}

/* Configure a TCB's entry point, stack, and IPC buffer */
static inline int salty_tcb_configure(cap_t tcb, uint64_t rip,
                                      uint64_t rsp, uint64_t ipc_buf) {
    struct salty_result r = salty_invoke(tcb, TCB_CONFIGURE, rip, rsp, ipc_buf, 0);
    return (int)r.error;
}

/* Resume (make runnable) a TCB */
static inline int salty_tcb_resume(cap_t tcb) {
    struct salty_result r = salty_invoke(tcb, TCB_RESUME, 0, 0, 0, 0);
    return (int)r.error;
}

/* Set a TCB's CSpace and VSpace */
static inline int salty_tcb_set_space(cap_t tcb, cap_t cspace, cap_t vspace) {
    struct salty_result r = salty_invoke(tcb, TCB_SET_SPACE, cspace, vspace, 0, 0);
    return (int)r.error;
}

/* Set a TCB's fault handler endpoint */
static inline int salty_tcb_set_fault_handler(cap_t tcb, cap_t fault_ep) {
    struct salty_result r = salty_invoke(tcb, TCB_SET_FAULT_HANDLER, fault_ep, 0, 0, 0);
    return (int)r.error;
}

/* Configure scheduling context parameters */
static inline int salty_sc_configure(cap_t sc, uint64_t budget_us,
                                     uint64_t period_us) {
    struct salty_result r = salty_invoke(sc, SC_CONFIGURE, budget_us, period_us, 0, 0);
    return (int)r.error;
}

/* Bind scheduling context to a TCB */
static inline int salty_sc_bind(cap_t sc, cap_t tcb) {
    struct salty_result r = salty_invoke(sc, SC_BIND, tcb, 0, 0, 0);
    return (int)r.error;
}

/* Map a frame into a VSpace */
static inline int salty_vspace_map(cap_t vspace, cap_t frame,
                                   uint64_t vaddr, uint64_t flags) {
    struct salty_result r = salty_invoke(vspace, VSPACE_MAP, frame, vaddr, flags, 0);
    return (int)r.error;
}

/* Unmap a page from a VSpace */
static inline int salty_vspace_unmap(cap_t vspace, uint64_t vaddr) {
    struct salty_result r = salty_invoke(vspace, VSPACE_UNMAP, vaddr, 0, 0, 0);
    return (int)r.error;
}

/* Install a page table at a specific level in a VSpace */
static inline int salty_vspace_map_pt(cap_t vspace, cap_t frame,
                                       uint64_t vaddr, uint64_t level) {
    struct salty_result r = salty_invoke(vspace, VSPACE_MAP_PT,
                                         frame, vaddr, level, 0);
    return (int)r.error;
}

/* Copy a capability from src CNode slot to dest CNode slot */
static inline int salty_cnode_copy(cap_t src_cnode, uint64_t src_slot,
                                   cap_t dest_cnode, uint64_t dest_slot,
                                   uint64_t rights) {
    struct salty_result r = salty_invoke(src_cnode, CNODE_COPY,
                                        src_slot, dest_cnode, dest_slot, rights);
    return (int)r.error;
}

/* IRQ handler operations */
static inline int salty_irq_handler_ack(cap_t irq_handler) {
    struct salty_result r = salty_invoke(irq_handler, IRQ_HANDLER_ACK, 0, 0, 0, 0);
    return (int)r.error;
}

static inline int salty_irq_handler_set_notification(cap_t irq_handler,
                                                      cap_t ntfn) {
    struct salty_result r = salty_invoke(irq_handler,
                                         IRQ_HANDLER_SET_NOTIFICATION,
                                         ntfn, 0, 0, 0);
    return (int)r.error;
}

/* Mint a badged capability */
static inline int salty_cnode_mint(cap_t src_cnode, uint64_t src_slot,
                                   cap_t dest_cnode, uint64_t dest_slot,
                                   uint64_t badge) {
    struct salty_result r = salty_invoke(src_cnode, CNODE_MINT,
                                        src_slot, dest_cnode, dest_slot, badge);
    return (int)r.error;
}

/* Move a capability */
static inline int salty_cnode_move(cap_t dest_cnode, uint64_t dest_slot,
                                   cap_t src_cnode, uint64_t src_slot) {
    struct salty_result r = salty_invoke(dest_cnode, CNODE_MOVE,
                                        dest_slot, src_cnode, src_slot, 0);
    return (int)r.error;
}

/* Mutate a capability (move + change badge) */
static inline int salty_cnode_mutate(cap_t dest_cnode, uint64_t dest_slot,
                                     cap_t src_cnode, uint64_t src_slot,
                                     uint64_t badge) {
    struct salty_result r = salty_invoke(dest_cnode, CNODE_MUTATE,
                                        dest_slot, src_cnode, src_slot, badge);
    return (int)r.error;
}

/* Save the reply capability from current IPC into a CNode slot */
static inline int salty_cnode_save_caller(cap_t cnode, uint64_t slot) {
    struct salty_result r = salty_invoke(cnode, CNODE_SAVE_CALLER, slot, 0, 0, 0);
    return (int)r.error;
}

/* Delete a single capability (fails if it has children) */
static inline int salty_cnode_delete(cap_t cnode, uint64_t slot) {
    struct salty_result r = salty_invoke(cnode, CNODE_DELETE, slot, 0, 0, 0);
    return (int)r.error;
}

/* Revoke a capability and all its descendants */
static inline int salty_cnode_revoke(cap_t cnode, uint64_t slot) {
    struct salty_result r = salty_invoke(cnode, CNODE_REVOKE, slot, 0, 0, 0);
    return (int)r.error;
}

/* Non-blocking send to endpoint */
static inline int salty_nbsend(cap_t ep, const struct salty_msg *msg) {
    uint64_t info = SALTY_MSGINFO(msg->label, msg->length, 0);
    struct salty_result r = salty_syscall(
        SYS_NBSEND, ep,
        info, msg->regs[0], msg->regs[1], msg->regs[2], msg->regs[3]
    );
    return (int)r.error;
}

/* Poll notification without blocking */
static inline int salty_poll(cap_t ntfn, uint64_t *bits) {
    struct salty_result r = salty_syscall(SYS_POLL, ntfn, 0, 0, 0, 0, 0);
    if (r.error == 0 && bits)
        *bits = r.value;
    return (int)r.error;
}

/* Write a character to the kernel debug serial port */
static inline void salty_debug_putchar(char c) {
    salty_syscall(SYS_DEBUG_PUTCHAR, (uint64_t)(uint8_t)c, 0, 0, 0, 0, 0);
}

/* Dump current thread state to kernel debug serial */
static inline void salty_debug_dump_state(void) {
    salty_syscall(SYS_DEBUG_DUMP_STATE, 0, 0, 0, 0, 0, 0);
}

/* Configure the IPC buffer receive slot for capability transfer.
 * When receiving IPC with extra_caps > 0, transferred capabilities
 * will be placed into the specified CNode starting at index.
 */
static inline void salty_set_receive_slot(cap_t cnode, uint64_t index, uint64_t depth) {
    if (__salty_ipc_buffer) {
        struct salty_ipc_buffer *buf = (struct salty_ipc_buffer *)__salty_ipc_buffer;
        buf->receive_cnode = cnode;
        buf->receive_index = index;
        buf->receive_depth = depth;
    }
}

/* Set a capability slot for transfer in the next IPC send.
 * slot_index: which of the 4 cap transfer slots (0-3) to set
 * cap_slot: the CNode slot index of the capability to transfer
 */
static inline void salty_set_send_cap(int slot_index, uint64_t cap_slot) {
    if (__salty_ipc_buffer && slot_index >= 0 && slot_index < 4) {
        struct salty_ipc_buffer *buf = (struct salty_ipc_buffer *)__salty_ipc_buffer;
        buf->caps[slot_index] = cap_slot;
    }
}

/* Set IPC buffer address for a TCB */
static inline int salty_tcb_set_ipc_buffer(cap_t tcb, uint64_t addr) {
    struct salty_result r = salty_invoke(tcb, TCB_SET_IPC_BUFFER, addr, 0, 0, 0);
    return (int)r.error;
}

#else /* !SALTY_STATIC — extern declarations for libsalty.so */

extern struct salty_result salty_invoke(cap_t cap, uint64_t label,
                                        uint64_t arg0, uint64_t arg1,
                                        uint64_t arg2, uint64_t arg3);
extern int salty_send(cap_t ep, const struct salty_msg *msg);
extern int salty_recv(cap_t ep, struct salty_msg *msg, uint64_t *badge);
extern int salty_call(cap_t ep, const struct salty_msg *msg, struct salty_msg *reply);
extern int salty_reply_recv(cap_t ep, const struct salty_msg *reply,
                             struct salty_msg *out_msg, uint64_t *badge);
extern int salty_signal(cap_t ntfn, uint64_t bits);
extern uint64_t salty_wait(cap_t ntfn);
extern void salty_yield(void);
extern int salty_untyped_retype(cap_t untyped, uint64_t new_type,
                                 uint64_t size_bits, uint64_t dest_slot);
extern int salty_tcb_configure(cap_t tcb, uint64_t rip,
                                uint64_t rsp, uint64_t ipc_buf);
extern int salty_tcb_resume(cap_t tcb);
extern int salty_tcb_set_space(cap_t tcb, cap_t cspace, cap_t vspace);
extern int salty_tcb_set_fault_handler(cap_t tcb, cap_t fault_ep);
extern int salty_sc_configure(cap_t sc, uint64_t budget_us,
                               uint64_t period_us);
extern int salty_sc_bind(cap_t sc, cap_t tcb);
extern int salty_vspace_map(cap_t vspace, cap_t frame,
                             uint64_t vaddr, uint64_t flags);
extern int salty_vspace_unmap(cap_t vspace, uint64_t vaddr);
extern int salty_vspace_map_pt(cap_t vspace, cap_t frame,
                                uint64_t vaddr, uint64_t level);
extern int salty_cnode_copy(cap_t src_cnode, uint64_t src_slot,
                             cap_t dest_cnode, uint64_t dest_slot,
                             uint64_t rights);
extern int salty_irq_handler_ack(cap_t irq_handler);
extern int salty_irq_handler_set_notification(cap_t irq_handler,
                                               cap_t ntfn);
extern int salty_cnode_mint(cap_t src_cnode, uint64_t src_slot,
                             cap_t dest_cnode, uint64_t dest_slot,
                             uint64_t badge);
extern int salty_cnode_move(cap_t dest_cnode, uint64_t dest_slot,
                             cap_t src_cnode, uint64_t src_slot);
extern int salty_cnode_mutate(cap_t dest_cnode, uint64_t dest_slot,
                               cap_t src_cnode, uint64_t src_slot,
                               uint64_t badge);
extern int salty_cnode_save_caller(cap_t cnode, uint64_t slot);
extern int salty_cnode_delete(cap_t cnode, uint64_t slot);
extern int salty_cnode_revoke(cap_t cnode, uint64_t slot);
extern int salty_nbsend(cap_t ep, const struct salty_msg *msg);
extern int salty_poll(cap_t ntfn, uint64_t *bits);
extern void salty_debug_putchar(char c);
extern void salty_debug_dump_state(void);
extern int salty_tcb_set_ipc_buffer(cap_t tcb, uint64_t addr);

#endif /* SALTY_STATIC */

#endif /* LIBSALTY_H */
