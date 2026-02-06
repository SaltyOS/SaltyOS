/* libsalty - System call wrapper implementations for libsalty.so
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * This file implements all extern functions declared in salty.h when
 * SALTY_STATIC is NOT defined. Each function calls salty_syscall()
 * (which is always static inline in salty.h).
 */

#include "salty.h"

/* IPC buffer - exported from libsalty.so, shared by all dynamically linked code */
void *__salty_ipc_buffer = (void *)0;

/* Generic capability invocation */
struct salty_result salty_invoke(
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
int salty_send(cap_t ep, const struct salty_msg *msg) {
    uint64_t info = SALTY_MSGINFO(msg->label, msg->length, 0);
    struct salty_result r = salty_syscall(
        SYS_SEND, ep,
        info, msg->regs[0], msg->regs[1], msg->regs[2], msg->regs[3]
    );
    return (int)r.error;
}

int salty_recv(cap_t ep, struct salty_msg *msg, uint64_t *badge) {
    struct salty_result r = salty_syscall(SYS_RECV, ep, 0, 0, 0, 0, 0);
    if (r.error == 0) {
        *badge = r.value;
        if (msg && __salty_ipc_buffer) {
            const struct salty_msg *buf = (const struct salty_msg *)__salty_ipc_buffer;
            *msg = *buf;
        }
    }
    return (int)r.error;
}

int salty_call(cap_t ep, const struct salty_msg *msg, struct salty_msg *reply) {
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

int salty_reply_recv(cap_t ep, const struct salty_msg *reply,
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
int salty_signal(cap_t ntfn, uint64_t bits) {
    struct salty_result r = salty_syscall(SYS_SIGNAL, ntfn, bits, 0, 0, 0, 0);
    return (int)r.error;
}

uint64_t salty_wait(cap_t ntfn) {
    struct salty_result r = salty_syscall(SYS_WAIT, ntfn, 0, 0, 0, 0, 0);
    return r.value;
}

/* Yield CPU */
void salty_yield(void) {
    salty_syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
}

/* Retype untyped memory into a new object */
int salty_untyped_retype(cap_t untyped, uint64_t new_type,
                         uint64_t size_bits, uint64_t dest_slot) {
    struct salty_result r = salty_invoke(untyped, UNTYPED_RETYPE,
                                        new_type, size_bits, dest_slot, 0);
    return (int)r.error;
}

/* Configure a TCB's entry point, stack, and IPC buffer */
int salty_tcb_configure(cap_t tcb, uint64_t rip,
                        uint64_t rsp, uint64_t ipc_buf) {
    struct salty_result r = salty_invoke(tcb, TCB_CONFIGURE, rip, rsp, ipc_buf, 0);
    return (int)r.error;
}

/* Resume (make runnable) a TCB */
int salty_tcb_resume(cap_t tcb) {
    struct salty_result r = salty_invoke(tcb, TCB_RESUME, 0, 0, 0, 0);
    return (int)r.error;
}

/* Set a TCB's CSpace and VSpace */
int salty_tcb_set_space(cap_t tcb, cap_t cspace, cap_t vspace) {
    struct salty_result r = salty_invoke(tcb, TCB_SET_SPACE, cspace, vspace, 0, 0);
    return (int)r.error;
}

/* Set a TCB's fault handler endpoint */
int salty_tcb_set_fault_handler(cap_t tcb, cap_t fault_ep) {
    struct salty_result r = salty_invoke(tcb, TCB_SET_FAULT_HANDLER, fault_ep, 0, 0, 0);
    return (int)r.error;
}

/* Configure scheduling context parameters */
int salty_sc_configure(cap_t sc, uint64_t budget_us, uint64_t period_us) {
    struct salty_result r = salty_invoke(sc, SC_CONFIGURE, budget_us, period_us, 0, 0);
    return (int)r.error;
}

/* Bind scheduling context to a TCB */
int salty_sc_bind(cap_t sc, cap_t tcb) {
    struct salty_result r = salty_invoke(sc, SC_BIND, tcb, 0, 0, 0);
    return (int)r.error;
}

/* Map a frame into a VSpace */
int salty_vspace_map(cap_t vspace, cap_t frame,
                     uint64_t vaddr, uint64_t flags) {
    struct salty_result r = salty_invoke(vspace, VSPACE_MAP, frame, vaddr, flags, 0);
    return (int)r.error;
}

/* Unmap a page from a VSpace */
int salty_vspace_unmap(cap_t vspace, uint64_t vaddr) {
    struct salty_result r = salty_invoke(vspace, VSPACE_UNMAP, vaddr, 0, 0, 0);
    return (int)r.error;
}

/* Install a page table at a specific level in a VSpace */
int salty_vspace_map_pt(cap_t vspace, cap_t frame,
                        uint64_t vaddr, uint64_t level) {
    struct salty_result r = salty_invoke(vspace, VSPACE_MAP_PT,
                                         frame, vaddr, level, 0);
    return (int)r.error;
}

/* Copy a capability from src CNode slot to dest CNode slot */
int salty_cnode_copy(cap_t src_cnode, uint64_t src_slot,
                     cap_t dest_cnode, uint64_t dest_slot,
                     uint64_t rights) {
    struct salty_result r = salty_invoke(src_cnode, CNODE_COPY,
                                        src_slot, dest_cnode, dest_slot, rights);
    return (int)r.error;
}

/* IRQ handler operations */
int salty_irq_handler_ack(cap_t irq_handler) {
    struct salty_result r = salty_invoke(irq_handler, IRQ_HANDLER_ACK, 0, 0, 0, 0);
    return (int)r.error;
}

int salty_irq_handler_set_notification(cap_t irq_handler, cap_t ntfn) {
    struct salty_result r = salty_invoke(irq_handler,
                                         IRQ_HANDLER_SET_NOTIFICATION,
                                         ntfn, 0, 0, 0);
    return (int)r.error;
}

/* Mint a badged capability */
int salty_cnode_mint(cap_t src_cnode, uint64_t src_slot,
                     cap_t dest_cnode, uint64_t dest_slot,
                     uint64_t badge) {
    struct salty_result r = salty_invoke(src_cnode, CNODE_MINT,
                                        src_slot, dest_cnode, dest_slot, badge);
    return (int)r.error;
}

/* Move a capability */
int salty_cnode_move(cap_t dest_cnode, uint64_t dest_slot,
                     cap_t src_cnode, uint64_t src_slot) {
    struct salty_result r = salty_invoke(dest_cnode, CNODE_MOVE,
                                        dest_slot, src_cnode, src_slot, 0);
    return (int)r.error;
}

/* Mutate a capability (move + change badge) */
int salty_cnode_mutate(cap_t dest_cnode, uint64_t dest_slot,
                       cap_t src_cnode, uint64_t src_slot,
                       uint64_t badge) {
    struct salty_result r = salty_invoke(dest_cnode, CNODE_MUTATE,
                                        dest_slot, src_cnode, src_slot, badge);
    return (int)r.error;
}

/* Save the reply capability */
int salty_cnode_save_caller(cap_t cnode, uint64_t slot) {
    struct salty_result r = salty_invoke(cnode, CNODE_SAVE_CALLER, slot, 0, 0, 0);
    return (int)r.error;
}

/* Delete a single capability */
int salty_cnode_delete(cap_t cnode, uint64_t slot) {
    struct salty_result r = salty_invoke(cnode, CNODE_DELETE, slot, 0, 0, 0);
    return (int)r.error;
}

/* Revoke a capability and all descendants */
int salty_cnode_revoke(cap_t cnode, uint64_t slot) {
    struct salty_result r = salty_invoke(cnode, CNODE_REVOKE, slot, 0, 0, 0);
    return (int)r.error;
}

/* Non-blocking send */
int salty_nbsend(cap_t ep, const struct salty_msg *msg) {
    uint64_t info = SALTY_MSGINFO(msg->label, msg->length, 0);
    struct salty_result r = salty_syscall(
        SYS_NBSEND, ep,
        info, msg->regs[0], msg->regs[1], msg->regs[2], msg->regs[3]
    );
    return (int)r.error;
}

/* Poll notification without blocking */
int salty_poll(cap_t ntfn, uint64_t *bits) {
    struct salty_result r = salty_syscall(SYS_POLL, ntfn, 0, 0, 0, 0, 0);
    if (r.error == 0 && bits)
        *bits = r.value;
    return (int)r.error;
}

/* Debug: write character to kernel serial */
void salty_debug_putchar(char c) {
    salty_syscall(SYS_DEBUG_PUTCHAR, (uint64_t)(uint8_t)c, 0, 0, 0, 0, 0);
}

/* Debug: dump thread state to kernel serial */
void salty_debug_dump_state(void) {
    salty_syscall(SYS_DEBUG_DUMP_STATE, 0, 0, 0, 0, 0, 0);
}

/* Set IPC buffer address for a TCB */
int salty_tcb_set_ipc_buffer(cap_t tcb, uint64_t addr) {
    struct salty_result r = salty_invoke(tcb, TCB_SET_IPC_BUFFER, addr, 0, 0, 0);
    return (int)r.error;
}
