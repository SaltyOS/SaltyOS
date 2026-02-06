/* SaltyOS Process Manager
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Manages process lifecycle: spawn, exit, wait, getpid.
 * Loads ELF binaries from the initrd CPIO archive.
 *
 * IPC protocol:
 *   Label 1 = SPAWN:  ELF name in MRs -> returns PID in regs[0]
 *   Label 2 = EXIT:   exit code in regs[0]
 *   Label 3 = WAIT:   child PID in regs[0] -> returns exit code in regs[0]
 *   Label 4 = GETPID: -> returns PID in regs[0]
 *
 * Cap layout (set by init):
 *   0 = self TCB
 *   1 = self VSpace
 *   2 = self CSpace
 *   3 = server endpoint
 *   7 = untyped memory
 *   8 = nameserv endpoint (for registering itself)
 */

#define SALTY_STATIC
#include "salty.h"
#include "cpio.h"
#include "elf_loader.h"

/* IPC buffer pointer */
__attribute__((visibility("hidden")))
void *__salty_ipc_buffer = (void *)0;

/* Send cap counter */
__attribute__((visibility("hidden")))
int __salty_send_cap_count = 0;

/* Cap layout */
#define CAP_SELF_TCB     0
#define CAP_SELF_VSPACE  1
#define CAP_SELF_CSPACE  2
#define CAP_SERVER_EP    3
#define CAP_UNTYPED      7
#define CAP_NAMESERV_EP  8

/* IPC buffer setup (pre-mapped by init) */
#define IPC_BUF_VADDR       0x0000000000200000ULL

/* Protocol labels */
#define PM_SPAWN   1
#define PM_EXIT    2
#define PM_WAIT    3
#define PM_GETPID  4

/* Process states */
#define PROC_FREE     0
#define PROC_RUNNING  1
#define PROC_ZOMBIE   2  /* Exited but not yet waited on */

/* Process table limits */
#define MAX_PROCESSES  32
#define MAX_NAME_LEN   32

/* Child VSpace layout */
#define CHILD_CODE_VADDR    0x0000000000400000ULL
#define CHILD_STACK_VADDR   0x0000000000800000ULL
#define CHILD_STACK_PAGES   4
#define CHILD_STACK_SIZE    (CHILD_STACK_PAGES * 4096ULL)
#define CHILD_STACK_TOP     (CHILD_STACK_VADDR + CHILD_STACK_SIZE)
#define CHILD_IPC_BUF_VADDR 0x0000000000200000ULL

/* Cap slots for child objects.
 * Each process gets a block of 128 cap slots starting at this base.
 * Within each block:
 *   +0  = child TCB
 *   +1  = child VSpace
 *   +2  = child CNode
 *   +3  = child SchedContext
 *   +4  = child stack frame (top page)
 *   +5  = child IPC buffer frame
 *   +16..+79 = ELF segment frames
 */
#define CAP_PROC_BASE       256
#define CAP_PROC_STRIDE     128
#define CAP_OFF_TCB         0
#define CAP_OFF_VSPACE      1
#define CAP_OFF_CNODE       2
#define CAP_OFF_SC           3
#define CAP_OFF_STACK_FR    4
#define CAP_OFF_IPC_FR      5
#define CAP_OFF_FRAME_START 16

/* Child CNode layout (set by procmgr when spawning):
 *   0 = child TCB (self)
 *   1 = child VSpace (self)
 *   2 = child CNode (self)
 *   3 = server endpoint (procmgr EP, badged with PID for identity)
 *   7 = untyped (for the child to retype its own IPC buffer, etc.)
 */
#define CHILD_CAP_TCB       0
#define CHILD_CAP_VSPACE    1
#define CHILD_CAP_CSPACE    2
#define CHILD_CAP_EP        3
#define CHILD_CAP_UNTYPED   7

struct process {
    uint32_t pid;
    uint8_t  state;
    int      exit_code;
    uint64_t badge;     /* Badge on the procmgr EP for this process */
    cap_t    tcb_cap;
    cap_t    vspace_cap;
    cap_t    cnode_cap;
    cap_t    sc_cap;
};

static struct process proctab[MAX_PROCESSES];
static uint32_t next_pid = 1;

static struct process *find_proc_by_badge(uint64_t badge) {
    for (int i = 0; i < MAX_PROCESSES; i++) {
        if (proctab[i].state != PROC_FREE && proctab[i].badge == badge)
            return &proctab[i];
    }
    return (struct process *)0;
}

static struct process *find_proc_by_pid(uint32_t pid) {
    for (int i = 0; i < MAX_PROCESSES; i++) {
        if (proctab[i].state != PROC_FREE && proctab[i].pid == pid)
            return &proctab[i];
    }
    return (struct process *)0;
}

static struct process *alloc_proc(void) {
    for (int i = 0; i < MAX_PROCESSES; i++) {
        if (proctab[i].state == PROC_FREE)
            return &proctab[i];
    }
    return (struct process *)0;
}

static void handle_spawn(const struct salty_msg *msg, struct salty_msg *reply) {
    /* Extract ELF name: regs[0] = length, regs[1..] = packed name bytes */
    uint8_t name_len = (uint8_t)msg->regs[0];
    if (name_len > MAX_NAME_LEN) name_len = MAX_NAME_LEN;

    char name[MAX_NAME_LEN + 5]; /* +4 for ".elf" + NUL */
    const uint8_t *raw = (const uint8_t *)&msg->regs[1];
    for (uint8_t i = 0; i < name_len; i++)
        name[i] = (char)raw[i];

    /* Append .elf suffix if not already present */
    int has_elf = 0;
    if (name_len >= 4 &&
        name[name_len-4] == '.' && name[name_len-3] == 'e' &&
        name[name_len-2] == 'l' && name[name_len-1] == 'f') {
        has_elf = 1;
    }
    if (!has_elf && name_len + 4 <= MAX_NAME_LEN) {
        name[name_len++] = '.';
        name[name_len++] = 'e';
        name[name_len++] = 'l';
        name[name_len++] = 'f';
    }
    name[name_len] = '\0';

    salty_serial_puts("[PROCMGR] SPAWN: '");
    salty_serial_puts(name);
    salty_serial_puts("'\n");

    /* Find ELF in initrd */
    const uint8_t *initrd = (const uint8_t *)INITRD_VADDR;
    size_t initrd_size = cpio_archive_size(initrd, 1024 * 1024);

    struct cpio_entry elf_entry;
    if (!cpio_find_file(initrd, initrd_size, name, &elf_entry)) {
        salty_serial_puts("[PROCMGR] ELF not found in initrd\n");
        reply->label = SALTY_NOT_FOUND;
        return;
    }

    salty_serial_puts("[PROCMGR] Found ELF (");
    salty_serial_hex(elf_entry.data_len);
    salty_serial_puts(" bytes)\n");

    /* Allocate process slot */
    struct process *proc = alloc_proc();
    if (!proc) {
        salty_serial_puts("[PROCMGR] process table full\n");
        reply->label = SALTY_OUT_OF_MEMORY;
        return;
    }

    uint32_t pid = next_pid++;
    int slot_idx = (int)(proc - proctab);
    cap_t base = CAP_PROC_BASE + (cap_t)slot_idx * CAP_PROC_STRIDE;

    cap_t child_tcb    = base + CAP_OFF_TCB;
    cap_t child_vs     = base + CAP_OFF_VSPACE;
    cap_t child_cn     = base + CAP_OFF_CNODE;
    cap_t child_sc     = base + CAP_OFF_SC;
    cap_t child_stk_fr = base + CAP_OFF_STACK_FR;
    cap_t child_ipc_fr = base + CAP_OFF_IPC_FR;

    int err;

    /* 1. Retype child objects */
    err = salty_untyped_retype(CAP_UNTYPED, OBJ_TCB, 0, child_tcb);
    if (err != 0) { reply->label = SALTY_OUT_OF_MEMORY; return; }

    err = salty_untyped_retype(CAP_UNTYPED, OBJ_VSPACE, 0, child_vs);
    if (err != 0) { reply->label = SALTY_OUT_OF_MEMORY; return; }

    err = salty_untyped_retype(CAP_UNTYPED, OBJ_CNODE, 0, child_cn);
    if (err != 0) { reply->label = SALTY_OUT_OF_MEMORY; return; }

    err = salty_untyped_retype(CAP_UNTYPED, OBJ_SCHED_CONTEXT, 0, child_sc);
    if (err != 0) { reply->label = SALTY_OUT_OF_MEMORY; return; }

    err = salty_untyped_retype(CAP_UNTYPED, OBJ_FRAME, 0, child_stk_fr);
    if (err != 0) { reply->label = SALTY_OUT_OF_MEMORY; return; }

    err = salty_untyped_retype(CAP_UNTYPED, OBJ_FRAME, 0, child_ipc_fr);
    if (err != 0) { reply->label = SALTY_OUT_OF_MEMORY; return; }

    salty_serial_puts("[PROCMGR] Objects retyped for PID ");
    salty_serial_hex((uint64_t)pid);
    salty_serial_puts("\n");

    /* 2. Load ELF into child VSpace */
    struct elf_loader_ctx loader_ctx;
    loader_ctx.untyped = CAP_UNTYPED;
    loader_ctx.self_vspace = CAP_SELF_VSPACE;
    loader_ctx.child_vspace = child_vs;
    loader_ctx.scratch_vaddr = SCRATCH_VADDR;
    loader_ctx.next_frame_slot = base + CAP_OFF_FRAME_START;

    struct elf_load_result elf_result;
    err = elf_load(elf_entry.data, elf_entry.data_len,
                   CHILD_CODE_VADDR, &loader_ctx, &elf_result);
    if (err != 0) {
        salty_serial_puts("[PROCMGR] ELF load failed err=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts("\n");
        reply->label = SALTY_INVALID_ARGUMENT;
        return;
    }

    salty_serial_puts("[PROCMGR] ELF loaded: entry=");
    salty_serial_hex(elf_result.entry);
    salty_serial_puts("\n");

    /* 3. Map stack pages */
    for (int pg = 0; pg < CHILD_STACK_PAGES; pg++) {
        uint64_t page_vaddr = CHILD_STACK_VADDR + (uint64_t)pg * 4096ULL;
        cap_t frame_slot;

        if (pg == CHILD_STACK_PAGES - 1) {
            frame_slot = child_stk_fr; /* Top page, already retyped */
        } else {
            frame_slot = loader_ctx.next_frame_slot++;
            err = salty_untyped_retype(CAP_UNTYPED, OBJ_FRAME, 0, frame_slot);
            if (err != 0) {
                salty_serial_puts("[PROCMGR] stack frame retype failed\n");
                reply->label = SALTY_OUT_OF_MEMORY;
                return;
            }
        }

        err = salty_vspace_map(child_vs, frame_slot, page_vaddr,
                               VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER);
        if (err != 0) {
            salty_serial_puts("[PROCMGR] stack map failed err=");
            salty_serial_hex((uint64_t)err);
            salty_serial_puts("\n");
            reply->label = SALTY_OUT_OF_MEMORY;
            return;
        }
    }

    /* 4. Map IPC buffer page in child VSpace */
    err = salty_vspace_map(child_vs, child_ipc_fr, CHILD_IPC_BUF_VADDR,
                           VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER);
    if (err != 0) {
        salty_serial_puts("[PROCMGR] IPC buf map failed\n");
        reply->label = SALTY_OUT_OF_MEMORY;
        return;
    }

    /* 5. Copy caps into child CNode */
    /* Child slot 0 = TCB (self) */
    err = salty_cnode_copy(CAP_SELF_CSPACE, child_tcb,
                           child_cn, CHILD_CAP_TCB, CAP_RIGHTS_ALL);
    if (err != 0) {
        salty_serial_puts("[PROCMGR] copy TCB cap failed\n");
        reply->label = SALTY_OUT_OF_MEMORY;
        return;
    }

    /* Child slot 1 = VSpace (self) */
    err = salty_cnode_copy(CAP_SELF_CSPACE, child_vs,
                           child_cn, CHILD_CAP_VSPACE, CAP_RIGHTS_ALL);
    if (err != 0) {
        salty_serial_puts("[PROCMGR] copy VSpace cap failed\n");
        reply->label = SALTY_OUT_OF_MEMORY;
        return;
    }

    /* Child slot 2 = CNode (self) */
    err = salty_cnode_copy(CAP_SELF_CSPACE, child_cn,
                           child_cn, CHILD_CAP_CSPACE, CAP_RIGHTS_ALL);
    if (err != 0) {
        salty_serial_puts("[PROCMGR] copy CNode cap failed\n");
        reply->label = SALTY_OUT_OF_MEMORY;
        return;
    }

    /* Child slot 3 = Procmgr EP (badged with PID for identity) */
    uint64_t badge = (uint64_t)pid;
    err = salty_cnode_mint(CAP_SELF_CSPACE, CAP_SERVER_EP,
                           child_cn, CHILD_CAP_EP, badge);
    if (err != 0) {
        salty_serial_puts("[PROCMGR] mint EP cap failed err=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts("\n");
        reply->label = SALTY_OUT_OF_MEMORY;
        return;
    }

    /* Child slot 7 = Untyped (for child to retype its own frames) */
    err = salty_cnode_copy(CAP_SELF_CSPACE, CAP_UNTYPED,
                           child_cn, CHILD_CAP_UNTYPED, CAP_RIGHTS_ALL);
    if (err != 0) {
        salty_serial_puts("[PROCMGR] WARN: copy Untyped cap failed\n");
    }

    /* 6. Configure child TCB */
    err = salty_tcb_set_space(child_tcb, child_cn, child_vs);
    if (err != 0) {
        salty_serial_puts("[PROCMGR] TCB set_space failed\n");
        reply->label = SALTY_OUT_OF_MEMORY;
        return;
    }

    err = salty_tcb_configure(child_tcb, elf_result.entry, CHILD_STACK_TOP, 0);
    if (err != 0) {
        salty_serial_puts("[PROCMGR] TCB configure failed\n");
        reply->label = SALTY_OUT_OF_MEMORY;
        return;
    }

    /* Set child IPC buffer */
    salty_invoke(child_tcb, TCB_SET_IPC_BUFFER, CHILD_IPC_BUF_VADDR, 0, 0, 0);

    /* 7. Configure and bind scheduling context */
    err = salty_sc_configure(child_sc, 10000, 100000);
    if (err != 0) {
        salty_serial_puts("[PROCMGR] SC configure failed\n");
        reply->label = SALTY_OUT_OF_MEMORY;
        return;
    }

    err = salty_sc_bind(child_sc, child_tcb);
    if (err != 0) {
        salty_serial_puts("[PROCMGR] SC bind failed\n");
        reply->label = SALTY_OUT_OF_MEMORY;
        return;
    }

    /* 8. Start the process */
    err = salty_tcb_resume(child_tcb);
    if (err != 0) {
        salty_serial_puts("[PROCMGR] TCB resume failed\n");
        reply->label = SALTY_OUT_OF_MEMORY;
        return;
    }

    /* Record in process table */
    proc->pid = pid;
    proc->state = PROC_RUNNING;
    proc->exit_code = 0;
    proc->badge = badge;
    proc->tcb_cap = child_tcb;
    proc->vspace_cap = child_vs;
    proc->cnode_cap = child_cn;
    proc->sc_cap = child_sc;

    salty_serial_puts("[PROCMGR] Process started PID=");
    salty_serial_hex((uint64_t)pid);
    salty_serial_puts("\n");

    reply->label = SALTY_OK;
    reply->length = 1;
    reply->regs[0] = (uint64_t)pid;
}

static void handle_exit(const struct salty_msg *msg, struct salty_msg *reply, uint64_t badge) {
    int exit_code = (int)msg->regs[0];

    struct process *proc = find_proc_by_badge(badge);
    if (!proc) {
        salty_serial_puts("[PROCMGR] EXIT from unknown badge=");
        salty_serial_hex(badge);
        salty_serial_puts("\n");
        reply->label = SALTY_NOT_FOUND;
        return;
    }

    salty_serial_puts("[PROCMGR] EXIT PID=");
    salty_serial_hex((uint64_t)proc->pid);
    salty_serial_puts(" code=");
    salty_serial_hex((uint64_t)exit_code);
    salty_serial_puts("\n");

    proc->state = PROC_ZOMBIE;
    proc->exit_code = exit_code;

    /* Suspend the thread (it called exit, so we don't reply) */
    salty_invoke(proc->tcb_cap, TCB_SUSPEND, 0, 0, 0, 0);
}

static void handle_wait(const struct salty_msg *msg, struct salty_msg *reply, uint64_t badge) {
    uint32_t child_pid = (uint32_t)msg->regs[0];

    struct process *child = find_proc_by_pid(child_pid);
    if (!child) {
        reply->label = SALTY_NOT_FOUND;
        return;
    }

    if (child->state == PROC_ZOMBIE) {
        /* Already exited, return immediately */
        reply->label = SALTY_OK;
        reply->length = 1;
        reply->regs[0] = (uint64_t)child->exit_code;

        /* Free the process slot */
        child->state = PROC_FREE;
    } else {
        /* Process still running. For now, return BUSY.
         * A proper implementation would block the caller until the child exits.
         */
        reply->label = SALTY_BUSY;
    }
    (void)badge;
}

static void handle_getpid(struct salty_msg *reply, uint64_t badge) {
    struct process *proc = find_proc_by_badge(badge);
    if (!proc) {
        reply->label = SALTY_NOT_FOUND;
        return;
    }

    reply->label = SALTY_OK;
    reply->length = 1;
    reply->regs[0] = (uint64_t)proc->pid;
}

void _start(void) {
    salty_serial_puts("[PROCMGR] SaltyOS process manager starting\n");

    int err;

    /* Init already mapped this process's IPC buffer at IPC_BUF_VADDR. */
    err = salty_tcb_set_ipc_buffer(CAP_SELF_TCB, IPC_BUF_VADDR);
    if (err != 0) {
        salty_serial_puts("[PROCMGR] FAIL: set IPC buffer err=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts("\n");
        goto idle;
    }
    __salty_ipc_buffer = (void *)IPC_BUF_VADDR;

    salty_serial_puts("[PROCMGR] IPC buffer ready\n");

    /* Initialize process table */
    for (int i = 0; i < MAX_PROCESSES; i++)
        proctab[i].state = PROC_FREE;

    /* Register with name server (if available) */
    if (CAP_NAMESERV_EP != 0) {
        struct salty_msg reg_msg, reg_reply;
        reg_msg.label = 1; /* NS_REGISTER */
        reg_msg.length = 5;
        reg_msg.regs[0] = 7; /* length of "procmgr" */
        const char *svc_name = "procmgr";
        uint8_t *dst = (uint8_t *)&reg_msg.regs[1];
        for (int i = 0; i < 7; i++) dst[i] = (uint8_t)svc_name[i];
        reg_msg.regs[2] = 0;
        reg_msg.regs[3] = 0;

        /* Set up cap transfer: send our server EP */
        salty_set_send_cap(0, CAP_SERVER_EP);

        err = salty_call(CAP_NAMESERV_EP, &reg_msg, &reg_reply);
        if (err == 0 && reg_reply.label == SALTY_OK) {
            salty_serial_puts("[PROCMGR] registered with nameserv\n");
        } else {
            salty_serial_puts("[PROCMGR] WARN: nameserv registration failed\n");
        }
    }

    /* Initial recv */
    struct salty_msg msg;
    uint64_t badge = 0;

    err = salty_recv(CAP_SERVER_EP, &msg, &badge);
    if (err != 0) {
        salty_serial_puts("[PROCMGR] initial recv failed\n");
        goto idle;
    }

    /* Server loop */
    for (;;) {
        struct salty_msg reply;
        reply.label = 0;
        reply.length = 0;
        for (int i = 0; i < 4; i++) reply.regs[i] = 0;
        int skip_reply = 0;

        switch (msg.label) {
        case PM_SPAWN:
            handle_spawn(&msg, &reply);
            break;
        case PM_EXIT:
            handle_exit(&msg, &reply, badge);
            skip_reply = 1;
            break;
        case PM_WAIT:
            handle_wait(&msg, &reply, badge);
            break;
        case PM_GETPID:
            handle_getpid(&reply, badge);
            break;
        default:
            salty_serial_puts("[PROCMGR] unknown label=");
            salty_serial_hex(msg.label);
            salty_serial_puts("\n");
            reply.label = SALTY_INVALID_OPERATION;
            break;
        }

        if (skip_reply) {
            err = salty_recv(CAP_SERVER_EP, &msg, &badge);
        } else {
            err = salty_reply_recv(CAP_SERVER_EP, &reply, &msg, &badge);
        }
        if (err != 0) {
            salty_serial_puts("[PROCMGR] reply_recv failed err=");
            salty_serial_hex((uint64_t)err);
            salty_serial_puts("\n");
            break;
        }
    }

idle:
    for (;;) { salty_yield(); }
}
