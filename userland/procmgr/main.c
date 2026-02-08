/* SaltyOS Process Manager
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Manages process lifecycle: spawn, exit, wait, getpid, fork, exec, getppid.
 * Loads ELF binaries from the initrd CPIO archive.
 *
 * IPC protocol:
 *   Label 1 = SPAWN:   ELF name in MRs -> returns PID in regs[0]
 *   Label 2 = EXIT:    exit code in regs[0]
 *   Label 3 = WAIT:    child PID in regs[0] -> returns exit code in regs[0]
 *   Label 4 = GETPID:  -> returns PID in regs[0]
 *   Label 5 = FORK:    caller RSP in regs[0], child entry in regs[1],
 *                       saved rbp/rbx/r12-r15 in regs[2..7],
 *                       caller return RIP in regs[8]
 *                       -> parent: returns child PID in regs[0]
 *                       -> child: starts at entry with RSP
 *   Label 6 = EXEC:    path in regs[0..] -> never returns on success
 *   Label 7 = GETPPID: -> returns parent PID in regs[0]
 *
 * Cap layout (set by init):
 *   0 = self TCB
 *   1 = self VSpace
 *   2 = self CSpace
 *   3 = server endpoint
 *   7 = untyped memory
 *   8 = nameserv endpoint (for registering itself)
 *   9 = VFS endpoint (passed directly by init)
 */

#include "salty.h"
#include "cpio.h"
#include "elf_loader.h"
#include "elf_dynamic.h"

/* Cap layout */
#define CAP_SELF_TCB     0
#define CAP_SELF_VSPACE  1
#define CAP_SELF_CSPACE  2
#define CAP_SERVER_EP    3
#define CAP_UNTYPED      7
#define CAP_NAMESERV_EP  8
#define CAP_VFS_EP       9

/* IPC buffer setup (pre-mapped by init) */
#define IPC_BUF_VADDR       0x0000000000200000ULL

/* Protocol labels */
#define PM_SPAWN   1
#define PM_EXIT    2
#define PM_WAIT    3
#define PM_GETPID  4
#define PM_FORK    5
#define PM_EXEC    6
#define PM_GETPPID 7

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
#define CHILD_RTLD_VADDR    0x0000000002000000ULL
#define CHILD_INITRD_VADDR  0x0000000001000000ULL
#define CHILD_SCRATCH_VADDR 0x0000000004000000ULL
#define CHILD_RTLD_FRAME_SLOT_START 64
/* Scratch VA in procmgr's own VSpace for ELF loader copy-in staging.
 * Must not overlap procmgr's own rtld mapping at 0x2000000.
 */
#define PROCMGR_SCRATCH_VADDR 0x0000000005000000ULL

/* Saved reply cap slots for blocking waitpid.
 * Each process that is blocked in waitpid gets a reply cap saved here.
 * These sit in the procmgr's own CSpace, separate from proc cap blocks.
 */
#define CAP_REPLY_STRIDE 1

/* x86_64 page-table bits returned by VSPACE_WALK (raw PTE flags). */
#define X86_PTE_WRITABLE (1ULL << 1)
#define X86_PTE_NX       (1ULL << 63)

/* Cap slots for child objects.
 * Each process gets a block of CAP_PROC_STRIDE cap slots starting at this base.
 * Within each block:
 *   +0  = child TCB
 *   +1  = child VSpace
 *   +2  = child CNode
 *   +3  = child SchedContext
 *   +4  = child stack frame (top page)
 *   +5  = child IPC buffer frame
 *   +16..    = ELF/stack/initrd staging frames
 */
#define CAP_PROC_BASE       256
#define CAP_PROC_STRIDE     192
#define CAP_OFF_TCB         0
#define CAP_OFF_VSPACE      1
#define CAP_OFF_CNODE       2
#define CAP_OFF_SC           3
#define CAP_OFF_STACK_FR    4
#define CAP_OFF_IPC_FR      5
#define CAP_OFF_FRAME_START 16
/* Place saved reply slots after all process cap blocks to avoid overlap. */
#define CAP_REPLY_BASE      (CAP_PROC_BASE + CAP_PROC_STRIDE * MAX_PROCESSES)

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
#define CHILD_CAP_VFS       4
#define CHILD_CAP_NAMESERV  5
#define CHILD_CAP_UNTYPED   7
/* Child CNode is created with size_bits=0 (kernel default = 2^10 slots). */
#define CHILD_CNODE_SLOTS   1024

/* Auxiliary vector types */
#define AT_NULL    0
#define AT_PHDR    3
#define AT_PHENT   4
#define AT_PHNUM   5
#define AT_PAGESZ  6
#define AT_BASE    7
#define AT_ENTRY   9

/* SaltyOS custom auxv types */
#define AT_SALTY_UNTYPED     0x1000
#define AT_SALTY_VSPACE      0x1001
#define AT_SALTY_SCRATCH     0x1002
#define AT_SALTY_INITRD      0x1003
#define AT_SALTY_INITRD_SZ   0x1004
#define AT_SALTY_FRAME_SLOT  0x1005

struct process {
    uint32_t pid;
    uint32_t ppid;       /* Parent PID (0 = spawned by init/procmgr) */
    uint8_t  state;
    int      exit_code;
    uint64_t badge;      /* Badge on the procmgr EP for this process */
    cap_t    tcb_cap;
    cap_t    vspace_cap;
    cap_t    cnode_cap;
    cap_t    sc_cap;
    /* Blocking waitpid support (specific child) */
    cap_t    waiter_reply;  /* CNode slot holding saved reply cap (0 = no waiter) */
    uint32_t waiter_pid;    /* PID of process blocked waiting on this child */
    /* Blocking waitpid(-1) support (any child) */
    cap_t    any_waiter_reply;  /* Reply cap for parent blocked on any child */
    uint8_t  waiting_for_any;   /* 1 if parent is blocked in waitpid(-1) */
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

static void cleanup_proc_resources(struct process *proc) {
    int slot_idx = (int)(proc - proctab);
    cap_t base = CAP_PROC_BASE + (cap_t)slot_idx * CAP_PROC_STRIDE;
    cap_t child_cn = proc->cnode_cap;

    /* Revoke entries inside the child CNode first so child-side descendants
     * (e.g. rtld allocations from CHILD_CAP_UNTYPED) are reclaimed. */
    if (child_cn != 0) {
        for (uint64_t i = 0; i < CHILD_CNODE_SLOTS; i++) {
            int err = salty_cnode_revoke(child_cn, i);
            if (err != 0)
                (void)salty_cnode_delete(child_cn, i);
        }
    }

    /* Clear the per-process cap block so the slot can be reused on next spawn. */
    for (cap_t i = 0; i < CAP_PROC_STRIDE; i++) {
        cap_t slot = base + i;
        int err = salty_cnode_revoke(CAP_SELF_CSPACE, slot);
        if (err != 0)
            (void)salty_cnode_delete(CAP_SELF_CSPACE, slot);
    }

    proc->pid = 0;
    proc->ppid = 0;
    proc->exit_code = 0;
    proc->badge = 0;
    proc->tcb_cap = 0;
    proc->vspace_cap = 0;
    proc->cnode_cap = 0;
    proc->sc_cap = 0;
    proc->waiter_reply = 0;
    proc->waiter_pid = 0;
    proc->state = PROC_FREE;
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

    int is_dynamic = elf_has_interp(elf_entry.data, elf_entry.data_len);
    if (is_dynamic) {
        salty_serial_puts("[PROCMGR] ELF is dynamically linked\n");
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

    /* 2. Load executable ELF into child VSpace */
    struct elf_loader_ctx loader_ctx;
    loader_ctx.untyped = CAP_UNTYPED;
    loader_ctx.self_vspace = CAP_SELF_VSPACE;
    loader_ctx.child_vspace = child_vs;
    loader_ctx.scratch_vaddr = PROCMGR_SCRATCH_VADDR;
    loader_ctx.next_frame_slot = base + CAP_OFF_FRAME_START;
    loader_ctx.alloc_frame_slot = 0;
    loader_ctx.alloc_opaque = 0;
    loader_ctx.record_page = 0;
    loader_ctx.record_opaque = 0;

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

    /* 2b. If dynamic, load rtld into child VSpace */
    struct elf_load_result rtld_result;
    rtld_result.entry = 0;
    rtld_result.base = 0;
    rtld_result.brk = 0;

    if (is_dynamic) {
        const char *rtld_name = "ld-salty.so";
        const char *interp = elf_get_interp(elf_entry.data, elf_entry.data_len);
        if (interp && interp[0]) {
            const char *last = interp;
            const char *p = interp;
            while (*p) {
                if (*p == '/')
                    last = p + 1;
                p++;
            }
            if (*last)
                rtld_name = last;
        }

        struct cpio_entry rtld_entry;
        if (!cpio_find_file(initrd, initrd_size, rtld_name, &rtld_entry)) {
            salty_serial_puts("[PROCMGR] rtld not found in initrd: ");
            salty_serial_puts(rtld_name);
            salty_serial_puts("\n");
            reply->label = SALTY_NOT_FOUND;
            return;
        }

        err = elf_load(rtld_entry.data, rtld_entry.data_len,
                       CHILD_RTLD_VADDR, &loader_ctx, &rtld_result);
        if (err != 0) {
            salty_serial_puts("[PROCMGR] rtld load failed err=");
            salty_serial_hex((uint64_t)err);
            salty_serial_puts("\n");
            reply->label = SALTY_INVALID_ARGUMENT;
            return;
        }
    }

    /* 3. Map stack pages */
    for (int pg = 0; pg < CHILD_STACK_PAGES; pg++) {
        uint64_t page_vaddr = CHILD_STACK_VADDR + (uint64_t)pg * 4096ULL;
        cap_t frame_slot;

        if (pg == CHILD_STACK_PAGES - 1) {
            frame_slot = child_stk_fr; /* Top page, already retyped */
        } else {
            cap_t frame_limit = base + CAP_PROC_STRIDE;
            if (loader_ctx.next_frame_slot >= frame_limit) {
                salty_serial_puts("[PROCMGR] stack frame slot overflow\n");
                reply->label = SALTY_OUT_OF_MEMORY;
                return;
            }
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

    /* 4b. Dynamic executables need initrd mapped so rtld can load .so files */
    if (is_dynamic) {
        size_t initrd_pages = (initrd_size + 4095) / 4096;
        for (size_t pg = 0; pg < initrd_pages; pg++) {
            cap_t frame_limit = base + CAP_PROC_STRIDE;
            if (loader_ctx.next_frame_slot >= frame_limit) {
                salty_serial_puts("[PROCMGR] initrd frame slot overflow\n");
                reply->label = SALTY_OUT_OF_MEMORY;
                return;
            }
            cap_t fr_slot = loader_ctx.next_frame_slot++;
            err = salty_untyped_retype(CAP_UNTYPED, OBJ_FRAME, 0, fr_slot);
            if (err != 0) {
                salty_serial_puts("[PROCMGR] initrd frame retype failed\n");
                reply->label = SALTY_OUT_OF_MEMORY;
                return;
            }

            err = salty_vspace_map(CAP_SELF_VSPACE, fr_slot,
                                   PROCMGR_SCRATCH_VADDR,
                                   VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER);
            if (err != 0) {
                salty_serial_puts("[PROCMGR] initrd scratch map failed\n");
                reply->label = SALTY_OUT_OF_MEMORY;
                return;
            }

            volatile uint8_t *scratch = (volatile uint8_t *)PROCMGR_SCRATCH_VADDR;
            const uint8_t *src = initrd + pg * 4096;
            size_t copy_len = 4096;
            if (pg * 4096 + copy_len > initrd_size)
                copy_len = initrd_size - pg * 4096;
            for (size_t i = 0; i < copy_len; i++)
                scratch[i] = src[i];
            for (size_t i = copy_len; i < 4096; i++)
                scratch[i] = 0;

            salty_vspace_unmap(CAP_SELF_VSPACE, PROCMGR_SCRATCH_VADDR);

            err = salty_vspace_map(child_vs, fr_slot,
                                   CHILD_INITRD_VADDR + pg * 4096,
                                   VSPACE_FLAG_USER);
            if (err != 0) {
                salty_serial_puts("[PROCMGR] initrd child map failed\n");
                reply->label = SALTY_OUT_OF_MEMORY;
                return;
            }
        }
    }

    /* 5. Copy caps into child CNode */
    err = salty_cnode_copy(CAP_SELF_CSPACE, child_tcb,
                           child_cn, CHILD_CAP_TCB, CAP_RIGHTS_ALL);
    if (err != 0) {
        salty_serial_puts("[PROCMGR] copy TCB cap failed\n");
        reply->label = SALTY_OUT_OF_MEMORY;
        return;
    }

    err = salty_cnode_copy(CAP_SELF_CSPACE, child_vs,
                           child_cn, CHILD_CAP_VSPACE, CAP_RIGHTS_ALL);
    if (err != 0) {
        salty_serial_puts("[PROCMGR] copy VSpace cap failed\n");
        reply->label = SALTY_OUT_OF_MEMORY;
        return;
    }

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

    /* Child slot 7 = Untyped (for child allocations / rtld) */
    err = salty_cnode_copy(CAP_SELF_CSPACE, CAP_UNTYPED,
                           child_cn, CHILD_CAP_UNTYPED, CAP_RIGHTS_ALL);
    if (err != 0) {
        if (is_dynamic) {
            salty_serial_puts("[PROCMGR] copy Untyped cap failed\n");
            reply->label = SALTY_OUT_OF_MEMORY;
            return;
        }
        salty_serial_puts("[PROCMGR] WARN: copy Untyped cap failed\n");
    }

    /* Child slot 4 = VFS EP (so child can do file I/O) */
    err = salty_cnode_copy(CAP_SELF_CSPACE, CAP_VFS_EP,
                           child_cn, CHILD_CAP_VFS, CAP_RIGHTS_ALL);
    if (err != 0) {
        salty_serial_puts("[PROCMGR] WARN: copy VFS EP cap failed\n");
    }

    /* Child slot 5 = Nameserv EP (so child can discover services) */
    err = salty_cnode_copy(CAP_SELF_CSPACE, CAP_NAMESERV_EP,
                           child_cn, CHILD_CAP_NAMESERV, CAP_RIGHTS_ALL);
    if (err != 0) {
        salty_serial_puts("[PROCMGR] WARN: copy Nameserv EP cap failed\n");
    }

    /* 6. Configure child TCB */
    err = salty_tcb_set_space(child_tcb, child_cn, child_vs);
    if (err != 0) {
        salty_serial_puts("[PROCMGR] TCB set_space failed\n");
        reply->label = SALTY_OUT_OF_MEMORY;
        return;
    }

    uint64_t child_entry = elf_result.entry;
    uint64_t child_rsp = CHILD_STACK_TOP;

    if (is_dynamic) {
        err = salty_vspace_map(CAP_SELF_VSPACE, child_stk_fr,
                               PROCMGR_SCRATCH_VADDR,
                               VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER);
        if (err != 0) {
            salty_serial_puts("[PROCMGR] dynamic stack scratch map failed\n");
            reply->label = SALTY_OUT_OF_MEMORY;
            return;
        }

        uint64_t phdr_vaddr = 0;
        uint64_t phent = 0;
        uint64_t phnum = 0;
        if (elf_get_phdr_info(elf_entry.data, elf_entry.data_len, CHILD_CODE_VADDR,
                              &phdr_vaddr, &phent, &phnum) != 0) {
            salty_serial_puts("[PROCMGR] dynamic phdr info extraction failed\n");
            salty_vspace_unmap(CAP_SELF_VSPACE, PROCMGR_SCRATCH_VADDR);
            reply->label = SALTY_INVALID_ARGUMENT;
            return;
        }

        const uint64_t auxv_entries = 13;
        const uint64_t stack_frame_size =
            3 * 8 + auxv_entries * 2 * 8 + 8; /* 240 bytes, 16-byte aligned */

        volatile uint64_t *stack_base =
            (volatile uint64_t *)((uint8_t *)PROCMGR_SCRATCH_VADDR + 4096 - stack_frame_size);

        size_t idx = 0;
        stack_base[idx++] = 0; /* argc */
        stack_base[idx++] = 0; /* argv terminator */
        stack_base[idx++] = 0; /* envp terminator */

        stack_base[idx++] = AT_PHDR;
        stack_base[idx++] = phdr_vaddr;
        stack_base[idx++] = AT_PHENT;
        stack_base[idx++] = phent;
        stack_base[idx++] = AT_PHNUM;
        stack_base[idx++] = phnum;
        stack_base[idx++] = AT_ENTRY;
        stack_base[idx++] = elf_result.entry;
        stack_base[idx++] = AT_BASE;
        stack_base[idx++] = rtld_result.base;
        stack_base[idx++] = AT_PAGESZ;
        stack_base[idx++] = 4096;

        stack_base[idx++] = AT_SALTY_UNTYPED;
        stack_base[idx++] = CHILD_CAP_UNTYPED;
        stack_base[idx++] = AT_SALTY_VSPACE;
        stack_base[idx++] = CHILD_CAP_VSPACE;
        stack_base[idx++] = AT_SALTY_SCRATCH;
        stack_base[idx++] = CHILD_SCRATCH_VADDR;
        stack_base[idx++] = AT_SALTY_INITRD;
        stack_base[idx++] = CHILD_INITRD_VADDR;
        stack_base[idx++] = AT_SALTY_INITRD_SZ;
        stack_base[idx++] = (uint64_t)initrd_size;
        stack_base[idx++] = AT_SALTY_FRAME_SLOT;
        stack_base[idx++] = (uint64_t)CHILD_RTLD_FRAME_SLOT_START;
        stack_base[idx++] = AT_NULL;
        stack_base[idx++] = 0;
        stack_base[idx++] = 0; /* padding */

        salty_vspace_unmap(CAP_SELF_VSPACE, PROCMGR_SCRATCH_VADDR);

        child_rsp = CHILD_STACK_TOP - stack_frame_size;
        child_entry = rtld_result.entry;
    }

    err = salty_tcb_configure(child_tcb, child_entry, child_rsp, 0);
    if (err != 0) {
        salty_serial_puts("[PROCMGR] TCB configure failed\n");
        reply->label = SALTY_OUT_OF_MEMORY;
        return;
    }

    err = salty_tcb_set_ipc_buffer(child_tcb, CHILD_IPC_BUF_VADDR);
    if (err != 0) {
        salty_serial_puts("[PROCMGR] set child IPC buffer failed\n");
        reply->label = SALTY_OUT_OF_MEMORY;
        return;
    }

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
    proc->ppid = 0; /* Spawned by procmgr, no parent process */
    proc->state = PROC_RUNNING;
    proc->exit_code = 0;
    proc->badge = badge;
    proc->tcb_cap = child_tcb;
    proc->vspace_cap = child_vs;
    proc->cnode_cap = child_cn;
    proc->sc_cap = child_sc;
    proc->waiter_reply = 0;
    proc->waiter_pid = 0;

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

    /* If a parent is blocked in waitpid for this specific child, wake them */
    if (proc->waiter_reply != 0) {
        salty_serial_puts("[PROCMGR] Waking waiter for PID=");
        salty_serial_hex((uint64_t)proc->pid);
        salty_serial_puts("\n");

        /* Build reply message for the waiting parent */
        struct salty_msg wake_reply;
        wake_reply.label = SALTY_OK;
        wake_reply.length = 2;
        wake_reply.regs[0] = (uint64_t)exit_code;
        wake_reply.regs[1] = (uint64_t)proc->pid;
        for (int i = 2; i < 20; i++) wake_reply.regs[i] = 0;

        /* Send reply via the saved reply cap */
        int wake_err = salty_send(proc->waiter_reply, &wake_reply);
        if (wake_err != 0) {
            salty_serial_puts("[PROCMGR] wake send failed err=");
            salty_serial_hex((uint64_t)wake_err);
            salty_serial_puts(" pid=");
            salty_serial_hex((uint64_t)proc->pid);
            salty_serial_puts("\n");
        }

        /* Clean up the saved reply cap */
        salty_cnode_delete(CAP_SELF_CSPACE, proc->waiter_reply);
        proc->waiter_reply = 0;
        proc->waiter_pid = 0;

        /* Parent consumed status; reclaim process resources now. */
        cleanup_proc_resources(proc);
        return;
    }

    /* Check if the parent is blocked in waitpid(-1) */
    struct process *parent = find_proc_by_pid(proc->ppid);
    if (parent && parent->waiting_for_any) {
        salty_serial_puts("[PROCMGR] Waking any-waiter parent PID=");
        salty_serial_hex((uint64_t)parent->pid);
        salty_serial_puts(" for child PID=");
        salty_serial_hex((uint64_t)proc->pid);
        salty_serial_puts("\n");

        struct salty_msg wake_reply;
        wake_reply.label = SALTY_OK;
        wake_reply.length = 2;
        wake_reply.regs[0] = (uint64_t)exit_code;
        wake_reply.regs[1] = (uint64_t)proc->pid;
        for (int i = 2; i < 20; i++) wake_reply.regs[i] = 0;

        int wake_err = salty_send(parent->any_waiter_reply, &wake_reply);
        if (wake_err != 0) {
            salty_serial_puts("[PROCMGR] any-wait wake send failed err=");
            salty_serial_hex((uint64_t)wake_err);
            salty_serial_puts("\n");
        }

        salty_cnode_delete(CAP_SELF_CSPACE, parent->any_waiter_reply);
        parent->any_waiter_reply = 0;
        parent->waiting_for_any = 0;

        cleanup_proc_resources(proc);
    }
}

/* WNOHANG flag for waitpid */
#define WNOHANG 1

/* handle_wait: blocking or non-blocking waitpid.
 * Supports specific child (pid > 0) and any child (pid == -1).
 * Returns 1 if the caller should NOT send a reply (blocked), 0 otherwise. */
static int handle_wait(const struct salty_msg *msg, struct salty_msg *reply, uint64_t badge) {
    uint32_t child_pid = (uint32_t)msg->regs[0];
    uint32_t options = (uint32_t)msg->regs[1];

    struct process *caller = find_proc_by_badge(badge);
    if (!caller) {
        reply->label = SALTY_NOT_FOUND;
        return 0;
    }

    /* waitpid(-1): wait for any child */
    if (child_pid == (uint32_t)-1) {
        /* Search for a ZOMBIE child of the caller */
        struct process *zombie = (struct process *)0;
        int has_running_child = 0;
        for (int i = 0; i < MAX_PROCESSES; i++) {
            if (proctab[i].state != PROC_FREE && proctab[i].ppid == caller->pid) {
                if (proctab[i].state == PROC_ZOMBIE && !zombie) {
                    zombie = &proctab[i];
                } else if (proctab[i].state == PROC_RUNNING) {
                    has_running_child = 1;
                }
            }
        }

        if (zombie) {
            /* Return immediately with zombie's info */
            reply->label = SALTY_OK;
            reply->length = 2;
            reply->regs[0] = (uint64_t)zombie->exit_code;
            reply->regs[1] = (uint64_t)zombie->pid;
            cleanup_proc_resources(zombie);
            return 0;
        }

        if (!has_running_child) {
            /* No children at all -> ECHILD equivalent */
            reply->label = SALTY_NOT_FOUND;
            return 0;
        }

        if (options & WNOHANG) {
            /* Non-blocking: no zombie yet, return 0 */
            reply->label = SALTY_OK;
            reply->length = 2;
            reply->regs[0] = 0;
            reply->regs[1] = 0; /* pid=0 means no child exited yet */
            return 0;
        }

        /* Block: save reply cap on the caller (parent) */
        cap_t reply_slot = CAP_REPLY_BASE + MAX_PROCESSES + (cap_t)(caller - proctab);
        int err = salty_cnode_save_caller(CAP_SELF_CSPACE, reply_slot);
        if (err != 0) {
            reply->label = SALTY_OUT_OF_MEMORY;
            return 0;
        }

        caller->any_waiter_reply = reply_slot;
        caller->waiting_for_any = 1;

        salty_serial_puts("[PROCMGR] WAIT(-1) blocking parent PID=");
        salty_serial_hex((uint64_t)caller->pid);
        salty_serial_puts("\n");

        return 1;
    }

    /* waitpid(specific child) */
    struct process *child = find_proc_by_pid(child_pid);
    if (!child) {
        reply->label = SALTY_NOT_FOUND;
        return 0;
    }

    /* Only the parent may wait on a child */
    if (child->ppid != caller->pid) {
        reply->label = SALTY_NOT_FOUND;
        return 0;
    }

    if (child->state == PROC_ZOMBIE) {
        /* Already exited, return immediately */
        reply->label = SALTY_OK;
        reply->length = 2;
        reply->regs[0] = (uint64_t)child->exit_code;
        reply->regs[1] = (uint64_t)child->pid;

        /* Reclaim resources now that status is consumed. */
        cleanup_proc_resources(child);
        return 0;
    }

    if (options & WNOHANG) {
        /* Non-blocking: child still running, return 0 */
        reply->label = SALTY_OK;
        reply->length = 2;
        reply->regs[0] = 0;
        reply->regs[1] = 0;
        return 0;
    }

    /* Child still running — block the caller.
     * Save the reply cap so we can wake the parent later when child exits. */
    cap_t reply_slot = CAP_REPLY_BASE + (cap_t)(child - proctab);
    int err = salty_cnode_save_caller(CAP_SELF_CSPACE, reply_slot);
    if (err != 0) {
        salty_serial_puts("[PROCMGR] save_caller failed for WAIT, err=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts("\n");
        reply->label = SALTY_OUT_OF_MEMORY;
        return 0;
    }

    child->waiter_reply = reply_slot;
    child->waiter_pid = caller->pid;

    salty_serial_puts("[PROCMGR] WAIT blocking for PID=");
    salty_serial_hex((uint64_t)child_pid);
    salty_serial_puts("\n");

    /* Return 1 = skip reply (caller is blocked) */
    return 1;
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

static void handle_getppid(struct salty_msg *reply, uint64_t badge) {
    struct process *proc = find_proc_by_badge(badge);
    if (!proc) {
        reply->label = SALTY_NOT_FOUND;
        return;
    }

    reply->label = SALTY_OK;
    reply->length = 1;
    reply->regs[0] = (uint64_t)proc->ppid;
}

/* handle_fork: Create a child process that is a copy of the caller.
 *
 * Protocol:
 *   regs[0] = caller's current RSP (after saving callee-saved regs)
 *   regs[1] = child entry point (fork_child_entry address)
 *   regs[2] = saved RBP
 *   regs[3] = saved RBX
 *   regs[4] = saved R12
 *   regs[5] = saved R13
 *   regs[6] = saved R14
 *   regs[7] = saved R15
 *   regs[8] = caller return RIP
 *
 * The child gets a copy of the parent's entire user address space.
 * The parent receives the child PID; the child starts at the given entry
 * with the same RSP, and will return 0 from posix_fork().
 */
static void handle_fork(const struct salty_msg *msg, struct salty_msg *reply,
                         uint64_t badge) {
    uint64_t parent_rsp   = msg->regs[0];
    uint64_t child_entry  = msg->regs[1];
    uint64_t saved_rbp    = msg->regs[2];
    uint64_t saved_rbx    = msg->regs[3];
    uint64_t saved_r12    = msg->regs[4];
    uint64_t saved_r13    = msg->regs[5];
    uint64_t saved_r14    = msg->regs[6];
    uint64_t saved_r15    = msg->regs[7];
    uint64_t return_rip   = msg->regs[8];

    if (child_entry == 0 || return_rip == 0) {
        reply->label = SALTY_INVALID_ARGUMENT;
        return;
    }
    /* Child entry pops 6 registers and returns (7 qwords total). */
    if ((parent_rsp & 0xFFFULL) > (4096ULL - 56ULL)) {
        salty_serial_puts("[PROCMGR] FORK: parent stack frame crosses page boundary\n");
        reply->label = SALTY_INVALID_OPERATION;
        return;
    }

    struct process *parent = find_proc_by_badge(badge);
    if (!parent) {
        salty_serial_puts("[PROCMGR] FORK from unknown badge\n");
        reply->label = SALTY_NOT_FOUND;
        return;
    }

    salty_serial_puts("[PROCMGR] FORK from PID=");
    salty_serial_hex((uint64_t)parent->pid);
    salty_serial_puts("\n");

    /* Allocate child process slot */
    struct process *child = alloc_proc();
    if (!child) {
        salty_serial_puts("[PROCMGR] FORK: process table full\n");
        reply->label = SALTY_OUT_OF_MEMORY;
        return;
    }

    uint32_t child_pid = next_pid++;
    int slot_idx = (int)(child - proctab);
    cap_t base = CAP_PROC_BASE + (cap_t)slot_idx * CAP_PROC_STRIDE;

    cap_t child_tcb    = base + CAP_OFF_TCB;
    cap_t child_vs     = base + CAP_OFF_VSPACE;
    cap_t child_cn     = base + CAP_OFF_CNODE;
    cap_t child_sc     = base + CAP_OFF_SC;
    cap_t child_ipc_fr = base + CAP_OFF_IPC_FR;

    int err;

    /* 1. Retype child kernel objects */
    err = salty_untyped_retype(CAP_UNTYPED, OBJ_TCB, 0, child_tcb);
    if (err) { reply->label = SALTY_OUT_OF_MEMORY; return; }
    err = salty_untyped_retype(CAP_UNTYPED, OBJ_VSPACE, 0, child_vs);
    if (err) { reply->label = SALTY_OUT_OF_MEMORY; return; }
    err = salty_untyped_retype(CAP_UNTYPED, OBJ_CNODE, 0, child_cn);
    if (err) { reply->label = SALTY_OUT_OF_MEMORY; return; }
    err = salty_untyped_retype(CAP_UNTYPED, OBJ_SCHED_CONTEXT, 0, child_sc);
    if (err) { reply->label = SALTY_OUT_OF_MEMORY; return; }
    err = salty_untyped_retype(CAP_UNTYPED, OBJ_FRAME, 0, child_ipc_fr);
    if (err) { reply->label = SALTY_OUT_OF_MEMORY; return; }

    /* 2. Walk parent VSpace and copy all user pages into child VSpace */
    cap_t next_frame = base + CAP_OFF_FRAME_START;
    uint64_t walk_start = 0;
    int total_pages = 0;
    uint64_t rsp_page_vaddr = parent_rsp & ~0xFFFULL;
    cap_t rsp_frame = 0;

    for (;;) {
        err = salty_vspace_walk(parent->vspace_cap, walk_start, 6);
        if (err != 0) {
            salty_serial_puts("[PROCMGR] FORK: vspace_walk failed\n");
            break;
        }

        /* Read VSPACE_WALK results from IPC buffer:
         * msg[0]=count, msg[1]=next_vaddr, msg[2..]=(vaddr,phys,flags)* */
        volatile uint64_t *ipc = (volatile uint64_t *)IPC_BUF_VADDR;
        uint64_t count     = ipc[0];
        uint64_t next_addr = ipc[1];

        if (count == 0)
            break;

        for (uint64_t i = 0; i < count; i++) {
            uint64_t page_vaddr = ipc[2 + i * 3 + 0];
            uint64_t page_phys  = ipc[2 + i * 3 + 1];
            uint64_t page_flags = ipc[2 + i * 3 + 2];
            (void)page_phys;

            /* Child gets a dedicated IPC frame in step 3. */
            if (page_vaddr == CHILD_IPC_BUF_VADDR)
                continue;

            /* Retype a new frame for the child */
            err = salty_untyped_retype(CAP_UNTYPED, OBJ_FRAME, 0, next_frame);
            if (err) {
                salty_serial_puts("[PROCMGR] FORK: frame retype failed\n");
                reply->label = SALTY_OUT_OF_MEMORY;
                return;
            }

            /* Copy parent page content into the new child frame.
             * Kernel walks parent page tables and copies via direct mapping. */
            err = salty_vspace_copy_page(parent->vspace_cap,
                                          page_vaddr, next_frame);
            if (err) {
                salty_serial_puts("[PROCMGR] FORK: copy_page failed at ");
                salty_serial_hex(page_vaddr);
                salty_serial_puts(" err=");
                salty_serial_hex((uint64_t)err);
                salty_serial_puts("\n");
                reply->label = SALTY_INVALID_OPERATION;
                return;
            }

            /* Determine child page flags from parent PTE flags */
            uint64_t map_flags = VSPACE_FLAG_USER;
            if (page_flags & X86_PTE_WRITABLE)
                map_flags |= VSPACE_FLAG_WRITABLE;
            if ((page_flags & X86_PTE_NX) == 0)
                map_flags |= VSPACE_FLAG_EXECUTABLE;

            /* Map the frame into child VSpace at the same virtual address */
            err = salty_vspace_map(child_vs, next_frame, page_vaddr, map_flags);
            if (err) {
                salty_serial_puts("[PROCMGR] FORK: child map failed at ");
                salty_serial_hex(page_vaddr);
                salty_serial_puts(" err=");
                salty_serial_hex((uint64_t)err);
                salty_serial_puts("\n");
                reply->label = SALTY_OUT_OF_MEMORY;
                return;
            }

            if (!err && page_vaddr == rsp_page_vaddr)
                rsp_frame = next_frame;

            next_frame++;
            total_pages++;

            cap_t frame_limit = base + CAP_PROC_STRIDE;
            if (next_frame >= frame_limit) {
                salty_serial_puts("[PROCMGR] FORK: frame slot overflow\n");
                reply->label = SALTY_OUT_OF_MEMORY;
                return;
            }
        }

        if (next_addr == 0)
            break;
        walk_start = next_addr;
    }

    salty_serial_puts("[PROCMGR] FORK: copied ");
    salty_serial_hex((uint64_t)total_pages);
    salty_serial_puts(" pages\n");

    if (rsp_frame == 0) {
        salty_serial_puts("[PROCMGR] FORK: parent RSP page not mapped in child\n");
        reply->label = SALTY_INVALID_OPERATION;
        return;
    }

    /* Reconstruct the saved fork trampoline frame on the child stack page so
     * fork_child_entry can pop registers and return to caller safely.
     */
    err = salty_vspace_map(CAP_SELF_VSPACE, rsp_frame,
                           PROCMGR_SCRATCH_VADDR,
                           VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER);
    if (err) {
        salty_serial_puts("[PROCMGR] FORK: stack scratch map failed\n");
        reply->label = SALTY_OUT_OF_MEMORY;
        return;
    }
    {
        size_t off = (size_t)(parent_rsp - rsp_page_vaddr);
        volatile uint64_t *saved = (volatile uint64_t *)(PROCMGR_SCRATCH_VADDR + off);
        saved[0] = saved_r15;
        saved[1] = saved_r14;
        saved[2] = saved_r13;
        saved[3] = saved_r12;
        saved[4] = saved_rbx;
        saved[5] = saved_rbp;
        saved[6] = return_rip;
    }
    salty_vspace_unmap(CAP_SELF_VSPACE, PROCMGR_SCRATCH_VADDR);

    /* 3. Map IPC buffer in child */
    err = salty_vspace_map(child_vs, child_ipc_fr, CHILD_IPC_BUF_VADDR,
                           VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER);
    if (err) {
        salty_serial_puts("[PROCMGR] FORK: IPC buf map failed\n");
        reply->label = SALTY_OUT_OF_MEMORY;
        return;
    }

    /* 4. Copy caps into child CNode */
    /* TCB (self) */
    err = salty_cnode_copy(CAP_SELF_CSPACE, child_tcb,
                           child_cn, CHILD_CAP_TCB, CAP_RIGHTS_ALL);
    if (err) { salty_serial_puts("[PROCMGR] FORK: copy TCB failed\n"); }

    /* VSpace (self) */
    err = salty_cnode_copy(CAP_SELF_CSPACE, child_vs,
                           child_cn, CHILD_CAP_VSPACE, CAP_RIGHTS_ALL);
    if (err) { salty_serial_puts("[PROCMGR] FORK: copy VSpace failed\n"); }

    /* CNode (self) */
    err = salty_cnode_copy(CAP_SELF_CSPACE, child_cn,
                           child_cn, CHILD_CAP_CSPACE, CAP_RIGHTS_ALL);
    if (err) { salty_serial_puts("[PROCMGR] FORK: copy CNode failed\n"); }

    /* Procmgr EP (badged with child PID) */
    uint64_t child_badge = (uint64_t)child_pid;
    err = salty_cnode_mint(CAP_SELF_CSPACE, CAP_SERVER_EP,
                           child_cn, CHILD_CAP_EP, child_badge);
    if (err) { salty_serial_puts("[PROCMGR] FORK: mint EP failed\n"); }

    /* VFS EP */
    err = salty_cnode_copy(CAP_SELF_CSPACE, CAP_VFS_EP,
                           child_cn, CHILD_CAP_VFS, CAP_RIGHTS_ALL);
    if (err) { salty_serial_puts("[PROCMGR] FORK: copy VFS failed\n"); }

    /* Nameserv EP */
    err = salty_cnode_copy(CAP_SELF_CSPACE, CAP_NAMESERV_EP,
                           child_cn, CHILD_CAP_NAMESERV, CAP_RIGHTS_ALL);
    if (err) { salty_serial_puts("[PROCMGR] FORK: copy Nameserv failed\n"); }

    /* Untyped */
    err = salty_cnode_copy(CAP_SELF_CSPACE, CAP_UNTYPED,
                           child_cn, CHILD_CAP_UNTYPED, CAP_RIGHTS_ALL);
    if (err) { salty_serial_puts("[PROCMGR] FORK: copy Untyped failed\n"); }

    /* 5. Configure child TCB */
    err = salty_tcb_set_space(child_tcb, child_cn, child_vs);
    if (err) {
        salty_serial_puts("[PROCMGR] FORK: set_space failed\n");
        reply->label = SALTY_OUT_OF_MEMORY;
        return;
    }

    /* Child starts at fork_child_entry with parent's RSP */
    err = salty_tcb_configure(child_tcb, child_entry, parent_rsp, 0);
    if (err) {
        salty_serial_puts("[PROCMGR] FORK: configure failed\n");
        reply->label = SALTY_OUT_OF_MEMORY;
        return;
    }

    err = salty_tcb_set_ipc_buffer(child_tcb, CHILD_IPC_BUF_VADDR);
    if (err) {
        salty_serial_puts("[PROCMGR] FORK: set IPC buf failed\n");
        reply->label = SALTY_OUT_OF_MEMORY;
        return;
    }

    /* 6. Schedule the child */
    err = salty_sc_configure(child_sc, 10000, 100000);
    if (err) { reply->label = SALTY_OUT_OF_MEMORY; return; }
    err = salty_sc_bind(child_sc, child_tcb);
    if (err) { reply->label = SALTY_OUT_OF_MEMORY; return; }
    err = salty_tcb_resume(child_tcb);
    if (err) { reply->label = SALTY_OUT_OF_MEMORY; return; }

    /* Record in process table */
    child->pid = child_pid;
    child->ppid = parent->pid;
    child->state = PROC_RUNNING;
    child->exit_code = 0;
    child->badge = child_badge;
    child->tcb_cap = child_tcb;
    child->vspace_cap = child_vs;
    child->cnode_cap = child_cn;
    child->sc_cap = child_sc;
    child->waiter_reply = 0;
    child->waiter_pid = 0;

    salty_serial_puts("[PROCMGR] FORK: child PID=");
    salty_serial_hex((uint64_t)child_pid);
    salty_serial_puts(" started\n");

    /* Reply to parent with child PID */
    reply->label = SALTY_OK;
    reply->length = 1;
    reply->regs[0] = (uint64_t)child_pid;
}

/* handle_exec: Replace process image with a new ELF.
 *
 * Protocol:
 *   regs[0] = path length
 *   regs[1..] = packed path bytes
 *
 * On success, the caller's TCB is reconfigured with the new entry point
 * and a fresh stack. The old address space pages are unmapped and replaced.
 */
static void handle_exec(const struct salty_msg *msg, struct salty_msg *reply,
                         uint64_t badge) {
    struct process *proc = find_proc_by_badge(badge);
    if (!proc) {
        reply->label = SALTY_NOT_FOUND;
        return;
    }

    /* Extract path */
    uint8_t path_len = (uint8_t)msg->regs[0];
    if (path_len > MAX_NAME_LEN) path_len = MAX_NAME_LEN;

    char name[MAX_NAME_LEN + 5];
    const uint8_t *raw = (const uint8_t *)&msg->regs[1];
    for (uint8_t i = 0; i < path_len; i++)
        name[i] = (char)raw[i];

    /* Append .elf if needed */
    int has_elf = 0;
    if (path_len >= 4 &&
        name[path_len-4] == '.' && name[path_len-3] == 'e' &&
        name[path_len-2] == 'l' && name[path_len-1] == 'f') {
        has_elf = 1;
    }
    if (!has_elf && path_len + 4 <= MAX_NAME_LEN) {
        name[path_len++] = '.';
        name[path_len++] = 'e';
        name[path_len++] = 'l';
        name[path_len++] = 'f';
    }
    name[path_len] = '\0';

    salty_serial_puts("[PROCMGR] EXEC PID=");
    salty_serial_hex((uint64_t)proc->pid);
    salty_serial_puts(" -> '");
    salty_serial_puts(name);
    salty_serial_puts("'\n");

    /* Find ELF in initrd */
    const uint8_t *initrd = (const uint8_t *)INITRD_VADDR;
    size_t initrd_size = cpio_archive_size(initrd, 1024 * 1024);

    struct cpio_entry elf_entry;
    if (!cpio_find_file(initrd, initrd_size, name, &elf_entry)) {
        salty_serial_puts("[PROCMGR] EXEC: ELF not found\n");
        reply->label = SALTY_NOT_FOUND;
        return;
    }

    int is_dynamic = elf_has_interp(elf_entry.data, elf_entry.data_len);

    /* 1. Unmap existing user pages from the process VSpace.
     * Keep IPC buffer mapped so an error reply can still be delivered
     * safely if exec setup fails before commit. */
    uint64_t walk_start = 0;
    for (;;) {
        int err = salty_vspace_walk(proc->vspace_cap, walk_start, 6);
        if (err != 0) break;

        volatile uint64_t *ipc = (volatile uint64_t *)IPC_BUF_VADDR;
        uint64_t count     = ipc[0];
        uint64_t next_addr = ipc[1];

        if (count == 0) break;

        for (uint64_t i = 0; i < count; i++) {
            uint64_t page_vaddr = ipc[2 + i * 3 + 0];
            if (page_vaddr == CHILD_IPC_BUF_VADDR)
                continue;
            salty_vspace_unmap(proc->vspace_cap, page_vaddr);
        }

        if (next_addr == 0) break;
        walk_start = next_addr;
    }

    /* 2. Load new ELF into the process VSpace.
     * Reuse the existing cap block (frame slots start fresh). */
    int slot_idx = (int)(proc - proctab);
    cap_t frame_base = CAP_PROC_BASE + (cap_t)slot_idx * CAP_PROC_STRIDE + CAP_OFF_FRAME_START;

    /* Reclaim per-process frame slots before reusing them for the new image. */
    cap_t frame_limit = CAP_PROC_BASE + (cap_t)slot_idx * CAP_PROC_STRIDE + CAP_PROC_STRIDE;
    for (cap_t slot = frame_base; slot < frame_limit; slot++) {
        int cerr = salty_cnode_revoke(CAP_SELF_CSPACE, slot);
        if (cerr != 0)
            (void)salty_cnode_delete(CAP_SELF_CSPACE, slot);
    }

    struct elf_loader_ctx loader_ctx;
    loader_ctx.untyped = CAP_UNTYPED;
    loader_ctx.self_vspace = CAP_SELF_VSPACE;
    loader_ctx.child_vspace = proc->vspace_cap;
    loader_ctx.scratch_vaddr = PROCMGR_SCRATCH_VADDR;
    loader_ctx.next_frame_slot = frame_base;
    loader_ctx.alloc_frame_slot = 0;
    loader_ctx.alloc_opaque = 0;
    loader_ctx.record_page = 0;
    loader_ctx.record_opaque = 0;

    struct elf_load_result elf_result;
    int err = elf_load(elf_entry.data, elf_entry.data_len,
                       CHILD_CODE_VADDR, &loader_ctx, &elf_result);
    if (err != 0) {
        salty_serial_puts("[PROCMGR] EXEC: ELF load failed\n");
        salty_serial_puts("[PROCMGR] EXEC: ELF load err=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts("\n");
        reply->label = SALTY_INVALID_ARGUMENT;
        return;
    }

    /* 2b. Load rtld if dynamic */
    struct elf_load_result rtld_result;
    rtld_result.entry = 0;
    rtld_result.base = 0;
    rtld_result.brk = 0;

    if (is_dynamic) {
        const char *rtld_name = "ld-salty.so";
        const char *interp = elf_get_interp(elf_entry.data, elf_entry.data_len);
        if (interp && interp[0]) {
            const char *last = interp;
            const char *p = interp;
            while (*p) {
                if (*p == '/') last = p + 1;
                p++;
            }
            if (*last) rtld_name = last;
        }

        struct cpio_entry rtld_entry;
        if (!cpio_find_file(initrd, initrd_size, rtld_name, &rtld_entry)) {
            salty_serial_puts("[PROCMGR] EXEC: rtld not found\n");
            reply->label = SALTY_NOT_FOUND;
            return;
        }

        err = elf_load(rtld_entry.data, rtld_entry.data_len,
                       CHILD_RTLD_VADDR, &loader_ctx, &rtld_result);
        if (err != 0) {
            salty_serial_puts("[PROCMGR] EXEC: rtld load failed\n");
            reply->label = SALTY_INVALID_ARGUMENT;
            return;
        }
    }

    /* 3. Set up new stack */
    if (loader_ctx.next_frame_slot >= frame_limit) {
        salty_serial_puts("[PROCMGR] EXEC: stack frame slot overflow\n");
        reply->label = SALTY_OUT_OF_MEMORY;
        return;
    }
    cap_t stk_frame = loader_ctx.next_frame_slot++;
    for (int pg = 0; pg < CHILD_STACK_PAGES; pg++) {
        cap_t fr;
        if (pg == CHILD_STACK_PAGES - 1) {
            fr = stk_frame;
        } else {
            if (loader_ctx.next_frame_slot >= frame_limit) {
                salty_serial_puts("[PROCMGR] EXEC: stack frame slot overflow\n");
                reply->label = SALTY_OUT_OF_MEMORY;
                return;
            }
            fr = loader_ctx.next_frame_slot++;
        }
        err = salty_untyped_retype(CAP_UNTYPED, OBJ_FRAME, 0, fr);
        if (err) { reply->label = SALTY_OUT_OF_MEMORY; return; }

        err = salty_vspace_map(proc->vspace_cap, fr,
                               CHILD_STACK_VADDR + (uint64_t)pg * 4096,
                               VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER);
        if (err) { reply->label = SALTY_OUT_OF_MEMORY; return; }
    }

    /* 4. IPC buffer mapping is preserved at CHILD_IPC_BUF_VADDR. */

    /* 5. Map initrd for dynamic executables */
    if (is_dynamic) {
        size_t initrd_pages = (initrd_size + 4095) / 4096;
        for (size_t pg = 0; pg < initrd_pages; pg++) {
            if (loader_ctx.next_frame_slot >= frame_limit) {
                salty_serial_puts("[PROCMGR] EXEC: initrd frame slot overflow\n");
                reply->label = SALTY_OUT_OF_MEMORY;
                return;
            }
            cap_t fr_slot = loader_ctx.next_frame_slot++;
            err = salty_untyped_retype(CAP_UNTYPED, OBJ_FRAME, 0, fr_slot);
            if (err) { reply->label = SALTY_OUT_OF_MEMORY; return; }

            err = salty_vspace_map(CAP_SELF_VSPACE, fr_slot,
                                   PROCMGR_SCRATCH_VADDR,
                                   VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER);
            if (err) { reply->label = SALTY_OUT_OF_MEMORY; return; }

            volatile uint8_t *scratch = (volatile uint8_t *)PROCMGR_SCRATCH_VADDR;
            const uint8_t *src = initrd + pg * 4096;
            size_t copy_len = 4096;
            if (pg * 4096 + copy_len > initrd_size)
                copy_len = initrd_size - pg * 4096;
            for (size_t i = 0; i < copy_len; i++)
                scratch[i] = src[i];
            for (size_t i = copy_len; i < 4096; i++)
                scratch[i] = 0;

            salty_vspace_unmap(CAP_SELF_VSPACE, PROCMGR_SCRATCH_VADDR);

            err = salty_vspace_map(proc->vspace_cap, fr_slot,
                                   CHILD_INITRD_VADDR + pg * 4096,
                                   VSPACE_FLAG_USER);
            if (err) { reply->label = SALTY_OUT_OF_MEMORY; return; }
        }
    }

    /* 6. Determine entry point and set up stack for dynamic linking */
    uint64_t new_entry = elf_result.entry;
    uint64_t new_rsp = CHILD_STACK_TOP;

    if (is_dynamic) {
        /* Write auxv to top stack page */
        err = salty_vspace_map(CAP_SELF_VSPACE, stk_frame,
                               PROCMGR_SCRATCH_VADDR,
                               VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER);
        if (err) { reply->label = SALTY_OUT_OF_MEMORY; return; }

        uint64_t phdr_vaddr = 0, phent = 0, phnum = 0;
        elf_get_phdr_info(elf_entry.data, elf_entry.data_len,
                          CHILD_CODE_VADDR, &phdr_vaddr, &phent, &phnum);

        const uint64_t auxv_entries = 13;
        const uint64_t stack_frame_size = 3 * 8 + auxv_entries * 2 * 8 + 8;

        volatile uint64_t *stack_base =
            (volatile uint64_t *)((uint8_t *)PROCMGR_SCRATCH_VADDR + 4096 - stack_frame_size);

        size_t idx = 0;
        stack_base[idx++] = 0; /* argc */
        stack_base[idx++] = 0; /* argv terminator */
        stack_base[idx++] = 0; /* envp terminator */

        stack_base[idx++] = AT_PHDR;     stack_base[idx++] = phdr_vaddr;
        stack_base[idx++] = AT_PHENT;    stack_base[idx++] = phent;
        stack_base[idx++] = AT_PHNUM;    stack_base[idx++] = phnum;
        stack_base[idx++] = AT_ENTRY;    stack_base[idx++] = elf_result.entry;
        stack_base[idx++] = AT_BASE;     stack_base[idx++] = rtld_result.base;
        stack_base[idx++] = AT_PAGESZ;   stack_base[idx++] = 4096;

        stack_base[idx++] = AT_SALTY_UNTYPED;   stack_base[idx++] = CHILD_CAP_UNTYPED;
        stack_base[idx++] = AT_SALTY_VSPACE;    stack_base[idx++] = CHILD_CAP_VSPACE;
        stack_base[idx++] = AT_SALTY_SCRATCH;   stack_base[idx++] = CHILD_SCRATCH_VADDR;
        stack_base[idx++] = AT_SALTY_INITRD;    stack_base[idx++] = CHILD_INITRD_VADDR;
        stack_base[idx++] = AT_SALTY_INITRD_SZ; stack_base[idx++] = (uint64_t)initrd_size;
        stack_base[idx++] = AT_SALTY_FRAME_SLOT;stack_base[idx++] = CHILD_RTLD_FRAME_SLOT_START;
        stack_base[idx++] = AT_NULL;     stack_base[idx++] = 0;
        stack_base[idx++] = 0; /* padding */

        salty_vspace_unmap(CAP_SELF_VSPACE, PROCMGR_SCRATCH_VADDR);

        new_rsp = CHILD_STACK_TOP - stack_frame_size;
        new_entry = rtld_result.entry;
    }

    /* 7. Suspend the process and reconfigure user entry context.
     * Use TCB_CONFIGURE so the kernel rebuilds the usermode trampoline
     * context (r12/r13/r14/r15 + ring3 iret path). */
    salty_tcb_suspend(proc->tcb_cap);
    err = salty_tcb_configure(proc->tcb_cap, new_entry, new_rsp, 0);
    if (err) {
        salty_serial_puts("[PROCMGR] EXEC: tcb_configure failed\n");
        reply->label = SALTY_INVALID_ARGUMENT;
        return;
    }

    err = salty_tcb_set_ipc_buffer(proc->tcb_cap, CHILD_IPC_BUF_VADDR);
    if (err) {
        salty_serial_puts("[PROCMGR] EXEC: set IPC buf failed\n");
    }

    err = salty_tcb_resume(proc->tcb_cap);
    if (err) {
        salty_serial_puts("[PROCMGR] EXEC: resume failed\n");
        reply->label = SALTY_INVALID_ARGUMENT;
        return;
    }

    salty_serial_puts("[PROCMGR] EXEC: PID=");
    salty_serial_hex((uint64_t)proc->pid);
    salty_serial_puts(" -> entry=");
    salty_serial_hex(new_entry);
    salty_serial_puts("\n");

    /* Don't reply — the process image has been replaced and resumed. */
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
    salty_ipc_context_init(&__salty_ipc_ctx, (void *)IPC_BUF_VADDR);

    salty_serial_puts("[PROCMGR] IPC buffer ready\n");

    /* Initialize process table */
    for (int i = 0; i < MAX_PROCESSES; i++)
        proctab[i].state = PROC_FREE;

    /* Register with name server (if available) */
    if (CAP_NAMESERV_EP != 0) {
        struct salty_msg reg_msg, reg_reply;
        reg_msg.label = 1; /* NS_REGISTER */
        reg_msg.regs[0] = 7; /* length of "procmgr" */
        reg_msg.length = 1 + (uint64_t)((reg_msg.regs[0] + 7) / 8);
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
        for (int i = 0; i < 20; i++) reply.regs[i] = 0;
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
            skip_reply = handle_wait(&msg, &reply, badge);
            break;
        case PM_GETPID:
            handle_getpid(&reply, badge);
            break;
        case PM_FORK:
            handle_fork(&msg, &reply, badge);
            break;
        case PM_EXEC:
            handle_exec(&msg, &reply, badge);
            /* exec replaces process image; don't reply on success */
            if (reply.label == 0)
                skip_reply = 1;
            break;
        case PM_GETPPID:
            handle_getppid(&reply, badge);
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
