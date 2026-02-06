/* SaltyOS Init Process / Process Manager
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * First userspace process. Receives initial capabilities from kernel
 * and bootstraps the system:
 *   Phase 1: IPC test (send/recv between two threads)
 *   Phase 2: Fault handling test (page fault -> handler -> resume)
 *   Phase 3: Spawn console server from initrd
 *   Phase 4: Process manager loop
 */

#include "salty.h"
#include "cpio.h"
#include "elf_loader.h"

/* Well-known capability slots in init's CSpace (set by kernel) */
#define CAP_SELF_TCB        0
#define CAP_SELF_VSPACE     1
#define CAP_SELF_CSPACE     2
#define CAP_PROCMGR_EP      3
#define CAP_VFS_EP          4
#define CAP_NAMESERV_EP     5
#define CAP_UNTYPED_START   16

/* Dynamically allocated capability slots (from retype)
 * Must be above CAP_UNTYPED_START + MAX_INIT_UNTYPEDS (16+64=80) */
#define CAP_TEST_EP         128
#define CAP_TEST_TCB        129
#define CAP_TEST_SC         130

/* Phase 2: Fault handling caps */
#define CAP_FAULT_EP        131
#define CAP_FAULT_TCB       132
#define CAP_FAULT_SC        133
#define CAP_FAULT_FRAME     134

/* Phase 3+4: Process manager dynamic caps
 * We allocate from slot 200+ for child process objects */
#define CAP_CHILD_BASE      200
#define CAP_CHILD_TCB       (CAP_CHILD_BASE + 0)
#define CAP_CHILD_VSPACE    (CAP_CHILD_BASE + 1)
#define CAP_CHILD_CNODE     (CAP_CHILD_BASE + 2)
#define CAP_CHILD_SC        (CAP_CHILD_BASE + 3)
#define CAP_CHILD_STACK_FR  (CAP_CHILD_BASE + 4)
#define CAP_CHILD_EP        (CAP_CHILD_BASE + 5)  /* Endpoint for console */
/* ELF loader will use cap slots starting at CAP_CHILD_BASE + 16 for frames */
#define CAP_CHILD_FRAME_START (CAP_CHILD_BASE + 16)

/* Unmapped user address for fault test (1GB, page-aligned) */
#define FAULT_TEST_ADDR     0x40000000ULL

/* Child process code base address (4 MB in child VSpace) */
#define CHILD_CODE_VADDR    0x0000000000400000ULL
/* Child stack (8 MB in child VSpace) */
#define CHILD_STACK_VADDR   0x0000000000800000ULL
#define CHILD_STACK_TOP     (CHILD_STACK_VADDR + 4096)

/* Thread 2 stack (4KB in BSS, page-aligned) */
static uint8_t thread2_stack[4096] __attribute__((aligned(4096)));

/* Fault handler stack */
static uint8_t fault_handler_stack[4096] __attribute__((aligned(4096)));

/* Thread 2 entry point: receives a message from the endpoint */
static void thread2_entry(void) {
    salty_serial_puts("[THREAD2] started, waiting on endpoint\n");

    struct salty_msg msg;
    uint64_t badge = 0;

    int err = salty_recv(CAP_TEST_EP, &msg, &badge);
    if (err == 0) {
        salty_serial_puts("[THREAD2] received message! label=");
        salty_serial_hex(msg.label);
        salty_serial_puts(" reg0=");
        salty_serial_hex(msg.regs[0]);
        salty_serial_puts("\n");
    } else {
        salty_serial_puts("[THREAD2] recv failed, error=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts("\n");
    }

    /* Yield loop after receiving */
    for (;;) {
        salty_yield();
    }
}

/* Fault handler thread: receives fault, maps page, replies */
static void fault_handler_entry(void) {
    salty_serial_puts("[FAULT_HANDLER] started, waiting for fault\n");

    struct salty_msg msg;
    uint64_t badge = 0;

    int err = salty_recv(CAP_FAULT_EP, &msg, &badge);
    if (err != 0) {
        salty_serial_puts("[FAULT_HANDLER] recv failed err=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts("\n");
        goto done;
    }
    salty_serial_puts("[FAULT_HANDLER] received fault! mapping page...\n");

    /* Map a frame at the known fault address */
    err = salty_vspace_map(CAP_SELF_VSPACE, CAP_FAULT_FRAME,
                           FAULT_TEST_ADDR,
                           VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER);
    if (err != 0) {
        salty_serial_puts("[FAULT_HANDLER] vspace_map failed err=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts("\n");
    } else {
        salty_serial_puts("[FAULT_HANDLER] page mapped OK\n");
    }

    /* Reply to resume faulting thread, then wait for next fault */
    struct salty_msg reply;
    reply.label = 0;
    reply.regs[0] = 0;
    reply.regs[1] = 0;
    reply.regs[2] = 0;
    reply.regs[3] = 0;
    salty_reply_recv(CAP_FAULT_EP, &reply, &msg, &badge);

done:
    for (;;) { salty_yield(); }
}

/* ================================================================
 * Phase 1: IPC Test
 * ================================================================ */
static int phase1_ipc_test(cap_t ut) {
    int err;

    salty_serial_puts("[INIT] Phase 1: IPC test\n");

    /* 1. Retype an Endpoint */
    err = salty_untyped_retype(ut, OBJ_ENDPOINT, 0, CAP_TEST_EP);
    if (err != 0) {
        salty_serial_puts("[INIT] FAIL: Endpoint retype error=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts("\n");
        return -1;
    }
    salty_serial_puts("[INIT] Endpoint created at slot 32\n");

    /* 2. Retype a TCB */
    err = salty_untyped_retype(ut, OBJ_TCB, 0, CAP_TEST_TCB);
    if (err != 0) {
        salty_serial_puts("[INIT] FAIL: TCB retype error=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts("\n");
        return -1;
    }
    salty_serial_puts("[INIT] TCB created at slot 33\n");

    /* 3. Retype a SchedContext */
    err = salty_untyped_retype(ut, OBJ_SCHED_CONTEXT, 0, CAP_TEST_SC);
    if (err != 0) {
        salty_serial_puts("[INIT] FAIL: SchedContext retype error=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts("\n");
        return -1;
    }
    salty_serial_puts("[INIT] SchedContext created at slot 34\n");

    /* 4. Set CSpace/VSpace for thread2 (share with init) */
    err = salty_tcb_set_space(CAP_TEST_TCB, CAP_SELF_CSPACE, CAP_SELF_VSPACE);
    if (err != 0) {
        salty_serial_puts("[INIT] FAIL: TCB_SET_SPACE error=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts("\n");
        return -1;
    }
    salty_serial_puts("[INIT] TCB space set (shared CSpace/VSpace)\n");

    /* 5. Configure thread2 entry point and stack */
    uint64_t t2_rip = (uint64_t)thread2_entry;
    uint64_t t2_rsp = (uint64_t)(thread2_stack + sizeof(thread2_stack));
    err = salty_tcb_configure(CAP_TEST_TCB, t2_rip, t2_rsp, 0);
    if (err != 0) {
        salty_serial_puts("[INIT] FAIL: TCB_CONFIGURE error=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts("\n");
        return -1;
    }
    salty_serial_puts("[INIT] TCB configured: rip=");
    salty_serial_hex(t2_rip);
    salty_serial_puts(" rsp=");
    salty_serial_hex(t2_rsp);
    salty_serial_puts("\n");

    /* 6. Configure and bind scheduling context */
    err = salty_sc_configure(CAP_TEST_SC, 10000, 100000);
    if (err != 0) {
        salty_serial_puts("[INIT] FAIL: SC_CONFIGURE error=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts("\n");
        return -1;
    }

    err = salty_sc_bind(CAP_TEST_SC, CAP_TEST_TCB);
    if (err != 0) {
        salty_serial_puts("[INIT] FAIL: SC_BIND error=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts("\n");
        return -1;
    }
    salty_serial_puts("[INIT] SchedContext configured and bound\n");

    /* 7. Resume thread2 */
    err = salty_tcb_resume(CAP_TEST_TCB);
    if (err != 0) {
        salty_serial_puts("[INIT] FAIL: TCB_RESUME error=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts("\n");
        return -1;
    }
    salty_serial_puts("[INIT] Thread2 resumed\n");

    /* 8. Give thread2 time to start and block on recv */
    salty_yield();

    /* 9. Send a test message to the endpoint */
    salty_serial_puts("[INIT] Sending test message to endpoint\n");
    struct salty_msg msg;
    msg.label = 0x42;
    msg.regs[0] = 0xDEADBEEF;
    msg.regs[1] = 0;
    msg.regs[2] = 0;
    msg.regs[3] = 0;
    err = salty_send(CAP_TEST_EP, &msg);
    if (err != 0) {
        salty_serial_puts("[INIT] FAIL: send error=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts("\n");
        return -1;
    }
    salty_serial_puts("[INIT] Message sent successfully!\n");
    salty_serial_puts("[INIT] Phase 1 IPC test PASSED\n");
    return 0;
}

/* ================================================================
 * Phase 2: Fault Handling Test
 * ================================================================ */
static int phase2_fault_test(cap_t ut) {
    int err;

    salty_serial_puts("\n[INIT] Phase 2: Fault test\n");

    /* 1. Retype fault endpoint */
    err = salty_untyped_retype(ut, OBJ_ENDPOINT, 0, CAP_FAULT_EP);
    if (err != 0) {
        salty_serial_puts("[INIT] FAIL: fault EP retype err=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts("\n");
        return -1;
    }

    /* 2. Retype fault handler TCB */
    err = salty_untyped_retype(ut, OBJ_TCB, 0, CAP_FAULT_TCB);
    if (err != 0) {
        salty_serial_puts("[INIT] FAIL: fault TCB retype err=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts("\n");
        return -1;
    }

    /* 3. Retype SchedContext */
    err = salty_untyped_retype(ut, OBJ_SCHED_CONTEXT, 0, CAP_FAULT_SC);
    if (err != 0) {
        salty_serial_puts("[INIT] FAIL: fault SC retype err=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts("\n");
        return -1;
    }

    /* 4. Retype a Frame (physical page to map at fault address) */
    err = salty_untyped_retype(ut, OBJ_FRAME, 0, CAP_FAULT_FRAME);
    if (err != 0) {
        salty_serial_puts("[INIT] FAIL: fault Frame retype err=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts("\n");
        return -1;
    }
    salty_serial_puts("[INIT] Fault objects created (EP/TCB/SC/Frame)\n");

    /* 5. Set up fault handler thread */
    err = salty_tcb_set_space(CAP_FAULT_TCB, CAP_SELF_CSPACE, CAP_SELF_VSPACE);
    if (err != 0) {
        salty_serial_puts("[INIT] FAIL: fault TCB set_space err=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts("\n");
        return -1;
    }

    uint64_t fh_rip = (uint64_t)fault_handler_entry;
    uint64_t fh_rsp = (uint64_t)(fault_handler_stack + sizeof(fault_handler_stack));
    err = salty_tcb_configure(CAP_FAULT_TCB, fh_rip, fh_rsp, 0);
    if (err != 0) {
        salty_serial_puts("[INIT] FAIL: fault TCB configure err=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts("\n");
        return -1;
    }

    err = salty_sc_configure(CAP_FAULT_SC, 10000, 100000);
    if (err != 0) {
        salty_serial_puts("[INIT] FAIL: fault SC configure err=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts("\n");
        return -1;
    }

    err = salty_sc_bind(CAP_FAULT_SC, CAP_FAULT_TCB);
    if (err != 0) {
        salty_serial_puts("[INIT] FAIL: fault SC bind err=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts("\n");
        return -1;
    }

    /* 6. Set init's fault handler to the fault endpoint */
    err = salty_tcb_set_fault_handler(CAP_SELF_TCB, CAP_FAULT_EP);
    if (err != 0) {
        salty_serial_puts("[INIT] FAIL: set_fault_handler err=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts("\n");
        return -1;
    }
    salty_serial_puts("[INIT] Fault handler set on init TCB\n");

    /* 7. Start fault handler thread */
    err = salty_tcb_resume(CAP_FAULT_TCB);
    if (err != 0) {
        salty_serial_puts("[INIT] FAIL: fault TCB resume err=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts("\n");
        return -1;
    }

    /* 8. Let handler start and block on recv */
    salty_yield();

    /* 9. Trigger page fault at unmapped address */
    salty_serial_puts("[INIT] Triggering page fault at ");
    salty_serial_hex(FAULT_TEST_ADDR);
    salty_serial_puts("\n");

    volatile uint64_t *fault_ptr = (volatile uint64_t *)FAULT_TEST_ADDR;
    uint64_t val = *fault_ptr;

    salty_serial_puts("[INIT] Resumed after fault! val=");
    salty_serial_hex(val);
    salty_serial_puts("\n");
    salty_serial_puts("[INIT] Phase 2 Fault test PASSED\n");
    return 0;
}

/* ================================================================
 * Phase 3: Spawn Console Server
 * ================================================================
 * Creates a child process from console.elf in the initrd:
 *   1. Retype: TCB, VSpace, CNode, SchedContext, stack Frame
 *   2. Load ELF segments into child VSpace
 *   3. Copy required caps (IoPort, IRQ, Notification, Endpoint) into child CNode
 *   4. Configure TCB and start the process
 *
 * Requires kernel to have placed IoPort/IRQ/Notification caps at
 * well-known slots (CAP_COM1_IOPORT, CAP_COM1_IRQ, CAP_COM1_NTFN)
 * and mapped the initrd at INITRD_VADDR.
 */
static int phase3_spawn_console(cap_t ut) {
    int err;

    salty_serial_puts("\n[INIT] Phase 3: Spawning console server\n");

    /* Check if initrd is accessible. The kernel should have mapped it.
     * If the first 6 bytes are not CPIO magic, skip Phase 3. */
    const uint8_t *initrd = (const uint8_t *)INITRD_VADDR;

    /* We need the initrd size. The kernel places it in a well-known location.
     * For now, scan up to 1MB for the TRAILER!!! entry. */
    size_t initrd_size = 1024 * 1024; /* Conservative upper bound */

    /* Find console.elf in the CPIO archive */
    struct cpio_entry console_entry;
    if (!cpio_find_file(initrd, initrd_size, "console.elf", &console_entry)) {
        salty_serial_puts("[INIT] console.elf not found in initrd, skipping Phase 3\n");
        return -1;
    }

    salty_serial_puts("[INIT] Found console.elf (");
    salty_serial_hex(console_entry.data_len);
    salty_serial_puts(" bytes)\n");

    /* 1. Retype child process objects */
    err = salty_untyped_retype(ut, OBJ_TCB, 0, CAP_CHILD_TCB);
    if (err != 0) {
        salty_serial_puts("[INIT] FAIL: child TCB retype err=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts("\n");
        return -1;
    }

    err = salty_untyped_retype(ut, OBJ_VSPACE, 0, CAP_CHILD_VSPACE);
    if (err != 0) {
        salty_serial_puts("[INIT] FAIL: child VSpace retype err=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts("\n");
        return -1;
    }

    err = salty_untyped_retype(ut, OBJ_CNODE, 0, CAP_CHILD_CNODE);
    if (err != 0) {
        salty_serial_puts("[INIT] FAIL: child CNode retype err=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts("\n");
        return -1;
    }

    err = salty_untyped_retype(ut, OBJ_SCHED_CONTEXT, 0, CAP_CHILD_SC);
    if (err != 0) {
        salty_serial_puts("[INIT] FAIL: child SC retype err=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts("\n");
        return -1;
    }

    err = salty_untyped_retype(ut, OBJ_FRAME, 0, CAP_CHILD_STACK_FR);
    if (err != 0) {
        salty_serial_puts("[INIT] FAIL: child stack Frame retype err=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts("\n");
        return -1;
    }

    /* Retype an endpoint for console server IPC */
    err = salty_untyped_retype(ut, OBJ_ENDPOINT, 0, CAP_CHILD_EP);
    if (err != 0) {
        salty_serial_puts("[INIT] FAIL: child EP retype err=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts("\n");
        return -1;
    }

    salty_serial_puts("[INIT] Child objects created (TCB/VS/CN/SC/FR/EP)\n");

    /* 2. Load ELF into child VSpace */
    struct elf_loader_ctx loader_ctx;
    loader_ctx.untyped = ut;
    loader_ctx.self_vspace = CAP_SELF_VSPACE;
    loader_ctx.child_vspace = CAP_CHILD_VSPACE;
    loader_ctx.scratch_vaddr = SCRATCH_VADDR;
    loader_ctx.next_frame_slot = CAP_CHILD_FRAME_START;

    struct elf_load_result elf_result;
    err = elf_load(console_entry.data, console_entry.data_len,
                   CHILD_CODE_VADDR, &loader_ctx, &elf_result);
    if (err != 0) {
        salty_serial_puts("[INIT] FAIL: ELF load err=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts("\n");
        return -1;
    }

    salty_serial_puts("[INIT] ELF loaded: entry=");
    salty_serial_hex(elf_result.entry);
    salty_serial_puts(" brk=");
    salty_serial_hex(elf_result.brk);
    salty_serial_puts("\n");

    /* 3. Map child stack */
    err = salty_vspace_map(CAP_CHILD_VSPACE, CAP_CHILD_STACK_FR,
                           CHILD_STACK_VADDR,
                           VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER);
    if (err != 0) {
        salty_serial_puts("[INIT] FAIL: child stack map err=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts("\n");
        return -1;
    }

    /* 4. Copy caps into child's CNode.
     * Child CNode layout (must match console/main.c):
     *   0 = TCB (self)
     *   1 = VSpace (self)
     *   2 = CSpace (self)
     *   3 = Server endpoint
     *   4 = IoPort (COM1)
     *   5 = IRQ handler (COM1)
     *   6 = Notification (COM1)
     */

    /* Copy child TCB cap -> child CNode slot 0 */
    err = salty_cnode_copy(CAP_SELF_CSPACE, CAP_CHILD_TCB,
                           CAP_CHILD_CNODE, 0, 0);
    if (err != 0) {
        salty_serial_puts("[INIT] FAIL: copy child TCB cap err=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts("\n");
        return -1;
    }

    /* Copy child VSpace cap -> child CNode slot 1 */
    err = salty_cnode_copy(CAP_SELF_CSPACE, CAP_CHILD_VSPACE,
                           CAP_CHILD_CNODE, 1, 0);
    if (err != 0) {
        salty_serial_puts("[INIT] FAIL: copy child VSpace cap err=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts("\n");
        return -1;
    }

    /* Copy child CNode cap -> child CNode slot 2 */
    err = salty_cnode_copy(CAP_SELF_CSPACE, CAP_CHILD_CNODE,
                           CAP_CHILD_CNODE, 2, 0);
    if (err != 0) {
        salty_serial_puts("[INIT] FAIL: copy child CNode cap err=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts("\n");
        return -1;
    }

    /* Copy console endpoint -> child CNode slot 3 */
    err = salty_cnode_copy(CAP_SELF_CSPACE, CAP_CHILD_EP,
                           CAP_CHILD_CNODE, 3, 0);
    if (err != 0) {
        salty_serial_puts("[INIT] FAIL: copy child EP cap err=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts("\n");
        return -1;
    }

    /* Copy IoPort cap -> child CNode slot 4 */
    err = salty_cnode_copy(CAP_SELF_CSPACE, CAP_COM1_IOPORT,
                           CAP_CHILD_CNODE, 4, 0);
    if (err != 0) {
        salty_serial_puts("[INIT] WARN: copy IoPort cap err=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts(" (kernel may not have IoPort support yet)\n");
        /* Not fatal: continue without IoPort */
    }

    /* Copy IRQ handler -> child CNode slot 5 */
    err = salty_cnode_copy(CAP_SELF_CSPACE, CAP_COM1_IRQ,
                           CAP_CHILD_CNODE, 5, 0);
    if (err != 0) {
        salty_serial_puts("[INIT] WARN: copy IRQ cap err=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts(" (may not be provisioned yet)\n");
    }

    /* Copy notification -> child CNode slot 6 */
    err = salty_cnode_copy(CAP_SELF_CSPACE, CAP_COM1_NTFN,
                           CAP_CHILD_CNODE, 6, 0);
    if (err != 0) {
        salty_serial_puts("[INIT] WARN: copy NTFN cap err=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts(" (may not be provisioned yet)\n");
    }

    /* 5. Configure child TCB */
    err = salty_tcb_set_space(CAP_CHILD_TCB, CAP_CHILD_CNODE, CAP_CHILD_VSPACE);
    if (err != 0) {
        salty_serial_puts("[INIT] FAIL: child TCB set_space err=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts("\n");
        return -1;
    }

    err = salty_tcb_configure(CAP_CHILD_TCB, elf_result.entry,
                               CHILD_STACK_TOP, 0);
    if (err != 0) {
        salty_serial_puts("[INIT] FAIL: child TCB configure err=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts("\n");
        return -1;
    }

    /* 6. Configure and bind scheduling context */
    err = salty_sc_configure(CAP_CHILD_SC, 10000, 100000);
    if (err != 0) {
        salty_serial_puts("[INIT] FAIL: child SC configure err=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts("\n");
        return -1;
    }

    err = salty_sc_bind(CAP_CHILD_SC, CAP_CHILD_TCB);
    if (err != 0) {
        salty_serial_puts("[INIT] FAIL: child SC bind err=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts("\n");
        return -1;
    }

    /* 7. Start the console server */
    err = salty_tcb_resume(CAP_CHILD_TCB);
    if (err != 0) {
        salty_serial_puts("[INIT] FAIL: child TCB resume err=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts("\n");
        return -1;
    }

    salty_serial_puts("[INIT] Console server started!\n");
    salty_serial_puts("[INIT] Phase 3 PASSED\n");
    return 0;
}

/* ================================================================
 * Phase 4: Process Manager Loop
 * ================================================================
 * After spawning console, the init process becomes the process
 * manager. It waits for requests on CAP_PROCMGR_EP.
 * For now, just enters an idle loop.
 */
static void phase4_procmgr_loop(void) {
    salty_serial_puts("\n[INIT] Phase 4: Process manager active\n");
    salty_serial_puts("[INIT] All phases complete. Entering idle loop.\n");

    for (;;) {
        salty_yield();
    }
}

/* Entry point */
void _start(void) {
    salty_serial_puts("[INIT] SaltyOS init process starting\n");

    /* Find a usable untyped memory region */
    cap_t ut = CAP_UNTYPED_START;

    /* Phase 1: IPC test */
    if (phase1_ipc_test(ut) != 0)
        goto fail;

    /* Phase 2: Fault handling test */
    if (phase2_fault_test(ut) != 0)
        goto fail;

    /* Phase 3: Spawn console server (may fail if kernel support not ready) */
    phase3_spawn_console(ut);

    /* Phase 4: Process manager idle loop */
    phase4_procmgr_loop();

fail:
    /* Loop forever (init should never exit) */
    for (;;) {
        salty_yield();
    }
}
