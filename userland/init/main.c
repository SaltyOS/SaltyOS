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
#include "elf_dynamic.h"

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

/* IPC buffer caps */
#define CAP_IPC_BUF_FRAME   131
#define CAP_IPC_BUF2_FRAME  132

/* Phase 2: Fault handling caps */
#define CAP_FAULT_EP        133
#define CAP_FAULT_TCB       134
#define CAP_FAULT_SC        135
#define CAP_FAULT_FRAME     136

/* Phase 3+4: Process manager dynamic caps
 * We allocate from slot 200+ for child process objects.
 * Each child gets a 128-slot block:
 *   +0 = TCB, +1 = VSpace, +2 = CNode, +3 = SC,
 *   +4 = stack frame, +5 = EP, +6 = IPC buf frame,
 *   +16.. = ELF/stack frames
 */
#define CAP_CHILD_BASE      200
#define CAP_CHILD_STRIDE    128
#define CAP_CHILD_TCB       (CAP_CHILD_BASE + 0)
#define CAP_CHILD_VSPACE    (CAP_CHILD_BASE + 1)
#define CAP_CHILD_CNODE     (CAP_CHILD_BASE + 2)
#define CAP_CHILD_SC        (CAP_CHILD_BASE + 3)
#define CAP_CHILD_STACK_FR  (CAP_CHILD_BASE + 4)
#define CAP_CHILD_EP        (CAP_CHILD_BASE + 5)  /* Endpoint for console */
#define CAP_CHILD_IPC_FR    (CAP_CHILD_BASE + 6)  /* IPC buffer frame */
/* ELF loader will use cap slots starting at CAP_CHILD_BASE + 16 for frames */
#define CAP_CHILD_FRAME_START (CAP_CHILD_BASE + 16)

/* Phase 4: Nameserv, Procmgr, VFS server cap blocks */
#define CAP_NS_BASE         (CAP_CHILD_BASE + CAP_CHILD_STRIDE * 1)  /* 328 */
#define CAP_PM_BASE         (CAP_CHILD_BASE + CAP_CHILD_STRIDE * 2)  /* 456 */
#define CAP_VFS_BASE        (CAP_CHILD_BASE + CAP_CHILD_STRIDE * 3)  /* 584 */

/* Per-child offsets within a block */
#define COFF_TCB            0
#define COFF_VSPACE         1
#define COFF_CNODE          2
#define COFF_SC             3
#define COFF_STACK_FR       4
#define COFF_EP             5
#define COFF_IPC_FR         6
#define COFF_FRAME_START    16

/* Dynamic frame-cap pool for phase4 server loading.
 * Keep this above fixed phase3/4 object slots.
 */
#define INIT_DYN_FRAME_MIN  720

/* IPC buffer addresses */
#define IPC_BUF_VADDR       0x0000000000200000ULL  /* 2 MB - init's IPC buffer */
#define IPC_BUF2_VADDR      0x0000000000201000ULL  /* 2 MB + 4K - thread2's IPC buffer */

/* Default IPC context for init's main thread (used by legacy wrappers). */
__attribute__((visibility("hidden")))
struct salty_ipc_context __salty_ipc_ctx = { 0 };

/* Unmapped user address for fault test (1GB, page-aligned) */
#define FAULT_TEST_ADDR     0x40000000ULL

/* Child process code base address (4 MB in child VSpace) */
#define CHILD_CODE_VADDR    0x0000000000400000ULL
/* Child stack region in child VSpace */
#define CHILD_STACK_VADDR   0x0000000000800000ULL
#define CHILD_STACK_PAGES   8
#define CHILD_STACK_SIZE    (CHILD_STACK_PAGES * 4096ULL)
#define CHILD_STACK_TOP     (CHILD_STACK_VADDR + CHILD_STACK_SIZE)

/* Dynamic linking addresses in child VSpace */
#define CHILD_RTLD_VADDR    0x0000000002000000ULL  /* ld-salty.so load address */
#define CHILD_INITRD_VADDR  0x0000000001000000ULL  /* initrd mapped in child */
#define CHILD_SCRATCH_VADDR 0x0000000004000000ULL  /* scratch area for rtld */
#define CHILD_IPC_BUF_VADDR 0x0000000000200000ULL  /* IPC buffer for child */

/* init still uses legacy (default-context) libsalty wrappers.
 * Keep that default IPC context pinned to init's own IPC buffer.
 */
static void restore_init_ipc_context(void) {
    salty_invoke(CAP_SELF_TCB, TCB_SET_IPC_BUFFER, IPC_BUF_VADDR, 0, 0, 0);
    salty_ipc_context_init(&__salty_ipc_ctx, (void *)IPC_BUF_VADDR);
}

/* Cap slot for untyped cap copied into child CNode (for rtld frame alloc) */
#define CAP_CHILD_UNTYPED_OFFSET  7
/* First child CNode slot reserved for rtld frame allocations.
 * Keep this above low well-known/service slots to avoid collisions.
 */
#define CHILD_RTLD_FRAME_SLOT_START 64

/* Auxiliary vector types (standard) */
#define AT_NULL    0
#define AT_PHDR    3
#define AT_PHENT   4
#define AT_PHNUM   5
#define AT_PAGESZ  6
#define AT_BASE    7
#define AT_ENTRY   9

/* SaltyOS custom auxv types (pass cap info to rtld) */
#define AT_SALTY_UNTYPED     0x1000
#define AT_SALTY_VSPACE      0x1001
#define AT_SALTY_SCRATCH     0x1002
#define AT_SALTY_INITRD      0x1003
#define AT_SALTY_INITRD_SZ   0x1004
#define AT_SALTY_FRAME_SLOT  0x1005

/* Thread 2 stack (4KB in BSS, page-aligned) */
static uint8_t thread2_stack[4096] __attribute__((aligned(4096)));

/* Fault handler stack */
static uint8_t fault_handler_stack[4096] __attribute__((aligned(4096)));

/* Per-thread IPC contexts used by init's helper threads. */
static struct salty_ipc_context thread2_ipc_ctx;
static struct salty_ipc_context fault_ipc_ctx;

static cap_t init_dyn_frame_next = INIT_DYN_FRAME_MIN;

static cap_t init_alloc_frame_slot(void *opaque) {
    (void)opaque;
    return init_dyn_frame_next++;
}

/* Thread 2 entry point: receives a message from the endpoint */
static void thread2_entry(void) {
    salty_ipc_context_init(&thread2_ipc_ctx, (void *)IPC_BUF2_VADDR);
    salty_serial_puts("[THREAD2] started, waiting on endpoint\n");

    struct salty_msg msg;
    uint64_t badge = 0;

    int err = salty_recv_ctx(&thread2_ipc_ctx, CAP_TEST_EP, &msg, &badge);
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
    salty_ipc_context_init(&fault_ipc_ctx, (void *)IPC_BUF_VADDR);
    salty_serial_puts("[FAULT_HANDLER] started, waiting for fault\n");

    struct salty_msg msg;
    uint64_t badge = 0;

    int err = salty_recv_ctx(&fault_ipc_ctx, CAP_FAULT_EP, &msg, &badge);
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
    reply.length = 0;
    reply.regs[0] = 0;
    reply.regs[1] = 0;
    reply.regs[2] = 0;
    reply.regs[3] = 0;
    salty_reply_recv_ctx(&fault_ipc_ctx, CAP_FAULT_EP, &reply, &msg, &badge);

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

    /* 5b. Set up IPC buffer for thread2 */
    err = salty_untyped_retype(ut, OBJ_FRAME, 0, CAP_IPC_BUF2_FRAME);
    if (err != 0) {
        salty_serial_puts("[INIT] WARN: thread2 IPC buf frame retype err\n");
    } else {
        err = salty_vspace_map(CAP_SELF_VSPACE, CAP_IPC_BUF2_FRAME,
                               IPC_BUF2_VADDR,
                               VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER);
        if (err == 0) {
            salty_invoke(CAP_TEST_TCB, TCB_SET_IPC_BUFFER, IPC_BUF2_VADDR, 0, 0, 0);
        }
    }

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
    msg.length = 1;
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
 * Phase 3: Spawn Console Server (with dynamic linking support)
 * ================================================================
 * Creates a child process from console.elf in the initrd:
 *   1. Retype: TCB, VSpace, CNode, SchedContext, stack Frame
 *   2. Load ELF segments into child VSpace
 *   3. Detect PT_INTERP: if present, load ld-salty.so into child VSpace
 *   4. Map initrd into child VSpace (for rtld to find .so files)
 *   5. Copy required caps into child CNode (including Untyped for rtld)
 *   6. Set up auxiliary vector on child stack
 *   7. Configure TCB (entry = rtld if dynamic, exe if static)
 *   8. Start the process
 */
static int phase3_spawn_console(cap_t ut) {
    int err;

    salty_serial_puts("\n[INIT] Phase 3: Spawning console server\n");

    const uint8_t *initrd = (const uint8_t *)INITRD_VADDR;
    size_t initrd_size = cpio_archive_size(initrd, 1024 * 1024);

    /* Find console.elf in the CPIO archive */
    struct cpio_entry console_entry;
    if (!cpio_find_file(initrd, initrd_size, "console.elf", &console_entry)) {
        salty_serial_puts("[INIT] console.elf not found in initrd, skipping Phase 3\n");
        return -1;
    }

    salty_serial_puts("[INIT] Found console.elf (");
    salty_serial_hex(console_entry.data_len);
    salty_serial_puts(" bytes)\n");

    /* Check if console.elf needs a dynamic linker */
    int is_dynamic = elf_has_interp(console_entry.data, console_entry.data_len);
    if (is_dynamic) {
        salty_serial_puts("[INIT] console.elf is dynamically linked\n");
    }

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

    err = salty_untyped_retype(ut, OBJ_FRAME, 0, CAP_CHILD_IPC_FR);
    if (err != 0) {
        salty_serial_puts("[INIT] FAIL: child IPC Frame retype err=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts("\n");
        return -1;
    }

    err = salty_untyped_retype(ut, OBJ_ENDPOINT, 0, CAP_CHILD_EP);
    if (err != 0) {
        salty_serial_puts("[INIT] FAIL: child EP retype err=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts("\n");
        return -1;
    }

    salty_serial_puts("[INIT] Child objects created (TCB/VS/CN/SC/STK_FR/IPC_FR/EP)\n");

    /* 2. Load console.elf into child VSpace */
    struct elf_loader_ctx loader_ctx;
    loader_ctx.untyped = ut;
    loader_ctx.self_vspace = CAP_SELF_VSPACE;
    loader_ctx.child_vspace = CAP_CHILD_VSPACE;
    loader_ctx.scratch_vaddr = SCRATCH_VADDR;
    loader_ctx.next_frame_slot = CAP_CHILD_FRAME_START;
    loader_ctx.alloc_frame_slot = 0;
    loader_ctx.alloc_opaque = 0;
    loader_ctx.record_page = 0;
    loader_ctx.record_opaque = 0;

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

    /* 3. If dynamically linked, load ld-salty.so into child VSpace */
    struct elf_load_result rtld_result;
    rtld_result.entry = 0;
    rtld_result.base = 0;
    rtld_result.brk = 0;

    if (is_dynamic) {
        struct cpio_entry rtld_entry;
        if (!cpio_find_file(initrd, initrd_size, "ld-salty.so", &rtld_entry)) {
            salty_serial_puts("[INIT] FAIL: ld-salty.so not found in initrd\n");
            return -1;
        }
        salty_serial_puts("[INIT] Found ld-salty.so (");
        salty_serial_hex(rtld_entry.data_len);
        salty_serial_puts(" bytes)\n");

        err = elf_load(rtld_entry.data, rtld_entry.data_len,
                       CHILD_RTLD_VADDR, &loader_ctx, &rtld_result);
        if (err != 0) {
            salty_serial_puts("[INIT] FAIL: rtld ELF load err=");
            salty_serial_hex((uint64_t)err);
            salty_serial_puts("\n");
            return -1;
        }
        salty_serial_puts("[INIT] rtld loaded: entry=");
        salty_serial_hex(rtld_result.entry);
        salty_serial_puts(" base=");
        salty_serial_hex(rtld_result.base);
        salty_serial_puts("\n");
    }

    /* 4. If dynamic, map initrd into child VSpace (read-only).
     * The rtld will search this for .so files.
     */
    if (is_dynamic) {
        size_t initrd_pages = (initrd_size + 4095) / 4096;
        salty_serial_puts("[INIT] Mapping initrd into child (");
        salty_serial_hex(initrd_pages);
        salty_serial_puts(" pages)\n");

        for (size_t pg = 0; pg < initrd_pages; pg++) {
            /* Retype a frame */
            cap_t fr_slot = loader_ctx.next_frame_slot++;
            err = salty_untyped_retype(ut, OBJ_FRAME, 0, fr_slot);
            if (err != 0) {
                salty_serial_puts("[INIT] FAIL: initrd frame retype err=");
                salty_serial_hex((uint64_t)err);
                salty_serial_puts("\n");
                return -1;
            }

            /* Map at scratch in our VSpace, copy initrd data */
            err = salty_vspace_map(CAP_SELF_VSPACE, fr_slot,
                                   SCRATCH_VADDR,
                                   VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER);
            if (err != 0) {
                salty_serial_puts("[INIT] FAIL: initrd scratch map err=");
                salty_serial_hex((uint64_t)err);
                salty_serial_puts("\n");
                return -1;
            }

            volatile uint8_t *scratch = (volatile uint8_t *)SCRATCH_VADDR;
            const uint8_t *src = initrd + pg * 4096;
            size_t copy_len = 4096;
            if (pg * 4096 + copy_len > initrd_size)
                copy_len = initrd_size - pg * 4096;
            for (size_t i = 0; i < copy_len; i++)
                scratch[i] = src[i];
            for (size_t i = copy_len; i < 4096; i++)
                scratch[i] = 0;

            salty_vspace_unmap(CAP_SELF_VSPACE, SCRATCH_VADDR);

            /* Map into child VSpace (read-only + user) */
            err = salty_vspace_map(CAP_CHILD_VSPACE, fr_slot,
                                   CHILD_INITRD_VADDR + pg * 4096,
                                   VSPACE_FLAG_USER);
            if (err != 0) {
                salty_serial_puts("[INIT] FAIL: initrd child map err=");
                salty_serial_hex((uint64_t)err);
                salty_serial_puts("\n");
                return -1;
            }
        }
        salty_serial_puts("[INIT] Initrd mapped in child VSpace\n");
    }

    /* 5. Map child stack pages.
     * Reserve CAP_CHILD_STACK_FR for the top page because we scratch-map it
     * later to write the initial argc/argv/envp/auxv frame.
     */
    for (size_t pg = 0; pg < CHILD_STACK_PAGES; pg++) {
        uint64_t page_vaddr = CHILD_STACK_VADDR + pg * 4096ULL;
        cap_t frame_slot = CAP_CHILD_STACK_FR;

        if (pg != CHILD_STACK_PAGES - 1) {
            frame_slot = loader_ctx.next_frame_slot++;
            err = salty_untyped_retype(ut, OBJ_FRAME, 0, frame_slot);
            if (err != 0) {
                salty_serial_puts("[INIT] FAIL: child stack frame retype err=");
                salty_serial_hex((uint64_t)err);
                salty_serial_puts("\n");
                return -1;
            }
        }

        err = salty_vspace_map(CAP_CHILD_VSPACE, frame_slot,
                               page_vaddr,
                               VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER);
        if (err != 0) {
            salty_serial_puts("[INIT] FAIL: child stack map err=");
            salty_serial_hex((uint64_t)err);
            salty_serial_puts("\n");
            return -1;
        }
    }

    /* 5b. Map IPC buffer frame in child VSpace */
    err = salty_vspace_map(CAP_CHILD_VSPACE, CAP_CHILD_IPC_FR,
                           CHILD_IPC_BUF_VADDR,
                           VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER);
    if (err != 0) {
        salty_serial_puts("[INIT] FAIL: child IPC map err=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts("\n");
        return -1;
    }

    /* 6. Copy caps into child's CNode.
     * Child CNode layout (must match console/main.c):
     *   0 = TCB (self)
     *   1 = VSpace (self)
     *   2 = CSpace (self)
     *   3 = Server endpoint
     *   4 = IoPort (COM1)
     *   5 = IRQ handler (COM1)
     *   6 = Notification (COM1)
     *   7 = Untyped (for rtld, if dynamic)
     */

    /* Copy child TCB cap -> child CNode slot 0 */
    err = salty_cnode_copy(CAP_SELF_CSPACE, CAP_CHILD_TCB,
                           CAP_CHILD_CNODE, 0, CAP_RIGHTS_ALL);
    if (err != 0) {
        salty_serial_puts("[INIT] FAIL: copy child TCB cap err=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts("\n");
        return -1;
    }

    /* Copy child VSpace cap -> child CNode slot 1 */
    err = salty_cnode_copy(CAP_SELF_CSPACE, CAP_CHILD_VSPACE,
                           CAP_CHILD_CNODE, 1, CAP_RIGHTS_ALL);
    if (err != 0) {
        salty_serial_puts("[INIT] FAIL: copy child VSpace cap err=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts("\n");
        return -1;
    }

    /* Copy child CNode cap -> child CNode slot 2 */
    err = salty_cnode_copy(CAP_SELF_CSPACE, CAP_CHILD_CNODE,
                           CAP_CHILD_CNODE, 2, CAP_RIGHTS_ALL);
    if (err != 0) {
        salty_serial_puts("[INIT] FAIL: copy child CNode cap err=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts("\n");
        return -1;
    }

    /* Copy console endpoint -> child CNode slot 3 */
    err = salty_cnode_copy(CAP_SELF_CSPACE, CAP_CHILD_EP,
                           CAP_CHILD_CNODE, 3, CAP_RIGHTS_ALL);
    if (err != 0) {
        salty_serial_puts("[INIT] FAIL: copy child EP cap err=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts("\n");
        return -1;
    }

    /* Copy IoPort cap -> child CNode slot 4 */
    err = salty_cnode_copy(CAP_SELF_CSPACE, CAP_COM1_IOPORT,
                           CAP_CHILD_CNODE, 4, CAP_RIGHTS_ALL);
    if (err != 0) {
        salty_serial_puts("[INIT] WARN: copy IoPort cap err=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts(" (kernel may not have IoPort support yet)\n");
    }

    /* Copy IRQ handler -> child CNode slot 5 */
    err = salty_cnode_copy(CAP_SELF_CSPACE, CAP_COM1_IRQ,
                           CAP_CHILD_CNODE, 5, CAP_RIGHTS_ALL);
    if (err != 0) {
        salty_serial_puts("[INIT] WARN: copy IRQ cap err=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts(" (may not be provisioned yet)\n");
    }

    /* Copy notification -> child CNode slot 6 */
    err = salty_cnode_copy(CAP_SELF_CSPACE, CAP_COM1_NTFN,
                           CAP_CHILD_CNODE, 6, CAP_RIGHTS_ALL);
    if (err != 0) {
        salty_serial_puts("[INIT] WARN: copy NTFN cap err=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts(" (may not be provisioned yet)\n");
    }

    /* Copy Untyped cap -> child CNode slot 7 (for rtld frame allocation) */
    if (is_dynamic) {
        err = salty_cnode_copy(CAP_SELF_CSPACE, ut,
                               CAP_CHILD_CNODE, CAP_CHILD_UNTYPED_OFFSET,
                               CAP_RIGHTS_ALL);
        if (err != 0) {
            salty_serial_puts("[INIT] FAIL: copy Untyped cap err=");
            salty_serial_hex((uint64_t)err);
            salty_serial_puts("\n");
            return -1;
        }
    }

    /* 7. Configure child TCB */
    err = salty_tcb_set_space(CAP_CHILD_TCB, CAP_CHILD_CNODE, CAP_CHILD_VSPACE);
    if (err != 0) {
        salty_serial_puts("[INIT] FAIL: child TCB set_space err=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts("\n");
        return -1;
    }

    /* Entry point and stack pointer depend on whether dynamic or static */
    uint64_t child_entry;
    uint64_t child_rsp = CHILD_STACK_TOP;

    if (is_dynamic) {
        /* Set up auxiliary vector on the child stack page.
         * We scratch-map the stack frame, write auxv at the top, then unmap.
         */
        err = salty_vspace_map(CAP_SELF_VSPACE, CAP_CHILD_STACK_FR,
                               SCRATCH_VADDR,
                               VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER);
        if (err != 0) {
            salty_serial_puts("[INIT] FAIL: scratch map stack err=");
            salty_serial_hex((uint64_t)err);
            salty_serial_puts("\n");
            return -1;
        }

        /* Get phdr info from the executable ELF */
        uint64_t phdr_vaddr, phent, phnum;
        elf_get_phdr_info(console_entry.data, console_entry.data_len,
                          CHILD_CODE_VADDR, &phdr_vaddr, &phent, &phnum);

        /* Build the initial stack layout at the TOP of the page.
         * Stack grows downward, so we place data near the end.
         *
         * Layout (14 auxv entries * 16 bytes = 224, + argc/argv/envp = 24):
         *   total = 248 bytes
         *
         * [page_top - 248] = argc (0)
         * [page_top - 240] = NULL (argv terminator)
         * [page_top - 232] = NULL (envp terminator)
         * [page_top - 224] = AT_PHDR, phdr_vaddr
         * ...
         * [page_top - 8]   = 0 (AT_NULL value)
         */
        #define AUXV_ENTRIES 13  /* 12 entries + AT_NULL terminator */
        #define STACK_FRAME_SIZE  (3 * 8 + AUXV_ENTRIES * 2 * 8 + 8)  /* 240 bytes (16-byte aligned) */

        volatile uint64_t *stack_base =
            (volatile uint64_t *)((uint8_t *)SCRATCH_VADDR + 4096 - STACK_FRAME_SIZE);

        size_t idx = 0;
        /* argc = 0 */
        stack_base[idx++] = 0;
        /* argv terminator (NULL) */
        stack_base[idx++] = 0;
        /* envp terminator (NULL) */
        stack_base[idx++] = 0;

        /* Auxiliary vector entries (key, value pairs) */
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
        stack_base[idx++] = CAP_CHILD_UNTYPED_OFFSET;  /* slot 7 in child */

        stack_base[idx++] = AT_SALTY_VSPACE;
        stack_base[idx++] = 1;  /* VSpace is always slot 1 */

        stack_base[idx++] = AT_SALTY_SCRATCH;
        stack_base[idx++] = CHILD_SCRATCH_VADDR;

        stack_base[idx++] = AT_SALTY_INITRD;
        stack_base[idx++] = CHILD_INITRD_VADDR;

        stack_base[idx++] = AT_SALTY_INITRD_SZ;
        stack_base[idx++] = (uint64_t)initrd_size;

        stack_base[idx++] = AT_SALTY_FRAME_SLOT;
        stack_base[idx++] = (uint64_t)CHILD_RTLD_FRAME_SLOT_START;

        /* AT_NULL terminator */
        stack_base[idx++] = AT_NULL;
        stack_base[idx++] = 0;

        /* 8-byte padding for 16-byte stack alignment */
        stack_base[idx++] = 0;

        salty_vspace_unmap(CAP_SELF_VSPACE, SCRATCH_VADDR);

        /* Set child RSP to point at the auxv data on the top stack page */
        child_rsp = CHILD_STACK_TOP - STACK_FRAME_SIZE;
        /* Entry point is the rtld, not the executable */
        child_entry = rtld_result.entry;

        salty_serial_puts("[INIT] Dynamic: entry=rtld at ");
        salty_serial_hex(child_entry);
        salty_serial_puts(" rsp=");
        salty_serial_hex(child_rsp);
        salty_serial_puts("\n");
    } else {
        child_entry = elf_result.entry;
    }

    err = salty_tcb_configure(CAP_CHILD_TCB, child_entry, child_rsp, 0);
    if (err != 0) {
        salty_serial_puts("[INIT] FAIL: child TCB configure err=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts("\n");
        return -1;
    }

    /* Set console thread IPC buffer address */
    err = salty_tcb_set_ipc_buffer(CAP_CHILD_TCB, CHILD_IPC_BUF_VADDR);
    if (err != 0) {
        salty_serial_puts("[INIT] FAIL: child TCB set_ipc_buffer err=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts("\n");
        return -1;
    }

    /* 8. Configure and bind scheduling context */
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

    /* 9. Start the console server */
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
 * Generic server spawn helper (static + dynamic)
 * ================================================================
 * Spawns a server from initrd and supports both static and dynamic ELF:
 *   1. Retype: TCB, VSpace, CNode, SC, stack Frame, IPC buf Frame, EP
 *   2. Load executable ELF into child VSpace
 *   3. If PT_INTERP exists: load rtld and prepare auxv bootstrap stack
 *   4. Map stack + IPC buffer (+ initrd when needed)
 *   5. Copy standard caps and requested extra caps into child CNode
 *   6. Configure TCB, bind SC, and start
 */
struct extra_cap_copy {
    cap_t    src;   /* Source slot in init's CSpace */
    uint64_t dst;   /* Destination slot in child's CNode */
};

/* Static stack pages for spawned servers (4 pages each) */
#define SRV_STACK_PAGES   4
#define SRV_STACK_SIZE    (SRV_STACK_PAGES * 4096ULL)
#define SRV_STACK_TOP     (CHILD_STACK_VADDR + SRV_STACK_SIZE)
/* procmgr uses high cap slots (CAP_REPLY_BASE=4096 and per-process blocks),
 * so it needs a larger CNode than the default 1024 slots.
 */
#define PROCMGR_CNODE_SIZE_BITS 13 /* 8192 slots */

static int spawn_server(
    cap_t ut,
    cap_t cap_base,
    const char *elf_name,
    const char *label,
    const struct extra_cap_copy *extras,
    int extra_count,
    int map_initrd,
    uint64_t cnode_size_bits
) {
    int err;

    salty_serial_puts("[INIT] Spawning ");
    salty_serial_puts(label);
    salty_serial_puts(" (");
    salty_serial_puts(elf_name);
    salty_serial_puts(")\n");

    const uint8_t *initrd = (const uint8_t *)INITRD_VADDR;
    size_t initrd_size = cpio_archive_size(initrd, 1024 * 1024);

    struct cpio_entry entry;
    if (!cpio_find_file(initrd, initrd_size, elf_name, &entry)) {
        salty_serial_puts("[INIT] ");
        salty_serial_puts(elf_name);
        salty_serial_puts(" not found in initrd\n");
        return -1;
    }

    int is_dynamic = elf_has_interp(entry.data, entry.data_len);
    if (is_dynamic) {
        salty_serial_puts("[INIT] ");
        salty_serial_puts(label);
        salty_serial_puts(" is dynamically linked\n");
    }

    cap_t child_tcb    = cap_base + COFF_TCB;
    cap_t child_vs     = cap_base + COFF_VSPACE;
    cap_t child_cn     = cap_base + COFF_CNODE;
    cap_t child_sc     = cap_base + COFF_SC;
    cap_t child_stk_fr = cap_base + COFF_STACK_FR;
    cap_t child_ipc_fr = cap_base + COFF_IPC_FR;
    cap_t child_ep     = cap_base + COFF_EP;

    /* 1. Retype objects */
    err = salty_untyped_retype(ut, OBJ_TCB, 0, child_tcb);
    if (err != 0) { salty_serial_puts("[INIT] retype TCB failed\n"); return -1; }

    err = salty_untyped_retype(ut, OBJ_VSPACE, 0, child_vs);
    if (err != 0) { salty_serial_puts("[INIT] retype VSpace failed\n"); return -1; }

    err = salty_untyped_retype(ut, OBJ_CNODE, cnode_size_bits, child_cn);
    if (err != 0) { salty_serial_puts("[INIT] retype CNode failed\n"); return -1; }

    err = salty_untyped_retype(ut, OBJ_SCHED_CONTEXT, 0, child_sc);
    if (err != 0) { salty_serial_puts("[INIT] retype SC failed\n"); return -1; }

    err = salty_untyped_retype(ut, OBJ_FRAME, 0, child_stk_fr);
    if (err != 0) { salty_serial_puts("[INIT] retype stack frame failed\n"); return -1; }

    err = salty_untyped_retype(ut, OBJ_FRAME, 0, child_ipc_fr);
    if (err != 0) { salty_serial_puts("[INIT] retype IPC frame failed\n"); return -1; }

    err = salty_untyped_retype(ut, OBJ_ENDPOINT, 0, child_ep);
    if (err != 0) { salty_serial_puts("[INIT] retype EP failed\n"); return -1; }

    /* 2. Load ELF */
    struct elf_loader_ctx loader_ctx;
    loader_ctx.untyped = ut;
    loader_ctx.self_vspace = CAP_SELF_VSPACE;
    loader_ctx.child_vspace = child_vs;
    loader_ctx.scratch_vaddr = SCRATCH_VADDR;
    loader_ctx.next_frame_slot = cap_base + COFF_FRAME_START;
    loader_ctx.alloc_frame_slot = init_alloc_frame_slot;
    loader_ctx.alloc_opaque = 0;
    loader_ctx.record_page = 0;
    loader_ctx.record_opaque = 0;

    struct elf_load_result elf_result;
    err = elf_load(entry.data, entry.data_len,
                   CHILD_CODE_VADDR, &loader_ctx, &elf_result);
    if (err != 0) {
        salty_serial_puts("[INIT] ELF load failed err=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts("\n");
        return -1;
    }

    salty_serial_puts("[INIT] ELF loaded: entry=");
    salty_serial_hex(elf_result.entry);
    salty_serial_puts("\n");

    /* 2b. If dynamic, load rtld into child VSpace */
    struct elf_load_result rtld_result;
    rtld_result.entry = 0;
    rtld_result.base = 0;
    rtld_result.brk = 0;

    if (is_dynamic) {
        const char *rtld_name = "ld-salty.so";
        const char *interp = elf_get_interp(entry.data, entry.data_len);
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
            salty_serial_puts("[INIT] rtld not found in initrd: ");
            salty_serial_puts(rtld_name);
            salty_serial_puts("\n");
            return -1;
        }

        err = elf_load(rtld_entry.data, rtld_entry.data_len,
                       CHILD_RTLD_VADDR, &loader_ctx, &rtld_result);
        if (err != 0) {
            salty_serial_puts("[INIT] rtld ELF load failed err=");
            salty_serial_hex((uint64_t)err);
            salty_serial_puts("\n");
            return -1;
        }

        salty_serial_puts("[INIT] rtld loaded: entry=");
        salty_serial_hex(rtld_result.entry);
        salty_serial_puts(" base=");
        salty_serial_hex(rtld_result.base);
        salty_serial_puts("\n");
    }

    /* 3. Map stack pages */
    for (int pg = 0; pg < SRV_STACK_PAGES; pg++) {
        uint64_t page_vaddr = CHILD_STACK_VADDR + (uint64_t)pg * 4096ULL;
        cap_t frame_slot;

        if (pg == SRV_STACK_PAGES - 1) {
            frame_slot = child_stk_fr;
        } else {
            frame_slot = init_alloc_frame_slot(0);
            if (frame_slot == (cap_t)-1) {
                salty_serial_puts("[INIT] stack frame slot alloc failed\n");
                return -1;
            }
            err = salty_untyped_retype(ut, OBJ_FRAME, 0, frame_slot);
            if (err != 0) {
                salty_serial_puts("[INIT] stack frame retype failed\n");
                return -1;
            }
        }

        err = salty_vspace_map(child_vs, frame_slot, page_vaddr,
                               VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER);
        if (err != 0) {
            salty_serial_puts("[INIT] stack map failed\n");
            return -1;
        }
    }

    /* Map IPC buffer page */
    err = salty_vspace_map(child_vs, child_ipc_fr, CHILD_IPC_BUF_VADDR,
                           VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER);
    if (err != 0) {
        salty_serial_puts("[INIT] IPC buf map failed\n");
        return -1;
    }

    /* Map initrd into child VSpace when requested, or always for dynamic ELFs
     * (rtld needs it to locate shared libraries).
     */
    if (map_initrd || is_dynamic) {
        size_t initrd_pages = (initrd_size + 4095) / 4096;
        salty_serial_puts("[INIT] Mapping initrd into child (");
        salty_serial_hex(initrd_pages);
        salty_serial_puts(" pages)\n");

        for (size_t pg = 0; pg < initrd_pages; pg++) {
            cap_t fr_slot = init_alloc_frame_slot(0);
            if (fr_slot == (cap_t)-1) {
                salty_serial_puts("[INIT] initrd frame slot alloc failed\n");
                return -1;
            }
            err = salty_untyped_retype(ut, OBJ_FRAME, 0, fr_slot);
            if (err != 0) {
                salty_serial_puts("[INIT] initrd frame retype failed\n");
                return -1;
            }

            /* Scratch-map in our VSpace, copy initrd data */
            err = salty_vspace_map(CAP_SELF_VSPACE, fr_slot,
                                   SCRATCH_VADDR,
                                   VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER);
            if (err != 0) {
                salty_serial_puts("[INIT] initrd scratch map failed\n");
                return -1;
            }

            volatile uint8_t *scratch = (volatile uint8_t *)SCRATCH_VADDR;
            const uint8_t *isrc = initrd + pg * 4096;
            size_t copy_len = 4096;
            if (pg * 4096 + copy_len > initrd_size)
                copy_len = initrd_size - pg * 4096;
            for (size_t i = 0; i < copy_len; i++)
                scratch[i] = isrc[i];
            for (size_t i = copy_len; i < 4096; i++)
                scratch[i] = 0;

            salty_vspace_unmap(CAP_SELF_VSPACE, SCRATCH_VADDR);

            /* Map into child VSpace at CHILD_INITRD_VADDR (read-only + user) */
            err = salty_vspace_map(child_vs, fr_slot,
                                   CHILD_INITRD_VADDR + pg * 4096,
                                   VSPACE_FLAG_USER);
            if (err != 0) {
                salty_serial_puts("[INIT] initrd child map failed\n");
                return -1;
            }
        }
        salty_serial_puts("[INIT] Initrd mapped in child VSpace\n");
    }

    /* 4. Copy standard caps into child CNode:
     *   0 = TCB, 1 = VSpace, 2 = CNode, 3 = server EP, 7 = untyped
     */
    err = salty_cnode_copy(CAP_SELF_CSPACE, child_tcb,
                           child_cn, 0, CAP_RIGHTS_ALL);
    if (err != 0) { salty_serial_puts("[INIT] copy TCB failed\n"); return -1; }

    err = salty_cnode_copy(CAP_SELF_CSPACE, child_vs,
                           child_cn, 1, CAP_RIGHTS_ALL);
    if (err != 0) { salty_serial_puts("[INIT] copy VSpace failed\n"); return -1; }

    err = salty_cnode_copy(CAP_SELF_CSPACE, child_cn,
                           child_cn, 2, CAP_RIGHTS_ALL);
    if (err != 0) { salty_serial_puts("[INIT] copy CNode failed\n"); return -1; }

    err = salty_cnode_copy(CAP_SELF_CSPACE, child_ep,
                           child_cn, 3, CAP_RIGHTS_ALL);
    if (err != 0) { salty_serial_puts("[INIT] copy EP failed\n"); return -1; }

    /* Copy untyped to child slot 7 */
    err = salty_cnode_copy(CAP_SELF_CSPACE, ut,
                           child_cn, 7, CAP_RIGHTS_ALL);
    if (err != 0) {
        if (is_dynamic) {
            salty_serial_puts("[INIT] copy Untyped to child failed\n");
            return -1;
        }
        salty_serial_puts("[INIT] WARN: copy Untyped to child failed\n");
    }

    /* 5. Copy extra caps */
    for (int i = 0; i < extra_count; i++) {
        err = salty_cnode_copy(CAP_SELF_CSPACE, extras[i].src,
                               child_cn, extras[i].dst, CAP_RIGHTS_ALL);
        if (err != 0) {
            salty_serial_puts("[INIT] WARN: extra cap copy failed slot=");
            salty_serial_hex(extras[i].dst);
            salty_serial_puts("\n");
        }
    }

    /* 6. Configure TCB */
    err = salty_tcb_set_space(child_tcb, child_cn, child_vs);
    if (err != 0) { salty_serial_puts("[INIT] TCB set_space failed\n"); return -1; }

    uint64_t child_entry = elf_result.entry;
    uint64_t child_rsp = SRV_STACK_TOP;

    if (is_dynamic) {
        err = salty_vspace_map(CAP_SELF_VSPACE, child_stk_fr,
                               SCRATCH_VADDR,
                               VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER);
        if (err != 0) {
            salty_serial_puts("[INIT] dynamic stack scratch map failed\n");
            return -1;
        }

        uint64_t phdr_vaddr = 0;
        uint64_t phent = 0;
        uint64_t phnum = 0;
        if (elf_get_phdr_info(entry.data, entry.data_len, CHILD_CODE_VADDR,
                              &phdr_vaddr, &phent, &phnum) != 0) {
            salty_serial_puts("[INIT] dynamic phdr info extraction failed\n");
            salty_vspace_unmap(CAP_SELF_VSPACE, SCRATCH_VADDR);
            return -1;
        }

        const uint64_t srv_auxv_entries = 13;
        const uint64_t srv_stack_frame_size =
            3 * 8 + srv_auxv_entries * 2 * 8 + 8; /* 240 bytes, 16-byte aligned */

        volatile uint64_t *stack_base =
            (volatile uint64_t *)((uint8_t *)SCRATCH_VADDR + 4096 - srv_stack_frame_size);

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
        stack_base[idx++] = CAP_CHILD_UNTYPED_OFFSET;
        stack_base[idx++] = AT_SALTY_VSPACE;
        stack_base[idx++] = 1;
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

        salty_vspace_unmap(CAP_SELF_VSPACE, SCRATCH_VADDR);

        child_rsp = SRV_STACK_TOP - srv_stack_frame_size;
        child_entry = rtld_result.entry;
    }

    err = salty_tcb_configure(child_tcb, child_entry, child_rsp, 0);
    if (err != 0) { salty_serial_puts("[INIT] TCB configure failed\n"); return -1; }

    /* Set child IPC buffer */
    err = salty_tcb_set_ipc_buffer(child_tcb, CHILD_IPC_BUF_VADDR);
    if (err != 0) { salty_serial_puts("[INIT] TCB set_ipc_buffer failed\n"); return -1; }

    /* Configure scheduling context */
    err = salty_sc_configure(child_sc, 10000, 100000);
    if (err != 0) { salty_serial_puts("[INIT] SC configure failed\n"); return -1; }

    err = salty_sc_bind(child_sc, child_tcb);
    if (err != 0) { salty_serial_puts("[INIT] SC bind failed\n"); return -1; }

    /* Start the process */
    err = salty_tcb_resume(child_tcb);
    if (err != 0) { salty_serial_puts("[INIT] TCB resume failed\n"); return -1; }

    salty_serial_puts("[INIT] ");
    salty_serial_puts(label);
    salty_serial_puts(" started!\n");
    return 0;
}

static int pm_spawn_and_wait(cap_t pm_ep, const char *prog, int *out_status) {
    struct salty_msg spawn_msg, spawn_reply;
    uint8_t len = 0;
    while (prog[len] && len < 31) len++;

    spawn_msg.label = 1; /* PM_SPAWN */
    spawn_msg.length = 1 + (uint64_t)((len + 7) / 8);
    for (int i = 0; i < 20; i++) spawn_msg.regs[i] = 0;
    spawn_msg.regs[0] = len;
    {
        uint8_t *dst = (uint8_t *)&spawn_msg.regs[1];
        for (uint8_t i = 0; i < len; i++) dst[i] = (uint8_t)prog[i];
    }

    int err = salty_call(pm_ep, &spawn_msg, &spawn_reply);
    if (err != 0 || spawn_reply.label != SALTY_OK)
        return -1;

    uint32_t pid = (uint32_t)spawn_reply.regs[0];

    struct salty_msg wait_msg, wait_reply;
    wait_msg.label = 3; /* PM_WAIT */
    wait_msg.length = 1;
    for (int i = 0; i < 20; i++) wait_msg.regs[i] = 0;
    wait_msg.regs[0] = (uint64_t)pid;

    err = salty_call(pm_ep, &wait_msg, &wait_reply);
    if (err != 0 || wait_reply.label != SALTY_OK)
        return -1;

    if (out_status) *out_status = (int)wait_reply.regs[0];
    return 0;
}

/* ================================================================
 * Phase 4: Spawn system servers (nameserv, procmgr, vfs)
 * ================================================================
 * Spawns servers in dependency order:
 *   1. nameserv - no deps (other servers register with it)
 *   2. procmgr  - needs nameserv EP
 *   3. vfs      - needs nameserv EP and console EP
 * Then enters idle loop (init's job is done).
 */
static void phase4_spawn_servers(cap_t ut) {
    salty_serial_puts("\n[INIT] Phase 4: Spawning system servers\n");

    /* Cap slots for the server endpoints (in init's CSpace).
     * These are the EP caps created during spawn that we can
     * pass to later servers.
     */
    cap_t ns_ep  = CAP_NS_BASE  + COFF_EP;
    cap_t pm_ep  = CAP_PM_BASE  + COFF_EP;
    cap_t vfs_ep = CAP_VFS_BASE + COFF_EP;
    cap_t console_ep = CAP_CHILD_BASE + 5; /* Console's EP from phase 3 */

    /* 1. Spawn nameserv (no extra caps needed beyond standard set) */
    if (spawn_server(ut, CAP_NS_BASE, "nameserv.elf", "nameserv",
                     (const struct extra_cap_copy *)0, 0, 0, 0) != 0) {
        salty_serial_puts("[INIT] FAIL: nameserv spawn failed\n");
        goto idle;
    }

    /* Let nameserv start up and enter its recv loop */
    salty_yield();

    /* 2. Spawn VFS first (needs console EP + nameserv EP).
     * VFS must be spawned before procmgr so we can pass the VFS EP
     * to procmgr directly — avoids nested IPC lookups. */
    {
        struct extra_cap_copy vfs_extras[] = {
            { console_ep, 4 },  /* console EP -> child slot 4 */
            { ns_ep, 8 },       /* nameserv EP -> child slot 8 */
        };
        if (spawn_server(ut, CAP_VFS_BASE, "vfs.elf", "vfs",
                         vfs_extras, 2, 0, 0) != 0) {
            salty_serial_puts("[INIT] FAIL: vfs spawn failed\n");
            goto idle;
        }
    }

    /* Let VFS start up and register with nameserv */
    salty_yield();

    /* 3. Spawn procmgr (needs nameserv EP + VFS EP + initrd mapping) */
    {
        struct extra_cap_copy pm_extras[] = {
            { ns_ep, 8 },       /* nameserv EP -> child slot 8 */
            { vfs_ep, 9 },      /* VFS EP -> child slot 9 (CAP_VFS_EP) */
        };
        if (spawn_server(ut, CAP_PM_BASE, "procmgr.elf", "procmgr",
                         pm_extras, 2, 1, PROCMGR_CNODE_SIZE_BITS) != 0) {
            salty_serial_puts("[INIT] FAIL: procmgr spawn failed\n");
            goto idle;
        }
    }

    /* Mint a badged EP so procmgr can identify init (badge=1 → PID 1) */
    {
        cap_t pm_badged_slot = init_dyn_frame_next++;
        int merr = salty_cnode_mint(CAP_SELF_CSPACE, pm_ep,
                                     CAP_SELF_CSPACE, pm_badged_slot, 1);
        if (merr == 0) {
            pm_ep = pm_badged_slot;
            salty_serial_puts("[INIT] Minted badged PM EP (badge=1)\n");
        } else {
            salty_serial_puts("[INIT] WARN: mint badged PM EP failed\n");
        }
    }

    /* Let procmgr start up */
    salty_yield();

    salty_serial_puts("[INIT] Phase 4: All servers spawned!\n");

    /* Let all servers finish initialization (register with nameserv, etc.) */
    for (int i = 0; i < 5; i++) salty_yield();

    /* ================================================================
     * Phase 5: Runtime userland tests through procmgr
     * ================================================================ */
    salty_serial_puts("\n[INIT] Phase 5: Running userland runtime tests\n");
    {
        const char *tests[] = { "hello", "fstest", "mmap_test", "test_fork", "test_signal" };
        const int test_count = (int)(sizeof(tests) / sizeof(tests[0]));

        for (int i = 0; i < test_count; i++) {
            int status = -1;
            salty_serial_puts("[INIT] Phase 5: spawn ");
            salty_serial_puts(tests[i]);
            salty_serial_puts("\n");

            if (pm_spawn_and_wait(pm_ep, tests[i], &status) != 0) {
                salty_serial_puts("[INIT] FAIL: spawn/wait failed for ");
                salty_serial_puts(tests[i]);
                salty_serial_puts("\n");
                goto idle;
            }

            salty_serial_puts("[INIT] ");
            salty_serial_puts(tests[i]);
            salty_serial_puts(" exited with code ");
            salty_serial_hex((uint64_t)status);
            salty_serial_puts("\n");

            /* status is POSIX wstatus: normal exit = (code << 8) | 0 */
            if (!(((status & 0x7f) == 0) && (((status >> 8) & 0xff) == 42))) {
                salty_serial_puts("[INIT] FAIL: unexpected exit code from ");
                salty_serial_puts(tests[i]);
                salty_serial_puts("\n");
                goto idle;
            }
        }

        salty_serial_puts("[INIT] Phase 5 PASSED\n");
    }

    (void)ns_ep;
    (void)vfs_ep;

idle:
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
    int err;

    /* Set up IPC buffer for init */
    err = salty_untyped_retype(ut, OBJ_FRAME, 0, CAP_IPC_BUF_FRAME);
    if (err != 0) {
        salty_serial_puts("[INIT] FAIL: IPC buf frame retype\n");
        goto fail;
    }
    err = salty_vspace_map(CAP_SELF_VSPACE, CAP_IPC_BUF_FRAME,
                           IPC_BUF_VADDR,
                           VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER);
    if (err != 0) {
        salty_serial_puts("[INIT] FAIL: IPC buf map\n");
        goto fail;
    }
    salty_invoke(CAP_SELF_TCB, TCB_SET_IPC_BUFFER, IPC_BUF_VADDR, 0, 0, 0);
    salty_ipc_context_init(&__salty_ipc_ctx, (void *)IPC_BUF_VADDR);
    salty_serial_puts("[INIT] IPC buffer mapped at ");
    salty_serial_hex(IPC_BUF_VADDR);
    salty_serial_puts("\n");

    /* Phase 1: IPC test */
    if (phase1_ipc_test(ut) != 0)
        goto fail;
    /* Phase 1 helper thread is no longer needed. */
    salty_invoke(CAP_TEST_TCB, TCB_SUSPEND, 0, 0, 0, 0);
    restore_init_ipc_context();

    /* Phase 2: Fault handling test */
    if (phase2_fault_test(ut) != 0)
        goto fail;
    restore_init_ipc_context();

    /* Phase 3: Spawn console server (may fail if kernel support not ready) */
    phase3_spawn_console(ut);

    /* Phase 4: Spawn system servers (nameserv, procmgr, vfs) */
    phase4_spawn_servers(ut);

fail:
    /* Loop forever (init should never exit) */
    for (;;) {
        salty_yield();
    }
}
