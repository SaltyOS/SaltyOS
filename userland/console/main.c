/* SaltyOS Console Server
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Provides serial console access over IPC.
 * Receives CONSOLE_WRITE / CONSOLE_READ requests on its endpoint
 * and translates them to COM1 I/O via IoPort capability invocations.
 */

#include "salty.h"

/* IPC buffer setup (pre-mapped by init). */
#define IPC_BUF_VADDR 0x0000000000200000ULL

/* COM1 register offsets (relative to base 0x3F8) */
#define COM1_THR  0   /* Transmit Holding Register (write) */
#define COM1_RBR  0   /* Receive Buffer Register (read) */
#define COM1_IER  1   /* Interrupt Enable Register */
#define COM1_FCR  2   /* FIFO Control Register (write) */
#define COM1_LCR  3   /* Line Control Register */
#define COM1_MCR  4   /* Modem Control Register */
#define COM1_LSR  5   /* Line Status Register */
#define COM1_DLL  0   /* Divisor Latch Low (when DLAB=1) */
#define COM1_DLH  1   /* Divisor Latch High (when DLAB=1) */

/* LSR bits */
#define LSR_DR    (1 << 0)  /* Data Ready */
#define LSR_THRE  (1 << 5)  /* Transmitter Holding Register Empty */

/* Well-known cap slots (must match kernel init setup) */
#define CAP_SELF_TCB     0
#define CAP_SELF_VSPACE  1
#define CAP_SELF_CSPACE  2
#define CAP_SERVER_EP    3   /* Endpoint clients use to reach us */
#define CAP_IOPORT       4   /* IoPort cap for COM1 (0x3F8-0x3FF) */
#define CAP_IRQ          5   /* IRQ handler for COM1 (IRQ 4) */
#define CAP_NTFN         6   /* Notification for IRQ delivery */

static void com1_init(void) {
    /* Disable interrupts */
    salty_ioport_out8(CAP_IOPORT, COM1_IER, 0x00);

    /* Set DLAB to configure baud rate */
    salty_ioport_out8(CAP_IOPORT, COM1_LCR, 0x80);

    /* 115200 baud: divisor = 1 */
    salty_ioport_out8(CAP_IOPORT, COM1_DLL, 0x01);
    salty_ioport_out8(CAP_IOPORT, COM1_DLH, 0x00);

    /* 8N1 (8 data bits, no parity, 1 stop bit), clear DLAB */
    salty_ioport_out8(CAP_IOPORT, COM1_LCR, 0x03);

    /* Enable FIFO, clear, 14-byte threshold */
    salty_ioport_out8(CAP_IOPORT, COM1_FCR, 0xC7);

    /* DTR + RTS + OUT2 (needed for IRQ delivery on some hardware) */
    salty_ioport_out8(CAP_IOPORT, COM1_MCR, 0x0B);

    /* Enable receive data available interrupt */
    salty_ioport_out8(CAP_IOPORT, COM1_IER, 0x01);
}

static void com1_putc(char c) {
    /* Wait for THR empty */
    while (!(salty_ioport_in8(CAP_IOPORT, COM1_LSR) & LSR_THRE)) {
        /* spin */
    }
    salty_ioport_out8(CAP_IOPORT, COM1_THR, (uint8_t)c);
}

static void com1_puts(const char *s) {
    while (*s) {
        if (*s == '\n') {
            com1_putc('\r');
        }
        com1_putc(*s++);
    }
}

static int com1_getc(void) {
    if (salty_ioport_in8(CAP_IOPORT, COM1_LSR) & LSR_DR) {
        return (int)salty_ioport_in8(CAP_IOPORT, COM1_RBR);
    }
    return -1;
}

/* Handle a CONSOLE_WRITE request.
 * msg.regs[0] contains a pointer to a character buffer in the caller's
 * address space. For simplicity in Phase 3, we send one character per
 * message register instead. regs[0..3] hold up to 4 packed characters.
 *
 * Protocol: label=CONSOLE_WRITE, regs[0]=length (1-32),
 *           regs[1..3] = packed chars (8 chars per register)
 */
static void handle_write(const struct salty_msg *msg) {
    uint64_t len = msg->regs[0];
    if (len > 24) len = 24;  /* max 3 regs * 8 chars */

    const uint8_t *data = (const uint8_t *)&msg->regs[1];
    for (uint64_t i = 0; i < len; i++) {
        char c = (char)data[i];
        if (c == '\n') com1_putc('\r');
        com1_putc(c);
    }
}

/* Handle a CONSOLE_READ request.
 * Returns one character (or -1 if nothing available) in reply regs[0].
 */
static uint64_t handle_read(void) {
    int c = com1_getc();
    return (c >= 0) ? (uint64_t)c : (uint64_t)-1;
}

void _start(void) {
    /* Initialize COM1 via IoPort invocations */
    com1_init();
    com1_puts("[CONSOLE] SaltyOS console server ready\n");

    /* Bind libsalty default context to this thread's IPC buffer. */
    salty_tcb_set_ipc_buffer(CAP_SELF_TCB, IPC_BUF_VADDR);
    salty_ipc_context_init(&__salty_ipc_ctx, (void *)IPC_BUF_VADDR);

    /* Set up IRQ notification: bind notification to IRQ handler */
    salty_irq_handler_set_notification(CAP_IRQ, CAP_NTFN);

    /* Server loop: receive request, process, reply+recv */
    struct salty_msg msg;
    uint64_t badge = 0;

    int err = salty_recv(CAP_SERVER_EP, &msg, &badge);
    if (err != 0) {
        com1_puts("[CONSOLE] initial recv failed\n");
        goto idle;
    }

    for (;;) {
        struct salty_msg reply;
        reply.label = 0;
        reply.length = 0;
        reply.regs[0] = 0;
        reply.regs[1] = 0;
        reply.regs[2] = 0;
        reply.regs[3] = 0;

        switch (msg.label) {
        case CONSOLE_WRITE:
            handle_write(&msg);
            reply.label = SALTY_OK;
            break;
        case CONSOLE_READ:
            reply.regs[0] = handle_read();
            reply.label = SALTY_OK;
            reply.length = 1;
            break;
        default:
            reply.label = SALTY_INVALID_OPERATION;
            break;
        }

        err = salty_reply_recv(CAP_SERVER_EP, &reply, &msg, &badge);
        if (err != 0) {
            com1_puts("[CONSOLE] reply_recv failed\n");
            break;
        }
    }

idle:
    for (;;) { salty_yield(); }
}
