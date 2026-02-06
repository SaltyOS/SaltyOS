/* SaltyOS Name Server
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Service registry: servers register name->endpoint mappings,
 * clients look up services by name.
 *
 * IPC protocol:
 *   Label 1 = REGISTER: name packed in MRs (up to 32 chars), EP cap via cap transfer
 *   Label 2 = LOOKUP:   name packed in MRs -> returns EP cap via cap transfer
 *
 * Cap layout (set by init/procmgr):
 *   0 = self TCB
 *   1 = self VSpace
 *   2 = self CSpace
 *   3 = server endpoint (clients reach us here)
 */

#include "salty.h"

/* Cap layout */
#define CAP_SELF_TCB     0
#define CAP_SELF_VSPACE  1
#define CAP_SELF_CSPACE  2
#define CAP_SERVER_EP    3

/* IPC buffer setup (pre-mapped by init) */
#define IPC_BUF_VADDR       0x0000000000200000ULL

/* Protocol labels */
#define NS_REGISTER  1
#define NS_LOOKUP    2

/* Cap slots for storing registered service endpoints */
#define CAP_SERVICE_BASE  32
#define MAX_SERVICES      32
#define MAX_NAME_LEN      32

struct service_entry {
    char     name[MAX_NAME_LEN];
    uint8_t  name_len;
    cap_t    ep_slot;
    uint8_t  active;
};

static struct service_entry services[MAX_SERVICES];
static int service_count = 0;

static int name_equal(const char *a, uint8_t alen, const char *b, uint8_t blen) {
    if (alen != blen) return 0;
    for (uint8_t i = 0; i < alen; i++) {
        if (a[i] != b[i]) return 0;
    }
    return 1;
}

/* Extract a name from message registers.
 * Name bytes are packed 8 per register in regs[0..3] (up to 32 chars).
 * regs[0] low byte = first char, etc.
 * The length is given in the message length field (number of bytes).
 */
static uint8_t extract_name(const struct salty_msg *msg, char *out) {
    uint8_t len = (uint8_t)msg->regs[0];
    if (len > MAX_NAME_LEN) len = MAX_NAME_LEN;

    const uint8_t *raw = (const uint8_t *)&msg->regs[1];
    for (uint8_t i = 0; i < len; i++) {
        out[i] = (char)raw[i];
    }
    return len;
}

static void handle_register(const struct salty_msg *msg, struct salty_msg *reply) {
    char name[MAX_NAME_LEN];
    uint8_t name_len = extract_name(msg, name);

    if (name_len == 0) {
        salty_serial_puts("[NAMESERV] REGISTER: empty name\n");
        reply->label = SALTY_INVALID_ARGUMENT;
        return;
    }

    /* Check for duplicate */
    for (int i = 0; i < service_count; i++) {
        if (services[i].active &&
            name_equal(services[i].name, services[i].name_len, name, name_len)) {
            salty_serial_puts("[NAMESERV] REGISTER: duplicate name '");
            for (uint8_t j = 0; j < name_len; j++) salty_serial_putc(name[j]);
            salty_serial_puts("'\n");
            reply->label = SALTY_ALREADY_EXISTS;
            return;
        }
    }

    if (service_count >= MAX_SERVICES) {
        salty_serial_puts("[NAMESERV] REGISTER: table full\n");
        reply->label = SALTY_OUT_OF_MEMORY;
        return;
    }

    /* The EP cap was transferred via IPC cap transfer into our receive slot.
     * We set up receive_index before each recv to point at CAP_SERVICE_BASE + service_count.
     */
    cap_t ep_slot = CAP_SERVICE_BASE + (cap_t)service_count;

    struct service_entry *entry = &services[service_count];
    for (uint8_t i = 0; i < name_len; i++) entry->name[i] = name[i];
    entry->name_len = name_len;
    entry->ep_slot = ep_slot;
    entry->active = 1;
    service_count++;

    salty_serial_puts("[NAMESERV] registered '");
    for (uint8_t i = 0; i < name_len; i++) salty_serial_putc(name[i]);
    salty_serial_puts("' at slot ");
    salty_serial_hex(ep_slot);
    salty_serial_puts("\n");

    reply->label = SALTY_OK;
}

static void handle_lookup(const struct salty_msg *msg, struct salty_msg *reply) {
    char name[MAX_NAME_LEN];
    uint8_t name_len = extract_name(msg, name);

    if (name_len == 0) {
        reply->label = SALTY_INVALID_ARGUMENT;
        return;
    }

    for (int i = 0; i < service_count; i++) {
        if (services[i].active &&
            name_equal(services[i].name, services[i].name_len, name, name_len)) {
            /* Found it. Transfer the EP cap back to the caller via IPC cap transfer. */
            salty_set_send_cap(0, services[i].ep_slot);
            reply->label = SALTY_OK;
            /* Tell the kernel we're transferring 1 cap */
            reply->length = 0;
            return;
        }
    }

    salty_serial_puts("[NAMESERV] LOOKUP: not found '");
    for (uint8_t i = 0; i < name_len; i++) salty_serial_putc(name[i]);
    salty_serial_puts("'\n");
    reply->label = SALTY_NOT_FOUND;
}

void _start(void) {
    salty_serial_puts("[NAMESERV] SaltyOS name server starting\n");

    /* Init already mapped this process's IPC buffer at IPC_BUF_VADDR. */
    int err = salty_tcb_set_ipc_buffer(CAP_SELF_TCB, IPC_BUF_VADDR);
    if (err != 0) {
        salty_serial_puts("[NAMESERV] FAIL: set IPC buffer err=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts("\n");
        goto idle;
    }
    salty_ipc_context_init(&__salty_ipc_ctx, (void *)IPC_BUF_VADDR);

    salty_serial_puts("[NAMESERV] IPC buffer ready\n");

    /* Set up receive slot for cap transfers:
     * Incoming caps will be placed at CAP_SERVICE_BASE + service_count */
    salty_set_receive_slot(CAP_SELF_CSPACE, CAP_SERVICE_BASE, 0);

    /* Initial recv */
    struct salty_msg msg;
    uint64_t badge = 0;

    err = salty_recv(CAP_SERVER_EP, &msg, &badge);
    if (err != 0) {
        salty_serial_puts("[NAMESERV] initial recv failed\n");
        goto idle;
    }

    /* Server loop */
    for (;;) {
        struct salty_msg reply;
        reply.label = 0;
        reply.length = 0;
        for (int i = 0; i < 4; i++) reply.regs[i] = 0;

        switch (msg.label) {
        case NS_REGISTER:
            handle_register(&msg, &reply);
            break;
        case NS_LOOKUP:
            handle_lookup(&msg, &reply);
            break;
        default:
            salty_serial_puts("[NAMESERV] unknown label=");
            salty_serial_hex(msg.label);
            salty_serial_puts("\n");
            reply.label = SALTY_INVALID_OPERATION;
            break;
        }

        /* Update receive slot for next incoming cap transfer */
        salty_set_receive_slot(CAP_SELF_CSPACE,
                               CAP_SERVICE_BASE + (cap_t)service_count, 0);

        err = salty_reply_recv(CAP_SERVER_EP, &reply, &msg, &badge);
        if (err != 0) {
            salty_serial_puts("[NAMESERV] reply_recv failed err=");
            salty_serial_hex((uint64_t)err);
            salty_serial_puts("\n");
            break;
        }
    }

idle:
    for (;;) { salty_yield(); }
}
