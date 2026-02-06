/* SaltyOS VFS Server
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Minimal virtual filesystem with devfs only (no real filesystem yet).
 * Routes I/O to device backends based on file descriptors.
 *
 * IPC protocol:
 *   Label 1 = OPEN:  path packed in MRs -> returns fd in regs[0]
 *   Label 2 = READ:  fd in regs[0], count in regs[1] -> data in regs[2..], actual in regs[0]
 *   Label 3 = WRITE: fd in regs[0], count in regs[1], data in regs[2..]
 *   Label 4 = CLOSE: fd in regs[0]
 *   Label 5 = STAT:  fd in regs[0] -> size in regs[0], type in regs[1]
 *
 * Initial devices:
 *   /dev/console - routes to console server EP
 *   /dev/null    - discards writes, reads return 0
 *   /dev/zero    - reads return zero bytes, discards writes
 *
 * Cap layout (set by init/procmgr):
 *   0 = self TCB
 *   1 = self VSpace
 *   2 = self CSpace
 *   3 = server endpoint
 *   4 = console server endpoint
 *   8 = nameserv endpoint
 */

#define SALTY_STATIC
#include "salty.h"

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
#define CAP_CONSOLE_EP   4
#define CAP_NAMESERV_EP  8

/* IPC buffer setup (pre-mapped by init) */
#define IPC_BUF_VADDR       0x0000000000200000ULL

/* Protocol labels */
#define VFS_OPEN    1
#define VFS_READ    2
#define VFS_WRITE   3
#define VFS_CLOSE   4
#define VFS_STAT    5

/* Device types */
#define DEV_CONSOLE  0
#define DEV_NULL     1
#define DEV_ZERO     2
#define DEV_COUNT    3

/* File type constants for STAT */
#define FTYPE_CHAR_DEVICE  1
#define FTYPE_REGULAR      2

/* Per-client file descriptor table */
#define MAX_CLIENTS  16
#define MAX_FDS      16

struct fd_entry {
    uint8_t  active;
    uint8_t  dev_type;  /* DEV_CONSOLE, DEV_NULL, DEV_ZERO */
};

struct client_state {
    uint64_t        badge;
    uint8_t         active;
    struct fd_entry fds[MAX_FDS];
};

static struct client_state clients[MAX_CLIENTS];

/* Device name table */
struct device_info {
    const char *path;
    uint8_t     path_len;
    uint8_t     dev_type;
};

static const struct device_info devices[] = {
    { "/dev/console", 12, DEV_CONSOLE },
    { "/dev/null",     9, DEV_NULL },
    { "/dev/zero",     9, DEV_ZERO },
};

static int str_equal(const char *a, uint8_t alen, const char *b, uint8_t blen) {
    if (alen != blen) return 0;
    for (uint8_t i = 0; i < alen; i++) {
        if (a[i] != b[i]) return 0;
    }
    return 1;
}

static struct client_state *get_client(uint64_t badge) {
    /* Find existing client */
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].active && clients[i].badge == badge)
            return &clients[i];
    }
    /* Allocate new client */
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!clients[i].active) {
            clients[i].badge = badge;
            clients[i].active = 1;
            for (int j = 0; j < MAX_FDS; j++)
                clients[i].fds[j].active = 0;
            return &clients[i];
        }
    }
    return (struct client_state *)0;
}

static void handle_open(const struct salty_msg *msg, struct salty_msg *reply, uint64_t badge) {
    /* Extract path: regs[0] = length, regs[1..] = packed path bytes */
    uint8_t path_len = (uint8_t)msg->regs[0];
    if (path_len > 64) path_len = 64;

    char path[64];
    const uint8_t *raw = (const uint8_t *)&msg->regs[1];
    for (uint8_t i = 0; i < path_len; i++)
        path[i] = (char)raw[i];

    /* Look up device */
    int dev_type = -1;
    for (int i = 0; i < DEV_COUNT; i++) {
        if (str_equal(path, path_len, devices[i].path, devices[i].path_len)) {
            dev_type = devices[i].dev_type;
            break;
        }
    }

    if (dev_type < 0) {
        salty_serial_puts("[VFS] OPEN: not found '");
        for (uint8_t i = 0; i < path_len; i++) salty_serial_putc(path[i]);
        salty_serial_puts("'\n");
        reply->label = SALTY_NOT_FOUND;
        return;
    }

    struct client_state *cli = get_client(badge);
    if (!cli) {
        reply->label = SALTY_OUT_OF_MEMORY;
        return;
    }

    /* Allocate fd */
    for (int fd = 0; fd < MAX_FDS; fd++) {
        if (!cli->fds[fd].active) {
            cli->fds[fd].active = 1;
            cli->fds[fd].dev_type = (uint8_t)dev_type;
            reply->label = SALTY_OK;
            reply->length = 1;
            reply->regs[0] = (uint64_t)fd;
            return;
        }
    }

    reply->label = SALTY_OUT_OF_MEMORY;
}

static void handle_read(const struct salty_msg *msg, struct salty_msg *reply, uint64_t badge) {
    int fd = (int)msg->regs[0];
    uint64_t count = msg->regs[1];

    struct client_state *cli = get_client(badge);
    if (!cli || fd < 0 || fd >= MAX_FDS || !cli->fds[fd].active) {
        reply->label = SALTY_INVALID_ARGUMENT;
        return;
    }

    /* Max bytes we can return in regs[1..19]: 19 regs * 8 bytes = 152 bytes */
    if (count > 152) count = 152;

    switch (cli->fds[fd].dev_type) {
    case DEV_CONSOLE: {
        /* Forward READ to console server */
        struct salty_msg creq, creply;
        creq.label = CONSOLE_READ;
        creq.length = 0;
        for (int i = 0; i < 4; i++) creq.regs[i] = 0;

        int err = salty_call(CAP_CONSOLE_EP, &creq, &creply);
        if (err != 0 || creply.label != SALTY_OK) {
            reply->label = SALTY_INVALID_OPERATION;
            return;
        }
        /* Console returns one char in regs[0] or -1 */
        uint64_t c = creply.regs[0];
        if (c == (uint64_t)-1) {
            reply->label = SALTY_OK;
            reply->length = 1;
            reply->regs[0] = 0;  /* 0 bytes read */
        } else {
            reply->label = SALTY_OK;
            reply->length = 2;
            reply->regs[0] = 1;  /* 1 byte read */
            uint8_t *data = (uint8_t *)&reply->regs[1];
            data[0] = (uint8_t)c;
        }
        break;
    }
    case DEV_NULL:
        /* /dev/null reads return 0 bytes (EOF) */
        reply->label = SALTY_OK;
        reply->length = 1;
        reply->regs[0] = 0;
        break;
    case DEV_ZERO: {
        /* /dev/zero reads return zero-filled bytes */
        reply->label = SALTY_OK;
        reply->length = 1 + (uint64_t)((count + 7) / 8);
        reply->regs[0] = count;
        uint8_t *data = (uint8_t *)&reply->regs[1];
        for (uint64_t i = 0; i < count; i++)
            data[i] = 0;
        break;
    }
    default:
        reply->label = SALTY_INVALID_OPERATION;
        break;
    }
}

static void handle_write(const struct salty_msg *msg, struct salty_msg *reply, uint64_t badge) {
    int fd = (int)msg->regs[0];
    uint64_t count = msg->regs[1];

    struct client_state *cli = get_client(badge);
    if (!cli || fd < 0 || fd >= MAX_FDS || !cli->fds[fd].active) {
        reply->label = SALTY_INVALID_ARGUMENT;
        return;
    }

    /* Max data in regs[2..19]: 18 regs * 8 bytes = 144 bytes */
    if (count > 144) count = 144;

    switch (cli->fds[fd].dev_type) {
    case DEV_CONSOLE: {
        /* Forward WRITE to console server in 24-byte chunks.
         * Each chunk fits in creq.regs[1..3] (3 regs = 24 bytes).
         * Returns actual bytes written, not the requested count.
         */
        const uint8_t *src = (const uint8_t *)&msg->regs[2];
        uint64_t sent = 0;
        while (sent < count) {
            struct salty_msg creq, creply;
            uint64_t chunk = count - sent;
            if (chunk > 24) chunk = 24;

            creq.label = CONSOLE_WRITE;
            creq.length = 2;
            creq.regs[0] = chunk;
            creq.regs[1] = 0;
            creq.regs[2] = 0;
            creq.regs[3] = 0;

            uint8_t *dst = (uint8_t *)&creq.regs[1];
            for (uint64_t i = 0; i < chunk; i++)
                dst[i] = src[sent + i];

            int err = salty_call(CAP_CONSOLE_EP, &creq, &creply);
            if (err != 0) break;
            sent += chunk;
        }
        reply->label = sent > 0 ? SALTY_OK : SALTY_INVALID_OPERATION;
        reply->length = 1;
        reply->regs[0] = sent;
        break;
    }
    case DEV_NULL:
    case DEV_ZERO:
        /* /dev/null and /dev/zero discard writes */
        reply->label = SALTY_OK;
        reply->length = 1;
        reply->regs[0] = count;
        break;
    default:
        reply->label = SALTY_INVALID_OPERATION;
        break;
    }
}

static void handle_close(const struct salty_msg *msg, struct salty_msg *reply, uint64_t badge) {
    int fd = (int)msg->regs[0];

    struct client_state *cli = get_client(badge);
    if (!cli || fd < 0 || fd >= MAX_FDS || !cli->fds[fd].active) {
        reply->label = SALTY_INVALID_ARGUMENT;
        return;
    }

    cli->fds[fd].active = 0;
    reply->label = SALTY_OK;
}

static void handle_stat(const struct salty_msg *msg, struct salty_msg *reply, uint64_t badge) {
    int fd = (int)msg->regs[0];

    struct client_state *cli = get_client(badge);
    if (!cli || fd < 0 || fd >= MAX_FDS || !cli->fds[fd].active) {
        reply->label = SALTY_INVALID_ARGUMENT;
        return;
    }

    reply->label = SALTY_OK;
    reply->length = 2;
    reply->regs[0] = 0;               /* size: 0 for char devices */
    reply->regs[1] = FTYPE_CHAR_DEVICE;
}

void _start(void) {
    salty_serial_puts("[VFS] SaltyOS VFS server starting\n");

    /* Init already mapped this process's IPC buffer at IPC_BUF_VADDR. */
    int err = salty_tcb_set_ipc_buffer(CAP_SELF_TCB, IPC_BUF_VADDR);
    if (err != 0) {
        salty_serial_puts("[VFS] FAIL: set IPC buffer err=");
        salty_serial_hex((uint64_t)err);
        salty_serial_puts("\n");
        goto idle;
    }
    __salty_ipc_buffer = (void *)IPC_BUF_VADDR;

    salty_serial_puts("[VFS] IPC buffer ready\n");
    salty_serial_puts("[VFS] Devices: /dev/console, /dev/null, /dev/zero\n");

    /* Initial recv */
    struct salty_msg msg;
    uint64_t badge = 0;

    err = salty_recv(CAP_SERVER_EP, &msg, &badge);
    if (err != 0) {
        salty_serial_puts("[VFS] initial recv failed\n");
        goto idle;
    }

    /* Server loop */
    for (;;) {
        struct salty_msg reply;
        reply.label = 0;
        reply.length = 0;
        for (int i = 0; i < 4; i++) reply.regs[i] = 0;

        switch (msg.label) {
        case VFS_OPEN:
            handle_open(&msg, &reply, badge);
            break;
        case VFS_READ:
            handle_read(&msg, &reply, badge);
            break;
        case VFS_WRITE:
            handle_write(&msg, &reply, badge);
            break;
        case VFS_CLOSE:
            handle_close(&msg, &reply, badge);
            break;
        case VFS_STAT:
            handle_stat(&msg, &reply, badge);
            break;
        default:
            salty_serial_puts("[VFS] unknown label=");
            salty_serial_hex(msg.label);
            salty_serial_puts("\n");
            reply.label = SALTY_INVALID_OPERATION;
            break;
        }

        err = salty_reply_recv(CAP_SERVER_EP, &reply, &msg, &badge);
        if (err != 0) {
            salty_serial_puts("[VFS] reply_recv failed err=");
            salty_serial_hex((uint64_t)err);
            salty_serial_puts("\n");
            break;
        }
    }

idle:
    for (;;) { salty_yield(); }
}
