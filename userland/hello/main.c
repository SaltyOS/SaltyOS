/* SaltyOS Hello Test Program
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Exercises POSIX wrapper API: getpid, open, write, close, exit.
 * Spawned by procmgr; expects the standard cap layout:
 *   0 = self TCB
 *   1 = self VSpace
 *   2 = self CSpace
 *   3 = procmgr EP (badged)
 *   4 = VFS EP
 *   5 = nameserv EP
 *   7 = untyped
 */

#include "salty.h"
#include "posix.h"

static void print_dec(int fd, int val) {
    if (val < 0) {
        posix_write(fd, "-", 1);
        val = -val;
    }
    char buf[16];
    int pos = 15;
    if (val == 0) {
        buf[pos--] = '0';
    } else {
        while (val > 0 && pos >= 0) {
            buf[pos--] = '0' + (char)(val % 10);
            val /= 10;
        }
    }
    posix_write(fd, &buf[pos + 1], (unsigned long)(15 - pos));
}

void _start(void) {
    /* Set up IPC buffer (pre-mapped by procmgr at 0x200000) */
    salty_tcb_set_ipc_buffer(POSIX_CAP_SELF_TCB, 0x200000ULL);
    salty_ipc_context_init(&__salty_ipc_ctx, (void *)0x200000ULL);

    salty_serial_puts("[HELLO] starting\n");

    /* 1. getpid */
    int pid = posix_getpid();
    salty_serial_puts("[HELLO] PID=");
    salty_serial_hex((uint64_t)pid);
    salty_serial_puts("\n");

    /* 2. open /dev/console */
    int fd = posix_open("/dev/console", 0);
    salty_serial_puts("[HELLO] open /dev/console fd=");
    salty_serial_hex((uint64_t)fd);
    salty_serial_puts("\n");

    if (fd >= 0) {
        /* 3. write greeting via VFS -> console */
        posix_write(fd, "[HELLO] Hello from POSIX! pid=", 30);
        print_dec(fd, pid);
        posix_write(fd, "\n", 1);
    }

    /* 4. open /dev/null and write to it */
    int fd_null = posix_open("/dev/null", 0);
    salty_serial_puts("[HELLO] open /dev/null fd=");
    salty_serial_hex((uint64_t)fd_null);
    salty_serial_puts("\n");

    if (fd_null >= 0) {
        posix_write(fd_null, "discard", 7);
        posix_close(fd_null);
        salty_serial_puts("[HELLO] close /dev/null\n");
    }

    /* 5. close console fd */
    if (fd >= 0) {
        posix_close(fd);
        salty_serial_puts("[HELLO] close /dev/console\n");
    }

    /* 6. exit with code 42 */
    salty_serial_puts("[HELLO] exiting with code 42\n");
    posix_exit(42);
}
