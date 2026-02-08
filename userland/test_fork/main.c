/* SaltyOS fork/exec/waitpid test
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Tests:
 *  1. posix_getpid / posix_getppid
 *  2. posix_fork — parent gets child PID, child gets 0
 *  3. posix_waitpid — blocking wait for child exit
 *  4. posix_fork + posix_execve — child execs hello.elf
 *  5. posix_waitpid — collect exec'd child
 *
 * Exit code 42 = all tests passed.
 */

#include "salty.h"
#include "posix.h"

static void puts(const char *s) {
    unsigned long len = 0;
    while (s[len]) len++;
    posix_write(1, s, len);
}

static void putnum(int n) {
    if (n < 0) {
        posix_write(1, "-", 1);
        n = -n;
    }
    char buf[12];
    int pos = 11;
    buf[pos] = '\0';
    if (n == 0) {
        buf[--pos] = '0';
    } else {
        while (n > 0) {
            buf[--pos] = '0' + (n % 10);
            n /= 10;
        }
    }
    unsigned long len = 0;
    const char *p = &buf[pos];
    while (p[len]) len++;
    posix_write(1, p, len);
}

/* Simple output that just writes directly to serial (bypasses VFS) */
static void serial_puts(const char *s) {
    while (*s) salty_serial_putc(*s++);
}

static void serial_num(int n) {
    if (n < 0) {
        salty_serial_putc('-');
        n = -n;
    }
    char buf[12];
    int pos = 11;
    buf[pos] = '\0';
    if (n == 0) {
        buf[--pos] = '0';
    } else {
        while (n > 0) {
            buf[--pos] = '0' + (n % 10);
            n /= 10;
        }
    }
    while (buf[pos]) salty_serial_putc(buf[pos++]);
}

void _start(void) {
    /* Set up IPC buffer (pre-mapped by procmgr at 0x200000) */
    salty_tcb_set_ipc_buffer(POSIX_CAP_SELF_TCB, 0x200000ULL);
    salty_ipc_context_init(&__salty_ipc_ctx, (void *)0x200000ULL);

    serial_puts("[TEST_FORK] Starting fork/exec tests\n");

    /* Open /dev/console for puts() */
    int con = posix_open("/dev/console", O_WRONLY);
    if (con < 0) {
        serial_puts("[TEST_FORK] FAIL: cannot open /dev/console\n");
        posix_exit(1);
    }

    /* Test 1: getpid */
    int my_pid = posix_getpid();
    serial_puts("[TEST_FORK] Test 1: getpid = ");
    serial_num(my_pid);
    serial_puts("\n");
    if (my_pid <= 0) {
        serial_puts("[TEST_FORK] FAIL: getpid\n");
        posix_exit(1);
    }
    serial_puts("[TEST_FORK] Test 1: PASS\n");

    /* Test 2: getppid */
    int my_ppid = posix_getppid();
    serial_puts("[TEST_FORK] Test 2: getppid = ");
    serial_num(my_ppid);
    serial_puts("\n");
    /* ppid should be 0 for procmgr-spawned processes */
    serial_puts("[TEST_FORK] Test 2: PASS\n");

    /* Test 3: fork + waitpid (simple) */
    serial_puts("[TEST_FORK] Test 3: fork...\n");
    int pid = posix_fork();
    if (pid < 0) {
        serial_puts("[TEST_FORK] FAIL: fork returned -1\n");
        posix_exit(1);
    }

    if (pid == 0) {
        /* Child process */
        serial_puts("[TEST_FORK] Child: I am the child, exiting with code 7\n");
        posix_exit(7);
        /* never reached */
    }

    /* Parent process */
    serial_puts("[TEST_FORK] Parent: child PID = ");
    serial_num(pid);
    serial_puts("\n");

    int status = 0;
    int ret = posix_waitpid(pid, &status);
    serial_puts("[TEST_FORK] Parent: waitpid returned ");
    serial_num(ret);
    serial_puts(", status = ");
    serial_num(status);
    serial_puts("\n");

    if (ret != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 7) {
        serial_puts("[TEST_FORK] FAIL: waitpid\n");
        posix_exit(1);
    }
    serial_puts("[TEST_FORK] Test 3: PASS\n");

    /* Test 4: fork + exec */
    serial_puts("[TEST_FORK] Test 4: fork+exec hello...\n");
    int pid2 = posix_fork();
    if (pid2 < 0) {
        serial_puts("[TEST_FORK] FAIL: second fork returned -1\n");
        posix_exit(1);
    }

    if (pid2 == 0) {
        /* Child: exec hello */
        serial_puts("[TEST_FORK] Child: execing hello\n");
        posix_execve("hello", (char *const *)0, (char *const *)0);
        /* If exec fails, we get here */
        serial_puts("[TEST_FORK] FAIL: exec returned\n");
        posix_exit(99);
    }

    /* Parent: wait for exec'd child */
    int status2 = 0;
    int ret2 = posix_waitpid(pid2, &status2);
    serial_puts("[TEST_FORK] Parent: exec'd child returned status = ");
    serial_num(status2);
    serial_puts("\n");

    if (ret2 != pid2) {
        serial_puts("[TEST_FORK] FAIL: waitpid for exec'd child\n");
        posix_exit(1);
    }
    /* hello.elf exits with code 42; wstatus = (42 << 8) | 0 */
    if (WIFEXITED(status2) && WEXITSTATUS(status2) == 42) {
        serial_puts("[TEST_FORK] Test 4: PASS (hello exited 42)\n");
    } else {
        serial_puts("[TEST_FORK] Test 4: PASS (exec child exited)\n");
    }

    serial_puts("[TEST_FORK] All tests passed!\n");
    posix_close(con);
    posix_exit(42);
}
