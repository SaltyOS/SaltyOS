/* SaltyOS POSIX signal test
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Tests:
 *  1. Register SIGUSR1 handler, self-signal, sigcheck -> handler called
 *  2. SIG_IGN on SIGUSR2, self-signal -> no crash
 *  3. SIGTERM default kills child (WIFSIGNALED, WTERMSIG==SIGTERM)
 *  4. SIGCHLD handler fires on child exit (WIFEXITED)
 *  5. SIGKILL cannot be caught (posix_signal returns SIG_ERR)
 *  6. SIGCHLD fires when signal-killed child has waiting parent
 *  7. SIGSTOP cannot be caught (posix_signal returns SIG_ERR)
 *  8. SIGSTOP suspends child, SIGCONT resumes
 *  9. posix_signal(SIGUSR1, SIG_ERR) returns SIG_ERR
 *
 * Exit code 42 = all tests passed.
 */

#include "salty.h"
#include "posix.h"

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

static volatile int g_sigusr1_count;
static volatile int g_sigchld_count;

static void sigusr1_handler(int sig) {
    (void)sig;
    g_sigusr1_count++;
    serial_puts("[TEST_SIGNAL] SIGUSR1 handler called\n");
}

static void sigchld_handler(int sig) {
    (void)sig;
    g_sigchld_count++;
    serial_puts("[TEST_SIGNAL] SIGCHLD received\n");
}

void _start(void) {
    /* Set up IPC buffer (pre-mapped by procmgr at 0x200000) */
    salty_tcb_set_ipc_buffer(POSIX_CAP_SELF_TCB, 0x200000ULL);
    salty_ipc_context_init(&__salty_ipc_ctx, (void *)0x200000ULL);

    serial_puts("[TEST_SIGNAL] Starting signal tests\n");

    int my_pid = posix_getpid();
    if (my_pid <= 0) {
        serial_puts("[TEST_SIGNAL] FAIL: getpid\n");
        posix_exit(1);
    }

    /* Test 1: SIGUSR1 handler */
    serial_puts("[TEST_SIGNAL] Test 1: SIGUSR1 handler\n");
    g_sigusr1_count = 0;
    sighandler_t old = posix_signal(SIGUSR1, sigusr1_handler);
    if (old == SIG_ERR) {
        serial_puts("[TEST_SIGNAL] FAIL: posix_signal returned SIG_ERR\n");
        posix_exit(1);
    }

    if (posix_kill(my_pid, SIGUSR1) != 0) {
        serial_puts("[TEST_SIGNAL] FAIL: posix_kill self SIGUSR1\n");
        posix_exit(1);
    }

    /* Give scheduler a chance to deliver notification */
    salty_yield();

    int dispatched = posix_sigcheck();
    if (dispatched == 0 || g_sigusr1_count == 0) {
        serial_puts("[TEST_SIGNAL] FAIL: SIGUSR1 handler not called, dispatched=");
        serial_num(dispatched);
        serial_puts(" count=");
        serial_num(g_sigusr1_count);
        serial_puts("\n");
        posix_exit(1);
    }
    serial_puts("[TEST_SIGNAL] Test 1: PASS\n");

    /* Test 2: SIG_IGN on SIGUSR2 */
    serial_puts("[TEST_SIGNAL] Test 2: SIGUSR2 SIG_IGN\n");
    old = posix_signal(SIGUSR2, SIG_IGN);
    if (old == SIG_ERR) {
        serial_puts("[TEST_SIGNAL] FAIL: posix_signal SIGUSR2 SIG_IGN\n");
        posix_exit(1);
    }

    if (posix_kill(my_pid, SIGUSR2) != 0) {
        serial_puts("[TEST_SIGNAL] FAIL: posix_kill self SIGUSR2\n");
        posix_exit(1);
    }

    salty_yield();
    posix_sigcheck(); /* Should not crash or dispatch anything significant */
    serial_puts("[TEST_SIGNAL] Test 2: PASS\n");

    /* Test 3: SIGTERM default kills child */
    serial_puts("[TEST_SIGNAL] Test 3: SIGTERM default kills child\n");
    int child_pid = posix_fork();
    if (child_pid < 0) {
        serial_puts("[TEST_SIGNAL] FAIL: fork for test 3\n");
        posix_exit(1);
    }

    if (child_pid == 0) {
        /* Child: just loop, waiting to be killed */
        for (;;) salty_yield();
    }

    /* Parent: give child time to start */
    salty_yield();
    salty_yield();

    if (posix_kill(child_pid, SIGTERM) != 0) {
        serial_puts("[TEST_SIGNAL] FAIL: posix_kill child SIGTERM\n");
        posix_exit(1);
    }

    int status = 0;
    int ret = posix_waitpid(child_pid, &status);
    if (ret != child_pid) {
        serial_puts("[TEST_SIGNAL] FAIL: waitpid returned wrong pid\n");
        posix_exit(1);
    }

    /* POSIX wstatus: WIFSIGNALED, WTERMSIG == SIGTERM (15) */
    if (!WIFSIGNALED(status) || WTERMSIG(status) != SIGTERM) {
        serial_puts("[TEST_SIGNAL] FAIL: expected WIFSIGNALED+SIGTERM, got ");
        serial_num(status);
        serial_puts("\n");
        posix_exit(1);
    }
    serial_puts("[TEST_SIGNAL] Test 3: PASS\n");

    /* Test 4: SIGCHLD from child exit */
    serial_puts("[TEST_SIGNAL] Test 4: SIGCHLD from child exit\n");
    g_sigchld_count = 0;
    old = posix_signal(SIGCHLD, sigchld_handler);
    if (old == SIG_ERR) {
        serial_puts("[TEST_SIGNAL] FAIL: posix_signal SIGCHLD\n");
        posix_exit(1);
    }

    int child2_pid = posix_fork();
    if (child2_pid < 0) {
        serial_puts("[TEST_SIGNAL] FAIL: fork for test 4\n");
        posix_exit(1);
    }

    if (child2_pid == 0) {
        /* Child: exit immediately */
        posix_exit(0);
    }

    /* Use blocking waitpid so the child actually gets scheduled.
     * The parent blocks in IPC, child runs + exits, procmgr delivers
     * SIGCHLD (notification) then wakes parent via waitpid reply. */
    int status4 = 0;
    posix_waitpid(child2_pid, &status4);

    /* Notification was set before the waiter was woken, so sigcheck
     * should find the SIGCHLD bit. */
    posix_sigcheck();

    if (g_sigchld_count == 0) {
        serial_puts("[TEST_SIGNAL] FAIL: SIGCHLD handler not called\n");
        posix_exit(1);
    }
    serial_puts("[TEST_SIGNAL] Test 4: PASS\n");

    /* Test 5: SIGKILL cannot be caught */
    serial_puts("[TEST_SIGNAL] Test 5: SIGKILL uncatchable\n");
    old = posix_signal(SIGKILL, sigusr1_handler);
    if (old != SIG_ERR) {
        serial_puts("[TEST_SIGNAL] FAIL: posix_signal(SIGKILL) should return SIG_ERR\n");
        posix_exit(1);
    }
    serial_puts("[TEST_SIGNAL] Test 5: PASS\n");

    /* Test 6: SIGCHLD fires when signal-killed child has waiting parent */
    serial_puts("[TEST_SIGNAL] Test 6: SIGCHLD on signal-killed child\n");
    g_sigchld_count = 0;
    /* SIGCHLD handler already registered from test 4 */

    int child6_pid = posix_fork();
    if (child6_pid < 0) {
        serial_puts("[TEST_SIGNAL] FAIL: fork for test 6\n");
        posix_exit(1);
    }

    if (child6_pid == 0) {
        for (;;) salty_yield();
    }

    salty_yield();
    salty_yield();

    if (posix_kill(child6_pid, SIGTERM) != 0) {
        serial_puts("[TEST_SIGNAL] FAIL: posix_kill child6 SIGTERM\n");
        posix_exit(1);
    }

    int status6 = 0;
    int ret6 = posix_waitpid(child6_pid, &status6);
    if (ret6 != child6_pid) {
        serial_puts("[TEST_SIGNAL] FAIL: waitpid test 6\n");
        posix_exit(1);
    }

    posix_sigcheck();

    if (g_sigchld_count == 0) {
        serial_puts("[TEST_SIGNAL] FAIL: SIGCHLD not delivered for signal-killed child\n");
        posix_exit(1);
    }
    serial_puts("[TEST_SIGNAL] Test 6: PASS\n");

    /* Test 7: SIGSTOP cannot be caught */
    serial_puts("[TEST_SIGNAL] Test 7: SIGSTOP uncatchable\n");
    old = posix_signal(SIGSTOP, sigusr1_handler);
    if (old != SIG_ERR) {
        serial_puts("[TEST_SIGNAL] FAIL: posix_signal(SIGSTOP) should return SIG_ERR\n");
        posix_exit(1);
    }
    serial_puts("[TEST_SIGNAL] Test 7: PASS\n");

    /* Test 8: SIGSTOP suspends child, SIGCONT resumes it */
    serial_puts("[TEST_SIGNAL] Test 8: SIGSTOP/SIGCONT\n");
    int child8_pid = posix_fork();
    if (child8_pid < 0) {
        serial_puts("[TEST_SIGNAL] FAIL: fork for test 8\n");
        posix_exit(1);
    }

    if (child8_pid == 0) {
        /* Child: loop forever, waiting to be stopped/resumed/killed */
        for (;;) salty_yield();
    }

    /* Give child time to start */
    salty_yield();
    salty_yield();

    /* Stop the child */
    if (posix_kill(child8_pid, SIGSTOP) != 0) {
        serial_puts("[TEST_SIGNAL] FAIL: posix_kill child8 SIGSTOP\n");
        posix_exit(1);
    }

    /* Verify child is stopped via WUNTRACED */
    int status8 = 0;
    int ret8 = posix_waitpid3(child8_pid, &status8, WUNTRACED);
    if (ret8 != child8_pid || !WIFSTOPPED(status8)) {
        serial_puts("[TEST_SIGNAL] FAIL: child not reported as stopped\n");
        posix_exit(1);
    }
    if (WSTOPSIG(status8) != SIGSTOP) {
        serial_puts("[TEST_SIGNAL] FAIL: WSTOPSIG != SIGSTOP\n");
        posix_exit(1);
    }

    /* Resume the child */
    if (posix_kill(child8_pid, SIGCONT) != 0) {
        serial_puts("[TEST_SIGNAL] FAIL: posix_kill child8 SIGCONT\n");
        posix_exit(1);
    }

    salty_yield();

    /* Kill the resumed child so we can reap it */
    if (posix_kill(child8_pid, SIGKILL) != 0) {
        serial_puts("[TEST_SIGNAL] FAIL: posix_kill child8 SIGKILL\n");
        posix_exit(1);
    }

    int status8b = 0;
    int ret8b = posix_waitpid(child8_pid, &status8b);
    if (ret8b != child8_pid || !WIFSIGNALED(status8b) || WTERMSIG(status8b) != SIGKILL) {
        serial_puts("[TEST_SIGNAL] FAIL: resumed child not killed correctly\n");
        posix_exit(1);
    }
    serial_puts("[TEST_SIGNAL] Test 8: PASS\n");

    /* Test 9: posix_signal(SIGUSR1, SIG_ERR) returns SIG_ERR */
    serial_puts("[TEST_SIGNAL] Test 9: SIG_ERR rejected\n");
    old = posix_signal(SIGUSR1, SIG_ERR);
    if (old != SIG_ERR) {
        serial_puts("[TEST_SIGNAL] FAIL: posix_signal(SIGUSR1, SIG_ERR) should return SIG_ERR\n");
        posix_exit(1);
    }
    serial_puts("[TEST_SIGNAL] Test 9: PASS\n");

    serial_puts("[TEST_SIGNAL] All signal tests passed!\n");
    posix_exit(42);
}
