/* SaltyOS mmap test - exercises brk/sbrk/mmap/munmap
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "salty.h"
#include "posix.h"
#include "posix_mm.h"

/* Imported from rtld: first available frame slot after dynamic linking */
extern uint64_t __salty_next_frame_slot;

static void puts(const char *s) {
    unsigned long len = 0;
    while (s[len]) len++;
    posix_write(1, s, len);
}

static void print_hex(uint64_t val) {
    char buf[19];
    buf[0] = '0'; buf[1] = 'x';
    const char *hex = "0123456789abcdef";
    for (int i = 15; i >= 0; i--) {
        buf[2 + (15 - i)] = hex[(val >> (i * 4)) & 0xF];
    }
    buf[18] = '\0';
    unsigned long len = 18;
    posix_write(1, buf, len);
}

static int console_fd = -1;

static void test_puts(const char *s) {
    if (console_fd < 0) return;
    unsigned long len = 0;
    while (s[len]) len++;
    posix_write(console_fd, s, len);
}

void _start(void) {
    /* Set up IPC buffer */
    salty_tcb_set_ipc_buffer(POSIX_CAP_SELF_TCB, 0x200000ULL);
    salty_ipc_context_init(&__salty_ipc_ctx, (void *)0x200000ULL);

    console_fd = posix_open("/dev/console", O_WRONLY);

    test_puts("[MMAP_TEST] Starting memory management tests\n");

    /* Initialize posix_mm with caps from procmgr */
    posix_mm_init(
        POSIX_CAP_UNTYPED,
        POSIX_CAP_SELF_VSPACE,
        POSIX_CAP_SELF_CSPACE,
        (cap_t)__salty_next_frame_slot,
        0x12000000ULL,  /* heap base (avoid rtld-loaded libs at 0x10000000/0x11000000) */
        0x20000000ULL   /* mmap base */
    );

    /* Test 1: sbrk */
    test_puts("[MMAP_TEST] Test 1: sbrk(4096)\n");
    void *old_brk = posix_sbrk(4096);
    if (old_brk == (void *)-1) {
        test_puts("[MMAP_TEST] FAIL: sbrk returned -1\n");
        posix_exit(1);
    }
    test_puts("[MMAP_TEST] sbrk returned: ");
    salty_serial_hex((uint64_t)old_brk);
    salty_serial_puts("\n");

    /* Write and read back */
    volatile uint8_t *heap = (volatile uint8_t *)old_brk;
    heap[0] = 0xAA;
    heap[4095] = 0xBB;
    if (heap[0] != 0xAA || heap[4095] != 0xBB) {
        test_puts("[MMAP_TEST] FAIL: heap read-back mismatch\n");
        posix_exit(1);
    }
    test_puts("[MMAP_TEST] PASS: sbrk write/read OK\n");

    /* Check current break */
    void *cur_brk = posix_sbrk(0);
    if ((uint64_t)cur_brk != (uint64_t)old_brk + 4096) {
        test_puts("[MMAP_TEST] FAIL: sbrk(0) not at expected break\n");
        posix_exit(1);
    }
    test_puts("[MMAP_TEST] PASS: sbrk(0) check OK\n");

    /* Test 2: mmap anonymous */
    test_puts("[MMAP_TEST] Test 2: mmap anonymous page\n");
    void *page = posix_mmap(0, 4096, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        test_puts("[MMAP_TEST] FAIL: mmap returned MAP_FAILED\n");
        posix_exit(1);
    }
    test_puts("[MMAP_TEST] mmap returned: ");
    salty_serial_hex((uint64_t)page);
    salty_serial_puts("\n");

    /* Verify zero-initialized */
    volatile uint8_t *mp = (volatile uint8_t *)page;
    if (mp[0] != 0 || mp[2048] != 0 || mp[4095] != 0) {
        test_puts("[MMAP_TEST] FAIL: mmap page not zero\n");
        posix_exit(1);
    }

    /* Write and read */
    mp[0] = 0xCC;
    mp[4095] = 0xDD;
    if (mp[0] != 0xCC || mp[4095] != 0xDD) {
        test_puts("[MMAP_TEST] FAIL: mmap read-back mismatch\n");
        posix_exit(1);
    }
    test_puts("[MMAP_TEST] PASS: mmap write/read OK\n");

    /* Test 3: munmap */
    test_puts("[MMAP_TEST] Test 3: munmap\n");
    int ret = posix_munmap(page, 4096);
    if (ret != 0) {
        test_puts("[MMAP_TEST] FAIL: munmap returned error\n");
        posix_exit(1);
    }
    test_puts("[MMAP_TEST] PASS: munmap OK\n");

    /* Test 4: Multiple mmap regions */
    test_puts("[MMAP_TEST] Test 4: multiple mmap regions\n");
    void *p1 = posix_mmap(0, 4096, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    void *p2 = posix_mmap(0, 8192, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p1 == MAP_FAILED || p2 == MAP_FAILED) {
        test_puts("[MMAP_TEST] FAIL: multi mmap failed\n");
        posix_exit(1);
    }

    /* Verify no overlap */
    uint64_t a1 = (uint64_t)p1, a2 = (uint64_t)p2;
    if (a1 == a2 || (a1 < a2 + 8192 && a2 < a1 + 4096)) {
        test_puts("[MMAP_TEST] FAIL: mmap regions overlap\n");
        posix_exit(1);
    }

    /* Write to both */
    ((volatile uint8_t *)p1)[0] = 0x11;
    ((volatile uint8_t *)p2)[0] = 0x22;
    if (((volatile uint8_t *)p1)[0] != 0x11 ||
        ((volatile uint8_t *)p2)[0] != 0x22) {
        test_puts("[MMAP_TEST] FAIL: multi mmap read-back mismatch\n");
        posix_exit(1);
    }
    test_puts("[MMAP_TEST] PASS: multiple mmap regions OK\n");

    posix_munmap(p1, 4096);
    posix_munmap(p2, 8192);

    test_puts("[MMAP_TEST] All memory management tests PASSED\n");
    posix_exit(42);
}
