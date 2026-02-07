/* SaltyOS filesystem test - exercises VFS ramfs operations
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "salty.h"
#include "posix.h"
#include "posix_mm.h"

/* Imported from rtld: first available frame slot after dynamic linking */
extern uint64_t __salty_next_frame_slot;

static int console_fd = -1;

static void test_puts(const char *s) {
    if (console_fd < 0) return;
    unsigned long len = 0;
    while (s[len]) len++;
    posix_write(console_fd, s, len);
}

static void test_hex(uint64_t val) {
    char buf[19];
    buf[0] = '0'; buf[1] = 'x';
    const char *hex = "0123456789abcdef";
    for (int i = 15; i >= 0; i--)
        buf[2 + (15 - i)] = hex[(val >> (i * 4)) & 0xF];
    buf[18] = '\0';
    if (console_fd >= 0)
        posix_write(console_fd, buf, 18);
}

static int streq(const char *a, const char *b) {
    while (*a && *b) {
        if (*a != *b) return 0;
        a++; b++;
    }
    return *a == *b;
}

void _start(void) {
    /* Set up IPC buffer */
    salty_tcb_set_ipc_buffer(POSIX_CAP_SELF_TCB, 0x200000ULL);
    salty_ipc_context_init(&__salty_ipc_ctx, (void *)0x200000ULL);

    console_fd = posix_open("/dev/console", O_WRONLY);

    test_puts("[FSTEST] Starting filesystem tests\n");

    /* Initialize posix_mm for any memory allocation needs */
    posix_mm_init(
        POSIX_CAP_UNTYPED,
        POSIX_CAP_SELF_VSPACE,
        POSIX_CAP_SELF_CSPACE,
        (cap_t)__salty_next_frame_slot,
        0x10000000ULL,
        0x20000000ULL
    );

    /* =================================================================
     * Test 1: stat /dev/console — should be a char device
     * ================================================================= */
    test_puts("[FSTEST] Test 1: stat /dev/console\n");
    struct salty_stat st;
    int ret = posix_stat("/dev/console", &st);
    if (ret != 0) {
        test_puts("[FSTEST] FAIL: stat /dev/console returned error\n");
        posix_exit(1);
    }
    if (!S_ISCHR(st.st_mode)) {
        test_puts("[FSTEST] FAIL: /dev/console is not a char device, mode=");
        test_hex(st.st_mode);
        test_puts("\n");
        posix_exit(1);
    }
    test_puts("[FSTEST] PASS: /dev/console is a char device\n");

    /* =================================================================
     * Test 2: stat /initrd — should be a directory
     * ================================================================= */
    test_puts("[FSTEST] Test 2: stat /initrd\n");
    ret = posix_stat("/initrd", &st);
    if (ret != 0) {
        test_puts("[FSTEST] FAIL: stat /initrd returned error\n");
        posix_exit(1);
    }
    if (!S_ISDIR(st.st_mode)) {
        test_puts("[FSTEST] FAIL: /initrd is not a directory\n");
        posix_exit(1);
    }
    test_puts("[FSTEST] PASS: /initrd is a directory\n");

    /* =================================================================
     * Test 3: opendir /initrd + readdir — list files
     * ================================================================= */
    test_puts("[FSTEST] Test 3: opendir/readdir /initrd\n");
    int dir_fd = posix_opendir("/initrd");
    if (dir_fd < 0) {
        test_puts("[FSTEST] FAIL: opendir /initrd failed\n");
        posix_exit(1);
    }

    struct salty_dirent dent;
    int file_count = 0;
    while (posix_readdir(dir_fd, &dent)) {
        test_puts("[FSTEST]   ");
        posix_write(console_fd, dent.d_name, dent.d_namlen);
        test_puts(" (type=");
        test_hex(dent.d_type);
        test_puts(")\n");
        file_count++;
    }
    posix_closedir(dir_fd);

    if (file_count == 0) {
        test_puts("[FSTEST] FAIL: /initrd is empty\n");
        posix_exit(1);
    }
    test_puts("[FSTEST] PASS: listed ");
    test_hex((uint64_t)file_count);
    test_puts(" initrd entries\n");

    /* =================================================================
     * Test 4: access — check file existence
     * ================================================================= */
    test_puts("[FSTEST] Test 4: access checks\n");
    ret = posix_access("/dev/console", F_OK);
    if (ret != 0) {
        test_puts("[FSTEST] FAIL: access /dev/console F_OK failed\n");
        posix_exit(1);
    }
    ret = posix_access("/nonexistent", F_OK);
    if (ret == 0) {
        test_puts("[FSTEST] FAIL: access /nonexistent should have failed\n");
        posix_exit(1);
    }
    test_puts("[FSTEST] PASS: access checks OK\n");

    /* =================================================================
     * Test 5: mkdir — create /tmp
     * ================================================================= */
    test_puts("[FSTEST] Test 5: mkdir /tmp\n");
    ret = posix_mkdir("/tmp", 0755);
    if (ret != 0) {
        test_puts("[FSTEST] FAIL: mkdir /tmp returned error\n");
        posix_exit(1);
    }
    ret = posix_stat("/tmp", &st);
    if (ret != 0 || !S_ISDIR(st.st_mode)) {
        test_puts("[FSTEST] FAIL: /tmp is not a directory after mkdir\n");
        posix_exit(1);
    }
    test_puts("[FSTEST] PASS: mkdir /tmp OK\n");

    /* =================================================================
     * Test 6: create + write + close + open + read round-trip
     * ================================================================= */
    test_puts("[FSTEST] Test 6: file create/write/read round-trip\n");
    int fd = posix_open("/tmp/test.txt", O_CREAT | O_RDWR);
    if (fd < 0) {
        test_puts("[FSTEST] FAIL: open /tmp/test.txt O_CREAT failed\n");
        posix_exit(1);
    }

    const char *test_data = "Hello, SaltyOS filesystem!";
    unsigned long data_len = 0;
    while (test_data[data_len]) data_len++;

    long written = posix_write(fd, test_data, data_len);
    if (written != (long)data_len) {
        test_puts("[FSTEST] FAIL: write returned wrong count\n");
        posix_exit(1);
    }
    posix_close(fd);

    /* Re-open and read back */
    fd = posix_open("/tmp/test.txt", O_RDONLY);
    if (fd < 0) {
        test_puts("[FSTEST] FAIL: re-open /tmp/test.txt failed\n");
        posix_exit(1);
    }

    char buf[64];
    for (int i = 0; i < 64; i++) buf[i] = 0;
    long rd = posix_read(fd, buf, 64);
    if (rd != (long)data_len) {
        test_puts("[FSTEST] FAIL: read returned wrong count: ");
        test_hex((uint64_t)rd);
        test_puts(" expected ");
        test_hex(data_len);
        test_puts("\n");
        posix_exit(1);
    }

    /* Verify content */
    int match = 1;
    for (unsigned long i = 0; i < data_len; i++) {
        if (buf[i] != test_data[i]) { match = 0; break; }
    }
    if (!match) {
        test_puts("[FSTEST] FAIL: read-back content mismatch\n");
        posix_exit(1);
    }
    test_puts("[FSTEST] PASS: file write/read round-trip OK\n");

    /* =================================================================
     * Test 7: lseek + re-read
     * ================================================================= */
    test_puts("[FSTEST] Test 7: lseek\n");
    long off = posix_lseek(fd, 7, SEEK_SET);
    if (off != 7) {
        test_puts("[FSTEST] FAIL: lseek SEEK_SET returned wrong offset\n");
        posix_exit(1);
    }

    for (int i = 0; i < 64; i++) buf[i] = 0;
    rd = posix_read(fd, buf, 64);
    /* Should read "SaltyOS filesystem!" */
    if (rd <= 0 || buf[0] != 'S') {
        test_puts("[FSTEST] FAIL: read after lseek got wrong data\n");
        posix_exit(1);
    }
    posix_close(fd);
    test_puts("[FSTEST] PASS: lseek OK\n");

    /* =================================================================
     * Test 8: fstat on an open file
     * ================================================================= */
    test_puts("[FSTEST] Test 8: fstat\n");
    fd = posix_open("/tmp/test.txt", O_RDONLY);
    if (fd < 0) {
        test_puts("[FSTEST] FAIL: open for fstat failed\n");
        posix_exit(1);
    }
    ret = posix_fstat(fd, &st);
    if (ret != 0) {
        test_puts("[FSTEST] FAIL: fstat returned error\n");
        posix_exit(1);
    }
    if (!S_ISREG(st.st_mode)) {
        test_puts("[FSTEST] FAIL: fstat mode is not regular file\n");
        posix_exit(1);
    }
    if (st.st_size != data_len) {
        test_puts("[FSTEST] FAIL: fstat size mismatch: ");
        test_hex(st.st_size);
        test_puts(" vs ");
        test_hex(data_len);
        test_puts("\n");
        posix_exit(1);
    }
    posix_close(fd);
    test_puts("[FSTEST] PASS: fstat OK\n");

    /* =================================================================
     * Test 9: unlink + access (should fail after unlink)
     * ================================================================= */
    test_puts("[FSTEST] Test 9: unlink\n");
    ret = posix_unlink("/tmp/test.txt");
    if (ret != 0) {
        test_puts("[FSTEST] FAIL: unlink returned error\n");
        posix_exit(1);
    }
    ret = posix_access("/tmp/test.txt", F_OK);
    if (ret == 0) {
        test_puts("[FSTEST] FAIL: file still exists after unlink\n");
        posix_exit(1);
    }
    test_puts("[FSTEST] PASS: unlink OK\n");

    /* =================================================================
     * Test 10: rmdir
     * ================================================================= */
    test_puts("[FSTEST] Test 10: rmdir /tmp\n");
    ret = posix_rmdir("/tmp");
    if (ret != 0) {
        test_puts("[FSTEST] FAIL: rmdir /tmp returned error\n");
        posix_exit(1);
    }
    ret = posix_access("/tmp", F_OK);
    if (ret == 0) {
        test_puts("[FSTEST] FAIL: /tmp still exists after rmdir\n");
        posix_exit(1);
    }
    test_puts("[FSTEST] PASS: rmdir OK\n");

    /* =================================================================
     * Test 11: opendir /dev + readdir — verify device entries
     * ================================================================= */
    test_puts("[FSTEST] Test 11: readdir /dev\n");
    dir_fd = posix_opendir("/dev");
    if (dir_fd < 0) {
        test_puts("[FSTEST] FAIL: opendir /dev failed\n");
        posix_exit(1);
    }

    int found_console = 0, found_null = 0, found_zero = 0;
    while (posix_readdir(dir_fd, &dent)) {
        if (streq(dent.d_name, "console")) found_console = 1;
        if (streq(dent.d_name, "null"))    found_null = 1;
        if (streq(dent.d_name, "zero"))    found_zero = 1;
    }
    posix_closedir(dir_fd);

    if (!found_console || !found_null || !found_zero) {
        test_puts("[FSTEST] FAIL: missing device entries in /dev\n");
        posix_exit(1);
    }
    test_puts("[FSTEST] PASS: /dev contains console, null, zero\n");

    /* =================================================================
     * Test 12: rename
     * ================================================================= */
    test_puts("[FSTEST] Test 12: rename\n");
    ret = posix_mkdir("/tmp2", 0755);
    if (ret != 0) {
        test_puts("[FSTEST] FAIL: mkdir /tmp2 failed\n");
        posix_exit(1);
    }
    fd = posix_open("/tmp2/a.txt", O_CREAT | O_RDWR);
    if (fd < 0) {
        test_puts("[FSTEST] FAIL: create /tmp2/a.txt failed\n");
        posix_exit(1);
    }
    posix_write(fd, "rename", 6);
    posix_close(fd);

    ret = posix_rename("/tmp2/a.txt", "/tmp2/b.txt");
    if (ret != 0) {
        test_puts("[FSTEST] FAIL: rename failed\n");
        posix_exit(1);
    }

    ret = posix_access("/tmp2/a.txt", F_OK);
    if (ret == 0) {
        test_puts("[FSTEST] FAIL: old name still exists after rename\n");
        posix_exit(1);
    }

    fd = posix_open("/tmp2/b.txt", O_RDONLY);
    if (fd < 0) {
        test_puts("[FSTEST] FAIL: open renamed file failed\n");
        posix_exit(1);
    }
    for (int i = 0; i < 64; i++) buf[i] = 0;
    rd = posix_read(fd, buf, 64);
    posix_close(fd);
    if (rd != 6 || buf[0] != 'r') {
        test_puts("[FSTEST] FAIL: renamed file content wrong\n");
        posix_exit(1);
    }
    test_puts("[FSTEST] PASS: rename OK\n");

    /* Clean up */
    posix_unlink("/tmp2/b.txt");
    posix_rmdir("/tmp2");

    test_puts("[FSTEST] All filesystem tests PASSED\n");
    posix_exit(42);
}
