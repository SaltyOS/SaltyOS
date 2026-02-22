/* Hello world — C cross-compilation test for SaltyOS
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Tests: headers compile, argc/argv passing, printf, fork+exec
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    printf("Hello from C! argc=%d pid=%d\n", argc, getpid());
    for (int i = 0; i < argc; i++) {
        printf("  argv[%d]=%s\n", i, argv[i]);
    }

    /* Test basic string operations */
    char buf[64];
    snprintf(buf, sizeof(buf), "SaltyOS version %d.%d", 0, 1);
    printf("snprintf: %s (len=%d)\n", buf, (int)strlen(buf));

    /* Test getcwd */
    char cwd[256];
    if (getcwd(cwd, sizeof(cwd))) {
        printf("cwd: %s\n", cwd);
    }

    return 0;
}
