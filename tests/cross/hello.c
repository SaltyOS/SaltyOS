/* Cross-compilation smoke test for SaltyOS
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Build: bash tests/cross/build.sh <sysroot-path>
 * Verify: add hello.elf to initrd, boot, check serial output
 */
#include <stdio.h>

int main(void) {
    printf("Hello from cross-compiled C on SaltyOS!\n");
    return 0;
}
