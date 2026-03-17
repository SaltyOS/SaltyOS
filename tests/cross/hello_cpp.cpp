/* C++ cross-compilation smoke test for SaltyOS
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Build: bash tests/cross/build_cpp.sh <sysroot-path>
 * Verify: add hello_cpp.elf + libc++.so to initrd, boot, check serial output
 *
 * Tests:
 *   - Dynamic linking against libc++.so
 *   - std::string construction/destruction (__cxa_atexit)
 *   - std::vector heap allocation (malloc/free)
 *   - C/C++ interop (printf)
 */
#include <cstdio>
#include <string>
#include <vector>

int main() {
    std::string msg = "Hello from C++ on SaltyOS!";
    std::vector<int> v = {1, 2, 3};
    printf("%s (vec size: %zu)\n", msg.c_str(), v.size());
    return 0;
}
