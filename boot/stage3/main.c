/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SaltyOS Bootloader - Stage 3 Shared Code
 *
 * Contains global context and panic handler shared by both
 * BIOS (bios_main.c) and UEFI (uefi_main.c) paths.
 */

#include "../common/types.h"
#include "../common/print.h"
#include "stage3.h"

/* Global context */
struct Stage3Context g_ctx;

/*
 * Panic and halt
 */
NORETURN void stage3_panic(const char *msg)
{
    print_str("PANIC: ");
    print_line(msg);

    /* Halt */
    for (;;) {
#if defined(__x86_64__) || defined(__i386__)
        __asm__ volatile("cli; hlt");
#elif defined(__aarch64__)
        __asm__ volatile("msr DAIFSet, #0xF; wfi");
#endif
    }
}
