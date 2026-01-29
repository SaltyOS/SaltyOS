/* SaltyOS Stage 2 Common Main
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Shared Stage 2 logic for both BIOS and UEFI
 * Loads Stage 3, kernel, and prepares BootInfo
 */

#include "stage2.h"
#include "../../common/print.h"

/* Stage3 entry point type */
typedef void (*stage3_entry_fn)(struct boot_info *);

/* Default addresses */
#define STAGE3_LOAD_ADDR    0x10000ULL
#define KERNEL_TEMP_ADDR    0x20000ULL

/* Main Stage2 function - called from both BIOS and UEFI wrappers */
void stage2_main(struct stage2_context *ctx) {
    void *stage3_addr = 0;
    void *kernel_addr = 0;
    size_t stage3_size = 0;
    size_t kernel_size = 0;

    println("S2: stage2_main start");

    /* 1. Load Stage3 using platform callback */
    if (ctx->load_stage3) {
        if (ctx->load_stage3(&stage3_addr, &stage3_size) != 0) {
            println("S2: load_stage3 failed");
            for (;;) {
                __asm__ volatile("cli; hlt");
            }
        }
        print("S2: stage3 loaded size=");
        serial_puthex(stage3_size);
        println("");
        ctx->stage3_buffer = stage3_addr;
        ctx->stage3_size = stage3_size;
    } else {
        stage3_addr = (void *)STAGE3_LOAD_ADDR;
    }

    /* 2. Load kernel ELF using platform callback */
    if (ctx->load_kernel) {
        if (ctx->load_kernel(&kernel_addr, &kernel_size) != 0) {
            println("S2: load_kernel failed");
            for (;;) {
                __asm__ volatile("cli; hlt");
            }
        }
        print("S2: kernel loaded size=");
        serial_puthex(kernel_size);
        println("");
        ctx->kernel_buffer = kernel_addr;
        ctx->kernel_size = kernel_size;
    } else {
        kernel_addr = (void *)KERNEL_TEMP_ADDR;
    }

    /* 3. Build BootInfo */
    struct boot_info *bi = stage2_build_bootinfo(ctx);

    stage3_entry_fn stage3 = (stage3_entry_fn)stage3_addr;

    print("S2: jumping to stage3 @");
    serial_puthex((uint64_t)stage3_addr);
    println("");

    /* Call Stage3 - it will parse ELF and jump to kernel */
    __asm__ volatile(
        "mov %0, %%rdi\n\t"
        "jmp *%1\n\t"
        :
        : "r"(bi), "r"(stage3)
        : "rdi"
    );

    /* Should never return */
    for (;;) {
        __asm__ volatile("cli; hlt");
    }
}
