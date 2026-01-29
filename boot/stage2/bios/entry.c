/* SaltyOS Stage 2 BIOS C Entry Point
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Called from entry.asm after long mode transition
 * Sets up stage2_context with BIOS-specific callbacks and calls common stage2_main()
 */

#include "../common/stage2.h"
#include "../../common/print.h"
#include "../../common/types.h"

/* Platform callback implementations (in separate files) */
extern int bios_load_stage3(void **stage3_addr, size_t *size);
extern int bios_load_kernel(void **kernel_addr, size_t *size);
extern int bios_get_memory_map(struct memory_map_entry **map, size_t *count);
extern uint64_t bios_get_rsdp(void);
extern struct framebuffer_info bios_get_framebuffer(void);

/* Main C entry point called from assembly */
void stage2_bios_main(void) {
    println("S2: BIOS C entry");

    /* Set up stage2_context */
    struct stage2_context ctx = {
        .kernel_phys_base = 0,
        .kernel_virt_base = 0xFFFFFFFF80000000ULL,
        .stage3_buffer = NULL,
        .stage3_size = 0,
        .kernel_buffer = NULL,
        .kernel_size = 0,
        .load_stage3 = bios_load_stage3,
        .load_kernel = bios_load_kernel,
        .get_memory_map = bios_get_memory_map,
        .get_rsdp = bios_get_rsdp,
        .get_framebuffer = bios_get_framebuffer,
    };

    /* Call common Stage2 */
    stage2_main(&ctx);

    /* Should never return */
    for (;;) {
        __asm__ volatile("cli; hlt");
    }
}
