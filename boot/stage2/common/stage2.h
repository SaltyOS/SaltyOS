/* SaltyOS Stage 2 Common Header
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Shared definitions and interfaces for Stage 2
 * Used by both BIOS and UEFI implementations
 */

#ifndef SALTYOS_STAGE2_STAGE2_H
#define SALTYOS_STAGE2_STAGE2_H

#include "../../common/types.h"

/* Stage2 platform context (BIOS or UEFI) */
struct stage2_context {
    uint64_t kernel_phys_base;
    uint64_t kernel_virt_base;

    /* Buffers loaded by platform */
    void *stage3_buffer;
    size_t stage3_size;
    void *kernel_buffer;
    size_t kernel_size;

    /* Platform-specific callbacks */
    int (*load_stage3)(void **stage3_addr, size_t *size);
    int (*load_kernel)(void **kernel_addr, size_t *size);
    int (*get_memory_map)(struct memory_map_entry **map, size_t *count);
    uint64_t (*get_rsdp)(void);
    struct framebuffer_info (*get_framebuffer)(void);
};

/* Main Stage2 function (called from both BIOS and UEFI) */
void stage2_main(struct stage2_context *ctx);

/* BootInfo construction */
struct boot_info *stage2_build_bootinfo(struct stage2_context *ctx);

#endif /* SALTYOS_STAGE2_STAGE2_H */
