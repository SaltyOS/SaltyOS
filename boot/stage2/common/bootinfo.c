/* SaltyOS Stage 2 BootInfo Construction
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Build BootInfo structure for kernel handoff
 */

#include "stage2.h"
#include "../../common/types.h"

/* Simple memory allocation */
static void *boot_alloc(uint64_t size) {
    static uint8_t boot_heap[0x10000];  /* 64KB boot heap */
    static uint64_t offset = 0;

    void *ptr = &boot_heap[offset];
    offset += size;
    offset = (offset + 7) & ~7ULL;  /* Align to 8 bytes */
    return ptr;
}

/* Simple memset */
static void memset_local(void *s, int c, uint64_t n) {
    uint8_t *p = s;
    while (n--) *p++ = (uint8_t)c;
}

/* Build BootInfo structure */
struct boot_info *stage2_build_bootinfo(struct stage2_context *ctx) {
    struct boot_info *bi = boot_alloc(sizeof(struct boot_info));

    memset_local(bi, 0, sizeof(struct boot_info));

    bi->magic = BOOT_INFO_MAGIC;
    bi->kernel_phys_base = ctx->kernel_phys_base;
    bi->kernel_virt_base = ctx->kernel_virt_base;

    /* Provide kernel ELF buffer via initrd fields (temporary handoff) */
    bi->initrd_addr = (uint64_t)ctx->kernel_buffer;
    bi->initrd_size = ctx->kernel_size;

    /* Pass loaded kernel ELF buffer address/size via initrd fields for now */
    bi->initrd_addr = (uint64_t)ctx->kernel_buffer;
    bi->initrd_size = ctx->kernel_size;

    /* Get memory map from platform */
    if (ctx->get_memory_map) {
        ctx->get_memory_map(&bi->memory_map, &bi->memory_map_len);
    }

    /* Get RSDP from platform */
    if (ctx->get_rsdp) {
        bi->rsdp_addr = ctx->get_rsdp();
    }

    /* Get framebuffer from platform */
    if (ctx->get_framebuffer) {
        bi->framebuffer = ctx->get_framebuffer();
    }

    /* TODO: initrd, cmdline */

    return bi;
}
