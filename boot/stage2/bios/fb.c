/* SaltyOS Stage 2 BIOS Framebuffer
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * VBE 2.0+ framebuffer support for BIOS
 */

#include "../common/stage2.h"
#include "../../common/types.h"

/* External assembly helper for VBE calls */
extern uint64_t bios_get_vbe_framebuffer(struct framebuffer_info *fb);

/* Static framebuffer info in low memory (must be < 1MB) */
static struct framebuffer_info fb_struct __attribute__((section(".lowmem"))) = {0};

/* Get framebuffer info using VBE BIOS interrupt via assembly helper */
struct framebuffer_info bios_get_framebuffer(void) {
    /* Call assembly helper to get VBE framebuffer */
    uint64_t result = bios_get_vbe_framebuffer(&fb_struct);

    /* If result is 0, no framebuffer available (text mode) */
    if (result == 0) {
        fb_struct.addr = 0;
        fb_struct.width = 0;
        fb_struct.height = 0;
        fb_struct.pitch = 0;
        fb_struct.bpp = 0;
    }

    return fb_struct;
}
