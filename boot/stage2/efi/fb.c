/* SaltyOS Stage 2 EFI Framebuffer
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Framebuffer information from EFI Graphics Output Protocol
 */

#include "efi.h"
#include "../common/stage2.h"
#include <types.h>

/* EFI system table pointer (set by entry point) */
static EFI_SYSTEM_TABLE *g_st = NULL;

/* Graphics Output Protocol GUID */
static EFI_GUID gop_guid = EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID;

/* Get framebuffer info from EFI */
struct framebuffer_info efi_get_framebuffer(void) {
    struct framebuffer_info fb = {0};
    EFI_STATUS status;
    EFI_GRAPHICS_OUTPUT_PROTOCOL *gop;

    /* Locate Graphics Output Protocol */
    status = g_st->boot_services->locate_protocol(
        &gop_guid,
        NULL,
        (void **)&gop
    );
    if (status != EFI_SUCCESS) {
        return fb;
    }

    /* Use current mode */
    EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE *mode = gop->mode;
    if (mode && mode->info) {
        fb.addr = mode->frame_buffer_base;
        fb.width = mode->info->horizontal_resolution;
        fb.height = mode->info->vertical_resolution;
        fb.pitch = mode->info->pixels_per_scan_line * 4;  /* Assuming 32bpp */
        fb.bpp = 32;
    }

    return fb;
}

/* Initialize EFI context for framebuffer operations */
void efi_fb_init(EFI_SYSTEM_TABLE *st) {
    g_st = st;
}

/* Get framebuffer callback for stage2 context */
static struct framebuffer_info efi_get_framebuffer_callback(void) {
    return efi_get_framebuffer();
}

/* Get framebuffer callback function */
struct framebuffer_info (*efi_get_framebuffer_fn_ptr)(void) = efi_get_framebuffer_callback;

