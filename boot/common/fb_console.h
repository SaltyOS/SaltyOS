/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SaltyOS Bootloader - Framebuffer Text Console
 *
 * Renders text to a linear framebuffer using an 8x16 bitmap font.
 */

#ifndef BOOT_COMMON_FB_CONSOLE_H
#define BOOT_COMMON_FB_CONSOLE_H

#include "types.h"

/*
 * Initialize the framebuffer console.
 *
 * Must be called before fb_console_putc(). Parameters come from
 * Stage2Info framebuffer fields (VBE or UEFI GOP).
 *
 * fb_addr:   Physical address of the linear framebuffer
 * width:     Horizontal resolution in pixels
 * height:    Vertical resolution in pixels
 * pitch:     Bytes per scanline
 * bpp:       Bits per pixel (must be 32)
 * red_pos:   Bit position of the red channel
 * green_pos: Bit position of the green channel
 * blue_pos:  Bit position of the blue channel
 */
void fb_console_init(uint64_t fb_addr, uint32_t width, uint32_t height,
                     uint32_t pitch, uint32_t bpp, uint8_t red_pos,
                     uint8_t green_pos, uint8_t blue_pos);

/* Output a single character to the framebuffer console */
void fb_console_putc(char c);

/* Clear the framebuffer screen */
void fb_console_clear(void);

#endif /* BOOT_COMMON_FB_CONSOLE_H */
