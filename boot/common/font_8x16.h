/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SaltyOS Bootloader - VGA 8x16 Bitmap Font
 *
 * 256 glyphs, 16 bytes per glyph (1 byte per row, MSB = leftmost pixel).
 */

#ifndef BOOT_COMMON_FONT_8X16_H
#define BOOT_COMMON_FONT_8X16_H

#include "types.h"

#define FONT_GLYPH_WIDTH 8
#define FONT_GLYPH_HEIGHT 16

extern const uint8_t font_8x16_data[4096]; /* 256 glyphs * 16 bytes */

#endif /* BOOT_COMMON_FONT_8X16_H */
