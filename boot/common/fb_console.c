/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SaltyOS Bootloader - Framebuffer Text Console Implementation
 *
 * Renders text onto a 32bpp linear framebuffer using an 8x16 bitmap font.
 */

#include "fb_console.h"
#include "font_8x16.h"
#include "string.h"

/* Console state */
static uint8_t *fb_base;
static uint32_t fb_width;
static uint32_t fb_height;
static uint32_t fb_pitch;
static uint32_t fb_col;
static uint32_t fb_row;
static uint32_t fb_max_cols;
static uint32_t fb_max_rows;
static uint32_t fb_fg_color;
static uint32_t fb_bg_color;
static int      fb_ready;

/* Pack an RGB color using the framebuffer's channel positions */
static uint32_t pack_color(uint8_t r, uint8_t g, uint8_t b,
                           uint8_t red_pos, uint8_t green_pos, uint8_t blue_pos)
{
    return ((uint32_t)r << red_pos) |
           ((uint32_t)g << green_pos) |
           ((uint32_t)b << blue_pos);
}

/* Draw a single glyph at character grid position (col, row) */
static void draw_glyph(uint8_t c, uint32_t col, uint32_t row)
{
    const uint8_t *glyph = &font_8x16_data[(uint32_t)c * FONT_GLYPH_HEIGHT];
    uint32_t px_x = col * FONT_GLYPH_WIDTH;
    uint32_t px_y = row * FONT_GLYPH_HEIGHT;
    uint32_t y, bit;

    for (y = 0; y < FONT_GLYPH_HEIGHT; y++) {
        uint8_t row_bits = glyph[y];
        uint32_t *pixel = (uint32_t *)(fb_base + (px_y + y) * fb_pitch + px_x * 4);

        for (bit = 0; bit < FONT_GLYPH_WIDTH; bit++) {
            /* MSB = leftmost pixel */
            pixel[bit] = (row_bits & (0x80 >> bit)) ? fb_fg_color : fb_bg_color;
        }
    }
}

/* Scroll the screen up by one text row (FONT_GLYPH_HEIGHT pixels) */
static void scroll_up(void)
{
    uint32_t row_bytes = FONT_GLYPH_HEIGHT * fb_pitch;
    uint32_t total_bytes = (fb_height - FONT_GLYPH_HEIGHT) * fb_pitch;
    uint32_t x;

    /* Move all rows up by one glyph height */
    memmove(fb_base, fb_base + row_bytes, total_bytes);

    /* Clear the last text row with background color */
    {
        uint32_t clear_y;
        uint32_t clear_start = fb_height - FONT_GLYPH_HEIGHT;

        for (clear_y = clear_start; clear_y < fb_height; clear_y++) {
            uint32_t *row_ptr = (uint32_t *)(fb_base + clear_y * fb_pitch);
            for (x = 0; x < fb_width; x++) {
                row_ptr[x] = fb_bg_color;
            }
        }
    }

    fb_row = fb_max_rows - 1;
}

void fb_console_init(uint64_t fb_addr, uint32_t width, uint32_t height,
                     uint32_t pitch, uint32_t bpp,
                     uint8_t red_pos, uint8_t green_pos, uint8_t blue_pos)
{
    if (fb_addr == 0 || width == 0 || height == 0 || bpp != 32)
        return;

    /*
     * BIOS stage 3 is 32-bit: VBE framebuffer is always below 4GB.
     * UEFI stage 3 is 64-bit: use address directly.
     */
    fb_base = (uint8_t *)(uintptr_t)fb_addr;
    fb_width = width;
    fb_height = height;
    fb_pitch = pitch;
    fb_col = 0;
    fb_row = 0;
    fb_max_cols = width / FONT_GLYPH_WIDTH;
    fb_max_rows = height / FONT_GLYPH_HEIGHT;

    /* Light gray text (#C0C0C0) on black background (#000000) */
    fb_fg_color = pack_color(0xC0, 0xC0, 0xC0, red_pos, green_pos, blue_pos);
    fb_bg_color = pack_color(0x00, 0x00, 0x00, red_pos, green_pos, blue_pos);

    fb_console_clear();
    fb_ready = 1;
}

void fb_console_putc(char c)
{
    if (!fb_ready)
        return;

    if (c == '\n') {
        fb_col = 0;
        fb_row++;
    } else if (c == '\r') {
        fb_col = 0;
    } else if (c == '\t') {
        fb_col = (fb_col + 8) & ~7u;
    } else {
        draw_glyph((uint8_t)c, fb_col, fb_row);
        fb_col++;
    }

    if (fb_col >= fb_max_cols) {
        fb_col = 0;
        fb_row++;
    }

    if (fb_row >= fb_max_rows) {
        scroll_up();
    }
}

void fb_console_clear(void)
{
    uint32_t y, x;

    if (!fb_base)
        return;

    for (y = 0; y < fb_height; y++) {
        uint32_t *row_ptr = (uint32_t *)(fb_base + y * fb_pitch);
        for (x = 0; x < fb_width; x++) {
            row_ptr[x] = fb_bg_color;
        }
    }

    fb_col = 0;
    fb_row = 0;
}
