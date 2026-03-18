//! SaltyOS Display Server
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Framebuffer display server. Maps the physical framebuffer with
//! write-combining, maintains a shadow buffer for rendering, and
//! serves display requests via IPC.

#![no_std]
#![no_main]

extern crate besalt;

mod font;
mod vt100;

use besalt::consts::*;
use besalt::framebuffer;
use besalt::invoke;
use besalt::ipc;
use besalt::serial;
use besalt::serial::LineBuf;
use besalt::syscall::syscall;
use besalt::types::*;

const IPC_BUF_VADDR: u64 = 0x0000_0000_0020_0000;
const FB_MAP_VADDR: u64 = 0x0000_0000_3000_0000;
const MAX_DAMAGE_SCANLINES: usize = 8192;
const DAMAGE_WORD_BITS: usize = 64;
const DAMAGE_WORDS: usize = MAX_DAMAGE_SCANLINES / DAMAGE_WORD_BITS;

// slot 3 is kept as procmgr EP for slot_alloc expansion; display service EP is separate.
const CAP_SELF_TCB: u64 = 0;
const CAP_SELF_VSPACE: u64 = 1;
const CAP_NAMESERV_EP: u64 = 5;   // Standard well-known slot (consts::CAP_NAMESERV_EP)
const CAP_MMSRV_EP: u64 = 7;
const CAP_FB_UNTYPED: u64 = 13;   // Standard well-known slot (consts::CAP_FB_UNTYPED)
const CAP_READINESS_NTFN: u64 = 14;
const CAP_SERVER_EP: u64 = 68;    // Pre-created display service EP (injected by procmgr)
const TERMINAL_BATCH_TIMEOUT_NS: u64 = 1_000_000;

struct DisplayState {
    vram: *mut u8,
    shadow: *mut u8,
    width: u32,
    height: u32,
    pitch: u32,
    bpp: u8,
    red_pos: u8,
    green_pos: u8,
    blue_pos: u8,
    red_size: u8,
    green_size: u8,
    blue_size: u8,
    text_col: u32,
    text_row: u32,
    max_cols: u32,
    max_rows: u32,
    scroll_top: u32,
    scroll_bottom: u32,
    fg: u32,
    bg: u32,
    default_fg: u32,
    default_bg: u32,
    cursor_visible: bool,
    cursor_drawn: bool,
    drawn_col: u32,
    drawn_row: u32,
    saved_col: u32,
    saved_row: u32,
    saved_fg: u32,
    saved_bg: u32,
    bold: bool,
    reverse_video: bool,
    saved_bold: bool,
    saved_reverse: bool,
    pending_wrap: bool,
    autowrap: bool,
    vt_state: vt100::VtState,
    csi_parser: vt100::CsiParser,
    damage_min_y: u32,
    damage_max_y: u32,
    damage_rows: [u64; DAMAGE_WORDS],
    // Alternate screen buffer
    alt_shadow: *mut u8,
    alt_active: bool,
    // Saved primary screen state (restored when leaving alt screen)
    primary_col: u32,
    primary_row: u32,
    primary_fg: u32,
    primary_bg: u32,
    primary_scroll_top: u32,
    primary_scroll_bottom: u32,
    // Character sets: 0=ASCII(B), 1=DecGraphics(0), 2=UK(A)
    g0_charset: u8,
    g1_charset: u8,
    active_charset: u8, // 0=G0, 1=G1 (toggled by SO/SI)
    esc_intermediate: u8, // Tracks '(', ')', '*', '+', '#' for EscapeIntermediate state
    // Saved charset state for DECSC/DECRC
    saved_g0_charset: u8,
    saved_g1_charset: u8,
    saved_active_charset: u8,
    // SGR attributes
    dim: bool,
    underline: bool,
    italic: bool,
    blink: bool,
    hidden: bool,
    strikethrough: bool,
    // Saved SGR attributes for DECSC/DECRC
    saved_dim: bool,
    saved_underline: bool,
    // DEC modes
    origin_mode: bool,
    screen_reverse: bool,
    // Tab stops (bitmask — bit N = tab stop at column N, supports up to 128 cols)
    tab_stops: u128,
    // OSC/DCS parsing
    osc_saw_esc: bool,
    // REP support
    last_printed_char: u8,
    // Cell buffer for character-level storage (enables DECSCNM repaint)
    cells: *mut Cell,
    alt_cells: *mut Cell,
}

/// Per-cell storage for character-level terminal state.
/// Enables full-screen repaint when DECSCNM (reverse video mode) toggles.
#[repr(C)]
#[derive(Clone, Copy)]
struct Cell {
    ch: u8,
    charset: u8, // 0=ASCII, 1=DEC Graphics
    flags: u8,   // bit 0=bold, 1=reverse, 2=dim, 3=underline, 4=italic, 5=hidden, 6=strikethrough
    _pad: u8,
    fg: u32,
    bg: u32,
}

impl Cell {
    const fn blank(fg: u32, bg: u32) -> Self {
        Cell { ch: b' ', charset: 0, flags: 0, _pad: 0, fg, bg }
    }
}

fn cell_idx(state: &DisplayState, col: u32, row: u32) -> usize {
    (row * state.max_cols + col) as usize
}

fn cell_put(state: &mut DisplayState, col: u32, row: u32, ch: u8) {
    if col >= state.max_cols || row >= state.max_rows || state.cells.is_null() {
        return;
    }
    let charset_id = if state.active_charset == 0 { state.g0_charset } else { state.g1_charset };
    let flags = (state.bold as u8)
        | ((state.reverse_video as u8) << 1)
        | ((state.dim as u8) << 2)
        | ((state.underline as u8) << 3)
        | ((state.italic as u8) << 4)
        | ((state.hidden as u8) << 5)
        | ((state.strikethrough as u8) << 6);
    let idx = cell_idx(state, col, row);
    // SAFETY: cells buffer is allocated with max_cols * max_rows entries.
    unsafe {
        *state.cells.add(idx) = Cell { ch, charset: charset_id, flags, _pad: 0, fg: state.fg, bg: state.bg };
    }
}

fn cell_clear(state: &mut DisplayState, col: u32, row: u32) {
    if col >= state.max_cols || row >= state.max_rows || state.cells.is_null() {
        return;
    }
    let bg = effective_bg(state);
    let idx = cell_idx(state, col, row);
    // SAFETY: cells buffer is allocated with max_cols * max_rows entries.
    unsafe {
        *state.cells.add(idx) = Cell::blank(state.fg, bg);
    }
}

fn cell_clear_range(state: &mut DisplayState, col_start: u32, col_end: u32, row: u32) {
    if state.cells.is_null() || row >= state.max_rows {
        return;
    }
    let end = if col_end > state.max_cols { state.max_cols } else { col_end };
    let bg = effective_bg(state);
    for col in col_start..end {
        let idx = cell_idx(state, col, row);
        // SAFETY: cells buffer is allocated with max_cols * max_rows entries.
        unsafe {
            *state.cells.add(idx) = Cell::blank(state.fg, bg);
        }
    }
}

fn cell_clear_rows(state: &mut DisplayState, row_start: u32, row_end: u32) {
    if state.cells.is_null() {
        return;
    }
    let end = if row_end > state.max_rows { state.max_rows } else { row_end };
    let bg = effective_bg(state);
    let cols = state.max_cols;
    for row in row_start..end {
        for col in 0..cols {
            let idx = cell_idx(state, col, row);
            // SAFETY: cells buffer is allocated with max_cols * max_rows entries.
            unsafe {
                *state.cells.add(idx) = Cell::blank(state.fg, bg);
            }
        }
    }
}

fn puts(s: &[u8]) {
    serial::serial_puts(s);
}

fn idle() -> ! {
    loop {
        syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
    }
}

fn ipc_ctx() -> *mut IpcContext {
    &raw mut besalt::__besalt_ipc_ctx
}

unsafe fn recv_timed_ctx(
    ctx: *mut IpcContext,
    ep: Cap,
    timeout_ns: u64,
    msg: *mut BesaltMsg,
    badge: *mut u64,
) -> i32 {
    let r = syscall(SYS_RECV_TIMED, ep, timeout_ns, 0, 0, 0, 0);
    if r.error == 0 {
        unsafe {
            if !badge.is_null() {
                *badge = r.value;
            }
            if !msg.is_null() && !ctx.is_null() && !(*ctx).ipc_buffer.is_null() {
                let buf = (*ctx).ipc_buffer as *const BesaltMsg;
                *msg = *buf;
            }
        }
    }
    r.error as i32
}

fn signal_ready() {
    let _ = syscall(SYS_SIGNAL, CAP_READINESS_NTFN, 1, 0, 0, 0, 0);
}

fn pack_color(r: u8, g: u8, b: u8, rp: u8, gp: u8, bp: u8) -> u32 {
    ((r as u32) << rp) | ((g as u32) << gp) | ((b as u32) << bp)
}

fn mark_damage(state: &mut DisplayState, y_start: u32, y_end: u32) {
    let start = if y_start > state.height { state.height } else { y_start };
    let end = if y_end > state.height { state.height } else { y_end };
    if start >= end {
        return;
    }
    if start < state.damage_min_y {
        state.damage_min_y = start;
    }
    if end > state.damage_max_y {
        state.damage_max_y = end;
    }

    let mut row = start as usize;
    let end_row = end as usize;
    while row < end_row && row < MAX_DAMAGE_SCANLINES {
        let word = row / DAMAGE_WORD_BITS;
        let bit = row % DAMAGE_WORD_BITS;
        state.damage_rows[word] |= 1u64 << bit;
        row += 1;
    }
}

/// XOR-invert a glyph cell in the shadow buffer for cursor display.
fn invert_cursor_cell(state: &mut DisplayState, col: u32, row: u32) {
    let gw = font::GLYPH_WIDTH;
    let gh = font::GLYPH_HEIGHT;
    let px = col * gw;
    let py = row * gh;
    if px + gw > state.width || py + gh > state.height {
        return;
    }
    let pitch = state.pitch as usize;
    let bpp_bytes = (state.bpp / 8) as usize;
    for gy in 0..gh as usize {
        let y_off = (py as usize + gy) * pitch;
        for gx in 0..gw as usize {
            let off = y_off + (px as usize + gx) * bpp_bytes;
            // SAFETY: Bounds checked above, shadow buffer is mapped.
            unsafe {
                let dst = state.shadow.add(off);
                let val = read_pixel(dst, bpp_bytes);
                write_pixel(dst, val ^ 0x00FF_FFFF, bpp_bytes);
            }
        }
    }
    mark_damage(state, py, py + gh);
}

/// Re-render every cell from the cell buffer into the shadow buffer.
/// Called when DECSCNM toggles so that `effective_fg`/`effective_bg` pick up
/// the new `screen_reverse` flag and every glyph gets redrawn with correct colors.
fn repaint_all_cells(state: &mut DisplayState) {
    if state.cells.is_null() {
        return;
    }
    // Save current SGR/charset state
    let saved_fg = state.fg;
    let saved_bg = state.bg;
    let saved_bold = state.bold;
    let saved_reverse = state.reverse_video;
    let saved_dim = state.dim;
    let saved_underline = state.underline;
    let saved_italic = state.italic;
    let saved_hidden = state.hidden;
    let saved_strikethrough = state.strikethrough;
    let saved_active_charset = state.active_charset;
    let saved_g0 = state.g0_charset;
    let saved_g1 = state.g1_charset;

    for row in 0..state.max_rows {
        for col in 0..state.max_cols {
            // SAFETY: cells buffer is allocated with max_cols * max_rows entries.
            let cell = unsafe { *state.cells.add(cell_idx(state, col, row)) };

            // Temporarily apply cell's stored attributes
            state.fg = cell.fg;
            state.bg = cell.bg;
            state.bold = cell.flags & 0x01 != 0;
            state.reverse_video = cell.flags & 0x02 != 0;
            state.dim = cell.flags & 0x04 != 0;
            state.underline = cell.flags & 0x08 != 0;
            state.italic = cell.flags & 0x10 != 0;
            state.hidden = cell.flags & 0x20 != 0;
            state.strikethrough = cell.flags & 0x40 != 0;
            state.g0_charset = cell.charset;
            state.active_charset = 0;

            render_glyph_pixels(state, cell.ch, col, row);
        }
    }

    // Restore saved state
    state.fg = saved_fg;
    state.bg = saved_bg;
    state.bold = saved_bold;
    state.reverse_video = saved_reverse;
    state.dim = saved_dim;
    state.underline = saved_underline;
    state.italic = saved_italic;
    state.hidden = saved_hidden;
    state.strikethrough = saved_strikethrough;
    state.active_charset = saved_active_charset;
    state.g0_charset = saved_g0;
    state.g1_charset = saved_g1;

    mark_damage(state, 0, state.height);
}

fn flush_damage(state: &mut DisplayState) {
    // Erase previously drawn cursor (un-invert)
    if state.cursor_drawn {
        invert_cursor_cell(state, state.drawn_col, state.drawn_row);
        state.cursor_drawn = false;
    }

    // Draw new cursor (invert)
    if state.cursor_visible {
        invert_cursor_cell(state, state.text_col, state.text_row);
        state.cursor_drawn = true;
        state.drawn_col = state.text_col;
        state.drawn_row = state.text_row;
    }

    if state.damage_min_y >= state.damage_max_y {
        return;
    }
    let min_y = state.damage_min_y;
    let max_y = if state.damage_max_y > state.height {
        state.height
    } else {
        state.damage_max_y
    };
    let pitch = state.pitch as usize;
    let mut row = min_y as usize;
    let max_row = max_y as usize;
    while row < max_row && row < MAX_DAMAGE_SCANLINES {
        let word = row / DAMAGE_WORD_BITS;
        let bit = row % DAMAGE_WORD_BITS;
        if (state.damage_rows[word] & (1u64 << bit)) == 0 {
            row += 1;
            continue;
        }

        let run_start = row;
        row += 1;
        while row < max_row && row < MAX_DAMAGE_SCANLINES {
            let word = row / DAMAGE_WORD_BITS;
            let bit = row % DAMAGE_WORD_BITS;
            if (state.damage_rows[word] & (1u64 << bit)) == 0 {
                break;
            }
            row += 1;
        }

        let start_offset = run_start * pitch;
        let len = (row - run_start) * pitch;
        // SAFETY: Both shadow and vram are mapped with sufficient size.
        unsafe {
            core::ptr::copy_nonoverlapping(
                state.shadow.add(start_offset),
                state.vram.add(start_offset),
                len,
            );
        }
    }

    let mut clear_row = min_y as usize;
    while clear_row < max_row && clear_row < MAX_DAMAGE_SCANLINES {
        let word = clear_row / DAMAGE_WORD_BITS;
        let bit = clear_row % DAMAGE_WORD_BITS;
        state.damage_rows[word] &= !(1u64 << bit);
        clear_row += 1;
    }
    state.damage_min_y = state.height;
    state.damage_max_y = 0;
}

#[inline(always)]
unsafe fn write_pixel(dst: *mut u8, pixel: u32, bpp_bytes: usize) {
    unsafe {
        match bpp_bytes {
            4 => core::ptr::write(dst as *mut u32, pixel),
            3 => {
                *dst = pixel as u8;
                *dst.add(1) = (pixel >> 8) as u8;
                *dst.add(2) = (pixel >> 16) as u8;
            }
            2 => core::ptr::write(dst as *mut u16, pixel as u16),
            _ => core::ptr::write(dst as *mut u32, pixel),
        }
    }
}

#[inline(always)]
unsafe fn read_pixel(src: *const u8, bpp_bytes: usize) -> u32 {
    unsafe {
        match bpp_bytes {
            4 => core::ptr::read(src as *const u32),
            3 => {
                (*src as u32) | ((*src.add(1) as u32) << 8) | ((*src.add(2) as u32) << 16)
            }
            2 => core::ptr::read(src as *const u16) as u32,
            _ => core::ptr::read(src as *const u32),
        }
    }
}

fn effective_fg(state: &DisplayState) -> u32 {
    if state.hidden {
        return effective_bg(state);
    }
    let fg = if state.reverse_video != state.screen_reverse {
        state.bg
    } else {
        state.fg
    };
    if state.dim {
        // Halve each RGB channel for dim effect
        let r = (fg >> 16) & 0xFF;
        let g = (fg >> 8) & 0xFF;
        let b = fg & 0xFF;
        ((r >> 1) << 16) | ((g >> 1) << 8) | (b >> 1)
    } else {
        fg
    }
}

fn effective_bg(state: &DisplayState) -> u32 {
    if state.reverse_video != state.screen_reverse {
        state.fg
    } else {
        state.bg
    }
}

/// Render a glyph's pixels into the shadow buffer without updating the cell buffer.
/// Used by both `draw_glyph` (normal rendering) and `repaint_all_cells` (DECSCNM).
fn render_glyph_pixels(state: &mut DisplayState, c: u8, col: u32, row: u32) {
    let gw = font::GLYPH_WIDTH;
    let gh = font::GLYPH_HEIGHT;
    let px = col * gw;
    let py = row * gh;

    if px + gw > state.width || py + gh > state.height {
        return;
    }

    let fg = effective_fg(state);
    let bg = effective_bg(state);

    // Determine which charset is active and whether to use DEC graphics
    let charset_id = if state.active_charset == 0 {
        state.g0_charset
    } else {
        state.g1_charset
    };
    let use_dec_graphics = charset_id == 1 && c >= 0x60 && c <= 0x7E;

    let pitch = state.pitch as usize;
    let bpp_bytes = (state.bpp / 8) as usize;

    if use_dec_graphics {
        let glyph_offset = (c as usize - 0x60) * (gh as usize);
        for gy in 0..gh as usize {
            let row_bits = vt100::DEC_GRAPHICS_GLYPHS[glyph_offset + gy];
            let y_off = (py as usize + gy) * pitch;
            for gx in 0..gw as usize {
                let pixel = if (row_bits >> (7 - gx)) & 1 != 0 {
                    fg
                } else {
                    bg
                };
                let off = y_off + (px as usize + gx) * bpp_bytes;
                // SAFETY: Bounds checked above, shadow buffer is mapped.
                unsafe {
                    write_pixel(state.shadow.add(off), pixel, bpp_bytes);
                }
            }
        }
    } else {
        let glyph_offset = (c as usize) * (gh as usize);
        for gy in 0..gh as usize {
            let row_bits = font::FONT_DATA[glyph_offset + gy];
            let y_off = (py as usize + gy) * pitch;
            for gx in 0..gw as usize {
                let pixel = if (row_bits >> (7 - gx)) & 1 != 0 {
                    fg
                } else {
                    bg
                };
                let off = y_off + (px as usize + gx) * bpp_bytes;
                // SAFETY: Bounds checked above, shadow buffer is mapped.
                unsafe {
                    write_pixel(state.shadow.add(off), pixel, bpp_bytes);
                }
            }
        }
    }

    // Underline: draw solid fg line at scanline 14
    if state.underline {
        let y_off = (py as usize + 14) * pitch;
        for gx in 0..gw as usize {
            let off = y_off + (px as usize + gx) * bpp_bytes;
            // SAFETY: Bounds checked above, shadow buffer is mapped.
            unsafe {
                write_pixel(state.shadow.add(off), fg, bpp_bytes);
            }
        }
    }

    // Strikethrough: draw solid fg line at scanline 7
    if state.strikethrough {
        let y_off = (py as usize + 7) * pitch;
        for gx in 0..gw as usize {
            let off = y_off + (px as usize + gx) * bpp_bytes;
            // SAFETY: Bounds checked above, shadow buffer is mapped.
            unsafe {
                write_pixel(state.shadow.add(off), fg, bpp_bytes);
            }
        }
    }

    mark_damage(state, py, py + gh);
}

fn draw_glyph(state: &mut DisplayState, c: u8, col: u32, row: u32) {
    render_glyph_pixels(state, c, col, row);
    cell_put(state, col, row, c);
}

fn fill_rect(state: &mut DisplayState, x: u32, y: u32, w: u32, h: u32, color: u32) {
    let pitch = state.pitch as usize;
    let bpp_bytes = (state.bpp / 8) as usize;

    let x_end = if x + w > state.width { state.width } else { x + w };
    let y_end = if y + h > state.height { state.height } else { y + h };

    if x >= state.width || y >= state.height {
        return;
    }

    for row in y..y_end {
        let row_off = row as usize * pitch;
        for col in x..x_end {
            let off = row_off + col as usize * bpp_bytes;
            // SAFETY: Bounds checked above, shadow buffer is mapped.
            unsafe {
                write_pixel(state.shadow.add(off), color, bpp_bytes);
            }
        }
    }

    mark_damage(state, y, y_end);
}

fn scroll_up_region(state: &mut DisplayState, top: u32, bottom: u32) {
    let gh = font::GLYPH_HEIGHT;
    let row_bytes = gh as usize * state.pitch as usize;
    let rows = bottom - top;
    if rows <= 1 {
        return;
    }

    let src_y = (top + 1) as usize * row_bytes;
    let dst_y = top as usize * row_bytes;
    // SAFETY: shadow buffer covers the full framebuffer; ranges are within bounds.
    unsafe {
        core::ptr::copy(
            state.shadow.add(src_y),
            state.shadow.add(dst_y),
            (rows as usize - 1) * row_bytes,
        );
    }

    // Cell buffer: shift rows up
    if !state.cells.is_null() {
        let grid_cols = state.max_cols as usize;
        // SAFETY: cells buffer is allocated with max_cols * max_rows entries.
        unsafe {
            let src = state.cells.add(((top + 1) as usize) * grid_cols);
            let dst = state.cells.add((top as usize) * grid_cols);
            core::ptr::copy(src, dst, ((rows - 1) as usize) * grid_cols);
        }
    }

    let last_row_y = (bottom - 1) * gh;
    let bg = effective_bg(state);
    fill_rect(state, 0, last_row_y, state.width, gh, bg);
    cell_clear_range(state, 0, state.max_cols, bottom - 1);

    mark_damage(state, top * gh, bottom * gh);
}

fn scroll_up(state: &mut DisplayState) {
    let top = state.scroll_top;
    let bottom = state.scroll_bottom;
    scroll_up_region(state, top, bottom);
}

fn scroll_down_region(state: &mut DisplayState, top: u32, bottom: u32) {
    let gh = font::GLYPH_HEIGHT;
    let row_bytes = gh as usize * state.pitch as usize;
    let rows = bottom - top;
    if rows <= 1 {
        return;
    }

    let src_y = top as usize * row_bytes;
    let dst_y = (top + 1) as usize * row_bytes;
    // SAFETY: shadow buffer covers the full framebuffer; ranges are within bounds.
    unsafe {
        core::ptr::copy(
            state.shadow.add(src_y),
            state.shadow.add(dst_y),
            (rows as usize - 1) * row_bytes,
        );
    }

    // Cell buffer: shift rows down
    if !state.cells.is_null() {
        let grid_cols = state.max_cols as usize;
        // SAFETY: cells buffer is allocated with max_cols * max_rows entries.
        unsafe {
            let src = state.cells.add((top as usize) * grid_cols);
            let dst = state.cells.add(((top + 1) as usize) * grid_cols);
            core::ptr::copy(src, dst, ((rows - 1) as usize) * grid_cols);
        }
    }

    let clear_y = top * gh;
    let bg = effective_bg(state);
    fill_rect(state, 0, clear_y, state.width, gh, bg);
    cell_clear_range(state, 0, state.max_cols, top);

    mark_damage(state, top * gh, bottom * gh);
}

fn insert_lines(state: &mut DisplayState, at_row: u32, count: u32) {
    let gh = font::GLYPH_HEIGHT;
    let row_bytes = gh as usize * state.pitch as usize;
    let max = state.scroll_bottom;
    if at_row >= max {
        return;
    }
    let count = if at_row + count > max { max - at_row } else { count };
    let rows_to_move = max - at_row - count;
    if rows_to_move > 0 && count > 0 {
        let src_y = at_row as usize * row_bytes;
        let dst_y = (at_row + count) as usize * row_bytes;
        // SAFETY: shadow buffer covers the full framebuffer; ranges are within bounds.
        unsafe {
            core::ptr::copy(
                state.shadow.add(src_y),
                state.shadow.add(dst_y),
                rows_to_move as usize * row_bytes,
            );
        }
        // Cell buffer: shift rows down
        if !state.cells.is_null() {
            let grid_cols = state.max_cols as usize;
            // SAFETY: cells buffer is allocated with max_cols * max_rows entries.
            unsafe {
                let src = state.cells.add((at_row as usize) * grid_cols);
                let dst = state.cells.add(((at_row + count) as usize) * grid_cols);
                core::ptr::copy(src, dst, (rows_to_move as usize) * grid_cols);
            }
        }
    }
    let bg = effective_bg(state);
    for r in at_row..at_row + count {
        let y = r * gh;
        fill_rect(state, 0, y, state.width, gh, bg);
        cell_clear_range(state, 0, state.max_cols, r);
    }
    mark_damage(state, at_row * gh, max * gh);
}

fn delete_lines(state: &mut DisplayState, at_row: u32, count: u32) {
    let gh = font::GLYPH_HEIGHT;
    let row_bytes = gh as usize * state.pitch as usize;
    let max = state.scroll_bottom;
    if at_row >= max {
        return;
    }
    let count = if at_row + count > max { max - at_row } else { count };
    let rows_to_move = max - at_row - count;
    if rows_to_move > 0 && count > 0 {
        let src_y = (at_row + count) as usize * row_bytes;
        let dst_y = at_row as usize * row_bytes;
        // SAFETY: shadow buffer covers the full framebuffer; ranges are within bounds.
        unsafe {
            core::ptr::copy(
                state.shadow.add(src_y),
                state.shadow.add(dst_y),
                rows_to_move as usize * row_bytes,
            );
        }
        // Cell buffer: shift rows up
        if !state.cells.is_null() {
            let grid_cols = state.max_cols as usize;
            // SAFETY: cells buffer is allocated with max_cols * max_rows entries.
            unsafe {
                let src = state.cells.add(((at_row + count) as usize) * grid_cols);
                let dst = state.cells.add((at_row as usize) * grid_cols);
                core::ptr::copy(src, dst, (rows_to_move as usize) * grid_cols);
            }
        }
    }
    let clear_start = max - count;
    let bg = effective_bg(state);
    for r in clear_start..max {
        let y = r * gh;
        fill_rect(state, 0, y, state.width, gh, bg);
        cell_clear_range(state, 0, state.max_cols, r);
    }
    mark_damage(state, at_row * gh, max * gh);
}

fn insert_chars(state: &mut DisplayState, count: u32) {
    let gw = font::GLYPH_WIDTH;
    let gh = font::GLYPH_HEIGHT;
    let col = state.text_col;
    let row = state.text_row;
    let max_cols = state.max_cols;
    if col >= max_cols {
        return;
    }
    let count = if col + count > max_cols { max_cols - col } else { count };
    let chars_to_move = max_cols - col - count;

    let py = row * gh;
    let pitch = state.pitch as usize;
    let bpp_bytes = (state.bpp / 8) as usize;
    let char_bytes = gw as usize * bpp_bytes;

    if chars_to_move > 0 {
        let src_x = col as usize * char_bytes;
        let dst_x = (col + count) as usize * char_bytes;
        let move_bytes = chars_to_move as usize * char_bytes;
        for gy in 0..gh as usize {
            let row_off = (py as usize + gy) * pitch;
            // SAFETY: shadow buffer covers the full framebuffer; ranges are within bounds.
            unsafe {
                core::ptr::copy(
                    state.shadow.add(row_off + src_x),
                    state.shadow.add(row_off + dst_x),
                    move_bytes,
                );
            }
        }
        // Cell buffer: shift cells right
        if !state.cells.is_null() {
            // SAFETY: cells buffer is allocated with max_cols * max_rows entries.
            unsafe {
                let src = state.cells.add(cell_idx(state, col, row));
                let dst = state.cells.add(cell_idx(state, col + count, row));
                core::ptr::copy(src, dst, chars_to_move as usize);
            }
        }
    }

    let bg = effective_bg(state);
    let fill_x = col * gw;
    fill_rect(state, fill_x, py, count * gw, gh, bg);
    cell_clear_range(state, col, col + count, row);
}

fn delete_chars(state: &mut DisplayState, count: u32) {
    let gw = font::GLYPH_WIDTH;
    let gh = font::GLYPH_HEIGHT;
    let col = state.text_col;
    let row = state.text_row;
    let max_cols = state.max_cols;
    if col >= max_cols {
        return;
    }
    let count = if col + count > max_cols { max_cols - col } else { count };
    let chars_to_move = max_cols - col - count;

    let py = row * gh;
    let pitch = state.pitch as usize;
    let bpp_bytes = (state.bpp / 8) as usize;
    let char_bytes = gw as usize * bpp_bytes;

    if chars_to_move > 0 {
        let src_x = (col + count) as usize * char_bytes;
        let dst_x = col as usize * char_bytes;
        let move_bytes = chars_to_move as usize * char_bytes;
        for gy in 0..gh as usize {
            let row_off = (py as usize + gy) * pitch;
            // SAFETY: shadow buffer covers the full framebuffer; ranges are within bounds.
            unsafe {
                core::ptr::copy(
                    state.shadow.add(row_off + src_x),
                    state.shadow.add(row_off + dst_x),
                    move_bytes,
                );
            }
        }
        // Cell buffer: shift cells left
        if !state.cells.is_null() {
            // SAFETY: cells buffer is allocated with max_cols * max_rows entries.
            unsafe {
                let src = state.cells.add(cell_idx(state, col + count, row));
                let dst = state.cells.add(cell_idx(state, col, row));
                core::ptr::copy(src, dst, chars_to_move as usize);
            }
        }
    }

    let bg = effective_bg(state);
    let clear_start = (max_cols - count) * gw;
    fill_rect(state, clear_start, py, count * gw, gh, bg);
    cell_clear_range(state, max_cols - count, max_cols, row);
}

fn erase_chars(state: &mut DisplayState, count: u32) {
    let gw = font::GLYPH_WIDTH;
    let gh = font::GLYPH_HEIGHT;
    let col = state.text_col;
    let row = state.text_row;
    let max_cols = state.max_cols;
    if col >= max_cols {
        return;
    }
    let count = if col + count > max_cols { max_cols - col } else { count };
    let bg = effective_bg(state);
    let px = col * gw;
    let py = row * gh;
    fill_rect(state, px, py, count * gw, gh, bg);
    cell_clear_range(state, col, col + count, row);
}

fn switch_to_alt_screen(state: &mut DisplayState) {
    if state.alt_active {
        return;
    }

    let fb_size = state.height as u64 * state.pitch as u64;

    // Lazy-allocate alt buffer
    if state.alt_shadow.is_null() {
        let ptr = unsafe {
            besalt::posix_mm::posix_mmap(
                core::ptr::null_mut(),
                (fb_size + 4095) & !4095u64,
                0x3,  // PROT_READ | PROT_WRITE
                0x22, // MAP_PRIVATE | MAP_ANONYMOUS
                -1,
                0,
            )
        };
        if ptr == usize::MAX as *mut u8 || ptr.is_null() {
            return;
        }
        state.alt_shadow = ptr;
    }

    // Lazy-allocate alt cell buffer
    if !state.cells.is_null() && state.alt_cells.is_null() {
        let grid = (state.max_cols * state.max_rows) as usize;
        let cell_bytes = grid * core::mem::size_of::<Cell>();
        let cell_len = ((cell_bytes as u64) + 4095) & !4095u64;
        let ptr = unsafe {
            besalt::posix_mm::posix_mmap(
                core::ptr::null_mut(),
                cell_len,
                0x3,  // PROT_READ | PROT_WRITE
                0x22, // MAP_PRIVATE | MAP_ANONYMOUS
                -1,
                0,
            )
        };
        if ptr != usize::MAX as *mut u8 && !ptr.is_null() {
            state.alt_cells = ptr as *mut Cell;
        }
    }

    // Save primary state
    state.primary_col = state.text_col;
    state.primary_row = state.text_row;
    state.primary_fg = state.fg;
    state.primary_bg = state.bg;
    state.primary_scroll_top = state.scroll_top;
    state.primary_scroll_bottom = state.scroll_bottom;

    // Swap shadow buffers (save primary content into alt_shadow, then swap pointers)
    // SAFETY: Both buffers are valid and large enough.
    unsafe {
        core::ptr::copy_nonoverlapping(state.shadow, state.alt_shadow, fb_size as usize);
    }
    let tmp = state.shadow;
    state.shadow = state.alt_shadow;
    state.alt_shadow = tmp;

    // Swap cell buffers
    if !state.cells.is_null() && !state.alt_cells.is_null() {
        let grid = (state.max_cols * state.max_rows) as usize;
        // SAFETY: Both cell buffers are allocated with the same size.
        unsafe {
            core::ptr::copy_nonoverlapping(state.cells, state.alt_cells, grid);
        }
        let tmp = state.cells;
        state.cells = state.alt_cells;
        state.alt_cells = tmp;
    }

    state.alt_active = true;

    // Reset state for alt screen
    state.text_col = 0;
    state.text_row = 0;
    state.scroll_top = 0;
    state.scroll_bottom = state.max_rows;

    // Clear alt screen
    let w = state.width;
    let h = state.height;
    let bg = effective_bg(state);
    fill_rect(state, 0, 0, w, h, bg);
    cell_clear_rows(state, 0, state.max_rows);
    mark_damage(state, 0, h);
}

fn switch_to_primary_screen(state: &mut DisplayState) {
    if !state.alt_active {
        return;
    }

    // Swap back: alt_shadow currently holds primary content
    let tmp = state.shadow;
    state.shadow = state.alt_shadow;
    state.alt_shadow = tmp;

    // Swap cell buffers back
    if !state.cells.is_null() && !state.alt_cells.is_null() {
        let tmp = state.cells;
        state.cells = state.alt_cells;
        state.alt_cells = tmp;
    }

    state.alt_active = false;

    // Restore primary state
    state.text_col = state.primary_col;
    state.text_row = state.primary_row;
    state.fg = state.primary_fg;
    state.bg = state.primary_bg;
    state.scroll_top = state.primary_scroll_top;
    state.scroll_bottom = state.primary_scroll_bottom;

    mark_damage(state, 0, state.height);
}

fn advance_row(state: &mut DisplayState) {
    state.text_row += 1;
    if state.text_row >= state.scroll_bottom {
        state.text_row = state.scroll_bottom - 1;
        scroll_up(state);
    }
}

fn terminal_putc(state: &mut DisplayState, c: u8) {
    if c == b'\n' {
        // If pending_wrap, execute the deferred wrap first
        if state.pending_wrap {
            state.text_col = 0;
            advance_row(state);
            state.pending_wrap = false;
        }
        state.text_col = 0;
        advance_row(state);
        return;
    }
    if c == b'\r' {
        state.pending_wrap = false;
        state.text_col = 0;
        return;
    }
    if c == 0x08 {
        // Backspace
        state.pending_wrap = false;
        if state.text_col > 0 {
            state.text_col -= 1;
        }
        return;
    }
    if c == b'\t' {
        if state.pending_wrap {
            state.text_col = 0;
            advance_row(state);
            state.pending_wrap = false;
        }
        // Find next tab stop from bitmask
        let cur = state.text_col;
        let mut next = state.max_cols; // fallback: end of line
        {
            let mut col = cur + 1;
            while col < state.max_cols && col < 128 {
                if (state.tab_stops >> col) & 1 != 0 {
                    next = col;
                    break;
                }
                col += 1;
            }
        }
        let next = if next > state.max_cols { state.max_cols } else { next };
        while state.text_col < next {
            draw_glyph(state, b' ', state.text_col, state.text_row);
            state.text_col += 1;
        }
        if state.text_col >= state.max_cols {
            if state.autowrap {
                state.pending_wrap = true;
                state.text_col = state.max_cols - 1;
            } else {
                state.text_col = state.max_cols - 1;
            }
        }
        return;
    }

    // Printable character: execute deferred wrap if pending
    if state.pending_wrap {
        state.text_col = 0;
        advance_row(state);
        state.pending_wrap = false;
    }

    draw_glyph(state, c, state.text_col, state.text_row);
    state.text_col += 1;
    if state.text_col >= state.max_cols {
        if state.autowrap {
            // xenl: stay at last column, defer wrap to next printable char
            state.text_col = state.max_cols - 1;
            state.pending_wrap = true;
        } else {
            // No autowrap: stay at last column, overwrite in place
            state.text_col = state.max_cols - 1;
        }
    }
}

fn map_framebuffer(fb: &framebuffer::FramebufferInfo) -> bool {
    let fb_size = fb.height as u64 * fb.pitch as u64;
    let num_pages = (fb_size + 4095) / 4096;

    let map_flags = VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER | VSPACE_FLAG_WRITE_THROUGH;

    let (err, mapped) = invoke::vspace_map_device_range(
        CAP_SELF_VSPACE,
        CAP_FB_UNTYPED,
        0,
        FB_MAP_VADDR,
        num_pages,
        map_flags,
    );

    if err != 0 || mapped != num_pages {
        let mut lb = LineBuf::new();
        lb.str(b"[DISPLAY] FB batch map failed: err=");
        lb.hex(err as u64);
        lb.str(b" mapped=");
        lb.hex(mapped);
        lb.str(b"/");
        lb.hex(num_pages);
        lb.str(b"\n");
        lb.flush();
        return false;
    }

    {
        let mut lb = LineBuf::new();
        lb.str(b"[DISPLAY] Mapped ");
        lb.hex(num_pages);
        lb.str(b" FB pages at ");
        lb.hex(FB_MAP_VADDR);
        lb.str(b" (WC)\n");
        lb.flush();
    }

    true
}

fn alloc_shadow_buffer(fb_size: u64) -> *mut u8 {
    let len = (fb_size + 4095) & !4095u64;
    let ptr = unsafe {
        besalt::posix_mm::posix_mmap(
            core::ptr::null_mut(),
            len,
            0x3,  // PROT_READ | PROT_WRITE
            0x22, // MAP_PRIVATE | MAP_ANONYMOUS
            -1,
            0,
        )
    };
    if ptr == usize::MAX as *mut u8 || ptr.is_null() {
        serial::serial_puts(b"[DISPLAY] Shadow buffer posix_mmap failed\n");
        return core::ptr::null_mut();
    }

    {
        let mut lb = LineBuf::new();
        lb.str(b"[DISPLAY] Shadow buffer: ");
        lb.hex(len / 4096);
        lb.str(b" pages at ");
        lb.hex(ptr as u64);
        lb.str(b"\n");
        lb.flush();
    }

    ptr
}

fn register_with_nameserv() -> bool {
    let mut reg_msg = BesaltMsg::zeroed();
    let mut reg_reply = BesaltMsg::zeroed();
    let svc_name = b"display";
    reg_msg.label = POSIX_NS_REGISTER;
    reg_msg.regs[0] = svc_name.len() as u64;
    reg_msg.length = 1 + (svc_name.len() as u64 + 7) / 8;
    let ns_dst = &raw mut reg_msg.regs[1] as *mut u8;
    // SAFETY: Writing name bytes into message register area.
    unsafe {
        for i in 0..svc_name.len() {
            *ns_dst.add(i) = svc_name[i];
        }
    }

    unsafe {
        ipc::set_send_cap_ctx(ipc_ctx(), 0, CAP_SERVER_EP);
        let err = ipc::call_ctx(
            ipc_ctx(),
            CAP_NAMESERV_EP,
            &raw const reg_msg,
            &raw mut reg_reply,
        );
        if err == 0 && reg_reply.label == BESALT_OK {
            puts(b"[DISPLAY] registered with nameserv\n");
            return true;
        }
        let mut lb = LineBuf::new();
        lb.str(b"[DISPLAY] nameserv register failed: err=");
        lb.hex(err as u64);
        lb.str(b" label=");
        lb.hex(reg_reply.label);
        lb.str(b"\n");
        lb.flush();
        false
    }
}

fn handle_get_info(state: &DisplayState, reply: &mut BesaltMsg) {
    reply.label = BESALT_OK;
    reply.length = 6;
    reply.regs[0] = state.width as u64;
    reply.regs[1] = state.height as u64;
    reply.regs[2] = state.pitch as u64;
    reply.regs[3] = state.bpp as u64;
    reply.regs[4] = ((state.red_pos as u64) << 24)
        | ((state.red_size as u64) << 16)
        | ((state.green_pos as u64) << 8)
        | (state.green_size as u64);
    reply.regs[5] = ((state.blue_pos as u64) << 24) | ((state.blue_size as u64) << 16);
}

fn handle_fill_rect(state: &mut DisplayState, msg: &BesaltMsg, reply: &mut BesaltMsg) {
    if state.cursor_drawn {
        invert_cursor_cell(state, state.drawn_col, state.drawn_row);
        state.cursor_drawn = false;
    }

    let x = msg.regs[0] as u32;
    let y = msg.regs[1] as u32;
    let w = msg.regs[2] as u32;
    let h = msg.regs[3] as u32;
    let color = msg.regs[4] as u32;
    fill_rect(state, x, y, w, h, color);
    flush_damage(state);
    reply.label = BESALT_OK;
}

fn handle_write_text(state: &mut DisplayState, msg: &BesaltMsg, reply: &mut BesaltMsg) {
    if state.cursor_drawn {
        invert_cursor_cell(state, state.drawn_col, state.drawn_row);
        state.cursor_drawn = false;
    }

    let x_pixel = msg.regs[0] as u32;
    let y_pixel = msg.regs[1] as u32;
    let fg_color = msg.regs[2] as u32;
    let bg_color = msg.regs[3] as u32;
    let data_len = msg.regs[4] as usize;

    let saved_fg = state.fg;
    let saved_bg = state.bg;
    let saved_rv = state.reverse_video;
    state.fg = fg_color;
    state.bg = bg_color;
    state.reverse_video = false;

    let gw = font::GLYPH_WIDTH;
    let gh = font::GLYPH_HEIGHT;
    let col_start = x_pixel / gw;
    let row_start = y_pixel / gh;

    let text_ptr = &msg.regs[5] as *const u64 as *const u8;
    let max_bytes = if data_len > 120 { 120 } else { data_len };

    for i in 0..max_bytes {
        // SAFETY: Reading text bytes from message registers, bounded by max_bytes.
        let c = unsafe { *text_ptr.add(i) };
        let col = col_start + i as u32;
        if col < state.max_cols && row_start < state.max_rows {
            draw_glyph(state, c, col, row_start);
        }
    }

    state.fg = saved_fg;
    state.bg = saved_bg;
    state.reverse_video = saved_rv;
    flush_damage(state);
    reply.label = BESALT_OK;
}

fn handle_terminal_write(state: &mut DisplayState, msg: &BesaltMsg) {
    if state.cursor_drawn {
        invert_cursor_cell(state, state.drawn_col, state.drawn_row);
        state.cursor_drawn = false;
    }

    let data_len = msg.regs[0] as usize;
    let text_ptr = &msg.regs[1] as *const u64 as *const u8;
    let max_bytes = if data_len > 152 { 152 } else { data_len };

    for i in 0..max_bytes {
        // SAFETY: Reading text bytes from message registers, bounded by max_bytes.
        let c = unsafe { *text_ptr.add(i) };
        vt100::process_byte(state, c);
    }
}

fn handle_present(state: &mut DisplayState, reply: &mut BesaltMsg) {
    flush_damage(state);
    reply.label = BESALT_OK;
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    puts(b"[DISPLAY] Display server starting\n");

    // Set up IPC buffer
    unsafe {
        invoke::tcb_set_ipc_buffer(CAP_SELF_TCB, IPC_BUF_VADDR);
        ipc::ipc_context_init(ipc_ctx(), IPC_BUF_VADDR as *mut IpcBuffer);
    }

    // Initialize per-process slot allocator from RTLD-exported globals
    unsafe {
        let base = *(&raw const besalt::__besalt_slot_base);
        let count = *(&raw const besalt::__besalt_slot_count);
        let cspace_ntfn = *(&raw const besalt::__besalt_cspace_ntfn);
        if base != 0 {
            besalt::slot_alloc::slot_alloc_init(base, count, cspace_ntfn);
        } else {
            puts(b"[DISPLAY] FATAL: slot pool not provided by RTLD/auxv\n");
            signal_ready();
            idle();
        }
    }

    // Read framebuffer info from boot info page
    let fb = match unsafe { framebuffer::read_framebuffer_info() } {
        Some(fb) => fb,
        None => {
            puts(b"[DISPLAY] No framebuffer detected\n");
            signal_ready();
            idle();
        }
    };

    {
        let mut lb = LineBuf::new();
        lb.str(b"[DISPLAY] FB: ");
        lb.dec(fb.width as u64);
        lb.str(b"x");
        lb.dec(fb.height as u64);
        lb.str(b" bpp=");
        lb.dec(fb.bpp as u64);
        lb.str(b" pitch=");
        lb.dec(fb.pitch as u64);
        lb.str(b"\n");
        lb.flush();
    }

    // Initialize mmsrv client for posix_mmap
    unsafe {
        besalt::posix_mm::posix_mm_init(CAP_MMSRV_EP);
    }

    // Map framebuffer with write-combining (WRITE_THROUGH flag)
    if !map_framebuffer(&fb) {
        puts(b"[DISPLAY] Failed to map framebuffer\n");
        signal_ready();
        idle();
    }

    // Allocate shadow buffer via mmsrv
    let fb_size = fb.height as u64 * fb.pitch as u64;
    let shadow_ptr = alloc_shadow_buffer(fb_size);
    if shadow_ptr.is_null() {
        puts(b"[DISPLAY] Failed to allocate shadow buffer\n");
        signal_ready();
        idle();
    }

    // Copy current VRAM content into shadow buffer (preserve boot output)
    // SAFETY: Both VRAM and shadow are mapped with sufficient size.
    unsafe {
        core::ptr::copy_nonoverlapping(
            FB_MAP_VADDR as *const u8,
            shadow_ptr,
            fb_size as usize,
        );
    }

    let fg_val = pack_color(0xCC, 0xCC, 0xCC, fb.red_pos, fb.green_pos, fb.blue_pos);
    let bg_val = pack_color(0x00, 0x00, 0x00, fb.red_pos, fb.green_pos, fb.blue_pos);

    // Default tab stops: every 8th column
    let mut default_tabs: u128 = 0;
    let max_cols = fb.width / font::GLYPH_WIDTH;
    {
        let mut c = 0u32;
        while c < max_cols && c < 128 {
            default_tabs |= 1u128 << c;
            c += 8;
        }
    }

    let mut state = DisplayState {
        vram: FB_MAP_VADDR as *mut u8,
        shadow: shadow_ptr,
        width: fb.width,
        height: fb.height,
        pitch: fb.pitch,
        bpp: fb.bpp,
        red_pos: fb.red_pos,
        green_pos: fb.green_pos,
        blue_pos: fb.blue_pos,
        red_size: fb.red_size,
        green_size: fb.green_size,
        blue_size: fb.blue_size,
        text_col: 0,
        text_row: 0,
        max_cols,
        max_rows: fb.height / font::GLYPH_HEIGHT,
        scroll_top: 0,
        scroll_bottom: fb.height / font::GLYPH_HEIGHT,
        fg: fg_val,
        bg: bg_val,
        default_fg: fg_val,
        default_bg: bg_val,
        cursor_visible: true,
        cursor_drawn: false,
        drawn_col: 0,
        drawn_row: 0,
        saved_col: 0,
        saved_row: 0,
        saved_fg: fg_val,
        saved_bg: bg_val,
        bold: false,
        reverse_video: false,
        saved_bold: false,
        saved_reverse: false,
        pending_wrap: false,
        autowrap: true,
        vt_state: vt100::VtState::Normal,
        csi_parser: vt100::CsiParser::new(),
        damage_min_y: fb.height,
        damage_max_y: 0,
        damage_rows: [0; DAMAGE_WORDS],
        alt_shadow: core::ptr::null_mut(),
        alt_active: false,
        primary_col: 0,
        primary_row: 0,
        primary_fg: fg_val,
        primary_bg: bg_val,
        primary_scroll_top: 0,
        primary_scroll_bottom: fb.height / font::GLYPH_HEIGHT,
        g0_charset: 0,
        g1_charset: 0,
        active_charset: 0,
        esc_intermediate: 0,
        saved_g0_charset: 0,
        saved_g1_charset: 0,
        saved_active_charset: 0,
        dim: false,
        underline: false,
        italic: false,
        blink: false,
        hidden: false,
        strikethrough: false,
        saved_dim: false,
        saved_underline: false,
        origin_mode: false,
        screen_reverse: false,
        tab_stops: default_tabs,
        osc_saw_esc: false,
        last_printed_char: 0x20,
        cells: core::ptr::null_mut(),
        alt_cells: core::ptr::null_mut(),
    };

    // Disable kernel console so we own the framebuffer
    syscall(SYS_DEBUG_CONSOLE_CONTROL, 0, 0, 0, 0, 0, 0);
    puts(b"[DISPLAY] Kernel console disabled, display server owns FB\n");

    // Allocate cell buffer for character-level storage
    {
        let grid = (state.max_cols * state.max_rows) as usize;
        let cell_bytes = grid * core::mem::size_of::<Cell>();
        let cell_len = ((cell_bytes as u64) + 4095) & !4095u64;
        let ptr = unsafe {
            besalt::posix_mm::posix_mmap(
                core::ptr::null_mut(),
                cell_len,
                0x3,  // PROT_READ | PROT_WRITE
                0x22, // MAP_PRIVATE | MAP_ANONYMOUS
                -1,
                0,
            )
        };
        if ptr != usize::MAX as *mut u8 && !ptr.is_null() {
            state.cells = ptr as *mut Cell;
            // Initialize all cells to space with default colors
            for i in 0..grid {
                // SAFETY: Just-allocated buffer, i < grid.
                unsafe {
                    *state.cells.add(i) = Cell::blank(fg_val, bg_val);
                }
            }
        }
    }

    // Clear screen to background color for a clean terminal
    let w = state.width;
    let h = state.height;
    let bg = state.bg;
    fill_rect(&mut state, 0, 0, w, h, bg);
    flush_damage(&mut state);

    // Register with nameserv
    register_with_nameserv();

    // Signal readiness
    signal_ready();
    puts(b"[DISPLAY] Ready, entering server loop\n");

    // IPC server loop
    let mut msg = BesaltMsg::zeroed();
    let mut badge: u64 = 0;

    let err = unsafe { ipc::recv_ctx(ipc_ctx(), CAP_SERVER_EP, &raw mut msg, &raw mut badge) };
    if err != 0 {
        let mut lb = LineBuf::new();
        lb.str(b"[DISPLAY] initial recv failed err=");
        lb.hex(err as u64);
        lb.str(b"\n");
        lb.flush();
        idle();
    }

    loop {
        if msg.label == DISPLAY_TERMINAL_WRITE {
            loop {
                handle_terminal_write(&mut state, &msg);
                flush_damage(&mut state);

                let timed_err = unsafe {
                    recv_timed_ctx(
                        ipc_ctx(),
                        CAP_SERVER_EP,
                        TERMINAL_BATCH_TIMEOUT_NS,
                        &raw mut msg,
                        &raw mut badge,
                    )
                };

                if timed_err != 0 {
                    flush_damage(&mut state);
                    let err = unsafe {
                        ipc::recv_ctx(ipc_ctx(), CAP_SERVER_EP, &raw mut msg, &raw mut badge)
                    };
                    if err != 0 {
                        let mut lb = LineBuf::new();
                        lb.str(b"[DISPLAY] recv failed err=");
                        lb.hex(err as u64);
                        lb.str(b"\n");
                        lb.flush();
                        break;
                    }
                    break;
                }

                if msg.label != DISPLAY_TERMINAL_WRITE {
                    flush_damage(&mut state);
                    break;
                }
            }

            continue;
        }

        let mut reply = BesaltMsg::zeroed();

        match msg.label {
            DISPLAY_GET_INFO => {
                handle_get_info(&state, &mut reply);
            }
            DISPLAY_PRESENT => {
                handle_present(&mut state, &mut reply);
            }
            DISPLAY_FILL_RECT => {
                handle_fill_rect(&mut state, &msg, &mut reply);
            }
            DISPLAY_WRITE_TEXT => {
                handle_write_text(&mut state, &msg, &mut reply);
            }
            DISPLAY_TERMINAL_WRITE => {
                handle_terminal_write(&mut state, &msg);
                flush_damage(&mut state);
                reply.label = BESALT_OK;
            }
            _ => {
                reply.label = BESALT_INVALID_OPERATION;
            }
        }

        let err = unsafe {
            ipc::reply_recv_ctx(
                ipc_ctx(),
                CAP_SERVER_EP,
                &raw const reply,
                &raw mut msg,
                &raw mut badge,
            )
        };
        if err != 0 {
            let mut lb = LineBuf::new();
            lb.str(b"[DISPLAY] reply_recv failed err=");
            lb.hex(err as u64);
            lb.str(b"\n");
            lb.flush();
            break;
        }
    }

    idle();
}
