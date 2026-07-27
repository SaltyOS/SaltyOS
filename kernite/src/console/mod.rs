//! Framebuffer Text Console
//!
//! Renders text to a linear framebuffer using an 8x16 bitmap font.
//! Mirrors serial output to the framebuffer for visible boot diagnostics.
//!
//! Performance: All rendering targets a Write-Back (WB) shadow buffer in
//! system RAM. A ring buffer design eliminates memmove on scroll — only a
//! pointer advance + one row clear. Dirty line tracking copies only changed
//! text rows to WC-mapped VRAM in bulk.
//!
//! No separate lock is needed — console writes are called from serial_putc_hw(),
//! which is always called under SERIAL_LOCK (or unlocked in panic/crash paths,
//! which is acceptable for crash output).
//!
//! SPDX-License-Identifier: GPL-2.0-only

mod fb;
mod font;

use crate::init::bootinfo::FramebufferInfo;
use crate::mm::{PAGE_SIZE, phys_to_virt, pmm_free_count};
use core::sync::atomic::{AtomicBool, Ordering};

static CONSOLE_READY: AtomicBool = AtomicBool::new(false);
static CONSOLE_DISABLED: AtomicBool = AtomicBool::new(false);
const GLYPH_WIDTH_USIZE: usize = font::GLYPH_WIDTH as usize;
const GLYPH_HEIGHT_USIZE: usize = font::GLYPH_HEIGHT as usize;

/// Maximum text rows supported for dirty tracking (static array, no alloc).
/// 1080 / 16 = 67 rows. 128 covers up to 2048px vertical.
const MAX_DIRTY_ROWS: usize = 128;

/// Text-mode cell grid dimensions (covers up to 1920x2048 with 8x16 font).
const MAX_TEXT_COLS: usize = 240;
const MAX_TEXT_ROWS: usize = MAX_DIRTY_ROWS;

/// Compact cell representation for text-mode fallback.
#[derive(Clone, Copy)]
struct Cell {
    ch: u8,
    fg_idx: u8, // 0-15 = palette index, 0xFF = default_fg
    bg_idx: u8, // 0-15 = palette index, 0xFE = default_bg
}

/// Static cell grid for text-mode (no dynamic allocation).
/// ~90 KB in BSS (zero-initialized to avoid inflating .data).
/// Properly initialized at runtime by clear_screen() during console::init().
static mut CELL_GRID: [[Cell; MAX_TEXT_COLS]; MAX_TEXT_ROWS] = [[Cell {
    ch: 0,
    fg_idx: 0,
    bg_idx: 0,
}; MAX_TEXT_COLS]; MAX_TEXT_ROWS];

/// ANSI escape sequence parser state.
#[derive(Clone, Copy, PartialEq)]
enum AnsiState {
    Normal,
    Escape,  // seen ESC (0x1B)
    Bracket, // seen ESC[
}

/// Maximum ANSI CSI parameters per sequence.
const MAX_ANSI_PARAMS: usize = 8;

struct ConsoleState {
    fb_base: *mut u8,    // VRAM (WC mapped)
    shadow: *mut u8,     // Ring shadow buffer in WB system RAM
    shadow_total: usize, // Total shadow buffer size in bytes (2 * visible_size)
    visible_size: usize, // Visible area size in bytes (height * pitch)
    top_scanline: usize, // Byte offset into shadow for current top of screen
    dirty_lines: [bool; MAX_DIRTY_ROWS],
    width: u32,
    height: u32,
    pitch: u32,
    col: u32,
    row: u32,
    max_cols: u32,
    max_rows: u32,
    fg: u32,
    bg: u32,
    has_ring: bool, // true = 2x ring buffer allocated; false = 1x fallback (uses memmove)
    text_mode: bool, // true = cell grid mode (lowmem); false = pixel shadow mode
    // ANSI escape sequence state
    ansi_state: AnsiState,
    ansi_params: [u16; MAX_ANSI_PARAMS],
    ansi_param_count: u8,
    ansi_cur_param: u16,
    bold: bool,
    current_fg: u32,
    current_bg: u32,
    default_fg: u32,
    default_bg: u32,
    saved_col: u32,
    saved_row: u32,
    red_pos: u8,
    green_pos: u8,
    blue_pos: u8,
    palette: [u32; 16],
}

static mut CONSOLE: Option<ConsoleState> = None;
static mut GLYPH_ROW_LUT: [[u32; GLYPH_WIDTH_USIZE]; 256] = [[0; GLYPH_WIDTH_USIZE]; 256];

fn rebuild_glyph_row_lut(fg: u32, bg: u32) {
    // SAFETY: Called during single-threaded console init before CONSOLE_READY.
    unsafe {
        for row_bits in 0..256usize {
            let bits = row_bits as u8;
            for bit in 0..GLYPH_WIDTH_USIZE {
                GLYPH_ROW_LUT[row_bits][bit] = if bits & (0x80 >> bit) != 0 { fg } else { bg };
            }
        }
    }
}

/// Pack an RGB color using the framebuffer's channel bit positions.
fn pack_color(r: u8, g: u8, b: u8, red_pos: u8, green_pos: u8, blue_pos: u8) -> u32 {
    ((r as u32) << red_pos) | ((g as u32) << green_pos) | ((b as u32) << blue_pos)
}

/// Allocate a shadow buffer in WB system RAM.
///
/// Tries 2x visible size first (ring buffer, O(1) scroll). Falls back to 1x
/// (requires memmove on scroll, but still avoids rendering to VRAM directly).
fn alloc_shadow(visible_size: usize) -> (*mut u8, usize, bool) {
    let shadow_owner = crate::mm::frame::FrameOwner::KernelPrivate {
        subkind: crate::mm::frame::KernelMetaKind::General,
    };
    let pages_2x = (visible_size * 2 + PAGE_SIZE - 1) / PAGE_SIZE;
    if let Some(phys) = crate::mm::pmm_alloc_contiguous_owned(pages_2x, &shadow_owner) {
        let ptr = phys_to_virt(phys) as *mut u8;
        // SAFETY: Contiguous physical frames mapped via direct physical map.
        unsafe { core::ptr::write_bytes(ptr, 0, pages_2x * PAGE_SIZE) };
        return (ptr, pages_2x * PAGE_SIZE, true);
    }

    // Fallback: 1x visible size (no ring, memmove on scroll)
    let pages_1x = (visible_size + PAGE_SIZE - 1) / PAGE_SIZE;
    if let Some(phys) = crate::mm::pmm_alloc_contiguous_owned(pages_1x, &shadow_owner) {
        let ptr = phys_to_virt(phys) as *mut u8;
        // SAFETY: Contiguous physical frames mapped via direct physical map.
        unsafe { core::ptr::write_bytes(ptr, 0, pages_1x * PAGE_SIZE) };
        return (ptr, pages_1x * PAGE_SIZE, false);
    }

    (core::ptr::null_mut(), 0, false)
}

/// Initialize the framebuffer console.
///
/// Maps the framebuffer into kernel virtual address space and sets up
/// the text console state. Allocates a shadow buffer for rendering.
///
/// Must be called:
/// - After arch::init() (paging + frame allocator ready)
/// - Before init_smp() (so APs inherit the PML4[257] mapping)
pub fn init(fb_info: &FramebufferInfo) {
    if fb_info.addr == 0 || fb_info.bpp != 32 || fb_info.width == 0 || fb_info.height == 0 {
        crate::kernel::printk::serial_puts("[CONSOLE] No usable framebuffer, skipping\n");
        return;
    }

    // SAFETY: Called once during single-threaded boot, after paging::init()
    let fb_base = match unsafe { fb::map_framebuffer(fb_info) } {
        Some(ptr) => ptr,
        None => {
            crate::kernel::printk::serial_puts("[CONSOLE] Failed to map framebuffer\n");
            return;
        }
    };

    let max_cols = fb_info.width / font::GLYPH_WIDTH;
    let max_rows = fb_info.height / font::GLYPH_HEIGHT;

    if max_rows as usize > MAX_DIRTY_ROWS {
        crate::kernel::printk::serial_puts(
            "[CONSOLE] Too many rows for dirty tracking, skipping\n",
        );
        return;
    }

    // Light gray text on black background
    let fg = pack_color(
        0xC0,
        0xC0,
        0xC0,
        fb_info.red_pos,
        fb_info.green_pos,
        fb_info.blue_pos,
    );
    let bg = pack_color(
        0x00,
        0x00,
        0x00,
        fb_info.red_pos,
        fb_info.green_pos,
        fb_info.blue_pos,
    );
    rebuild_glyph_row_lut(fg, bg);

    let visible_size = fb_info.height as usize * fb_info.pitch as usize;
    let visible_pages = (visible_size + PAGE_SIZE - 1) / PAGE_SIZE;
    let free = pmm_free_count();

    // If shadow would consume >= 1/3 of free frames, skip it to preserve
    // memory for userland (display server, procmgr, etc.).
    let skip_shadow = visible_pages * 3 > free;

    let (shadow, shadow_total, has_ring, text_mode) = if skip_shadow {
        crate::kernel::printk::serial_puts("[CONSOLE] Low memory -- using text-mode (no shadow)\n");
        (core::ptr::null_mut(), 0, false, true)
    } else {
        let (s, st, hr) = alloc_shadow(visible_size);
        if s.is_null() {
            crate::kernel::printk::serial_puts(
                "[CONSOLE] Shadow alloc failed -- text-mode fallback\n",
            );
            (s, st, hr, true)
        } else {
            (s, st, hr, false)
        }
    };

    // Build 16-color palette (8 normal + 8 bright) using FB channel positions
    let rp = fb_info.red_pos;
    let gp = fb_info.green_pos;
    let bp = fb_info.blue_pos;
    let palette = [
        // Normal colors (30-37)
        pack_color(0x00, 0x00, 0x00, rp, gp, bp), // 0: black
        pack_color(0xAA, 0x00, 0x00, rp, gp, bp), // 1: red
        pack_color(0x00, 0xAA, 0x00, rp, gp, bp), // 2: green
        pack_color(0xAA, 0x55, 0x00, rp, gp, bp), // 3: yellow/brown
        pack_color(0x00, 0x00, 0xAA, rp, gp, bp), // 4: blue
        pack_color(0xAA, 0x00, 0xAA, rp, gp, bp), // 5: magenta
        pack_color(0x00, 0xAA, 0xAA, rp, gp, bp), // 6: cyan
        pack_color(0xAA, 0xAA, 0xAA, rp, gp, bp), // 7: white (light gray)
        // Bright colors (90-97)
        pack_color(0x55, 0x55, 0x55, rp, gp, bp), // 8: bright black (dark gray)
        pack_color(0xFF, 0x55, 0x55, rp, gp, bp), // 9: bright red
        pack_color(0x55, 0xFF, 0x55, rp, gp, bp), // 10: bright green
        pack_color(0xFF, 0xFF, 0x55, rp, gp, bp), // 11: bright yellow
        pack_color(0x55, 0x55, 0xFF, rp, gp, bp), // 12: bright blue
        pack_color(0xFF, 0x55, 0xFF, rp, gp, bp), // 13: bright magenta
        pack_color(0x55, 0xFF, 0xFF, rp, gp, bp), // 14: bright cyan
        pack_color(0xFF, 0xFF, 0xFF, rp, gp, bp), // 15: bright white
    ];

    let state = ConsoleState {
        fb_base,
        shadow,
        shadow_total,
        visible_size,
        top_scanline: 0,
        dirty_lines: [false; MAX_DIRTY_ROWS],
        width: fb_info.width,
        height: fb_info.height,
        pitch: fb_info.pitch,
        col: 0,
        row: 0,
        max_cols,
        max_rows,
        fg,
        bg,
        has_ring,
        text_mode,
        ansi_state: AnsiState::Normal,
        ansi_params: [0; MAX_ANSI_PARAMS],
        ansi_param_count: 0,
        ansi_cur_param: 0,
        bold: false,
        current_fg: fg,
        current_bg: bg,
        default_fg: fg,
        default_bg: bg,
        saved_col: 0,
        saved_row: 0,
        red_pos: fb_info.red_pos,
        green_pos: fb_info.green_pos,
        blue_pos: fb_info.blue_pos,
        palette,
    };

    // SAFETY: Single-threaded boot, CONSOLE_READY is false
    unsafe {
        (*(&raw mut CONSOLE)) = Some(state);
    }

    // Clear screen (shadow + VRAM)
    clear_screen();

    CONSOLE_READY.store(true, Ordering::Release);

    crate::kernel::printk::kinfo!(|_g| {
        _g.puts("[CONSOLE] Framebuffer console initialized: ");
        _g.dec(fb_info.width as u64);
        _g.puts("x");
        _g.dec(fb_info.height as u64);
        _g.puts(" (");
        _g.dec(max_cols as u64);
        _g.puts("x");
        _g.dec(max_rows as u64);
        if text_mode {
            _g.puts(" chars, text-mode)\n");
        } else if has_ring {
            _g.puts(" chars, ring shadow)\n");
        } else {
            _g.puts(" chars, linear shadow)\n");
        }
    });
}

/// Disable framebuffer console output (display server takes over).
pub(crate) fn disable() {
    CONSOLE_DISABLED.store(true, Ordering::Release);
}

/// Re-enable framebuffer console output (used by panic handler).
pub(crate) fn enable() {
    CONSOLE_DISABLED.store(false, Ordering::Release);
}

/// Output a single character to the framebuffer console.
///
/// Called from serial_putc_hw() to mirror serial output to the screen.
/// Returns immediately if the console is not initialized or disabled.
#[inline]
pub(crate) fn putc(c: u8) {
    if !CONSOLE_READY.load(Ordering::Acquire) || CONSOLE_DISABLED.load(Ordering::Acquire) {
        return;
    }

    // SAFETY: CONSOLE is only written during single-threaded init,
    // and reads here are protected by SERIAL_LOCK (or unlocked in panic path).
    let state = unsafe {
        match (*(&raw mut CONSOLE)).as_mut() {
            Some(s) => s,
            None => return,
        }
    };

    write_char(state, c);
    // No flush here — deferred to SerialGuard::drop(), serial_putc(),
    // or the next console::write() call for batching.
}

/// Flush any pending dirty lines to VRAM.
///
/// Called from SerialGuard::drop() to batch all output within a guard scope
/// into a single VRAM update, and from serial_putc() for standalone chars.
#[inline]
pub(crate) fn flush_pending() {
    if !CONSOLE_READY.load(Ordering::Acquire) || CONSOLE_DISABLED.load(Ordering::Acquire) {
        return;
    }

    let state = unsafe {
        match (*(&raw mut CONSOLE)).as_mut() {
            Some(s) => s,
            None => return,
        }
    };

    flush(state);
}

/// Output a byte slice to the framebuffer console.
#[inline]
pub(crate) fn write(bytes: &[u8]) {
    if bytes.is_empty()
        || !CONSOLE_READY.load(Ordering::Acquire)
        || CONSOLE_DISABLED.load(Ordering::Acquire)
    {
        return;
    }

    let state = unsafe {
        match (*(&raw mut CONSOLE)).as_mut() {
            Some(s) => s,
            None => return,
        }
    };

    for &c in bytes {
        write_char(state, c);
    }
    // Single flush after all characters — batch effect
    flush(state);
}

#[inline]
fn write_char(state: &mut ConsoleState, c: u8) {
    match state.ansi_state {
        AnsiState::Normal => {
            if c == 0x1B {
                // ESC
                state.ansi_state = AnsiState::Escape;
                return;
            }
            emit_char(state, c);
        }
        AnsiState::Escape => {
            if c == b'[' {
                state.ansi_state = AnsiState::Bracket;
                state.ansi_param_count = 0;
                state.ansi_cur_param = 0;
                for i in 0..MAX_ANSI_PARAMS {
                    state.ansi_params[i] = 0;
                }
                return;
            }
            // Not a CSI sequence — emit ESC as-is and re-process char
            state.ansi_state = AnsiState::Normal;
            emit_char(state, c);
        }
        AnsiState::Bracket => {
            if c >= b'0' && c <= b'9' {
                // Accumulate digit
                state.ansi_cur_param = state
                    .ansi_cur_param
                    .wrapping_mul(10)
                    .wrapping_add((c - b'0') as u16);
                return;
            }
            if c == b';' {
                // Next parameter
                if (state.ansi_param_count as usize) < MAX_ANSI_PARAMS {
                    state.ansi_params[state.ansi_param_count as usize] = state.ansi_cur_param;
                    state.ansi_param_count += 1;
                }
                state.ansi_cur_param = 0;
                return;
            }
            // Final byte — store last parameter and dispatch
            if (state.ansi_param_count as usize) < MAX_ANSI_PARAMS {
                state.ansi_params[state.ansi_param_count as usize] = state.ansi_cur_param;
                state.ansi_param_count += 1;
            }
            state.ansi_state = AnsiState::Normal;
            dispatch_csi(state, c);
        }
    }
}

/// Emit a printable/control character (non-ANSI path).
fn emit_char(state: &mut ConsoleState, c: u8) {
    match c {
        b'\n' => {
            state.col = 0;
            state.row += 1;
        }
        b'\r' => {
            state.col = 0;
        }
        b'\t' => {
            state.col = (state.col + 8) & !7;
        }
        0x08 => {
            // Backspace
            if state.col > 0 {
                state.col -= 1;
            }
        }
        _ => {
            draw_glyph_color(
                state,
                c,
                state.col,
                state.row,
                state.current_fg,
                state.current_bg,
            );
            state.col += 1;
        }
    }

    if state.col >= state.max_cols {
        state.col = 0;
        state.row += 1;
    }

    if state.row >= state.max_rows {
        scroll_up(state);
    }
}

/// Dispatch a completed CSI sequence (ESC[...X).
fn dispatch_csi(state: &mut ConsoleState, final_byte: u8) {
    let p = |i: usize| -> u32 {
        if i < state.ansi_param_count as usize {
            state.ansi_params[i] as u32
        } else {
            0
        }
    };

    match final_byte {
        b'm' => handle_sgr(state),
        b'A' => {
            // Cursor up N (default 1)
            let n = if p(0) == 0 { 1 } else { p(0) };
            state.row = state.row.saturating_sub(n);
        }
        b'B' => {
            // Cursor down N (default 1)
            let n = if p(0) == 0 { 1 } else { p(0) };
            state.row = (state.row + n).min(state.max_rows - 1);
        }
        b'C' => {
            // Cursor right N (default 1)
            let n = if p(0) == 0 { 1 } else { p(0) };
            state.col = (state.col + n).min(state.max_cols - 1);
        }
        b'D' => {
            // Cursor left N (default 1)
            let n = if p(0) == 0 { 1 } else { p(0) };
            state.col = state.col.saturating_sub(n);
        }
        b'H' | b'f' => {
            // Cursor position (row;col — 1-based)
            let row = if p(0) == 0 { 1 } else { p(0) };
            let col = if p(1) == 0 { 1 } else { p(1) };
            state.row = (row - 1).min(state.max_rows - 1);
            state.col = (col - 1).min(state.max_cols - 1);
        }
        b'J' => {
            // Erase in display
            let mode = p(0);
            erase_display(state, mode);
        }
        b'K' => {
            // Erase in line
            let mode = p(0);
            erase_line(state, mode);
        }
        b's' => {
            // Save cursor position
            state.saved_col = state.col;
            state.saved_row = state.row;
        }
        b'u' => {
            // Restore cursor position
            state.col = state.saved_col.min(state.max_cols - 1);
            state.row = state.saved_row.min(state.max_rows - 1);
        }
        _ => {
            // Unknown CSI sequence — ignore
        }
    }
}

/// Handle SGR (Select Graphic Rendition) — ESC[...m
fn handle_sgr(state: &mut ConsoleState) {
    if state.ansi_param_count == 0 {
        // ESC[m with no params is same as ESC[0m
        sgr_reset(state);
        return;
    }

    for i in 0..state.ansi_param_count as usize {
        let code = state.ansi_params[i] as u32;
        match code {
            0 => sgr_reset(state),
            1 => {
                state.bold = true;
                // If using a standard color, upgrade to bright variant
                update_bold_fg(state);
            }
            22 => {
                state.bold = false;
            }
            30..=37 => {
                let idx = (code - 30) as usize;
                state.current_fg = if state.bold {
                    state.palette[idx + 8]
                } else {
                    state.palette[idx]
                };
            }
            39 => {
                state.current_fg = state.default_fg;
            }
            40..=47 => {
                let idx = (code - 40) as usize;
                state.current_bg = state.palette[idx];
            }
            49 => {
                state.current_bg = state.default_bg;
            }
            90..=97 => {
                let idx = (code - 90 + 8) as usize;
                state.current_fg = state.palette[idx];
            }
            100..=107 => {
                let idx = (code - 100 + 8) as usize;
                state.current_bg = state.palette[idx];
            }
            _ => {} // Unsupported SGR code — ignore
        }
    }
}

fn sgr_reset(state: &mut ConsoleState) {
    state.bold = false;
    state.current_fg = state.default_fg;
    state.current_bg = state.default_bg;
}

/// When bold is active and we have a normal-range fg, upgrade to bright.
fn update_bold_fg(state: &mut ConsoleState) {
    for i in 0..8 {
        if state.current_fg == state.palette[i] {
            state.current_fg = state.palette[i + 8];
            return;
        }
    }
}

/// Clear a range of cells in the cell grid (text-mode only).
fn clear_cells(
    state: &mut ConsoleState,
    start_col: u32,
    start_row: u32,
    end_col: u32,
    end_row: u32,
) {
    let bg_idx = palette_index(state, state.current_bg);
    let blank = Cell {
        ch: b' ',
        fg_idx: 0xFF,
        bg_idx,
    };
    // SAFETY: Bounds clamped below, single-writer under SERIAL_LOCK.
    unsafe {
        let grid = &raw mut CELL_GRID;
        for r in start_row as usize..end_row as usize {
            if r >= MAX_TEXT_ROWS {
                break;
            }
            for c in start_col as usize..end_col as usize {
                if c >= MAX_TEXT_COLS {
                    break;
                }
                (*grid)[r][c] = blank;
            }
            mark_dirty(state, r);
        }
    }
}

/// Erase in display: 0=below cursor, 1=above cursor, 2=entire screen.
fn erase_display(state: &mut ConsoleState, mode: u32) {
    if state.text_mode {
        match mode {
            0 => {
                // Cursor to end of screen
                clear_cells(state, state.col, state.row, state.max_cols, state.row + 1);
                clear_cells(state, 0, state.row + 1, state.max_cols, state.max_rows);
            }
            1 => {
                // Top to cursor
                clear_cells(state, 0, 0, state.max_cols, state.row);
                clear_cells(state, 0, state.row, state.col + 1, state.row + 1);
            }
            2 => {
                clear_cells(state, 0, 0, state.max_cols, state.max_rows);
            }
            _ => {}
        }
        return;
    }

    // Shadow mode
    let bg = state.current_bg;
    match mode {
        0 => {
            // Erase from cursor to end of screen
            // Clear rest of current line
            let x = state.col * GLYPH_WIDTH_USIZE as u32;
            let y = state.row * font::GLYPH_HEIGHT;
            let remaining_w = state.width - x;
            fill_rect(state, x, y, remaining_w, font::GLYPH_HEIGHT, bg);
            // Clear all rows below
            for r in (state.row + 1)..state.max_rows {
                let ry = r * font::GLYPH_HEIGHT;
                fill_rect(state, 0, ry, state.width, font::GLYPH_HEIGHT, bg);
            }
        }
        1 => {
            // Erase from top to cursor
            for r in 0..state.row {
                let ry = r * font::GLYPH_HEIGHT;
                fill_rect(state, 0, ry, state.width, font::GLYPH_HEIGHT, bg);
            }
            // Clear current line up to and including cursor
            let y = state.row * font::GLYPH_HEIGHT;
            let w = (state.col + 1) * GLYPH_WIDTH_USIZE as u32;
            fill_rect(state, 0, y, w, font::GLYPH_HEIGHT, bg);
        }
        2 => {
            // Erase entire screen
            for r in 0..state.max_rows {
                let ry = r * font::GLYPH_HEIGHT;
                fill_rect(state, 0, ry, state.width, font::GLYPH_HEIGHT, bg);
            }
        }
        _ => {}
    }
}

/// Erase in line: 0=right of cursor, 1=left of cursor, 2=entire line.
fn erase_line(state: &mut ConsoleState, mode: u32) {
    if state.text_mode {
        match mode {
            0 => clear_cells(state, state.col, state.row, state.max_cols, state.row + 1),
            1 => clear_cells(state, 0, state.row, state.col + 1, state.row + 1),
            2 => clear_cells(state, 0, state.row, state.max_cols, state.row + 1),
            _ => {}
        }
        return;
    }

    // Shadow mode
    let bg = state.current_bg;
    let y = state.row * font::GLYPH_HEIGHT;
    match mode {
        0 => {
            let x = state.col * GLYPH_WIDTH_USIZE as u32;
            let w = state.width - x;
            fill_rect(state, x, y, w, font::GLYPH_HEIGHT, bg);
        }
        1 => {
            let w = (state.col + 1) * GLYPH_WIDTH_USIZE as u32;
            fill_rect(state, 0, y, w, font::GLYPH_HEIGHT, bg);
        }
        2 => {
            fill_rect(state, 0, y, state.width, font::GLYPH_HEIGHT, bg);
        }
        _ => {}
    }
}

// --- Text-mode helpers ---

/// Map a packed u32 color to a palette index for cell grid storage.
fn palette_index(state: &ConsoleState, color: u32) -> u8 {
    if color == state.default_fg {
        return 0xFF;
    }
    if color == state.default_bg {
        return 0xFE;
    }
    for i in 0..16 {
        if state.palette[i] == color {
            return i as u8;
        }
    }
    0xFF // fallback to default_fg for unknown colors
}

/// Resolve a palette index back to a packed u32 color.
fn resolve_color(state: &ConsoleState, idx: u8) -> u32 {
    match idx {
        0xFF => state.default_fg,
        0xFE => state.default_bg,
        i if (i as usize) < 16 => state.palette[i as usize],
        _ => state.default_fg,
    }
}

/// Render a single glyph directly to WC VRAM at character grid position.
/// Used by text-mode flush path.
fn render_glyph_to_vram(state: &ConsoleState, c: u8, col: u32, row: u32, fg: u32, bg: u32) {
    let glyph_offset = (c as usize) * GLYPH_HEIGHT_USIZE;
    let px_x = col as usize * GLYPH_WIDTH_USIZE;
    let row_byte_offset = row as usize * GLYPH_HEIGHT_USIZE * state.pitch as usize;
    let use_lut = fg == state.default_fg && bg == state.default_bg;

    for y in 0..GLYPH_HEIGHT_USIZE {
        let row_bits = font::FONT_DATA[glyph_offset + y];
        let line_offset = row_byte_offset + y * state.pitch as usize;
        let line_base = unsafe { state.fb_base.add(line_offset) } as *mut u32;

        if use_lut {
            // SAFETY: row_bits is 0..=255, line_base points within VRAM mapping.
            let src = unsafe { GLYPH_ROW_LUT[row_bits as usize].as_ptr() };
            unsafe {
                core::ptr::copy_nonoverlapping(src, line_base.add(px_x), GLYPH_WIDTH_USIZE);
            }
        } else {
            for bit in 0..GLYPH_WIDTH_USIZE {
                let pixel = if row_bits & (0x80 >> bit) != 0 {
                    fg
                } else {
                    bg
                };
                // SAFETY: within VRAM mapping bounds
                unsafe {
                    line_base.add(px_x + bit).write(pixel);
                }
            }
        }
    }
}

/// Draw a single glyph at character grid position (col, row) into the shadow buffer.
/// Uses the fast LUT path (default colors only).
fn draw_glyph(state: &mut ConsoleState, c: u8, col: u32, row: u32) {
    draw_glyph_color(state, c, col, row, state.fg, state.bg);
}

/// Draw a glyph with explicit fg/bg colors.
///
/// Shadow mode: renders pixels into WB shadow buffer.
/// Text mode: stores character + color indices in cell grid.
fn draw_glyph_color(state: &mut ConsoleState, c: u8, col: u32, row: u32, fg: u32, bg: u32) {
    if state.text_mode {
        let col_idx = col as usize;
        let row_idx = row as usize;
        if col_idx < MAX_TEXT_COLS && row_idx < MAX_TEXT_ROWS {
            let fi = palette_index(state, fg);
            let bi = palette_index(state, bg);
            // SAFETY: Bounds checked above, single-writer under SERIAL_LOCK.
            unsafe {
                (*(&raw mut CELL_GRID))[row_idx][col_idx] = Cell {
                    ch: c,
                    fg_idx: fi,
                    bg_idx: bi,
                };
            }
        }
        mark_dirty(state, row as usize);
        return;
    }

    // Shadow mode: render pixels into WB shadow buffer
    let glyph_offset = (c as usize) * GLYPH_HEIGHT_USIZE;
    let px_x = col as usize * GLYPH_WIDTH_USIZE;
    let row_byte_offset = row as usize * GLYPH_HEIGHT_USIZE * state.pitch as usize;

    let use_lut = fg == state.default_fg && bg == state.default_bg;

    for y in 0..GLYPH_HEIGHT_USIZE {
        let row_bits = font::FONT_DATA[glyph_offset + y];
        let line_offset = state.top_scanline + row_byte_offset + y * state.pitch as usize;
        let line_base = unsafe { state.shadow.add(line_offset) } as *mut u32;

        if use_lut {
            // SAFETY: row_bits is 0..=255, line_base points within shadow buffer.
            let src = unsafe { GLYPH_ROW_LUT[row_bits as usize].as_ptr() };
            // SAFETY: destination range is within shadow buffer.
            unsafe {
                core::ptr::copy_nonoverlapping(src, line_base.add(px_x), GLYPH_WIDTH_USIZE);
            }
        } else {
            // Per-pixel rendering for custom colors
            for bit in 0..GLYPH_WIDTH_USIZE {
                let pixel = if row_bits & (0x80 >> bit) != 0 {
                    fg
                } else {
                    bg
                };
                // SAFETY: within shadow buffer bounds
                unsafe {
                    line_base.add(px_x + bit).write(pixel);
                }
            }
        }
    }

    mark_dirty(state, row as usize);
}

/// Scroll the screen up by one text row.
fn scroll_up(state: &mut ConsoleState) {
    if state.text_mode {
        // Text mode: copy cell grid rows up (~18 KB for 128 cols × 48 rows)
        let max_c = state.max_cols as usize;
        let max_r = state.max_rows as usize;
        let bg_idx = palette_index(state, state.current_bg);
        // SAFETY: Single-writer under SERIAL_LOCK, indices within bounds.
        unsafe {
            let grid = &raw mut CELL_GRID;
            for r in 1..max_r {
                core::ptr::copy_nonoverlapping(
                    (*grid)[r].as_ptr(),
                    (*grid)[r - 1].as_mut_ptr(),
                    max_c,
                );
            }
            let last = max_r - 1;
            for c in 0..max_c {
                (*grid)[last][c] = Cell {
                    ch: b' ',
                    fg_idx: 0xFF,
                    bg_idx: bg_idx,
                };
            }
        }
        state.row = state.max_rows - 1;
        mark_all_dirty(state);
        return;
    }

    // Shadow mode
    let row_bytes = GLYPH_HEIGHT_USIZE * state.pitch as usize;

    if state.has_ring {
        // O(1) ring buffer scroll: advance top_scanline pointer
        state.top_scanline += row_bytes;

        // Wrap-around: if visible window exceeds ring buffer, compact
        if state.top_scanline + state.visible_size > state.shadow_total {
            let live_bytes = state.visible_size - row_bytes;
            // SAFETY: source and destination are within shadow buffer bounds.
            // Regions may overlap (source > dest), so use copy (memmove).
            unsafe {
                core::ptr::copy(
                    state.shadow.add(state.top_scanline),
                    state.shadow,
                    live_bytes,
                );
            }
            state.top_scanline = 0;
        }
    } else {
        // Fallback: 1x buffer, memmove within shadow (still better than VRAM)
        let total_bytes = state.visible_size - row_bytes;
        // SAFETY: source and destination within shadow buffer, overlapping
        unsafe {
            core::ptr::copy(
                state.shadow.add(state.top_scanline + row_bytes),
                state.shadow.add(state.top_scanline),
                total_bytes,
            );
        }
    }

    state.row = state.max_rows - 1;

    // Clear the last text row in shadow buffer with current background color
    let last_row_offset = state.top_scanline + (state.max_rows as usize - 1) * row_bytes;
    fill_rect_shadow(
        state,
        last_row_offset,
        state.width,
        font::GLYPH_HEIGHT,
        state.current_bg,
    );

    // All lines are dirty after scroll
    mark_all_dirty(state);
}

/// Fill a rectangular region in the shadow buffer at a given byte offset.
fn fill_rect_shadow(state: &ConsoleState, offset: usize, w: u32, h: u32, color: u32) {
    if color == 0 {
        for row in 0..h as usize {
            let line_offset = offset + row * state.pitch as usize;
            // SAFETY: offset range is within shadow buffer
            unsafe {
                core::ptr::write_bytes(state.shadow.add(line_offset), 0, w as usize * 4);
            }
        }
    } else {
        for row in 0..h as usize {
            let line_offset = offset + row * state.pitch as usize;
            let ptr = unsafe { state.shadow.add(line_offset) as *mut u32 };
            for col in 0..w as usize {
                // SAFETY: within shadow buffer
                unsafe {
                    ptr.add(col).write(color);
                }
            }
        }
    }
}

/// Fill a rectangular region at pixel coordinates in the shadow buffer.
fn fill_rect(state: &mut ConsoleState, x: u32, y: u32, w: u32, h: u32, color: u32) {
    let offset = state.top_scanline + y as usize * state.pitch as usize + x as usize * 4;
    fill_rect_shadow(state, offset, w, h, color);

    // Mark affected text rows as dirty
    let first_row = y as usize / GLYPH_HEIGHT_USIZE;
    let last_row = ((y + h) as usize + GLYPH_HEIGHT_USIZE - 1) / GLYPH_HEIGHT_USIZE;
    for r in first_row..last_row.min(state.max_rows as usize) {
        mark_dirty(state, r);
    }
}

/// Flush dirty lines to VRAM.
///
/// Shadow mode: memcpy from WB shadow to WC VRAM (fast).
/// Text mode: re-render dirty rows from cell grid directly to WC VRAM.
fn flush(state: &mut ConsoleState) {
    if state.text_mode {
        let max_c = state.max_cols as usize;
        for row in 0..state.max_rows as usize {
            if !state.dirty_lines[row] {
                continue;
            }
            // SAFETY: row < MAX_TEXT_ROWS, col < MAX_TEXT_COLS
            for col in 0..max_c {
                let cell = unsafe { (*(&raw const CELL_GRID))[row][col] };
                let fg = resolve_color(state, cell.fg_idx);
                let bg = resolve_color(state, cell.bg_idx);
                render_glyph_to_vram(state, cell.ch, col as u32, row as u32, fg, bg);
            }
            state.dirty_lines[row] = false;
        }
        return;
    }

    // Shadow mode: bulk copy dirty rows from WB shadow to WC VRAM
    let row_bytes = GLYPH_HEIGHT_USIZE * state.pitch as usize;
    for row in 0..state.max_rows as usize {
        if !state.dirty_lines[row] {
            continue;
        }
        let shadow_offset = state.top_scanline + row * row_bytes;
        let vram_offset = row * row_bytes;
        // SAFETY: shadow_offset is within shadow buffer, vram_offset within
        // mapped framebuffer. Both cover row_bytes of valid memory.
        unsafe {
            core::ptr::copy_nonoverlapping(
                state.shadow.add(shadow_offset),
                state.fb_base.add(vram_offset),
                row_bytes,
            );
        }
        state.dirty_lines[row] = false;
    }
}

/// Mark a specific text row as dirty (needs flush to VRAM).
#[inline]
fn mark_dirty(state: &mut ConsoleState, row: usize) {
    if row < MAX_DIRTY_ROWS {
        state.dirty_lines[row] = true;
    }
}

/// Mark all text rows as dirty.
fn mark_all_dirty(state: &mut ConsoleState) {
    for row in 0..state.max_rows as usize {
        state.dirty_lines[row] = true;
    }
}

/// Clear the entire screen with the background color.
fn clear_screen() {
    // SAFETY: Called during single-threaded init, CONSOLE is valid
    let state = unsafe {
        match (*(&raw mut CONSOLE)).as_mut() {
            Some(s) => s,
            None => return,
        }
    };

    if state.text_mode {
        let bg_idx = palette_index(state, state.bg);
        let blank = Cell {
            ch: b' ',
            fg_idx: 0xFF,
            bg_idx,
        };
        // SAFETY: Single-threaded init, bounds within MAX_TEXT_ROWS/MAX_TEXT_COLS
        unsafe {
            let grid = &raw mut CELL_GRID;
            for r in 0..state.max_rows as usize {
                for c in 0..state.max_cols as usize {
                    (*grid)[r][c] = blank;
                }
            }
        }
        mark_all_dirty(state);
        flush(state);
        return;
    }

    // Shadow mode: clear shadow buffer
    let offset = state.top_scanline;
    fill_rect_shadow(state, offset, state.width, state.height, state.bg);
    mark_all_dirty(state);

    // Flush to VRAM
    flush(state);
}
