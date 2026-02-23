//! VT100/ANSI escape sequence parser
//!
//! Comprehensive state machine parser for terminal escape sequences. Handles:
//! - C0 control characters (BS, HT, LF, CR, VT, FF, BEL, SO, SI)
//! - ESC sequences (charset designation, save/restore cursor, keypad modes, tab set)
//! - CSI sequences (cursor movement, erase, SGR, scroll, insert/delete, modes)
//! - SGR: bold, dim, italic, underline, blink, reverse, hidden, strikethrough,
//!   standard/bright ANSI colors, 256-color, truecolor (24-bit RGB)
//! - DEC Special Graphics charset (box-drawing glyphs)
//! - DEC private modes (origin, reverse screen, application cursor keys, alt screen)
//! - OSC/DCS sequence absorption
//! - Tab stop management
//!
//! SPDX-License-Identifier: GPL-2.0-only

use super::DisplayState;

/// ANSI standard 8-color palette (normal intensity).
const ANSI_COLORS: [u32; 8] = [
    0x00_00_00, // 0: Black
    0xAA_00_00, // 1: Red
    0x00_AA_00, // 2: Green
    0xAA_55_00, // 3: Yellow/Brown
    0x00_00_AA, // 4: Blue
    0xAA_00_AA, // 5: Magenta
    0x00_AA_AA, // 6: Cyan
    0xAA_AA_AA, // 7: White
];

/// Bright/bold variant: add 0x55 to each non-zero channel.
fn bright_color(idx: usize) -> u32 {
    if idx >= 8 {
        return ANSI_COLORS[7];
    }
    let base = ANSI_COLORS[idx];
    let r = (base >> 16) & 0xFF;
    let g = (base >> 8) & 0xFF;
    let b = base & 0xFF;
    let br = if r > 0 { r + 0x55 } else { 0 };
    let bg = if g > 0 { g + 0x55 } else { 0 };
    let bb = if b > 0 { b + 0x55 } else { 0 };
    // Special case: bright black is dark gray
    if idx == 0 {
        return 0x55_55_55;
    }
    let br = if br > 0xFF { 0xFF } else { br };
    let bg = if bg > 0xFF { 0xFF } else { bg };
    let bb = if bb > 0xFF { 0xFF } else { bb };
    (br << 16) | (bg << 8) | bb
}

/// Convert a 256-color index to RGB888.
fn color_from_256(idx: u16) -> u32 {
    match idx {
        0..=7 => ANSI_COLORS[idx as usize],
        8..=15 => bright_color((idx - 8) as usize),
        16..=231 => {
            // 6x6x6 RGB cube: index = 16 + 36*r + 6*g + b
            let i = idx - 16;
            let b_val = (i % 6) as u32;
            let g_val = ((i / 6) % 6) as u32;
            let r_val = (i / 36) as u32;
            // Map 0-5 to 0, 0x5F, 0x87, 0xAF, 0xD7, 0xFF
            let map = |v: u32| -> u32 {
                match v {
                    0 => 0,
                    1 => 0x5F,
                    2 => 0x87,
                    3 => 0xAF,
                    4 => 0xD7,
                    _ => 0xFF,
                }
            };
            (map(r_val) << 16) | (map(g_val) << 8) | map(b_val)
        }
        232..=255 => {
            // 24-step grayscale: 8, 18, 28, ..., 238
            let g = 8 + (idx - 232) as u32 * 10;
            (g << 16) | (g << 8) | g
        }
        _ => 0xAA_AA_AA,
    }
}

/// Convert an RGB888 value to the framebuffer's pixel format.
fn rgb_to_native(state: &DisplayState, rgb: u32) -> u32 {
    let r = ((rgb >> 16) & 0xFF) as u8;
    let g = ((rgb >> 8) & 0xFF) as u8;
    let b = (rgb & 0xFF) as u8;
    super::pack_color(r, g, b, state.red_pos, state.green_pos, state.blue_pos)
}

/// DEC Special Graphics charset glyph bitmaps.
///
/// 31 glyphs for bytes 0x60-0x7E, 16 rows each (8x16 format).
/// Each byte = one row, MSB = leftmost pixel, matching the main font format.
///
/// Box-drawing lines are centered: vertical at column 3 (bit 4 = 0x10),
/// horizontal at row 7. Lines extend from center to cell edges for clean
/// cell-to-cell connections.
#[rustfmt::skip]
pub static DEC_GRAPHICS_GLYPHS: [u8; 31 * 16] = [
    // 0x60: ` → ◆ (diamond)
    0x00, 0x00, 0x00, 0x10, 0x38, 0x7C, 0xFE, 0x7C,
    0x38, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x61: a → ▒ (checkerboard)
    0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55,
    0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55,
    // 0x62: b → HT (rendered as blank)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x63: c → FF (rendered as blank)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x64: d → CR (rendered as blank)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x65: e → LF (rendered as blank)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x66: f → ° (degree symbol)
    0x00, 0x00, 0x38, 0x44, 0x44, 0x38, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x67: g → ± (plus/minus)
    0x00, 0x00, 0x10, 0x10, 0x7C, 0x10, 0x10, 0x00,
    0x7C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x68: h → NL (rendered as blank)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x69: i → VT (rendered as blank)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x6A: j → ┘ (lower-right corner)
    //   Vertical line down column 3 from row 0 to row 7, horizontal line at row 7 from col 0 to col 3
    0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x1F,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x6B: k → ┐ (upper-right corner)
    //   Horizontal at row 7 from col 0 to col 3, vertical from row 7 to row 15
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1F,
    0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
    // 0x6C: l → ┌ (upper-left corner)
    //   Horizontal at row 7 from col 3 to col 7, vertical from row 7 to row 15
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF8,
    0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
    // 0x6D: m → └ (lower-left corner)
    //   Vertical from row 0 to row 7, horizontal at row 7 from col 3 to col 7
    0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0xF8,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x6E: n → ┼ (crossing lines)
    //   Vertical full height at col 3, horizontal full width at row 7
    0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0xFF,
    0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
    // 0x6F: o → ⎺ (scan line 1 — top horizontal)
    0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x70: p → ⎻ (scan line 3)
    0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x71: q → ─ (horizontal line, scan line 7 — center)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x72: r → ⎼ (scan line 9)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00,
    // 0x73: s → ⎽ (scan line 11 — bottom horizontal)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00,
    // 0x74: t → ├ (left tee)
    //   Vertical full height at col 3, horizontal at row 7 from col 3 to col 7
    0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0xF0,
    0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
    // 0x75: u → ┤ (right tee)
    //   Vertical full height at col 3, horizontal at row 7 from col 0 to col 3
    0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x1F,
    0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
    // 0x76: v → ┴ (bottom tee)
    //   Vertical from row 0 to row 7 at col 3, horizontal full width at row 7
    0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x77: w → ┬ (top tee)
    //   Horizontal full width at row 7, vertical from row 7 to row 15 at col 3
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF,
    0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
    // 0x78: x → │ (vertical line)
    //   Vertical full height at col 3
    0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
    0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
    // 0x79: y → ≤ (less-than-or-equal)
    0x00, 0x00, 0x00, 0x00, 0x04, 0x08, 0x10, 0x20,
    0x10, 0x08, 0x04, 0x00, 0x3C, 0x00, 0x00, 0x00,
    // 0x7A: z → ≥ (greater-than-or-equal)
    0x00, 0x00, 0x00, 0x00, 0x20, 0x10, 0x08, 0x04,
    0x08, 0x10, 0x20, 0x00, 0x3C, 0x00, 0x00, 0x00,
    // 0x7B: { → π (pi)
    0x00, 0x00, 0x00, 0x00, 0x7E, 0x24, 0x24, 0x24,
    0x24, 0x24, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x7C: | → ≠ (not-equal)
    0x00, 0x00, 0x00, 0x04, 0x7C, 0x08, 0x7C, 0x20,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x7D: } → £ (pound sterling)
    0x00, 0x00, 0x1C, 0x22, 0x20, 0x70, 0x20, 0x20,
    0x20, 0x62, 0xDC, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 0x7E: ~ → · (bullet/middle dot)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

#[derive(Copy, Clone)]
pub enum VtState {
    Normal,
    Escape,
    Csi,
    EscapeIntermediate,
    Osc,
    Dcs,
}

pub struct CsiParser {
    pub params: [u16; 16],
    pub param_count: u8,
    pub current_param: u16,
    pub has_current: bool,
    pub private_flag: bool,
    pub intermediate: u8,
}

impl CsiParser {
    pub fn new() -> Self {
        CsiParser {
            params: [0; 16],
            param_count: 0,
            current_param: 0,
            has_current: false,
            private_flag: false,
            intermediate: 0,
        }
    }

    fn reset(&mut self) {
        self.params = [0; 16];
        self.param_count = 0;
        self.current_param = 0;
        self.has_current = false;
        self.private_flag = false;
        self.intermediate = 0;
    }

    /// Finalize params: push current_param if accumulated.
    fn finalize(&mut self) {
        if self.has_current && (self.param_count as usize) < self.params.len() {
            self.params[self.param_count as usize] = self.current_param;
            self.param_count += 1;
        }
    }

    /// Get param at index with a default value if missing or zero.
    fn param(&self, idx: usize, default: u16) -> u16 {
        if idx < self.param_count as usize {
            let v = self.params[idx];
            if v == 0 { default } else { v }
        } else {
            default
        }
    }

    /// Get param at index, returning 0 if missing (for mode params like erase).
    fn param_raw(&self, idx: usize) -> u16 {
        if idx < self.param_count as usize {
            self.params[idx]
        } else {
            0
        }
    }
}

/// Process a single byte through the VT100 state machine.
pub fn process_byte(state: &mut DisplayState, byte: u8) {
    match state.vt_state {
        VtState::Normal => process_normal(state, byte),
        VtState::Escape => process_escape(state, byte),
        VtState::Csi => process_csi(state, byte),
        VtState::EscapeIntermediate => process_escape_intermediate(state, byte),
        VtState::Osc => process_osc(state, byte),
        VtState::Dcs => process_dcs(state, byte),
    }
}

fn process_normal(state: &mut DisplayState, byte: u8) {
    match byte {
        0x1B => state.vt_state = VtState::Escape,
        0x07 => {}                            // BEL — silently ignore
        0x08 | 0x09 | 0x0A | 0x0D =>         // BS, HT, LF, CR
            super::terminal_putc(state, byte),
        0x0B | 0x0C =>                        // VT, FF — treat as LF
            super::terminal_putc(state, b'\n'),
        0x0E => state.active_charset = 1,     // SO — shift to G1
        0x0F => state.active_charset = 0,     // SI — shift to G0
        0x20..=0x7E => {                      // Printable ASCII
            state.last_printed_char = byte;
            super::terminal_putc(state, byte);
        }
        _ => {}                               // NUL, DEL, other C0, high bytes — ignore
    }
}

fn process_escape(state: &mut DisplayState, byte: u8) {
    match byte {
        b'[' => {
            state.csi_parser.reset();
            state.vt_state = VtState::Csi;
        }
        b']' => {
            // OSC — Operating System Command
            state.osc_saw_esc = false;
            state.vt_state = VtState::Osc;
        }
        b'P' => {
            // DCS — Device Control String
            state.osc_saw_esc = false;
            state.vt_state = VtState::Dcs;
        }
        b'(' | b')' | b'*' | b'+' | b'#' => {
            // Charset designation or DEC line attribute — eat one more byte
            state.esc_intermediate = byte;
            state.vt_state = VtState::EscapeIntermediate;
        }
        b'c' => {
            // Full reset (RIS)
            full_reset(state);
            state.vt_state = VtState::Normal;
        }
        b'M' => {
            // Reverse Index — move cursor up one line, scroll down if at scroll_top
            state.pending_wrap = false;
            if state.text_row == state.scroll_top {
                super::scroll_down_region(state, state.scroll_top, state.scroll_bottom);
            } else if state.text_row > 0 {
                state.text_row -= 1;
            }
            state.vt_state = VtState::Normal;
        }
        b'D' => {
            // Index — move cursor down one line, scroll up if at scroll_bottom
            state.pending_wrap = false;
            if state.text_row + 1 >= state.scroll_bottom {
                super::scroll_up(state);
            } else {
                state.text_row += 1;
            }
            state.vt_state = VtState::Normal;
        }
        b'E' => {
            // Next Line — move to beginning of next line, scroll if needed
            state.pending_wrap = false;
            state.text_col = 0;
            if state.text_row + 1 >= state.scroll_bottom {
                super::scroll_up(state);
            } else {
                state.text_row += 1;
            }
            state.vt_state = VtState::Normal;
        }
        b'7' => {
            // DECSC — Save Cursor
            state.saved_col = state.text_col;
            state.saved_row = state.text_row;
            state.saved_fg = state.fg;
            state.saved_bg = state.bg;
            state.saved_bold = state.bold;
            state.saved_reverse = state.reverse_video;
            state.saved_dim = state.dim;
            state.saved_underline = state.underline;
            state.saved_g0_charset = state.g0_charset;
            state.saved_g1_charset = state.g1_charset;
            state.saved_active_charset = state.active_charset;
            state.vt_state = VtState::Normal;
        }
        b'8' => {
            // DECRC — Restore Cursor
            state.text_col = state.saved_col;
            state.text_row = state.saved_row;
            state.fg = state.saved_fg;
            state.bg = state.saved_bg;
            state.bold = state.saved_bold;
            state.reverse_video = state.saved_reverse;
            state.dim = state.saved_dim;
            state.underline = state.saved_underline;
            state.g0_charset = state.saved_g0_charset;
            state.g1_charset = state.saved_g1_charset;
            state.active_charset = state.saved_active_charset;
            state.pending_wrap = false;
            if state.text_row >= state.max_rows {
                state.text_row = state.max_rows - 1;
            }
            if state.text_col >= state.max_cols {
                state.text_col = state.max_cols - 1;
            }
            state.vt_state = VtState::Normal;
        }
        b'H' => {
            // HTS — Horizontal Tab Set at current column
            if state.text_col < 128 {
                state.tab_stops |= 1u128 << state.text_col;
            }
            state.vt_state = VtState::Normal;
        }
        b'=' | b'>' | b'<' | b'N' | b'O' => {
            // DECKPAM, DECKPNM, DECANM, SS2, SS3 — silently ignore
            state.vt_state = VtState::Normal;
        }
        _ => {
            // Unrecognized escape — discard and return to normal
            state.vt_state = VtState::Normal;
        }
    }
}

fn process_escape_intermediate(state: &mut DisplayState, byte: u8) {
    let intermediate = state.esc_intermediate;
    state.vt_state = VtState::Normal;

    // Map charset designator byte to charset ID: 'B'→ASCII(0), '0'→DEC Graphics(1), 'A'→UK(2)
    let charset_id = match byte {
        b'B' => 0, // ASCII
        b'0' => 1, // DEC Special Graphics
        b'A' => 2, // UK
        _ => 0,     // Default to ASCII for unknown
    };

    match intermediate {
        b'(' => state.g0_charset = charset_id,
        b')' => state.g1_charset = charset_id,
        // '*', '+', '#' — G2/G3/line attrs: ignore
        _ => {}
    }
}

fn process_osc(state: &mut DisplayState, byte: u8) {
    // Absorb all bytes until BEL (0x07) or ST (ESC \)
    if state.osc_saw_esc {
        state.osc_saw_esc = false;
        if byte == b'\\' {
            state.vt_state = VtState::Normal;
            return;
        }
        // ESC not followed by \ — treat ESC as start of new escape
        state.vt_state = VtState::Escape;
        process_escape(state, byte);
        return;
    }
    match byte {
        0x07 => state.vt_state = VtState::Normal, // BEL terminates OSC
        0x1B => state.osc_saw_esc = true,          // Possible ST start
        _ => {}                                     // Absorb
    }
}

fn process_dcs(state: &mut DisplayState, byte: u8) {
    // Absorb all bytes until ST (ESC \)
    if state.osc_saw_esc {
        state.osc_saw_esc = false;
        if byte == b'\\' {
            state.vt_state = VtState::Normal;
            return;
        }
        // ESC not followed by \ — treat ESC as start of new escape
        state.vt_state = VtState::Escape;
        process_escape(state, byte);
        return;
    }
    match byte {
        0x1B => state.osc_saw_esc = true,
        _ => {}
    }
}

fn process_csi(state: &mut DisplayState, byte: u8) {
    match byte {
        b'0'..=b'9' => {
            state.csi_parser.has_current = true;
            state.csi_parser.current_param =
                state.csi_parser.current_param.saturating_mul(10)
                    .saturating_add((byte - b'0') as u16);
        }
        b';' => {
            if (state.csi_parser.param_count as usize) < state.csi_parser.params.len() {
                let val = if state.csi_parser.has_current {
                    state.csi_parser.current_param
                } else {
                    0
                };
                state.csi_parser.params[state.csi_parser.param_count as usize] = val;
                state.csi_parser.param_count += 1;
            }
            state.csi_parser.current_param = 0;
            state.csi_parser.has_current = false;
        }
        b'?' => {
            state.csi_parser.private_flag = true;
        }
        b' ' | b'!' | b'"' | b'\'' => {
            // CSI intermediate bytes — store for dispatch
            state.csi_parser.intermediate = byte;
        }
        0x1B => {
            // ESC interrupts CSI — start new escape sequence
            state.vt_state = VtState::Escape;
        }
        // Final characters — dispatch and return to Normal
        b'A'..=b'Z' | b'a'..=b'z' | b'@' | b'`' | b'~' => {
            state.csi_parser.finalize();
            dispatch_csi(state, byte);
            state.vt_state = VtState::Normal;
        }
        _ => {
            // Unknown byte in CSI — abort sequence
            state.vt_state = VtState::Normal;
        }
    }
}

fn dispatch_csi(state: &mut DisplayState, cmd: u8) {
    let intermediate = state.csi_parser.intermediate;

    // Handle CSI ! p (DECSTR — soft reset)
    if intermediate == b'!' && cmd == b'p' {
        soft_reset(state);
        return;
    }

    // Extract params by value before any mutable operations on state.
    let param0 = state.csi_parser.param(0, 1);
    let param0_raw = state.csi_parser.param_raw(0);
    let param1 = state.csi_parser.param(1, 1);
    let private = state.csi_parser.private_flag;

    match cmd {
        b'A' => {
            // Cursor Up
            state.pending_wrap = false;
            let n = param0 as u32;
            if state.text_row >= n {
                state.text_row -= n;
            } else {
                state.text_row = 0;
            }
        }
        b'B' => {
            // Cursor Down
            state.pending_wrap = false;
            let n = param0 as u32;
            state.text_row += n;
            if state.text_row >= state.max_rows {
                state.text_row = state.max_rows - 1;
            }
        }
        b'C' => {
            // Cursor Forward
            state.pending_wrap = false;
            let n = param0 as u32;
            state.text_col += n;
            if state.text_col >= state.max_cols {
                state.text_col = state.max_cols - 1;
            }
        }
        b'D' => {
            // Cursor Backward
            state.pending_wrap = false;
            let n = param0 as u32;
            if state.text_col >= n {
                state.text_col -= n;
            } else {
                state.text_col = 0;
            }
        }
        b'E' => {
            // CNL — Cursor Next Line
            state.pending_wrap = false;
            state.text_col = 0;
            let n = param0 as u32;
            state.text_row += n;
            if state.text_row >= state.max_rows {
                state.text_row = state.max_rows - 1;
            }
        }
        b'F' => {
            // CPL — Cursor Previous Line
            state.pending_wrap = false;
            state.text_col = 0;
            let n = param0 as u32;
            if state.text_row >= n {
                state.text_row -= n;
            } else {
                state.text_row = 0;
            }
        }
        b'H' | b'f' => {
            // Cursor Position — params are 1-based
            state.pending_wrap = false;
            let row = param0 as u32;
            let col = param1 as u32;
            if state.origin_mode {
                // Origin mode: row is relative to scroll region
                state.text_row = state.scroll_top + (if row > 0 { row - 1 } else { 0 });
                if state.text_row >= state.scroll_bottom {
                    state.text_row = state.scroll_bottom - 1;
                }
            } else {
                state.text_row = if row > 0 { row - 1 } else { 0 };
                if state.text_row >= state.max_rows {
                    state.text_row = state.max_rows - 1;
                }
            }
            state.text_col = if col > 0 { col - 1 } else { 0 };
            if state.text_col >= state.max_cols {
                state.text_col = state.max_cols - 1;
            }
        }
        b'J' => {
            // Erase in Display
            erase_display(state, param0_raw);
        }
        b'K' => {
            // Erase in Line
            erase_line(state, param0_raw);
        }
        b'm' => {
            // SGR — Select Graphic Rendition
            sgr(state);
        }
        b'h' => {
            // Set Mode
            if private {
                set_dec_mode(state, param0_raw, true);
            }
        }
        b'l' => {
            // Reset Mode
            if private {
                set_dec_mode(state, param0_raw, false);
            }
        }
        b'L' => {
            // Insert Lines
            let n = param0 as u32;
            let n = if n > state.max_rows { state.max_rows } else { n };
            if state.text_row < state.max_rows {
                super::insert_lines(state, state.text_row, n);
            }
        }
        b'M' => {
            // Delete Lines
            let n = param0 as u32;
            let n = if n > state.max_rows { state.max_rows } else { n };
            if state.text_row < state.max_rows {
                super::delete_lines(state, state.text_row, n);
            }
        }
        b'@' => {
            // ICH — Insert Characters
            let n = param0 as u32;
            super::insert_chars(state, n);
        }
        b'P' => {
            // DCH — Delete Characters
            let n = param0 as u32;
            super::delete_chars(state, n);
        }
        b'X' => {
            // ECH — Erase Characters
            let n = param0 as u32;
            super::erase_chars(state, n);
        }
        b'S' => {
            // SU — Scroll Up
            let n = param0 as u32;
            for _ in 0..n {
                super::scroll_up(state);
            }
        }
        b'T' => {
            // SD — Scroll Down
            if !private {
                let n = param0 as u32;
                for _ in 0..n {
                    super::scroll_down_region(state, state.scroll_top, state.scroll_bottom);
                }
            }
        }
        b'r' => {
            // DECSTBM — Set Scrolling Region
            if !private {
                state.pending_wrap = false;
                let top = state.csi_parser.param(0, 1) as u32;
                let bottom = state.csi_parser.param(1, state.max_rows as u16) as u32;
                // Convert from 1-based to 0-based
                let top = if top > 0 { top - 1 } else { 0 };
                // bottom stays as-is since param is 1-based row and scroll_bottom is exclusive
                if top < bottom && bottom <= state.max_rows {
                    state.scroll_top = top;
                    state.scroll_bottom = bottom;
                } else {
                    state.scroll_top = 0;
                    state.scroll_bottom = state.max_rows;
                }
                // DECSTBM resets cursor to home (respecting origin mode)
                if state.origin_mode {
                    state.text_row = state.scroll_top;
                } else {
                    state.text_row = 0;
                }
                state.text_col = 0;
            }
        }
        b'd' => {
            // VPA — Vertical Position Absolute (1-based)
            state.pending_wrap = false;
            let row = param0 as u32;
            state.text_row = if row > 0 { row - 1 } else { 0 };
            if state.text_row >= state.max_rows {
                state.text_row = state.max_rows - 1;
            }
        }
        b'G' => {
            // CHA — Cursor Character Absolute (1-based)
            state.pending_wrap = false;
            let col = param0 as u32;
            state.text_col = if col > 0 { col - 1 } else { 0 };
            if state.text_col >= state.max_cols {
                state.text_col = state.max_cols - 1;
            }
        }
        b'g' => {
            // TBC — Tab Clear
            match param0_raw {
                0 => {
                    // Clear tab stop at current column
                    if state.text_col < 128 {
                        state.tab_stops &= !(1u128 << state.text_col);
                    }
                }
                3 => {
                    // Clear all tab stops
                    state.tab_stops = 0;
                }
                _ => {}
            }
        }
        b'b' => {
            // REP — Repeat Preceding Graphic Character
            let n = param0 as u32;
            let ch = state.last_printed_char;
            for _ in 0..n {
                super::terminal_putc(state, ch);
            }
        }
        b's' => {
            // Save Cursor Position (ANSI.SYS)
            state.pending_wrap = false;
            state.saved_col = state.text_col;
            state.saved_row = state.text_row;
            state.saved_fg = state.fg;
            state.saved_bg = state.bg;
            state.saved_bold = state.bold;
            state.saved_reverse = state.reverse_video;
        }
        b'u' => {
            // Restore Cursor Position (ANSI.SYS)
            state.pending_wrap = false;
            state.text_col = state.saved_col;
            state.text_row = state.saved_row;
            state.fg = state.saved_fg;
            state.bg = state.saved_bg;
            state.bold = state.saved_bold;
            state.reverse_video = state.saved_reverse;
            if state.text_row >= state.max_rows {
                state.text_row = state.max_rows - 1;
            }
            if state.text_col >= state.max_cols {
                state.text_col = state.max_cols - 1;
            }
        }
        b'n' | b'c' => {
            // DSR / DA — can't respond (output-only), silently ignore
        }
        _ => {
            // Unrecognized CSI command — ignore
        }
    }
}

fn set_dec_mode(state: &mut DisplayState, mode: u16, enable: bool) {
    match mode {
        1 => {
            // DECCKM — Application Cursor Keys (tracked but no response capability)
        }
        5 => {
            // DECSCNM — Reverse Screen
            state.screen_reverse = enable;
            // Redraw entire screen with inverted colors
            let w = state.width;
            let h = state.height;
            super::mark_damage(state, 0, h);
        }
        6 => {
            // DECOM — Origin Mode
            state.origin_mode = enable;
            state.pending_wrap = false;
            if enable {
                state.text_row = state.scroll_top;
            } else {
                state.text_row = 0;
            }
            state.text_col = 0;
        }
        7 => {
            state.autowrap = enable;
        }
        12 => {
            // Cursor blink — ignore
        }
        25 => {
            state.cursor_visible = enable;
        }
        47 | 1049 => {
            if enable {
                super::switch_to_alt_screen(state);
            } else {
                super::switch_to_primary_screen(state);
            }
        }
        1000 | 1002 | 1003 | 1006 => {
            // Mouse tracking modes — ignore (input-side)
        }
        2004 => {
            // Bracketed paste mode — ignore
        }
        _ => {}
    }
}

fn erase_display(state: &mut DisplayState, mode: u16) {
    let gh = super::font::GLYPH_HEIGHT;
    let bg = super::effective_bg(state);
    let w = state.width;

    match mode {
        0 => {
            // Erase below: rest of current line + all lines below
            let col_px = state.text_col * super::font::GLYPH_WIDTH;
            let row_py = state.text_row * gh;
            // Clear rest of current line
            super::fill_rect(state, col_px, row_py, w - col_px, gh, bg);
            // Clear all lines below
            let below_y = (state.text_row + 1) * gh;
            if below_y < state.height {
                super::fill_rect(state, 0, below_y, w, state.height - below_y, bg);
            }
        }
        1 => {
            // Erase above: beginning of screen to cursor
            let row_py = state.text_row * gh;
            // Clear all lines above
            if row_py > 0 {
                super::fill_rect(state, 0, 0, w, row_py, bg);
            }
            // Clear current line up to and including cursor
            let end_px = (state.text_col + 1) * super::font::GLYPH_WIDTH;
            super::fill_rect(state, 0, row_py, end_px, gh, bg);
        }
        2 => {
            // Erase entire display
            super::fill_rect(state, 0, 0, w, state.height, bg);
        }
        _ => {}
    }
}

fn erase_line(state: &mut DisplayState, mode: u16) {
    let gh = super::font::GLYPH_HEIGHT;
    let gw = super::font::GLYPH_WIDTH;
    let bg = super::effective_bg(state);
    let row_py = state.text_row * gh;

    match mode {
        0 => {
            // Erase from cursor to end of line
            let col_px = state.text_col * gw;
            super::fill_rect(state, col_px, row_py, state.width - col_px, gh, bg);
        }
        1 => {
            // Erase from beginning of line to cursor
            let end_px = (state.text_col + 1) * gw;
            super::fill_rect(state, 0, row_py, end_px, gh, bg);
        }
        2 => {
            // Erase entire line
            super::fill_rect(state, 0, row_py, state.width, gh, bg);
        }
        _ => {}
    }
}

fn sgr(state: &mut DisplayState) {
    let count = state.csi_parser.param_count as usize;
    // CSI m with no params means reset
    if count == 0 {
        sgr_apply(state, 0);
        return;
    }
    // Copy params to stack to avoid borrow conflict with sgr_apply(&mut state).
    let mut params = [0u16; 16];
    let n = if count > 16 { 16 } else { count };
    params[..n].copy_from_slice(&state.csi_parser.params[..n]);

    let mut i = 0;
    while i < n {
        let p = params[i];
        match p {
            38 => {
                // Extended foreground color
                if i + 1 < n {
                    match params[i + 1] {
                        5 => {
                            // 256-color: 38;5;n
                            if i + 2 < n {
                                let rgb = color_from_256(params[i + 2]);
                                state.fg = rgb_to_native(state, rgb);
                                i += 3;
                                continue;
                            }
                        }
                        2 => {
                            // Truecolor: 38;2;r;g;b
                            if i + 4 < n {
                                let r = params[i + 2] as u32 & 0xFF;
                                let g = params[i + 3] as u32 & 0xFF;
                                let b = params[i + 4] as u32 & 0xFF;
                                let rgb = (r << 16) | (g << 8) | b;
                                state.fg = rgb_to_native(state, rgb);
                                i += 5;
                                continue;
                            }
                        }
                        _ => {}
                    }
                }
                i += 1;
            }
            48 => {
                // Extended background color
                if i + 1 < n {
                    match params[i + 1] {
                        5 => {
                            // 256-color: 48;5;n
                            if i + 2 < n {
                                let rgb = color_from_256(params[i + 2]);
                                state.bg = rgb_to_native(state, rgb);
                                i += 3;
                                continue;
                            }
                        }
                        2 => {
                            // Truecolor: 48;2;r;g;b
                            if i + 4 < n {
                                let r = params[i + 2] as u32 & 0xFF;
                                let g = params[i + 3] as u32 & 0xFF;
                                let b = params[i + 4] as u32 & 0xFF;
                                let rgb = (r << 16) | (g << 8) | b;
                                state.bg = rgb_to_native(state, rgb);
                                i += 5;
                                continue;
                            }
                        }
                        _ => {}
                    }
                }
                i += 1;
            }
            _ => {
                sgr_apply(state, p);
                i += 1;
            }
        }
    }
}

fn sgr_apply(state: &mut DisplayState, param: u16) {
    match param {
        0 => {
            // Reset all attributes
            state.fg = state.default_fg;
            state.bg = state.default_bg;
            state.bold = false;
            state.dim = false;
            state.italic = false;
            state.underline = false;
            state.blink = false;
            state.reverse_video = false;
            state.hidden = false;
            state.strikethrough = false;
        }
        1 => state.bold = true,
        2 => state.dim = true,
        3 => state.italic = true,
        4 => state.underline = true,
        5 => state.blink = true,
        7 => state.reverse_video = true,
        8 => state.hidden = true,
        9 => state.strikethrough = true,
        21 => state.bold = false,       // xterm: bold off (double underline not supported)
        22 => {
            state.bold = false;
            state.dim = false;
        }
        23 => state.italic = false,
        24 => state.underline = false,
        25 => state.blink = false,
        27 => state.reverse_video = false,
        28 => state.hidden = false,
        29 => state.strikethrough = false,
        30..=37 => {
            // Set foreground color
            let idx = (param - 30) as usize;
            let rgb = if state.bold {
                bright_color(idx)
            } else {
                ANSI_COLORS[idx]
            };
            state.fg = rgb_to_native(state, rgb);
        }
        39 => {
            // Default foreground
            state.fg = state.default_fg;
        }
        40..=47 => {
            // Set background color
            let idx = (param - 40) as usize;
            state.bg = rgb_to_native(state, ANSI_COLORS[idx]);
        }
        49 => {
            // Default background
            state.bg = state.default_bg;
        }
        90..=97 => {
            // Bright foreground
            let idx = (param - 90) as usize;
            state.fg = rgb_to_native(state, bright_color(idx));
        }
        100..=107 => {
            // Bright background
            let idx = (param - 100) as usize;
            state.bg = rgb_to_native(state, bright_color(idx));
        }
        _ => {
            // Unrecognized SGR parameter — ignore
        }
    }
}

fn soft_reset(state: &mut DisplayState) {
    // DECSTR — Soft Terminal Reset
    // Reset modes but don't clear screen or move cursor
    state.autowrap = true;
    state.origin_mode = false;
    state.cursor_visible = true;
    state.screen_reverse = false;
    // Reset SGR
    state.fg = state.default_fg;
    state.bg = state.default_bg;
    state.bold = false;
    state.dim = false;
    state.italic = false;
    state.underline = false;
    state.blink = false;
    state.reverse_video = false;
    state.hidden = false;
    state.strikethrough = false;
    // Reset charsets
    state.g0_charset = 0;
    state.g1_charset = 0;
    state.active_charset = 0;
    // Reset scroll region
    state.scroll_top = 0;
    state.scroll_bottom = state.max_rows;
    state.pending_wrap = false;
}

fn full_reset(state: &mut DisplayState) {
    state.text_col = 0;
    state.text_row = 0;
    state.fg = state.default_fg;
    state.bg = state.default_bg;
    state.bold = false;
    state.dim = false;
    state.italic = false;
    state.underline = false;
    state.blink = false;
    state.reverse_video = false;
    state.hidden = false;
    state.strikethrough = false;
    state.saved_bold = false;
    state.saved_reverse = false;
    state.saved_dim = false;
    state.saved_underline = false;
    state.pending_wrap = false;
    state.autowrap = true;
    state.cursor_visible = true;
    state.saved_col = 0;
    state.saved_row = 0;
    state.saved_fg = state.default_fg;
    state.saved_bg = state.default_bg;
    state.scroll_top = 0;
    state.scroll_bottom = state.max_rows;
    // Reset charsets
    state.g0_charset = 0;
    state.g1_charset = 0;
    state.active_charset = 0;
    state.saved_g0_charset = 0;
    state.saved_g1_charset = 0;
    state.saved_active_charset = 0;
    // Reset DEC modes
    state.origin_mode = false;
    state.screen_reverse = false;
    // Reset tab stops to default (every 8 columns)
    state.tab_stops = 0;
    {
        let mut c = 0u32;
        while c < state.max_cols && c < 128 {
            state.tab_stops |= 1u128 << c;
            c += 8;
        }
    }
    state.osc_saw_esc = false;
    state.last_printed_char = 0x20;
    // Clear entire screen
    let w = state.width;
    let h = state.height;
    let bg = state.bg;
    super::fill_rect(state, 0, 0, w, h, bg);
}
