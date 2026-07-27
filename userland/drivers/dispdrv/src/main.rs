//! SaltyOS Display Server
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Framebuffer display server. Maps the physical framebuffer with
//! write-combining, maintains a shadow buffer for rendering, and
//! serves display requests via IPC.

#![no_std]
#![no_main]

extern crate trona_kernel;
extern crate trona_posix;
extern crate trona_protocol;
extern crate trona_runtime;
extern crate trona_server;

mod font;
mod vt100;

use trona_kernel::core_types::*;
use trona_kernel::invoke;
use trona_kernel::ipc;
use trona_kernel::uapi;
use trona_protocol::common::{TRONA_BUSY, TRONA_INVALID_OPERATION, TRONA_OK, TRONA_OUT_OF_MEMORY};
use trona_protocol::correlation::{
    CORRELATION_BACKEND_DISPDRV, CORRELATION_CLASS_DEV, CORRELATION_HEADER_REG_COUNT,
    CORRELATION_HEADER_REG_START, CORRELATION_KIND_COMPLETION, CORRELATION_KIND_REQUEST,
    CorrelationHeader, ensure_correlation_wire_length,
};
use trona_protocol::display::{
    DISPLAY_FILL_RECT, DISPLAY_GET_INFO, DISPLAY_PRESENT, DISPLAY_SETUP_CONSOLE_RING,
    DISPLAY_SETUP_RING, DISPLAY_WRITE_TEXT,
};
use trona_protocol::namesrv::NAMESRV_REGISTER;
use trona_protocol::vfs::backend::{
    BACKEND_FEATURE_ASYNC_V1, VFS_BACKEND_OPEN_SESSION, VFS_BACKEND_REPLY_INVALID,
    VFS_BACKEND_REPLY_OK,
};
use trona_runtime::core::slot_alloc::TransferCap;
use trona_runtime::debug::framebuffer;

const FB_MAP_VADDR: u64 = 0x0000_0000_5000_0000;
const MAX_DAMAGE_SCANLINES: usize = 8192;
const DAMAGE_WORD_BITS: usize = 64;
const DAMAGE_WORDS: usize = MAX_DAMAGE_SCANLINES / DAMAGE_WORD_BITS;

// slot 3 is kept as procmgr EP for slot_alloc expansion; display service EP is separate.
const CAP_SELF_VSPACE: u64 = 1;
const CAP_SELF_CSPACE: u64 = uapi::KERNITE_CAP_SELF_CSPACE as u64;

const TERM_RING_PAGES: u64 = 4; // matches posix_ttysrv producer
const CONSOLE_RING_PAGES: u64 = 16; // matches console producer
const TERM_RING_HDR_SIZE: usize = 16;
const CONSOLE_RING_HDR_SIZE: usize = 16;
const RECV_SLOT_COUNT: u64 = 8;

const FB_GET_INFO: u64 = 0xA00;
const FB_PRESENT: u64 = 0xA01;
const FB_GET_BACKING_MO: u64 = 0xA02;

static mut RECV_SLOTS: trona_server::recv_slot::RecvSlotArena =
    trona_server::recv_slot::RecvSlotArena::new_empty();
static mut VFS_CALLBACK_EP: u64 = 0;
static mut VFS_SESSION_ID: u32 = 0;

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
    // SHM ring buffer for terminal data from posix_ttysrv
    term_ring_base: *mut u8,
    term_ring_shm_id: u64,
    term_ring_active: bool,
    // SHM ring buffer for display output from console server
    console_ring_base: *mut u8,
    console_ring_shm_id: u64,
    console_ring_active: bool,
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
    active_charset: u8,   // 0=G0, 1=G1 (toggled by SO/SI)
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
        Cell {
            ch: b' ',
            charset: 0,
            flags: 0,
            _pad: 0,
            fg,
            bg,
        }
    }
}

fn cell_idx(state: &DisplayState, col: u32, row: u32) -> usize {
    (row * state.max_cols + col) as usize
}

fn cell_put(state: &mut DisplayState, col: u32, row: u32, ch: u8) {
    if col >= state.max_cols || row >= state.max_rows || state.cells.is_null() {
        return;
    }
    let charset_id = if state.active_charset == 0 {
        state.g0_charset
    } else {
        state.g1_charset
    };
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
        *state.cells.add(idx) = Cell {
            ch,
            charset: charset_id,
            flags,
            _pad: 0,
            fg: state.fg,
            bg: state.bg,
        };
    }
}

fn cell_clear_range(state: &mut DisplayState, col_start: u32, col_end: u32, row: u32) {
    if state.cells.is_null() || row >= state.max_rows {
        return;
    }
    let end = if col_end > state.max_cols {
        state.max_cols
    } else {
        col_end
    };
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
    let end = if row_end > state.max_rows {
        state.max_rows
    } else {
        row_end
    };
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

fn idle() -> ! {
    loop {
        trona_kernel::syscall::yield_now();
    }
}

fn ipc_ctx() -> *mut IpcContext {
    trona_runtime::current_ipc_ctx()
}

fn decode_request_correlation(msg: &TronaMsg) -> Option<CorrelationHeader> {
    if (msg.length as usize) < (CORRELATION_HEADER_REG_START + CORRELATION_HEADER_REG_COUNT) {
        return None;
    }
    let words = [
        msg.regs[CORRELATION_HEADER_REG_START],
        msg.regs[CORRELATION_HEADER_REG_START + 1],
        msg.regs[CORRELATION_HEADER_REG_START + 2],
        msg.regs[CORRELATION_HEADER_REG_START + 3],
    ];
    let header = CorrelationHeader::decode_words(words);
    if header.kind != CORRELATION_KIND_REQUEST
        || header.class != CORRELATION_CLASS_DEV
        || header.backend != CORRELATION_BACKEND_DISPDRV
    {
        return None;
    }
    Some(header)
}

fn stamp_completion_correlation(reply: &mut TronaMsg, request: CorrelationHeader) {
    let words = CorrelationHeader {
        class: request.class,
        backend: request.backend,
        kind: CORRELATION_KIND_COMPLETION,
        flags: 0,
        session: request.session,
        opcode: request.opcode,
        _reserved0: 0,
        token: request.token,
        request_seq: request.request_seq,
        request_seq_secondary: request.request_seq_secondary,
    }
    .encode_words();
    reply.regs[CORRELATION_HEADER_REG_START] = words[0];
    reply.regs[CORRELATION_HEADER_REG_START + 1] = words[1];
    reply.regs[CORRELATION_HEADER_REG_START + 2] = words[2];
    reply.regs[CORRELATION_HEADER_REG_START + 3] = words[3];
    ensure_correlation_wire_length(&mut reply.length);
}

fn handle_backend_open_session(msg: &TronaMsg, reply: &mut TronaMsg) {
    let incoming = unsafe {
        let arena = &mut *(&raw mut RECV_SLOTS);
        trona_server::recv_slot::capture_transferred_cap(ipc_ctx(), arena).unwrap_or(0)
    };
    if incoming == 0 {
        reply.label = VFS_BACKEND_REPLY_INVALID;
        return;
    }
    unsafe {
        let prev = *(&raw const VFS_CALLBACK_EP);
        if prev != 0 && prev != incoming {
            trona_runtime::core::slot_alloc::delete_and_free(prev);
        }
        *(&raw mut VFS_CALLBACK_EP) = incoming;
        *(&raw mut VFS_SESSION_ID) = msg.regs[1] as u32;
    }
    reply.label = VFS_BACKEND_REPLY_OK;
    reply.regs[0] = 8;
    reply.regs[1] = BACKEND_FEATURE_ASYNC_V1;
    reply.regs[2] = 0;
    reply.length = 3;
}

fn handle_get_backing_mo(state: &DisplayState, reply: &mut TronaMsg) -> Option<TransferCap> {
    let fb_untyped = trona_runtime::client::caps::fb_untyped().addr();
    let Some(temp_slot) = trona_runtime::core::slot_alloc::alloc_slot() else {
        reply.label = TRONA_OUT_OF_MEMORY;
        return None;
    };
    let copy_err = trona_kernel::invoke::cnode_copy_ref(
        trona_kernel::core_types::CapRef::flat(CAP_SELF_CSPACE),
        trona_runtime::core::slot_alloc::resolved_cap_ref(fb_untyped),
        trona_kernel::core_types::CapRef::flat(CAP_SELF_CSPACE),
        temp_slot.borrow(),
        // The framebuffer backing egressed to clients never confers EXECUTE —
        // a client may not map device memory executable (W^X).
        (trona_kernel::uapi::KERNITE_RIGHT_ALL & !trona_kernel::uapi::KERNITE_RIGHT_EXECUTE) as u64,
    );
    if copy_err != 0 {
        // copy failed: `temp_slot` (OwnedSlot) Drop frees the empty slot.
        reply.label = copy_err as u64;
        return None;
    }
    // The copy landed a cap; adopt the slot as an OwnedCap and transfer it.
    let tc = temp_slot.assume_filled().into_transfer();
    unsafe {
        ipc::set_send_cap_ctx(ipc_ctx(), 0, tc.slot());
    }
    reply.label = TRONA_OK;
    reply.regs[0] = state.height as u64 * state.pitch as u64;
    reply.length = 1;
    Some(tc)
}

unsafe fn release_staged_cap(ctx: *mut IpcContext, cap_tc: Option<TransferCap>) {
    if cap_tc.is_none() {
        return;
    }
    unsafe {
        ipc::clear_send_caps_ctx(ctx);
    }
    drop(cap_tc);
}

/// Cookie for the single service-pipe `STATE_READABLE` Watch (kind 0, slot 0,
/// generation 1). dispdrv's only input source is the service pipe.
const DISPDRV_SERVICE_COOKIE: u64 = trona_server::event_loop::encode_cookie(0, 0, 1);

/// Single-source reactor dispatcher. The reactor blocks on the service pipe;
/// `dispatch_state` preserves the former `finish_request` reply routing —
/// correlated requests reply to `VFS_CALLBACK_EP`, direct ones reply on the
/// service pipe — and recycles the recv-slot arena in `prepare_mp_read`.
struct DispdrvDispatcher {
    recv_ep: Cap,
    watch_cap: Cap,
    eq_cap: Cap,
    state: *mut DisplayState,
}

impl trona_server::event_loop::EqDispatcher for DispdrvDispatcher {
    fn resolve_mp_recv(&self, _cookie: u64) -> Option<Cap> {
        Some(self.recv_ep)
    }

    fn dispatch_state(
        &mut self,
        _cookie: u64,
        msg: &TronaMsg,
        _meta: trona_server::event_loop::MpReadMeta,
    ) -> i32 {
        // SAFETY: single-threaded reactor; `state` points at main's live
        // DisplayState (the reactor loop never returns).
        let state = unsafe { &mut *self.state };
        let mut reply = TronaMsg::zeroed();
        let request_correlation = decode_request_correlation(msg);
        let mut cap_to_free: Option<TransferCap> = None;

        match msg.label {
            VFS_BACKEND_OPEN_SESSION => handle_backend_open_session(msg, &mut reply),
            DISPLAY_GET_INFO => handle_get_info(state, &mut reply),
            FB_GET_INFO => handle_get_info(state, &mut reply),
            DISPLAY_PRESENT => handle_present(state, &mut reply),
            FB_PRESENT => handle_present(state, &mut reply),
            FB_GET_BACKING_MO => {
                cap_to_free = handle_get_backing_mo(state, &mut reply);
            }
            DISPLAY_FILL_RECT => handle_fill_rect(state, msg, &mut reply),
            DISPLAY_WRITE_TEXT => handle_write_text(state, msg, &mut reply),
            DISPLAY_SETUP_RING => handle_setup_ring(state, msg, &mut reply),
            DISPLAY_SETUP_CONSOLE_RING => handle_setup_console_ring(state, msg, &mut reply),
            _ => reply.label = TRONA_INVALID_OPERATION,
        }

        let ctx = ipc_ctx();
        // SAFETY: `ctx` is this thread's IPC context. Mirrors finish_request's
        // reply routing without the read (the reactor owns the read).
        unsafe {
            if let Some(header) = request_correlation {
                stamp_completion_correlation(&mut reply, header);
                let ep = *(&raw const VFS_CALLBACK_EP);
                if ep != 0 {
                    let _ = ipc::mp_write_ctx(ctx, ep, &raw const reply);
                }
                release_staged_cap(ctx, cap_to_free);
            } else {
                let _ = ipc::mp_write_reply_ctx(ctx, self.recv_ep, &raw const reply);
                release_staged_cap(ctx, cap_to_free);
            }
        }
        0
    }

    fn prepare_mp_read(&mut self, _cookie: u64) -> bool {
        // Recycle the recv-slot arena before the next MP_READ (cap receiving),
        // mirroring the former finish_request recycle timing.
        // SAFETY: single-threaded reactor owns RECV_SLOTS.
        unsafe {
            (&mut *(&raw mut RECV_SLOTS)).recycle_for_next_recv(ipc_ctx(), CAP_SELF_CSPACE);
        }
        true
    }

    fn rearm_state_source(&mut self, _cookie: u64) -> i32 {
        trona_kernel::invoke::watch_register(
            trona_kernel::core_types::CapRef::flat(self.watch_cap),
            trona_kernel::core_types::CapRef::flat(self.recv_ep),
            trona_kernel::core_types::CapRef::flat(self.eq_cap),
            uapi::KERNITE_STATE_READABLE as u64,
            DISPDRV_SERVICE_COOKIE,
        )
    }

    fn handle_overflow(&mut self, _dropped: u64) {}

    fn handle_timer(&mut self, _cookie: u64) {}
}

fn pack_color(r: u8, g: u8, b: u8, rp: u8, gp: u8, bp: u8) -> u32 {
    ((r as u32) << rp) | ((g as u32) << gp) | ((b as u32) << bp)
}

fn mark_damage(state: &mut DisplayState, y_start: u32, y_end: u32) {
    let start = if y_start > state.height {
        state.height
    } else {
        y_start
    };
    let end = if y_end > state.height {
        state.height
    } else {
        y_end
    };
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
    if state.shadow.is_null() {
        return;
    }
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
    if state.shadow.is_null() || state.vram.is_null() {
        return;
    }
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
            3 => (*src as u32) | ((*src.add(1) as u32) << 8) | ((*src.add(2) as u32) << 16),
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
    if state.shadow.is_null() {
        return;
    }
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
    if state.shadow.is_null() {
        return;
    }
    let pitch = state.pitch as usize;
    let bpp_bytes = (state.bpp / 8) as usize;

    let x_end = if x + w > state.width {
        state.width
    } else {
        x + w
    };
    let y_end = if y + h > state.height {
        state.height
    } else {
        y + h
    };

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
    if state.shadow.is_null() {
        return;
    }
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
    if state.shadow.is_null() {
        return;
    }
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
    if state.shadow.is_null() {
        return;
    }
    let gh = font::GLYPH_HEIGHT;
    let row_bytes = gh as usize * state.pitch as usize;
    let max = state.scroll_bottom;
    if at_row >= max {
        return;
    }
    let count = if at_row + count > max {
        max - at_row
    } else {
        count
    };
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
    if state.shadow.is_null() {
        return;
    }
    let gh = font::GLYPH_HEIGHT;
    let row_bytes = gh as usize * state.pitch as usize;
    let max = state.scroll_bottom;
    if at_row >= max {
        return;
    }
    let count = if at_row + count > max {
        max - at_row
    } else {
        count
    };
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
    if state.shadow.is_null() {
        return;
    }
    let gw = font::GLYPH_WIDTH;
    let gh = font::GLYPH_HEIGHT;
    let col = state.text_col;
    let row = state.text_row;
    let max_cols = state.max_cols;
    if col >= max_cols {
        return;
    }
    let count = if col + count > max_cols {
        max_cols - col
    } else {
        count
    };
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
    if state.shadow.is_null() {
        return;
    }
    let gw = font::GLYPH_WIDTH;
    let gh = font::GLYPH_HEIGHT;
    let col = state.text_col;
    let row = state.text_row;
    let max_cols = state.max_cols;
    if col >= max_cols {
        return;
    }
    let count = if col + count > max_cols {
        max_cols - col
    } else {
        count
    };
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
    let count = if col + count > max_cols {
        max_cols - col
    } else {
        count
    };
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
            trona_runtime::client::mm::mmap(
                core::ptr::null_mut(),
                (fb_size + 4095) & !4095u64,
                0x3,  // PROT_READ | PROT_WRITE
                0x22, // MAP_PRIVATE | MAP_ANONYMOUS
                -1,
                0,
            )
            .unwrap_or(usize::MAX as *mut u8)
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
            trona_runtime::client::mm::mmap(
                core::ptr::null_mut(),
                cell_len,
                0x3,  // PROT_READ | PROT_WRITE
                0x22, // MAP_PRIVATE | MAP_ANONYMOUS
                -1,
                0,
            )
            .unwrap_or(usize::MAX as *mut u8)
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
        let next = if next > state.max_cols {
            state.max_cols
        } else {
            next
        };
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

    let map_flags = (uapi::KERNITE_PAGE_FLAG_WRITABLE
        | uapi::KERNITE_PAGE_FLAG_USER
        | uapi::KERNITE_PAGE_FLAG_NOCACHE) as u64;

    let (err, mapped) = invoke::vspace_map_device_range(
        trona_kernel::core_types::CapRef::flat(CAP_SELF_VSPACE),
        trona_runtime::client::caps::fb_untyped().cap_ref(),
        0,
        FB_MAP_VADDR,
        num_pages,
        map_flags,
    );

    if err != 0 || mapped != num_pages {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[dispdrv] FB batch map failed: err=");
            _lb.hex(err as u64);
            _lb.str(b" mapped=");
            _lb.hex(mapped);
            _lb.str(b"/");
            _lb.hex(num_pages);
            _lb.str(b"\n");
        });
        return false;
    }

    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[dispdrv] Mapped ");
        _lb.hex(num_pages);
        _lb.str(b" FB pages at ");
        _lb.hex(FB_MAP_VADDR);
        _lb.str(b" (WC)\n");
    });

    true
}

fn alloc_shadow_buffer(fb_size: u64) -> *mut u8 {
    let len = (fb_size + 4095) & !4095u64;
    let ptr = unsafe {
        trona_runtime::client::mm::mmap(
            core::ptr::null_mut(),
            len,
            0x3,  // PROT_READ | PROT_WRITE
            0x22, // MAP_PRIVATE | MAP_ANONYMOUS
            -1,
            0,
        )
        .unwrap_or(usize::MAX as *mut u8)
    };
    if ptr == usize::MAX as *mut u8 || ptr.is_null() {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[dispdrv] Shadow buffer posix_mmap failed\n");
        });
        return core::ptr::null_mut();
    }

    trona_runtime::udebug!(|_lb| {
        _lb.str(b"[dispdrv] Shadow buffer: ");
        _lb.hex(len / 4096);
        _lb.str(b" pages at ");
        _lb.hex(ptr as u64);
        _lb.str(b"\n");
    });

    ptr
}

fn register_with_namesrv() -> bool {
    const ENTRY_FLAG_BADGE_AS_CALLER: u64 = 1 << 0;
    const REGISTER_FLAGS_REG: usize = 31;

    let mut reg_msg = TronaMsg::zeroed();
    let mut reg_reply = TronaMsg::zeroed();
    let svc_name = b"dispdrv";
    reg_msg.label = NAMESRV_REGISTER;
    reg_msg.regs[0] = svc_name.len() as u64;
    let ns_dst = &raw mut reg_msg.regs[1] as *mut u8;
    // SAFETY: Writing name bytes into message register area.
    unsafe {
        for i in 0..svc_name.len() {
            *ns_dst.add(i) = svc_name[i];
        }
    }
    reg_msg.regs[REGISTER_FLAGS_REG] = ENTRY_FLAG_BADGE_AS_CALLER;
    reg_msg.length = (REGISTER_FLAGS_REG + 1) as u64;

    let Some(publish_tc) = trona_runtime::client::caps::service_client_ep_for_transfer() else {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[dispdrv] No service client ep to publish\n");
        });
        return false;
    };
    unsafe {
        ipc::set_send_cap_ctx(ipc_ctx(), 0, publish_tc.slot());
        let err = ipc::mp_call_ctx(
            ipc_ctx(),
            trona_runtime::client::caps::namesrv_ep().addr(),
            &raw const reg_msg,
            &raw mut reg_reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        drop(publish_tc);
        if err == 0 && reg_reply.label == TRONA_OK {
            trona_runtime::uinfo!(|_lb| {
                _lb.str(b"[dispdrv] registered with namesrv\n");
            });
            return true;
        }
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[dispdrv] namesrv register failed: err=");
            _lb.hex(err as u64);
            _lb.str(b" label=");
            _lb.hex(reg_reply.label);
            _lb.str(b"\n");
        });
        false
    }
}

fn handle_get_info(state: &DisplayState, reply: &mut TronaMsg) {
    reply.label = TRONA_OK;
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

fn handle_fill_rect(state: &mut DisplayState, msg: &TronaMsg, reply: &mut TronaMsg) {
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
    reply.label = TRONA_OK;
}

fn handle_write_text(state: &mut DisplayState, msg: &TronaMsg, reply: &mut TronaMsg) {
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
    reply.label = TRONA_OK;
}

/// Drain all available bytes from the SHM terminal ring and process through VT100.
fn drain_terminal_ring(state: &mut DisplayState) {
    if state.term_ring_base.is_null() {
        return;
    }
    // Undraw cursor before processing so a stale cursor glyph is not
    // left behind at the previous location while we push new bytes.
    if state.cursor_drawn {
        invert_cursor_cell(state, state.drawn_col, state.drawn_row);
        state.cursor_drawn = false;
    }
    let base = state.term_ring_base;
    // SAFETY: SHM is mapped and ring header is at base.
    unsafe {
        let ring_size = core::ptr::read_volatile(base.add(8) as *const u32) as usize;
        if ring_size == 0 {
            return;
        }
        let mut buf = [0u8; 256];
        loop {
            let head = core::ptr::read_volatile(base as *const u32) as usize;
            // Acquire: observe producer's data writes before reading ring contents.
            // Required on ARM (weak ordering); x86 TSO provides this implicitly.
            core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
            let tail = core::ptr::read_volatile(base.add(4) as *const u32) as usize;
            let available = (head + ring_size - tail) % ring_size;
            if available == 0 {
                break;
            }
            let count = core::cmp::min(available, buf.len());
            let dp = base.add(TERM_RING_HDR_SIZE);
            let mut i = 0usize;
            while i < count {
                buf[i] = core::ptr::read_volatile(dp.add((tail + i) % ring_size));
                i += 1;
            }
            // Release: all data reads above complete before the tail update
            // that publishes free space to the producer.
            core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
            core::ptr::write_volatile(base.add(4) as *mut u32, ((tail + count) % ring_size) as u32);
            for i in 0..count {
                vt100::process_byte(state, buf[i]);
            }
        }
    }
}

/// Handle DISPLAY_SETUP_RING: map the caller's SHM as the terminal ring.
/// Producers kick the display service endpoint with DISPLAY_PRESENT after
/// publishing bytes.
fn handle_setup_ring(state: &mut DisplayState, msg: &TronaMsg, reply: &mut TronaMsg) {
    let shm_id = msg.regs[0];

    if state.term_ring_active && !state.term_ring_base.is_null() {
        if state.term_ring_shm_id == shm_id {
            // The producer can replay setup after observing a stale
            // readiness signal. Treat it as idempotent so mmsrv is not
            // asked to map over the existing fixed ring VA.
            reply.label = TRONA_OK;
            reply.regs[0] = 0;
            reply.length = 1;
        } else {
            reply.label = TRONA_BUSY;
        }
        return;
    }

    // The producer created the ring under a well-known name; create-by-name
    // returns the same MO (with our own cap) so we can map it RW at the fixed
    // ring VA (we update the tail pointer). `shm_map` consumes the cap, so the
    // local slot is freed afterward.
    let bytes = TERM_RING_PAGES * 4096;
    let (shm_idx, shm_cap) = match trona_runtime::client::mm::shm_create(shm_id, bytes) {
        Ok(v) => v,
        Err(_) => {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[dispdrv] ring: SHM create-existing failed\n");
            });
            reply.label = TRONA_INVALID_OPERATION;
            return;
        }
    };
    // mmsrv auto-places the consumer's mapping in its mmap window; the ring
    // is position-independent, so use the returned VA as the base.
    let map_res =
        trona_runtime::client::mm::shm_map(shm_idx, shm_cap.into_transfer(), 0, bytes, 0x3);
    let ring_va = match map_res {
        Ok(va) => va,
        Err(_) => {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[dispdrv] ring: SHM map failed\n");
            });
            reply.label = TRONA_INVALID_OPERATION;
            return;
        }
    };

    state.term_ring_base = ring_va as *mut u8;
    state.term_ring_shm_id = shm_id;
    state.term_ring_active = true;

    reply.label = TRONA_OK;
    reply.regs[0] = 0; // bit index: terminal ring = bit 0
    reply.length = 1;
    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[dispdrv] Terminal ring buffer active\n");
    });
}

/// Drain all available bytes from the console SHM ring and process through VT100.
fn drain_console_ring(state: &mut DisplayState) {
    if state.console_ring_base.is_null() {
        return;
    }
    if state.cursor_drawn {
        invert_cursor_cell(state, state.drawn_col, state.drawn_row);
        state.cursor_drawn = false;
    }
    let base = state.console_ring_base;
    // SAFETY: SHM is mapped and ring header is at base.
    unsafe {
        let ring_size = core::ptr::read_volatile(base.add(8) as *const u32) as usize;
        if ring_size == 0 {
            return;
        }
        let mut buf = [0u8; 256];
        loop {
            let head = core::ptr::read_volatile(base as *const u32) as usize;
            core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
            let tail = core::ptr::read_volatile(base.add(4) as *const u32) as usize;
            let available = (head + ring_size - tail) % ring_size;
            if available == 0 {
                break;
            }
            let count = core::cmp::min(available, buf.len());
            let dp = base.add(CONSOLE_RING_HDR_SIZE);
            let mut i = 0usize;
            while i < count {
                buf[i] = core::ptr::read_volatile(dp.add((tail + i) % ring_size));
                i += 1;
            }
            core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
            core::ptr::write_volatile(base.add(4) as *mut u32, ((tail + count) % ring_size) as u32);
            for i in 0..count {
                vt100::process_byte(state, buf[i]);
            }
        }
    }
}

/// Handle DISPLAY_SETUP_CONSOLE_RING: map the caller's SHM as the
/// console display ring. Producers kick the display service endpoint
/// with DISPLAY_PRESENT after publishing bytes.
fn handle_setup_console_ring(state: &mut DisplayState, msg: &TronaMsg, reply: &mut TronaMsg) {
    let shm_id = msg.regs[0];

    if state.console_ring_active && !state.console_ring_base.is_null() {
        if state.console_ring_shm_id == shm_id {
            reply.label = TRONA_OK;
            reply.regs[0] = 1;
            reply.length = 1;
        } else {
            reply.label = TRONA_BUSY;
        }
        return;
    }

    // Create-by-name to obtain our own cap to the producer's SHM, then map it
    // RW at the fixed console ring VA (we update the tail pointer). `shm_map`
    // consumes the cap, so the local slot is freed afterward.
    let bytes = CONSOLE_RING_PAGES * 4096;
    let (shm_idx, shm_cap) = match trona_runtime::client::mm::shm_create(shm_id, bytes) {
        Ok(v) => v,
        Err(_) => {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[dispdrv] console ring: SHM create-existing failed\n");
            });
            reply.label = TRONA_INVALID_OPERATION;
            return;
        }
    };
    // Position-independent consumer mapping: use the returned VA as the base.
    let map_res =
        trona_runtime::client::mm::shm_map(shm_idx, shm_cap.into_transfer(), 0, bytes, 0x3);
    let ring_va = match map_res {
        Ok(va) => va,
        Err(_) => {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[dispdrv] console ring: SHM map failed\n");
            });
            reply.label = TRONA_INVALID_OPERATION;
            return;
        }
    };

    state.console_ring_base = ring_va as *mut u8;
    state.console_ring_shm_id = shm_id;
    state.console_ring_active = true;

    reply.label = TRONA_OK;
    reply.regs[0] = 1; // bit index: console display ring = bit 1
    reply.length = 1;
    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[dispdrv] Console ring buffer active\n");
    });
}

fn handle_present(state: &mut DisplayState, reply: &mut TronaMsg) {
    let mut drained_any = false;
    if state.term_ring_active {
        drain_terminal_ring(state);
        drained_any = true;
    }
    if state.console_ring_active {
        drain_console_ring(state);
        drained_any = true;
    }
    if drained_any {
        flush_damage(state);
    }
    flush_damage(state);
    reply.label = TRONA_OK;
}

#[unsafe(no_mangle)]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[dispdrv] Display server starting\n");
    });

    let fb = unsafe { framebuffer::read_framebuffer_info() };

    let mut vram_ptr: *mut u8 = core::ptr::null_mut();
    let mut shadow_ptr: *mut u8 = core::ptr::null_mut();
    let mut fb_width = 0u32;
    let mut fb_height = 0u32;
    let mut fb_pitch = 0u32;
    let mut fb_bpp = 0u8;
    let mut fb_red_pos = 0u8;
    let mut fb_green_pos = 0u8;
    let mut fb_blue_pos = 0u8;
    let mut fb_red_size = 0u8;
    let mut fb_green_size = 0u8;
    let mut fb_blue_size = 0u8;

    if let Some(ref fb) = fb {
        fb_width = fb.width;
        fb_height = fb.height;
        fb_pitch = fb.pitch;
        fb_bpp = fb.bpp;
        fb_red_pos = fb.red_pos;
        fb_green_pos = fb.green_pos;
        fb_blue_pos = fb.blue_pos;
        fb_red_size = fb.red_size;
        fb_green_size = fb.green_size;
        fb_blue_size = fb.blue_size;

        trona_runtime::uinfo!(|_lb| {
            _lb.str(b"[dispdrv] FB: ");
            _lb.dec(fb.width as u64);
            _lb.str(b"x");
            _lb.dec(fb.height as u64);
            _lb.str(b" bpp=");
            _lb.dec(fb.bpp as u64);
            _lb.str(b" pitch=");
            _lb.dec(fb.pitch as u64);
            _lb.str(b"\n");
        });

        if map_framebuffer(fb) {
            vram_ptr = FB_MAP_VADDR as *mut u8;
            let fb_size = fb.height as u64 * fb.pitch as u64;
            shadow_ptr = alloc_shadow_buffer(fb_size);

            if !shadow_ptr.is_null() {
                // SAFETY: Both VRAM and shadow are mapped with sufficient size.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        vram_ptr as *const u8,
                        shadow_ptr,
                        fb_size as usize,
                    );
                }
            }
        }
    }

    if fb.is_none() {
        trona_runtime::uwarn!(|_lb| {
            _lb.str(b"[dispdrv] No framebuffer detected, running degraded\n");
        });
    } else if vram_ptr.is_null() {
        trona_runtime::uwarn!(|_lb| {
            _lb.str(b"[dispdrv] Framebuffer mapping failed, running degraded\n");
        });
    } else if shadow_ptr.is_null() {
        trona_runtime::uwarn!(|_lb| {
            _lb.str(b"[dispdrv] Shadow buffer allocation failed, running degraded\n");
        });
    }

    let fg_val = if !shadow_ptr.is_null() {
        pack_color(0xCC, 0xCC, 0xCC, fb_red_pos, fb_green_pos, fb_blue_pos)
    } else {
        0
    };
    let bg_val = if !shadow_ptr.is_null() {
        pack_color(0x00, 0x00, 0x00, fb_red_pos, fb_green_pos, fb_blue_pos)
    } else {
        0
    };

    let max_cols = if fb_width > 0 {
        fb_width / font::GLYPH_WIDTH
    } else {
        0
    };
    let max_rows = if fb_height > 0 {
        fb_height / font::GLYPH_HEIGHT
    } else {
        0
    };

    let mut default_tabs: u128 = 0;
    {
        let mut c = 0u32;
        while c < max_cols && c < 128 {
            default_tabs |= 1u128 << c;
            c += 8;
        }
    }

    let mut state = DisplayState {
        vram: vram_ptr,
        shadow: shadow_ptr,
        width: fb_width,
        height: fb_height,
        pitch: fb_pitch,
        bpp: fb_bpp,
        red_pos: fb_red_pos,
        green_pos: fb_green_pos,
        blue_pos: fb_blue_pos,
        red_size: fb_red_size,
        green_size: fb_green_size,
        blue_size: fb_blue_size,
        text_col: 0,
        text_row: 0,
        max_cols,
        max_rows,
        scroll_top: 0,
        scroll_bottom: max_rows,
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
        damage_min_y: fb_height,
        damage_max_y: 0,
        damage_rows: [0; DAMAGE_WORDS],
        term_ring_base: core::ptr::null_mut(),
        term_ring_shm_id: 0,
        term_ring_active: false,
        console_ring_base: core::ptr::null_mut(),
        console_ring_shm_id: 0,
        console_ring_active: false,
        alt_shadow: core::ptr::null_mut(),
        alt_active: false,
        primary_col: 0,
        primary_row: 0,
        primary_fg: fg_val,
        primary_bg: bg_val,
        primary_scroll_top: 0,
        primary_scroll_bottom: max_rows,
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

    if !vram_ptr.is_null() && !shadow_ptr.is_null() {
        trona_kernel::syscall::invoke(
            trona_runtime::client::caps::kernel_debug_cap().addr(),
            uapi::KERNITE_INV_KDEBUG_CONSOLE_CONTROL as u64,
            0,
            0,
            0,
            0,
        );
        trona_runtime::uinfo!(|_lb| {
            _lb.str(b"[dispdrv] Kernel console disabled, display server owns FB\n");
        });

        {
            let grid = (max_cols * max_rows) as usize;
            let cell_bytes = grid * core::mem::size_of::<Cell>();
            let cell_len = ((cell_bytes as u64) + 4095) & !4095u64;
            let ptr = unsafe {
                trona_runtime::client::mm::mmap(core::ptr::null_mut(), cell_len, 0x3, 0x22, -1, 0)
                    .unwrap_or(usize::MAX as *mut u8)
            };
            if ptr != usize::MAX as *mut u8 && !ptr.is_null() {
                state.cells = ptr as *mut Cell;
                for i in 0..grid {
                    // SAFETY: Just-allocated buffer, i < grid.
                    unsafe {
                        *state.cells.add(i) = Cell::blank(fg_val, bg_val);
                    }
                }
            }
        }

        let w = state.width;
        let h = state.height;
        let bg = state.bg;
        fill_rect(&mut state, 0, 0, w, h, bg);
        flush_damage(&mut state);
    }

    unsafe {
        let allocator = trona_server::recv_slot::SlotAllocator {
            alloc_consecutive: trona_runtime::core::slot_alloc::slot_alloc_consecutive_cb,
            invoke_depth: trona_runtime::core::slot_alloc::slot_invoke_depth_cb,
        };
        let arena = &mut *(&raw mut RECV_SLOTS);
        if !arena.init_with_allocator(allocator, RECV_SLOT_COUNT) {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[dispdrv] FATAL: recv-slot arena allocation failed\n");
            });
            return -1;
        }
        arena.arm_first(ipc_ctx(), CAP_SELF_CSPACE);
    }

    register_with_namesrv();

    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[dispdrv] Ready, entering server loop\n");
    });

    // Single-source EventLoop reactor on the service pipe. `dispatch_state`
    // preserves the former finish_request reply routing (VFS callback EP for
    // correlated requests, service pipe otherwise); the recv-slot arena
    // (armed above) is recycled in `prepare_mp_read`. Replaces the former
    // mp_write_reply_read loop, which spun on WOULD_BLOCK once MP_READ became
    // non-blocking.
    let ctx = ipc_ctx();
    let recv_ep = trona_runtime::client::caps::service_recv_ep().addr();
    let eq =
        trona_runtime::core::slot_alloc::rsrc_alloc_object(uapi::KERNITE_OBJ_EVENT_QUEUE as u64, 4);
    let watch =
        trona_runtime::core::slot_alloc::rsrc_alloc_object(uapi::KERNITE_OBJ_WATCH as u64, 0);
    let (eq, watch) = match (eq, watch) {
        (Some(eq), Some(watch)) => (eq, watch),
        _ => {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[dispdrv] reactor EventQueue/Watch alloc failed\n");
            });
            idle();
        }
    };
    let eq_cap = eq.borrow().addr();
    let watch_cap = watch.borrow().addr();
    let _ = trona_kernel::invoke::watch_register(
        trona_kernel::core_types::CapRef::flat(watch_cap),
        trona_kernel::core_types::CapRef::flat(recv_ep),
        trona_kernel::core_types::CapRef::flat(eq_cap),
        uapi::KERNITE_STATE_READABLE as u64,
        DISPDRV_SERVICE_COOKIE,
    );
    core::mem::forget(eq);
    core::mem::forget(watch);
    let mut reactor = trona_server::event_loop::EventLoop::new(
        eq_cap,
        DispdrvDispatcher {
            recv_ep,
            watch_cap,
            eq_cap,
            state: &raw mut state,
        },
    );
    loop {
        // SAFETY: `ctx` is this thread's IPC context; block on the EQ and
        // dispatch one ready event (recv-slot recycle happens in
        // prepare_mp_read).
        unsafe {
            let _ = reactor.run_iteration(ctx);
        }
    }
}
