//! SaltyOS Display Server
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Framebuffer display server. Maps the physical framebuffer with
//! write-combining, maintains a shadow buffer for rendering, and
//! serves display requests via IPC.

#![no_std]
#![no_main]

extern crate salty;

mod font;

use salty::consts::*;
use salty::framebuffer;
use salty::invoke;
use salty::ipc;
use salty::serial;
use salty::serial::LineBuf;
use salty::syscall::syscall;
use salty::types::*;

const IPC_BUF_VADDR: u64 = 0x0000_0000_0020_0000;
const FB_MAP_VADDR: u64 = 0x0000_0000_3000_0000;
const SHADOW_BUF_VADDR: u64 = 0x0000_0000_3800_0000;

const CAP_SERVER_EP: u64 = 5;
const FRAME_SLOT_BASE: u64 = 64;
const UNTYPED_SCAN_COUNT: u64 = 16;

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
    fg: u32,
    bg: u32,
    damage_min_y: u32,
    damage_max_y: u32,
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
    &raw mut salty::__salty_ipc_ctx
}

fn signal_ready() {
    let _ = syscall(SYS_SIGNAL, CAP_READINESS_NTFN, 1, 0, 0, 0, 0);
}

fn pack_color(r: u8, g: u8, b: u8, rp: u8, gp: u8, bp: u8) -> u32 {
    ((r as u32) << rp) | ((g as u32) << gp) | ((b as u32) << bp)
}

fn mark_damage(state: &mut DisplayState, y_start: u32, y_end: u32) {
    if y_start < state.damage_min_y {
        state.damage_min_y = y_start;
    }
    if y_end > state.damage_max_y {
        state.damage_max_y = y_end;
    }
}

fn flush_damage(state: &mut DisplayState) {
    if state.damage_min_y >= state.damage_max_y {
        return;
    }
    let min_y = state.damage_min_y;
    let max_y = if state.damage_max_y > state.height {
        state.height
    } else {
        state.damage_max_y
    };
    let start_offset = min_y as usize * state.pitch as usize;
    let end_offset = max_y as usize * state.pitch as usize;
    let len = end_offset - start_offset;
    // SAFETY: Both shadow and vram are mapped with sufficient size.
    unsafe {
        core::ptr::copy_nonoverlapping(
            state.shadow.add(start_offset),
            state.vram.add(start_offset),
            len,
        );
    }
    state.damage_min_y = state.height;
    state.damage_max_y = 0;
}

fn draw_glyph(state: &mut DisplayState, c: u8, col: u32, row: u32) {
    let gw = font::GLYPH_WIDTH;
    let gh = font::GLYPH_HEIGHT;
    let px = col * gw;
    let py = row * gh;

    if px + gw > state.width || py + gh > state.height {
        return;
    }

    let glyph_offset = (c as usize) * (gh as usize);
    let pitch = state.pitch as usize;
    let bpp_bytes = (state.bpp / 8) as usize;

    for gy in 0..gh as usize {
        let row_bits = font::FONT_DATA[glyph_offset + gy];
        let y_off = (py as usize + gy) * pitch;
        for gx in 0..gw as usize {
            let pixel = if (row_bits >> (7 - gx)) & 1 != 0 {
                state.fg
            } else {
                state.bg
            };
            let off = y_off + (px as usize + gx) * bpp_bytes;
            // SAFETY: Bounds checked above, shadow buffer is mapped.
            unsafe {
                let dst = state.shadow.add(off) as *mut u32;
                core::ptr::write(dst, pixel);
            }
        }
    }

    mark_damage(state, py, py + gh);
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
                let dst = state.shadow.add(off) as *mut u32;
                core::ptr::write(dst, color);
            }
        }
    }

    mark_damage(state, y, y_end);
}

fn scroll_up(state: &mut DisplayState) {
    let gh = font::GLYPH_HEIGHT;
    let row_bytes = gh as usize * state.pitch as usize;
    let total_text_bytes = state.max_rows as usize * row_bytes;

    // SAFETY: shadow buffer covers the full framebuffer.
    unsafe {
        core::ptr::copy(
            state.shadow.add(row_bytes),
            state.shadow,
            total_text_bytes - row_bytes,
        );
    }

    let last_row_y = (state.max_rows - 1) * gh;
    fill_rect(state, 0, last_row_y, state.width, gh, state.bg);

    mark_damage(state, 0, state.height);
}

fn terminal_putc(state: &mut DisplayState, c: u8) {
    if c == b'\n' {
        state.text_col = 0;
        state.text_row += 1;
        if state.text_row >= state.max_rows {
            state.text_row = state.max_rows - 1;
            scroll_up(state);
        }
        return;
    }
    if c == b'\r' {
        state.text_col = 0;
        return;
    }
    if c == 0x08 {
        // Backspace
        if state.text_col > 0 {
            state.text_col -= 1;
            draw_glyph(state, b' ', state.text_col, state.text_row);
        }
        return;
    }
    if c == b'\t' {
        let next = (state.text_col + 8) & !7;
        let next = if next > state.max_cols { state.max_cols } else { next };
        while state.text_col < next {
            draw_glyph(state, b' ', state.text_col, state.text_row);
            state.text_col += 1;
        }
        if state.text_col >= state.max_cols {
            state.text_col = 0;
            state.text_row += 1;
            if state.text_row >= state.max_rows {
                state.text_row = state.max_rows - 1;
                scroll_up(state);
            }
        }
        return;
    }

    draw_glyph(state, c, state.text_col, state.text_row);
    state.text_col += 1;
    if state.text_col >= state.max_cols {
        state.text_col = 0;
        state.text_row += 1;
        if state.text_row >= state.max_rows {
            state.text_row = state.max_rows - 1;
            scroll_up(state);
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

fn alloc_shadow_buffer(num_pages: u64) -> bool {
    let mut next_slot = FRAME_SLOT_BASE;

    for i in 0..num_pages {
        let frame_slot = next_slot;
        next_slot += 1;

        let mut allocated = false;
        for ut in CAP_UNTYPED_START..(CAP_UNTYPED_START + UNTYPED_SCAN_COUNT) {
            let err = invoke::untyped_retype(ut, OBJ_FRAME, 0, frame_slot);
            if err == 0 {
                allocated = true;
                break;
            }
        }
        if !allocated {
            let mut lb = LineBuf::new();
            lb.str(b"[DISPLAY] Shadow alloc failed at page ");
            lb.hex(i);
            lb.str(b"\n");
            lb.flush();
            return false;
        }

        let vaddr = SHADOW_BUF_VADDR + i * 4096;
        let flags = VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER;
        let err = invoke::vspace_map(CAP_SELF_VSPACE, frame_slot, vaddr, flags);
        if err != 0 {
            let mut lb = LineBuf::new();
            lb.str(b"[DISPLAY] Shadow map failed at page ");
            lb.hex(i);
            lb.str(b" err=");
            lb.hex(err as u64);
            lb.str(b"\n");
            lb.flush();
            return false;
        }
    }

    {
        let mut lb = LineBuf::new();
        lb.str(b"[DISPLAY] Allocated ");
        lb.hex(num_pages);
        lb.str(b" shadow pages at ");
        lb.hex(SHADOW_BUF_VADDR);
        lb.str(b"\n");
        lb.flush();
    }

    true
}

fn register_with_nameserv() -> bool {
    let mut reg_msg = SaltyMsg::zeroed();
    let mut reg_reply = SaltyMsg::zeroed();
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
        if err == 0 && reg_reply.label == SALTY_OK {
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

fn handle_get_info(state: &DisplayState, reply: &mut SaltyMsg) {
    reply.label = SALTY_OK;
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

fn handle_fill_rect(state: &mut DisplayState, msg: &SaltyMsg, reply: &mut SaltyMsg) {
    let x = msg.regs[0] as u32;
    let y = msg.regs[1] as u32;
    let w = msg.regs[2] as u32;
    let h = msg.regs[3] as u32;
    let color = msg.regs[4] as u32;
    fill_rect(state, x, y, w, h, color);
    flush_damage(state);
    reply.label = SALTY_OK;
}

fn handle_write_text(state: &mut DisplayState, msg: &SaltyMsg, reply: &mut SaltyMsg) {
    let x_pixel = msg.regs[0] as u32;
    let y_pixel = msg.regs[1] as u32;
    let fg_color = msg.regs[2] as u32;
    let bg_color = msg.regs[3] as u32;
    let data_len = msg.regs[4] as usize;

    let saved_fg = state.fg;
    let saved_bg = state.bg;
    state.fg = fg_color;
    state.bg = bg_color;

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
    flush_damage(state);
    reply.label = SALTY_OK;
}

fn handle_terminal_write(state: &mut DisplayState, msg: &SaltyMsg, reply: &mut SaltyMsg) {
    let data_len = msg.regs[0] as usize;
    let text_ptr = &msg.regs[1] as *const u64 as *const u8;
    let max_bytes = if data_len > 152 { 152 } else { data_len };

    for i in 0..max_bytes {
        // SAFETY: Reading text bytes from message registers, bounded by max_bytes.
        let c = unsafe { *text_ptr.add(i) };
        terminal_putc(state, c);
    }

    flush_damage(state);
    reply.label = SALTY_OK;
}

fn handle_present(state: &mut DisplayState, reply: &mut SaltyMsg) {
    flush_damage(state);
    reply.label = SALTY_OK;
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    puts(b"[DISPLAY] Display server starting\n");

    // Set up IPC buffer
    unsafe {
        invoke::tcb_set_ipc_buffer(CAP_SELF_TCB, IPC_BUF_VADDR);
        ipc::ipc_context_init(ipc_ctx(), IPC_BUF_VADDR as *mut IpcBuffer);
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

    // Map framebuffer with write-combining (WRITE_THROUGH flag)
    if !map_framebuffer(&fb) {
        puts(b"[DISPLAY] Failed to map framebuffer\n");
        signal_ready();
        idle();
    }

    // Allocate shadow buffer
    let fb_size = fb.height as u64 * fb.pitch as u64;
    let shadow_pages = (fb_size + 4095) / 4096;
    if !alloc_shadow_buffer(shadow_pages) {
        puts(b"[DISPLAY] Failed to allocate shadow buffer\n");
        signal_ready();
        idle();
    }

    // Copy current VRAM content into shadow buffer (preserve boot output)
    // SAFETY: Both VRAM and shadow are mapped with sufficient size.
    unsafe {
        core::ptr::copy_nonoverlapping(
            FB_MAP_VADDR as *const u8,
            SHADOW_BUF_VADDR as *mut u8,
            fb_size as usize,
        );
    }

    let mut state = DisplayState {
        vram: FB_MAP_VADDR as *mut u8,
        shadow: SHADOW_BUF_VADDR as *mut u8,
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
        max_cols: fb.width / font::GLYPH_WIDTH,
        max_rows: fb.height / font::GLYPH_HEIGHT,
        fg: pack_color(0xCC, 0xCC, 0xCC, fb.red_pos, fb.green_pos, fb.blue_pos),
        bg: pack_color(0x00, 0x00, 0x00, fb.red_pos, fb.green_pos, fb.blue_pos),
        damage_min_y: fb.height,
        damage_max_y: 0,
    };

    // Disable kernel console so we own the framebuffer
    syscall(SYS_DEBUG_CONSOLE_CONTROL, 0, 0, 0, 0, 0, 0);
    puts(b"[DISPLAY] Kernel console disabled, display server owns FB\n");

    // Register with nameserv
    register_with_nameserv();

    // Signal readiness
    signal_ready();
    puts(b"[DISPLAY] Ready, entering server loop\n");

    // IPC server loop
    let mut msg = SaltyMsg::zeroed();
    let mut badge: u64 = 0;

    let err = unsafe { ipc::recv_ctx(ipc_ctx(), CAP_SERVER_EP, &raw mut msg, &raw mut badge) };
    if err != 0 {
        puts(b"[DISPLAY] initial recv failed\n");
        idle();
    }

    loop {
        let mut reply = SaltyMsg::zeroed();

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
                handle_terminal_write(&mut state, &msg, &mut reply);
            }
            _ => {
                reply.label = SALTY_INVALID_OPERATION;
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
