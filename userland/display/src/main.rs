//! SaltyOS Display Server
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Maps the framebuffer device untyped into userspace and draws a test pattern.
//! Requires CAP_FB_UNTYPED (slot 13) from init.

#![no_std]
#![no_main]

extern crate salty;

use salty::consts::*;
use salty::framebuffer;
use salty::invoke;
use salty::ipc;
use salty::serial;
use salty::serial::LineBuf;
use salty::syscall::syscall;
use salty::types::*;

const IPC_BUF_VADDR: u64 = 0x0000_0000_0020_0000;
// Keep framebuffer mapping away from RTLD shared-library region
// (which starts at 0x1000_0000 and grows upward in 16 MB steps).
const FB_MAP_VADDR: u64 = 0x0000_0000_3000_0000; // 768 MB

fn puts(s: &[u8]) {
    serial::serial_puts(s);
}

fn idle() -> ! {
    loop {
        syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
    }
}

/// Initialize the IPC context with the pre-mapped buffer from init
fn setup_ipc_buffer() {
    unsafe {
        invoke::tcb_set_ipc_buffer(CAP_SELF_TCB, IPC_BUF_VADDR);
        ipc::ipc_context_init(
            &raw mut salty::__salty_ipc_ctx,
            IPC_BUF_VADDR as *mut IpcBuffer,
        );
    }
}

/// Map the framebuffer into userspace directly from device untyped pages
fn map_framebuffer(fb: &framebuffer::FramebufferInfo) -> bool {
    let fb_size = fb.height as u64 * fb.pitch as u64;
    let num_pages = (fb_size + 4095) / 4096;

    {
        let mut lb = LineBuf::new();
        lb.str(b"[DISPLAY] Mapping ");
        lb.hex(num_pages);
        lb.str(b" pages at ");
        lb.hex(FB_MAP_VADDR);
        lb.str(b"\n");
        lb.flush();
    }

    let map_flags = VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER | VSPACE_FLAG_CACHE_DISABLE;

    for i in 0..num_pages {
        let page_offset = i * 4096;
        let vaddr = FB_MAP_VADDR + i * 4096;

        // Map one 4KB page directly from framebuffer device untyped.
        let err = invoke::vspace_map_device(
            CAP_SELF_VSPACE,
            CAP_FB_UNTYPED,
            page_offset,
            vaddr,
            map_flags,
        );
        if err != 0 {
            let mut lb = LineBuf::new();
            lb.str(b"[DISPLAY] Frame map-device failed at page ");
            lb.hex(i);
            lb.str(b" vaddr=");
            lb.hex(vaddr);
            lb.str(b" err=");
            lb.hex(err as u64);
            lb.str(b"\n");
            lb.flush();
            return false;
        }
    }

    {
        let mut lb = LineBuf::new();
        lb.str(b"[DISPLAY] Mapped ");
        lb.hex(num_pages);
        lb.str(b" pages, drawing test pattern\n");
        lb.flush();
    }

    true
}

/// Draw an RGB gradient test pattern on the framebuffer.
///
/// Red increases left-to-right, green increases top-to-bottom,
/// blue is a constant 128.
fn draw_test_pattern(fb: &framebuffer::FramebufferInfo) {
    let fb_ptr = FB_MAP_VADDR as *mut u8;
    let w = fb.width as u64;
    let h = fb.height as u64;
    let pitch = fb.pitch as u64;
    let rpos = fb.red_pos as u32;
    let gpos = fb.green_pos as u32;
    let bpos = fb.blue_pos as u32;

    for y in 0..h {
        let row = unsafe { fb_ptr.add((y * pitch) as usize) as *mut u32 };
        let g = ((y * 255) / h) as u32;
        for x in 0..w {
            let r = ((x * 255) / w) as u32;
            let b: u32 = 128;
            let pixel = (r << rpos) | (g << gpos) | (b << bpos);
            unsafe {
                core::ptr::write_volatile(row.add(x as usize), pixel);
            }
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    puts(b"[DISPLAY] Display server starting\n");

    setup_ipc_buffer();

    // Read framebuffer info from boot info page
    let fb = match unsafe { framebuffer::read_framebuffer_info() } {
        Some(fb) => fb,
        None => {
            puts(b"[DISPLAY] No framebuffer detected\n");
            idle();
        }
    };

    {
        let mut lb = LineBuf::new();
        lb.str(b"[DISPLAY] Framebuffer: ");
        lb.hex(fb.width as u64);
        lb.str(b"x");
        lb.hex(fb.height as u64);
        lb.str(b" bpp=");
        lb.hex(fb.bpp as u64);
        lb.str(b" pitch=");
        lb.hex(fb.pitch as u64);
        lb.str(b" phys=");
        lb.hex(fb.phys_addr);
        lb.str(b"\n");
        lb.flush();
    }

    // Map the framebuffer
    if !map_framebuffer(&fb) {
        puts(b"[DISPLAY] Failed to map framebuffer\n");
        idle();
    }

    // Draw the test pattern
    draw_test_pattern(&fb);

    puts(b"[DISPLAY] Test pattern drawn, idling\n");
    idle();
}
