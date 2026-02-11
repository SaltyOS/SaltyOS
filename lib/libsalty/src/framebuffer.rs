//! Framebuffer info reader for userspace
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Reads framebuffer metadata from the kernel boot info page at BOOTINFO_VADDR.

use crate::consts::{BOOTINFO_MAGIC, BOOTINFO_VADDR};

/// Framebuffer information read from the boot info page.
pub struct FramebufferInfo {
    pub phys_addr: u64,
    pub width: u32,
    pub height: u32,
    pub pitch: u32,
    pub bpp: u8,
    pub red_pos: u8,
    pub red_size: u8,
    pub green_pos: u8,
    pub green_size: u8,
    pub blue_pos: u8,
    pub blue_size: u8,
}

/// Read framebuffer info from the kernel boot info page.
///
/// Returns `None` if the boot info magic is wrong or no framebuffer is present.
///
/// # Safety
/// The boot info page must be mapped at `BOOTINFO_VADDR`.
pub unsafe fn read_framebuffer_info() -> Option<FramebufferInfo> {
    unsafe {
        let page = BOOTINFO_VADDR as *const u8;

        // Validate magic
        let magic = core::ptr::read_volatile(page as *const u64);
        if magic != BOOTINFO_MAGIC {
            return None;
        }

        // offset 24: fb_phys_addr (u64)
        let fb_addr = core::ptr::read_volatile((page as *const u64).add(3));
        if fb_addr == 0 {
            return None;
        }

        Some(FramebufferInfo {
            phys_addr: fb_addr,
            width: core::ptr::read_volatile(page.add(32) as *const u32),
            height: core::ptr::read_volatile(page.add(36) as *const u32),
            pitch: core::ptr::read_volatile(page.add(40) as *const u32),
            bpp: core::ptr::read_volatile(page.add(44)),
            red_pos: core::ptr::read_volatile(page.add(45)),
            red_size: core::ptr::read_volatile(page.add(46)),
            green_pos: core::ptr::read_volatile(page.add(47)),
            green_size: core::ptr::read_volatile(page.add(48)),
            blue_pos: core::ptr::read_volatile(page.add(49)),
            blue_size: core::ptr::read_volatile(page.add(50)),
        })
    }
}
