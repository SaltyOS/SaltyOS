//! Common boot layout constants shared by UEFI and BIOS loaders.

#![no_std]

pub const KERNEL_PHYS_BASE: u64 = 0x0020_0000;
pub const KERNEL_VIRT_BASE: u64 = 0xffff_ffff_8000_0000;

pub const USER_CODE_BASE: u64 = 0x0000_4000_0000_0000;
pub const USER_STACK_BASE: u64 = USER_CODE_BASE + 0x0000_0000_0010_0000;
pub const USER_STACK_PAGES: usize = 4;
pub const USER_STACK_SIZE: u64 = (USER_STACK_PAGES as u64) * 4096;
