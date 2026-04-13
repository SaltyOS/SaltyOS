//! Dedicated ELF fixture for VFS stress tests.
//! SPDX-License-Identifier: GPL-2.0-only

#![no_std]
#![no_main]

extern crate trona;

#[used]
static VFS_STRESS_BLOB_A: [u8; 64 * 1024] = [0x5A; 64 * 1024];

#[used]
static VFS_STRESS_BLOB_B: [u8; 64 * 1024] = [0xA5; 64 * 1024];

#[used]
static VFS_STRESS_BLOB_C: [u8; 64 * 1024] = [0x3C; 64 * 1024];

#[used]
static VFS_STRESS_BLOB_D: [u8; 64 * 1024] = [0xC3; 64 * 1024];

fn mix_blob(blob: &[u8], step: usize, seed: u32) -> u32 {
    let mut checksum = seed;
    let mut idx = seed as usize % step;
    while idx < blob.len() {
        checksum = checksum.rotate_left(5) ^ blob[idx] as u32;
        checksum = checksum.wrapping_mul(0x045D_9F3B);
        idx += step;
    }
    checksum
}

#[unsafe(no_mangle)]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    let mut checksum = 0x1357_9BDFu32;
    checksum ^= mix_blob(&VFS_STRESS_BLOB_A, 31, 0x11);
    checksum ^= mix_blob(&VFS_STRESS_BLOB_B, 47, 0x22);
    checksum ^= mix_blob(&VFS_STRESS_BLOB_C, 61, 0x33);
    checksum ^= mix_blob(&VFS_STRESS_BLOB_D, 73, 0x44);

    if checksum == 0 || checksum == 0x1357_9BDF {
        1
    } else {
        0
    }
}
