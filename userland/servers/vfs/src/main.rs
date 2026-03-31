//! SaltyOS VFS Server
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Virtual filesystem with ramfs (in-memory filesystem) and devfs.
//! Mounts initrd CPIO as read-only /initrd/. Device files at /dev/.

#![no_std]
#![no_main]

extern crate trona;
extern crate trona_posix;
extern crate trona_loader;

mod at_ops;
mod bulk;
mod client;
mod consts;
mod fileops;
mod inet;
mod misc;
mod mount;
mod path;
mod pipe;
mod poll;
mod procfs;
mod ramfs;
mod socket;
mod types;

use trona::consts::*;
use trona_loader::cpio;
use trona::ipc;
use trona::serial;
use trona::types::*;

use consts::*;
use types::*;

// ======================================================================
// Global state
// ======================================================================

pub(crate) static mut INODES_PTR: *mut RamfsInode = core::ptr::null_mut();
pub(crate) static mut INODES_CAP: usize = 0;
pub(crate) static mut NEXT_INO: u32 = 1;

pub(crate) static mut WRITABLE_POOL_PTR: *mut [u8; WRITABLE_SIZE] = core::ptr::null_mut();
pub(crate) static mut WRITABLE_USED_PTR: *mut u8 = core::ptr::null_mut();
pub(crate) static mut WRITABLE_NEXT_PTR: *mut u32 = core::ptr::null_mut();
pub(crate) static mut WRITABLE_CAP: usize = 0;

pub(crate) static mut SYMLINK_POOL_PTR: *mut [u8; MAX_PATH_LEN] = core::ptr::null_mut();
pub(crate) static mut SYMLINK_USED_PTR: *mut u8 = core::ptr::null_mut();
pub(crate) static mut SYMLINK_CAP: usize = 0;

pub(crate) static mut CLIENTS_PTR: *mut ClientState = core::ptr::null_mut();
pub(crate) static mut CLIENTS_CAP: usize = 0;

pub(crate) static mut FB_WIDTH: u32 = 0;
pub(crate) static mut FB_HEIGHT: u32 = 0;
pub(crate) static mut FB_PITCH: u32 = 0;
pub(crate) static mut FB_BPP: u8 = 0;
pub(crate) static mut FB_RED_POS: u8 = 0;
pub(crate) static mut FB_RED_SIZE: u8 = 0;
pub(crate) static mut FB_GREEN_POS: u8 = 0;
pub(crate) static mut FB_GREEN_SIZE: u8 = 0;
pub(crate) static mut FB_BLUE_POS: u8 = 0;
pub(crate) static mut FB_BLUE_SIZE: u8 = 0;
pub(crate) static mut FB_MMAP_BADGE: u64 = 0;

pub(crate) static mut SOCKETS_PTR: *mut SocketState = core::ptr::null_mut();
pub(crate) static mut SOCKETS_CAP: usize = 0;
pub(crate) static mut NEXT_SOCK_ID: u32 = 1;

pub(crate) static mut POLL_WAITERS_PTR: *mut PollWaiter = core::ptr::null_mut();
pub(crate) static mut POLL_WAITERS_CAP: usize = 0;

pub(crate) static mut EPOLLS_PTR: *mut EpollInstance = core::ptr::null_mut();
pub(crate) static mut EPOLLS_CAP: usize = 0;

pub(crate) static mut SHM_DATA_PTR: *mut ShmData = core::ptr::null_mut();
pub(crate) static mut SHM_CAP: usize = 0;

pub(crate) static mut PIPES_PTR: *mut PipeState = core::ptr::null_mut();
pub(crate) static mut PIPES_CAP: usize = 0;
pub(crate) static mut NEXT_PIPE_ID: u32 = 1;

pub(crate) static mut PTY_PENDING: [[PtyPendingReader; MAX_PTY_WAITERS]; MAX_PTYS] =
    [[PtyPendingReader::zeroed(); MAX_PTY_WAITERS]; MAX_PTYS];
pub(crate) static mut PTY_PENDING_COUNT: [usize; MAX_PTYS] = [0; MAX_PTYS];

pub(crate) static mut NEXT_REPLY_SLOT: u64 = CAP_REPLY_BASE;
pub(crate) static mut CURRENT_RECV_SLOT: u64 = 0;

pub(crate) static mut MOUNTS: [MountEntry; MAX_MOUNTS] = [MountEntry::zeroed(); MAX_MOUNTS];
pub(crate) static mut ROOT_UNDERLAY_IDX: i32 = -1;
pub(crate) static mut MOUNT_TRIED: u8 = 0;
pub(crate) static mut VFS_SHM_ACTIVE: bool = false;

pub(crate) static mut URANDOM_KEY: [u8; 32] = [0u8; 32];
pub(crate) static mut URANDOM_CTR: u64 = 0;
pub(crate) static mut URANDOM_BUF: [u8; 64] = [0u8; 64];
pub(crate) static mut URANDOM_BUF_POS: usize = 64;
pub(crate) static mut URANDOM_COUNTER: u64 = 0;
const URANDOM_RESEED_INTERVAL: u64 = 1024;

pub(crate) static mut PROC_ROOT_INO: u32 = 0;

// ======================================================================
// Pool access macros
// ======================================================================

#[macro_export]
macro_rules! INODES {
    () => {
        unsafe { core::slice::from_raw_parts_mut($crate::INODES_PTR, $crate::max_inodes()) }
    };
}

#[macro_export]
macro_rules! WRITABLE_POOL {
    () => {
        unsafe {
            core::slice::from_raw_parts_mut($crate::WRITABLE_POOL_PTR, $crate::max_writable())
        }
    };
}

#[macro_export]
macro_rules! WRITABLE_USED {
    () => {
        unsafe {
            core::slice::from_raw_parts_mut($crate::WRITABLE_USED_PTR, $crate::max_writable())
        }
    };
}

#[macro_export]
macro_rules! CLIENTS {
    () => {
        unsafe { core::slice::from_raw_parts_mut($crate::CLIENTS_PTR, $crate::max_clients()) }
    };
}

#[macro_export]
macro_rules! SOCKETS {
    () => {
        unsafe { core::slice::from_raw_parts_mut($crate::SOCKETS_PTR, $crate::max_sockets()) }
    };
}

#[macro_export]
macro_rules! POLL_WAITERS {
    () => {
        unsafe {
            core::slice::from_raw_parts_mut($crate::POLL_WAITERS_PTR, $crate::max_poll_waiters())
        }
    };
}

#[macro_export]
macro_rules! EPOLLS {
    () => {
        unsafe {
            core::slice::from_raw_parts_mut($crate::EPOLLS_PTR, $crate::max_epoll_instances())
        }
    };
}

#[macro_export]
macro_rules! SHM_DATA {
    () => {
        unsafe { core::slice::from_raw_parts_mut($crate::SHM_DATA_PTR, $crate::max_shm_objects()) }
    };
}

#[macro_export]
macro_rules! PIPES {
    () => {
        unsafe { core::slice::from_raw_parts_mut($crate::PIPES_PTR, $crate::max_pipes()) }
    };
}

// ======================================================================
// Capacity accessor functions
// ======================================================================

pub(crate) fn max_inodes() -> usize {
    unsafe { *(&raw const INODES_CAP) }
}

pub(crate) fn max_writable() -> usize {
    unsafe { *(&raw const WRITABLE_CAP) }
}

pub(crate) fn max_clients() -> usize {
    unsafe { *(&raw const CLIENTS_CAP) }
}

pub(crate) fn max_sockets() -> usize {
    unsafe { *(&raw const SOCKETS_CAP) }
}

pub(crate) fn max_poll_waiters() -> usize {
    unsafe { *(&raw const POLL_WAITERS_CAP) }
}

pub(crate) fn max_epoll_instances() -> usize {
    unsafe { *(&raw const EPOLLS_CAP) }
}

pub(crate) fn max_shm_objects() -> usize {
    unsafe { *(&raw const SHM_CAP) }
}

pub(crate) fn max_shm_pages() -> usize {
    MAX_SHM_PAGES
}

pub(crate) fn max_pipes() -> usize {
    unsafe { *(&raw const PIPES_CAP) }
}

// ======================================================================
// Pool allocation functions
// ======================================================================

pub(crate) unsafe fn vfs_grow_pool_with_min(
    ptr_loc: *mut *mut u8,
    cap_loc: *mut usize,
    item_size: usize,
    min_required: usize,
) -> i32 {
    let old_ptr = unsafe { *ptr_loc };
    let old_cap = unsafe { *cap_loc };
    if old_cap == 0 {
        return -1;
    }
    let growth = if old_cap < 128 {
        old_cap
    } else if old_cap < 1024 {
        old_cap / 2
    } else {
        256
    };
    let new_cap = core::cmp::max(min_required, old_cap + growth);
    let new_bytes = match new_cap.checked_mul(item_size) {
        Some(b) if b > 0 => b,
        _ => return -1,
    };
    let new_pages = (new_bytes + 4095) / 4096;
    let new_ptr = unsafe {
        trona_posix::mm::posix_mmap(
            core::ptr::null_mut(),
            (new_pages * 4096) as u64,
            0x3,
            0x22,
            -1,
            0,
        )
    };
    if new_ptr.is_null() || new_ptr == usize::MAX as *mut u8 {
        return -1;
    }
    let old_bytes = old_cap * item_size;
    unsafe {
        core::ptr::copy_nonoverlapping(old_ptr, new_ptr, old_bytes);
        core::ptr::write_bytes(new_ptr.add(old_bytes), 0, new_pages * 4096 - old_bytes);
    }
    if !old_ptr.is_null() {
        let old_pages = (old_bytes + 4095) / 4096;
        unsafe {
            trona_posix::mm::posix_munmap(old_ptr, (old_pages * 4096) as u64);
        }
    }
    unsafe {
        *ptr_loc = new_ptr;
        *cap_loc = new_cap;
    }
    0
}

pub(crate) unsafe fn vfs_grow_pool(
    ptr_loc: *mut *mut u8,
    cap_loc: *mut usize,
    item_size: usize,
) -> i32 {
    vfs_grow_pool_with_min(ptr_loc, cap_loc, item_size, 0)
}

pub(crate) unsafe fn vfs_alloc_array<T>(count: usize) -> *mut T {
    unsafe {
        let bytes = core::mem::size_of::<T>().checked_mul(count).unwrap_or(0);
        if bytes == 0 {
            return core::ptr::null_mut();
        }
        let pages = (bytes + 4095) / 4096;
        let ptr = trona_posix::mm::posix_mmap(
            core::ptr::null_mut(),
            (pages * 4096) as u64,
            0x3,
            0x22,
            -1,
            0,
        );
        if ptr.is_null() || ptr == usize::MAX as *mut u8 {
            return core::ptr::null_mut();
        }
        core::ptr::write_bytes(ptr, 0, pages * 4096);
        ptr as *mut T
    }
}

pub(crate) unsafe fn vfs_grow_array_with_min<T: Copy>(
    old_ptr: *mut T,
    old_cap: usize,
    min_required: usize,
) -> (*mut T, usize) {
    if old_cap == 0 || old_ptr.is_null() {
        return (core::ptr::null_mut(), 0);
    }
    let growth = if old_cap < 128 {
        old_cap
    } else if old_cap < 1024 {
        old_cap / 2
    } else {
        256
    };
    let new_cap = core::cmp::max(min_required, old_cap + growth);
    let new_ptr = vfs_alloc_array::<T>(new_cap);
    if new_ptr.is_null() {
        return (core::ptr::null_mut(), 0);
    }
    unsafe {
        for i in 0..old_cap {
            *new_ptr.add(i) = *old_ptr.add(i);
        }
    }
    let old_bytes = old_cap * core::mem::size_of::<T>();
    let old_pages = (old_bytes + 4095) / 4096;
    unsafe {
        trona_posix::mm::posix_munmap(old_ptr as *mut u8, (old_pages * 4096) as u64);
    }
    (new_ptr, new_cap)
}

pub(crate) unsafe fn vfs_grow_array<T: Copy>(old_ptr: *mut T, old_cap: usize) -> (*mut T, usize) {
    vfs_grow_array_with_min(old_ptr, old_cap, 0)
}

unsafe fn init_dynamic_state_storage() -> i32 {
    unsafe fn alloc_pool<T>(
        ptr_loc: *mut *mut T,
        cap_loc: *mut usize,
        initial_count: usize,
    ) -> i32 {
        let bytes = match core::mem::size_of::<T>().checked_mul(initial_count) {
            Some(b) if b > 0 => b,
            _ => return -1,
        };
        let pages = (bytes + 4095) / 4096;
        let ptr = unsafe {
            trona_posix::mm::posix_mmap(
                core::ptr::null_mut(),
                (pages * 4096) as u64,
                0x3,
                0x22,
                -1,
                0,
            )
        };
        if ptr.is_null() || ptr == usize::MAX as *mut u8 {
            return -1;
        }
        unsafe {
            core::ptr::write_bytes(ptr, 0, pages * 4096);
            *ptr_loc = ptr as *mut T;
            *cap_loc = initial_count;
        }
        0
    }

    unsafe {
        if alloc_pool(&raw mut INODES_PTR, &raw mut INODES_CAP, INITIAL_INODES) != 0 {
            return TRONA_OUT_OF_MEMORY as i32;
        }
        if alloc_pool(
            &raw mut WRITABLE_POOL_PTR,
            &raw mut WRITABLE_CAP,
            INITIAL_WRITABLE,
        ) != 0
        {
            return TRONA_OUT_OF_MEMORY as i32;
        }
        let writable_used_bytes = INITIAL_WRITABLE;
        let writable_used_pages = (writable_used_bytes + 4095) / 4096;
        let ptr = trona_posix::mm::posix_mmap(
            core::ptr::null_mut(),
            (writable_used_pages * 4096) as u64,
            0x3,
            0x22,
            -1,
            0,
        );
        if ptr.is_null() || ptr == usize::MAX as *mut u8 {
            return TRONA_OUT_OF_MEMORY as i32;
        }
        core::ptr::write_bytes(ptr, 0, writable_used_pages * 4096);
        WRITABLE_USED_PTR = ptr;

        let next_bytes = INITIAL_WRITABLE * core::mem::size_of::<u32>();
        let next_pages = (next_bytes + 4095) / 4096;
        let next_ptr = trona_posix::mm::posix_mmap(
            core::ptr::null_mut(),
            (next_pages * 4096) as u64,
            0x3,
            0x22,
            -1,
            0,
        );
        if next_ptr.is_null() || next_ptr == usize::MAX as *mut u8 {
            return TRONA_OUT_OF_MEMORY as i32;
        }
        let next_arr = next_ptr as *mut u32;
        for i in 0..INITIAL_WRITABLE {
            *next_arr.add(i) = u32::MAX;
        }
        WRITABLE_NEXT_PTR = next_arr;

        if alloc_pool(
            &raw mut SYMLINK_POOL_PTR,
            &raw mut SYMLINK_CAP,
            INITIAL_SYMLINKS,
        ) != 0
        {
            return TRONA_OUT_OF_MEMORY as i32;
        }
        let sym_used_pages = (INITIAL_SYMLINKS + 4095) / 4096;
        let sym_used_ptr = trona_posix::mm::posix_mmap(
            core::ptr::null_mut(),
            (sym_used_pages * 4096) as u64,
            0x3,
            0x22,
            -1,
            0,
        );
        if sym_used_ptr.is_null() || sym_used_ptr == usize::MAX as *mut u8 {
            return TRONA_OUT_OF_MEMORY as i32;
        }
        core::ptr::write_bytes(sym_used_ptr, 0, sym_used_pages * 4096);
        SYMLINK_USED_PTR = sym_used_ptr;

        if alloc_pool(&raw mut CLIENTS_PTR, &raw mut CLIENTS_CAP, INITIAL_CLIENTS) != 0 {
            return TRONA_OUT_OF_MEMORY as i32;
        }
        if alloc_pool(&raw mut SOCKETS_PTR, &raw mut SOCKETS_CAP, INITIAL_SOCKETS) != 0 {
            return TRONA_OUT_OF_MEMORY as i32;
        }
        if alloc_pool(
            &raw mut POLL_WAITERS_PTR,
            &raw mut POLL_WAITERS_CAP,
            INITIAL_POLL_WAITERS,
        ) != 0
        {
            return TRONA_OUT_OF_MEMORY as i32;
        }
        if alloc_pool(&raw mut EPOLLS_PTR, &raw mut EPOLLS_CAP, INITIAL_EPOLLS) != 0 {
            return TRONA_OUT_OF_MEMORY as i32;
        }
        if alloc_pool(&raw mut SHM_DATA_PTR, &raw mut SHM_CAP, INITIAL_SHM) != 0 {
            return TRONA_OUT_OF_MEMORY as i32;
        }
        if alloc_pool(&raw mut PIPES_PTR, &raw mut PIPES_CAP, INITIAL_PIPES) != 0 {
            return TRONA_OUT_OF_MEMORY as i32;
        }

        trona::uinfo!(|_lb| {
            _lb.str(b"[VFS] Growable pools initialized: inodes=128 clients=16 sockets=32 pipes=16\n");
        });

        0
    }
}

// ======================================================================
// Helper functions
// ======================================================================

pub(crate) fn puts(s: &[u8]) {
    serial::serial_puts(s);
}

fn signal_ready() {
    let _ = trona::syscall::syscall(SYS_SIGNAL, CAP_READINESS_NTFN, 1, 0, 0, 0, 0);
}

pub(crate) fn ipc_ctx() -> *mut IpcContext {
    trona_posix::tls::current_ipc_ctx()
}

// ======================================================================
// ChaCha20-based CSPRNG for /dev/urandom
// ======================================================================

const CHACHA20_SIGMA: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

#[inline(always)]
fn chacha_qr(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] ^= s[a];
    s[d] = s[d].rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] ^= s[c];
    s[b] = s[b].rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] ^= s[a];
    s[d] = s[d].rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] ^= s[c];
    s[b] = s[b].rotate_left(7);
}

/// Generate one 64-byte ChaCha20 keystream block into `out`.
unsafe fn chacha20_block(key: *const u8, counter: u64, out: *mut u8) {
    let mut state = [0u32; 16];

    state[0] = CHACHA20_SIGMA[0];
    state[1] = CHACHA20_SIGMA[1];
    state[2] = CHACHA20_SIGMA[2];
    state[3] = CHACHA20_SIGMA[3];

    unsafe {
        let mut i = 0;
        while i < 8 {
            let off = i * 4;
            state[4 + i] = u32::from_le_bytes([
                *key.add(off),
                *key.add(off + 1),
                *key.add(off + 2),
                *key.add(off + 3),
            ]);
            i += 1;
        }
    }

    state[12] = counter as u32;
    state[13] = (counter >> 32) as u32;
    state[14] = 0;
    state[15] = 0;

    let initial = state;

    let mut r = 0;
    while r < 10 {
        chacha_qr(&mut state, 0, 4, 8, 12);
        chacha_qr(&mut state, 1, 5, 9, 13);
        chacha_qr(&mut state, 2, 6, 10, 14);
        chacha_qr(&mut state, 3, 7, 11, 15);
        chacha_qr(&mut state, 0, 5, 10, 15);
        chacha_qr(&mut state, 1, 6, 11, 12);
        chacha_qr(&mut state, 2, 7, 8, 13);
        chacha_qr(&mut state, 3, 4, 9, 14);
        r += 1;
    }

    unsafe {
        let mut i = 0;
        while i < 16 {
            let val = state[i].wrapping_add(initial[i]);
            let bytes = val.to_le_bytes();
            *out.add(i * 4) = bytes[0];
            *out.add(i * 4 + 1) = bytes[1];
            *out.add(i * 4 + 2) = bytes[2];
            *out.add(i * 4 + 3) = bytes[3];
            i += 1;
        }
    }
}

pub(crate) unsafe fn urandom_init() {
    unsafe {
        let key = &raw mut URANDOM_KEY as *mut u8;
        let mut filled = 0usize;

        // Primary: seed from hardware RDRAND/RNDR via kernel syscall
        while filled < 32 {
            match trona::syscall::sys_getrandom() {
                Some(val) => {
                    let bytes = val.to_le_bytes();
                    let remain = 32 - filled;
                    let n = if remain < 8 { remain } else { 8 };
                    core::ptr::copy_nonoverlapping(bytes.as_ptr(), key.add(filled), n);
                    filled += n;
                }
                None => {
                    // Fallback: TSC + clock mixing
                    let mut ts = Timespec::zeroed();
                    trona::syscall::syscall(
                        SYS_CLOCK_GETTIME,
                        0,
                        &raw mut ts as u64,
                        0,
                        0,
                        0,
                        0,
                    );
                    let tsc: u64;
                    #[cfg(target_arch = "x86_64")]
                    {
                        let tsc_lo: u32;
                        let tsc_hi: u32;
                        core::arch::asm!("rdtsc", out("eax") tsc_lo, out("edx") tsc_hi);
                        tsc = (tsc_hi as u64) << 32 | tsc_lo as u64;
                    }
                    #[cfg(target_arch = "aarch64")]
                    {
                        core::arch::asm!("mrs {}, CNTVCT_EL0", out(reg) tsc);
                    }
                    let v = ts
                        .tv_nsec
                        .wrapping_mul(6364136223846793005)
                        .wrapping_add(tsc);
                    let bytes = v.to_le_bytes();
                    let remain = 32 - filled;
                    let n = if remain < 8 { remain } else { 8 };
                    core::ptr::copy_nonoverlapping(bytes.as_ptr(), key.add(filled), n);
                    filled += n;
                }
            }
        }

        URANDOM_COUNTER = 0;
        URANDOM_CTR = 0;
        URANDOM_BUF_POS = 64; // Force refill on first read
    }
}

pub(crate) unsafe fn urandom_next() -> u64 {
    unsafe {
        URANDOM_COUNTER += 1;
        if URANDOM_COUNTER >= URANDOM_RESEED_INTERVAL {
            URANDOM_COUNTER = 0;
            // Reseed: XOR fresh RDRAND bytes into the key
            if let Some(fresh) = trona::syscall::sys_getrandom() {
                let key = &raw mut URANDOM_KEY as *mut u8;
                let bytes = fresh.to_le_bytes();
                let mut i = 0;
                while i < 8 {
                    *key.add(i) ^= bytes[i];
                    i += 1;
                }
            }
        }

        // Refill buffer if exhausted
        let pos = URANDOM_BUF_POS;
        if pos + 8 > 64 {
            chacha20_block(
                &raw const URANDOM_KEY as *const u8,
                URANDOM_CTR,
                &raw mut URANDOM_BUF as *mut u8,
            );
            URANDOM_CTR = URANDOM_CTR.wrapping_add(1);
            URANDOM_BUF_POS = 0;
            let buf = &raw const URANDOM_BUF as *const u8;
            let result = u64::from_le_bytes([
                *buf, *buf.add(1), *buf.add(2), *buf.add(3),
                *buf.add(4), *buf.add(5), *buf.add(6), *buf.add(7),
            ]);
            URANDOM_BUF_POS = 8;
            return result;
        }

        let buf = (&raw const URANDOM_BUF as *const u8).add(pos);
        let result = u64::from_le_bytes([
            *buf, *buf.add(1), *buf.add(2), *buf.add(3),
            *buf.add(4), *buf.add(5), *buf.add(6), *buf.add(7),
        ]);
        URANDOM_BUF_POS = pos + 8;
        result
    }
}

pub(crate) fn str_equal_raw(a: *const u8, alen: usize, b: *const u8, blen: usize) -> bool {
    if alen != blen {
        return false;
    }
    for i in 0..alen {
        unsafe {
            if *a.add(i) != *b.add(i) {
                return false;
            }
        }
    }
    true
}

// ======================================================================
// Initialization
// ======================================================================

unsafe fn init_fb_info() {
    unsafe {
        let bootinfo = BOOTINFO_VADDR as *const u8;
        let magic = (bootinfo as *const u64).read();
        if magic != BOOTINFO_MAGIC {
            return;
        }
        let p32 = bootinfo.add(32) as *const u32;
        FB_WIDTH = p32.read();
        FB_HEIGHT = p32.add(1).read();
        FB_PITCH = p32.add(2).read();
        FB_BPP = *bootinfo.add(44);
        FB_RED_POS = *bootinfo.add(45);
        FB_RED_SIZE = *bootinfo.add(46);
        FB_GREEN_POS = *bootinfo.add(47);
        FB_GREEN_SIZE = *bootinfo.add(48);
        FB_BLUE_POS = *bootinfo.add(49);
        FB_BLUE_SIZE = *bootinfo.add(50);
    }
}

unsafe fn init_ramfs() {
    unsafe {
        for i in 0..max_inodes() {
            INODES!()[i].active = 0;
        }
        for i in 0..max_writable() {
            WRITABLE_USED!()[i] = 0;
        }

        let root = ramfs::alloc_inode();
        (*root).ftype = FTYPE_DIRECTORY;
        (*root).mode = S_IFDIR_L | 0o755;
        (*root).nlink = 2;

        let dev_dir = ramfs::alloc_inode();
        (*dev_dir).ftype = FTYPE_DIRECTORY;
        (*dev_dir).mode = S_IFDIR_L | 0o755;
        (*dev_dir).nlink = 2;
        (*dev_dir).parent_ino = (*root).ino;
        ramfs::dir_add_entry(root, b"dev".as_ptr(), 3, (*dev_dir).ino);

        let console = ramfs::alloc_inode();
        (*console).ftype = FTYPE_CHAR_DEVICE;
        (*console).mode = S_IFCHR_L | 0o666;
        (*console).dev_type = DEV_CONSOLE;
        (*console).parent_ino = (*dev_dir).ino;
        ramfs::dir_add_entry(dev_dir, b"console".as_ptr(), 7, (*console).ino);

        let null_dev = ramfs::alloc_inode();
        (*null_dev).ftype = FTYPE_CHAR_DEVICE;
        (*null_dev).mode = S_IFCHR_L | 0o666;
        (*null_dev).dev_type = DEV_NULL;
        (*null_dev).parent_ino = (*dev_dir).ino;
        ramfs::dir_add_entry(dev_dir, b"null".as_ptr(), 4, (*null_dev).ino);

        let zero_dev = ramfs::alloc_inode();
        (*zero_dev).ftype = FTYPE_CHAR_DEVICE;
        (*zero_dev).mode = S_IFCHR_L | 0o666;
        (*zero_dev).dev_type = DEV_ZERO;
        (*zero_dev).parent_ino = (*dev_dir).ino;
        ramfs::dir_add_entry(dev_dir, b"zero".as_ptr(), 4, (*zero_dev).ino);

        let fb0_dev = ramfs::alloc_inode();
        (*fb0_dev).ftype = FTYPE_CHAR_DEVICE;
        (*fb0_dev).mode = S_IFCHR_L | 0o666;
        (*fb0_dev).dev_type = DEV_FB0;
        (*fb0_dev).parent_ino = (*dev_dir).ino;
        ramfs::dir_add_entry(dev_dir, b"fb0".as_ptr(), 3, (*fb0_dev).ino);

        let pts_dir = ramfs::alloc_inode();
        (*pts_dir).ftype = FTYPE_DIRECTORY;
        (*pts_dir).mode = S_IFDIR_L | 0o755;
        (*pts_dir).nlink = 2;
        (*pts_dir).parent_ino = (*dev_dir).ino;
        ramfs::dir_add_entry(dev_dir, b"pts".as_ptr(), 3, (*pts_dir).ino);

        let pts0 = ramfs::alloc_inode();
        (*pts0).ftype = FTYPE_CHAR_DEVICE;
        (*pts0).mode = S_IFCHR_L | 0o666;
        (*pts0).dev_type = DEV_PTY_SLAVE;
        (*pts0).size = 0;
        (*pts0).parent_ino = (*pts_dir).ino;
        ramfs::dir_add_entry(pts_dir, b"0".as_ptr(), 1, (*pts0).ino);

        let tty_dev = ramfs::alloc_inode();
        (*tty_dev).ftype = FTYPE_CHAR_DEVICE;
        (*tty_dev).mode = S_IFCHR_L | 0o666;
        (*tty_dev).dev_type = DEV_PTY_SLAVE;
        (*tty_dev).size = 0;
        (*tty_dev).parent_ino = (*dev_dir).ino;
        ramfs::dir_add_entry(dev_dir, b"tty".as_ptr(), 3, (*tty_dev).ino);

        let urandom_dev = ramfs::alloc_inode();
        (*urandom_dev).ftype = FTYPE_CHAR_DEVICE;
        (*urandom_dev).mode = S_IFCHR_L | 0o666;
        (*urandom_dev).dev_type = DEV_URANDOM;
        (*urandom_dev).parent_ino = (*dev_dir).ino;
        ramfs::dir_add_entry(dev_dir, b"urandom".as_ptr(), 7, (*urandom_dev).ino);

        let random_dev = ramfs::alloc_inode();
        (*random_dev).ftype = FTYPE_CHAR_DEVICE;
        (*random_dev).mode = S_IFCHR_L | 0o666;
        (*random_dev).dev_type = DEV_URANDOM;
        (*random_dev).parent_ino = (*dev_dir).ino;
        ramfs::dir_add_entry(dev_dir, b"random".as_ptr(), 6, (*random_dev).ino);

        let proc_dir = ramfs::alloc_inode();
        (*proc_dir).ftype = FTYPE_PROC_FILE;
        (*proc_dir).dev_type = PROC_FILE_ROOT;
        (*proc_dir).mode = S_IFDIR_L | 0o555;
        (*proc_dir).readonly = 1;
        (*proc_dir).nlink = 2;
        (*proc_dir).parent_ino = (*root).ino;
        ramfs::dir_add_entry(root, b"proc".as_ptr(), 4, (*proc_dir).ino);
        PROC_ROOT_INO = (*proc_dir).ino;

        let proc_net_dir = ramfs::alloc_inode();
        (*proc_net_dir).ftype = FTYPE_PROC_FILE;
        (*proc_net_dir).dev_type = PROC_FILE_NET_DIR;
        (*proc_net_dir).mode = S_IFDIR_L | 0o555;
        (*proc_net_dir).readonly = 1;
        (*proc_net_dir).nlink = 2;
        (*proc_net_dir).parent_ino = (*proc_dir).ino;
        ramfs::dir_add_entry(proc_dir, b"net".as_ptr(), 3, (*proc_net_dir).ino);

        let proc_route = ramfs::alloc_inode();
        (*proc_route).ftype = FTYPE_PROC_FILE;
        (*proc_route).dev_type = PROC_FILE_NET_ROUTE;
        (*proc_route).mode = S_IFREG_L | 0o444;
        (*proc_route).readonly = 1;
        (*proc_route).parent_ino = (*proc_net_dir).ino;
        ramfs::dir_add_entry(proc_net_dir, b"route".as_ptr(), 5, (*proc_route).ino);

        let proc_arp = ramfs::alloc_inode();
        (*proc_arp).ftype = FTYPE_PROC_FILE;
        (*proc_arp).dev_type = PROC_FILE_NET_ARP;
        (*proc_arp).mode = S_IFREG_L | 0o444;
        (*proc_arp).readonly = 1;
        (*proc_arp).parent_ino = (*proc_net_dir).ino;
        ramfs::dir_add_entry(proc_net_dir, b"arp".as_ptr(), 3, (*proc_arp).ino);

        let proc_dev = ramfs::alloc_inode();
        (*proc_dev).ftype = FTYPE_PROC_FILE;
        (*proc_dev).dev_type = PROC_FILE_NET_DEV;
        (*proc_dev).mode = S_IFREG_L | 0o444;
        (*proc_dev).readonly = 1;
        (*proc_dev).parent_ino = (*proc_net_dir).ino;
        ramfs::dir_add_entry(proc_net_dir, b"dev".as_ptr(), 3, (*proc_dev).ino);

        let mnt_dir = ramfs::alloc_inode();
        (*mnt_dir).ftype = FTYPE_DIRECTORY;
        (*mnt_dir).mode = S_IFDIR_L | 0o755;
        (*mnt_dir).nlink = 2;
        (*mnt_dir).parent_ino = (*root).ino;
        ramfs::dir_add_entry(root, b"mnt".as_ptr(), 3, (*mnt_dir).ino);

        let initrd_dir = ramfs::alloc_inode();
        (*initrd_dir).ftype = FTYPE_DIRECTORY;
        (*initrd_dir).mode = S_IFDIR_L | 0o555;
        (*initrd_dir).readonly = 1;
        (*initrd_dir).nlink = 2;
        (*initrd_dir).parent_ino = (*root).ino;
        ramfs::dir_add_entry(root, b"initrd".as_ptr(), 6, (*initrd_dir).ino);

        let tmp_dir = ramfs::alloc_inode();
        (*tmp_dir).ftype = FTYPE_DIRECTORY;
        (*tmp_dir).mode = S_IFDIR_L | 0o1777;
        (*tmp_dir).nlink = 2;
        (*tmp_dir).parent_ino = (*root).ino;
        ramfs::dir_add_entry(root, b"tmp".as_ptr(), 3, (*tmp_dir).ino);

        let etc_dir = ramfs::alloc_inode();
        (*etc_dir).ftype = FTYPE_DIRECTORY;
        (*etc_dir).mode = S_IFDIR_L | 0o755;
        (*etc_dir).nlink = 2;
        (*etc_dir).parent_ino = (*root).ino;
        ramfs::dir_add_entry(root, b"etc".as_ptr(), 3, (*etc_dir).ino);

        let hosts = ramfs::alloc_inode();
        (*hosts).ftype = FTYPE_PROC_FILE;
        (*hosts).dev_type = PROC_FILE_ETC_HOSTS;
        (*hosts).mode = S_IFREG_L | 0o444;
        (*hosts).readonly = 1;
        (*hosts).parent_ino = (*etc_dir).ino;
        ramfs::dir_add_entry(etc_dir, b"hosts".as_ptr(), 5, (*hosts).ino);

        let host = ramfs::alloc_inode();
        (*host).ftype = FTYPE_PROC_FILE;
        (*host).dev_type = PROC_FILE_ETC_HOSTS;
        (*host).mode = S_IFREG_L | 0o444;
        (*host).readonly = 1;
        (*host).parent_ino = (*etc_dir).ino;
        ramfs::dir_add_entry(etc_dir, b"host".as_ptr(), 4, (*host).ino);

        let resolv_conf = ramfs::alloc_inode();
        (*resolv_conf).ftype = FTYPE_PROC_FILE;
        (*resolv_conf).dev_type = PROC_FILE_ETC_RESOLV_CONF;
        (*resolv_conf).mode = S_IFREG_L | 0o444;
        (*resolv_conf).readonly = 1;
        (*resolv_conf).parent_ino = (*etc_dir).ino;
        ramfs::dir_add_entry(etc_dir, b"resolv.conf".as_ptr(), 11, (*resolv_conf).ino);

        let initrd = INITRD_VADDR as *const u8;
        let initrd_size = ramfs::read_boot_info_initrd_size();

        trona::uinfo!(|_lb| {
            _lb.str(b"[VFS] Initrd size: ");
            _lb.hex(initrd_size as u64);
            _lb.str(b" bytes\n");
        });

        let mut offset: usize = 0;
        let mut entry = CpioEntryExt::zeroed();
        let mut file_count: u32 = 0;

        while cpio::cpio_next_ext(initrd, initrd_size, &raw mut offset, &raw mut entry) != 0 {
            if entry.name_len == 1 && *entry.name == b'.' {
                continue;
            }
            if ramfs::mount_initrd_entry(initrd_dir, &entry) {
                file_count += 1;
            }
        }

        trona::uinfo!(|_lb| {
            _lb.str(b"[VFS] Mounted ");
            _lb.hex(file_count as u64);
            _lb.str(b" initrd files\n");
        });
    }
}

// ======================================================================
// Entry point
// ======================================================================

#[unsafe(no_mangle)]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    trona::uinfo!(|_lb| {
        _lb.str(b"[VFS] SaltyOS VFS server starting\n");
    });

    unsafe {
        let derr = init_dynamic_state_storage();
        if derr != 0 {
            trona::uerror!(|_lb| {
                _lb.str(b"[VFS] FAIL: state storage init err=");
                _lb.hex(derr as u64);
                _lb.str(b"\n");
            });
            idle();
        }
    }

    unsafe {
        urandom_init();
        init_ramfs();
        init_fb_info();
    }

    trona::uinfo!(|_lb| {
        _lb.str(b"[VFS] Filesystem ready\n");
    });

    if VFS_CAP_NAMESERV_EP != 0 {
        let mut reg_msg = TronaMsg::zeroed();
        let mut reg_reply = TronaMsg::zeroed();
        let svc_name = b"vfs";
        reg_msg.label = POSIX_NS_REGISTER;
        reg_msg.regs[0] = svc_name.len() as u64;
        reg_msg.length = 1 + (svc_name.len() as u64 + 7) / 8;
        let ns_dst = &raw mut reg_msg.regs[1] as *mut u8;
        unsafe {
            for i in 0..svc_name.len() {
                *ns_dst.add(i) = svc_name[i];
            }
        }

        unsafe {
            ipc::set_send_cap_ctx(ipc_ctx(), 0, CAP_SERVER_EP);
            let err = ipc::call_ctx(
                ipc_ctx(),
                VFS_CAP_NAMESERV_EP,
                &raw const reg_msg,
                &raw mut reg_reply,
            );
            if err == 0 && reg_reply.label == TRONA_OK {
                trona::uinfo!(|_lb| {
                    _lb.str(b"[VFS] registered with nameserv\n");
                });
            } else {
                trona::uwarn!(|_lb| {
                    _lb.str(b"[VFS] WARN: nameserv registration failed\n");
                });
            }
        }
    }

    {
        let err = trona::invoke::tcb_bind_notification(CAP_SELF_TCB, VFS_CAP_PTY_NTFN);
        if err == 0 {
            trona::uinfo!(|_lb| {
                _lb.str(b"[VFS] PTY notification bound to TCB\n");
            });
        } else {
            trona::uwarn!(|_lb| {
                _lb.str(b"[VFS] WARN: PTY notification bind failed\n");
            });
        }
    }

    // Eagerly establish the root underlay mount (saltyfs/rootfs) during startup.
    // Doing this outside request handling avoids nested nameserv+cap-transfer mount setup
    // on the first /bin/* open path (e.g., procmgr VFS fallback loads).
    unsafe {
        mount::setup_saltyfs_mount();
    }

    signal_ready();

    unsafe {
        let slot = match trona::slot_alloc::slot_alloc() {
            Some(s) => s,
            None => {
                trona::uerror!(|_lb| {
                    _lb.str(b"[VFS] FATAL: no receive slot for pager IPC\n");
                });
                idle();
            }
        };
        CURRENT_RECV_SLOT = slot;
        ipc::set_receive_slot_ctx(ipc_ctx(), CAP_SELF_CSPACE, slot, 0);
    }

    if unsafe { !inet::prepare_inet_callback_endpoint() } {
        trona::uerror!(|_lb| {
            _lb.str(b"[VFS] failed to prepare netsrv callback endpoint\n");
        });
        idle();
    }

    let mut msg = TronaMsg::zeroed();
    let mut badge: u64 = 0;
    let mut recv_source: u64 = 0;
    let recv_endpoints = [CAP_SERVER_EP, VFS_CAP_NETSRV_CALLBACK_EP];
    let mut have_message = true;

    let err = unsafe {
        ipc::recv_any_ctx(
            ipc_ctx(),
            recv_endpoints.as_ptr(),
            recv_endpoints.len(),
            &raw mut msg,
            &raw mut badge,
            &raw mut recv_source,
        )
    };
    if err != 0 {
        trona::uerror!(|_lb| {
            _lb.str(b"[VFS] initial recv failed\n");
        });
        idle();
    }

    loop {
        let mut reply = TronaMsg::zeroed();
        let mut skip_reply = true;

        if have_message {
            skip_reply = false;

            if recv_source == IPC_RECV_SOURCE_NOTIFICATION {
                unsafe {
                    misc::handle_pty_notification(badge);
                }
                skip_reply = true;
            } else if recv_source == 1 {
                // Async completion from netsrv. netsrv rebadges the transferred
                // callback endpoint locally, so callback identity is enforced by
                // the badge on the dedicated callback EP.
                if badge == consts::NETSRV_CALLBACK_BADGE {
                    unsafe {
                        inet::handle_netsrv_callback(&raw const msg, &raw mut reply);
                    }
                } else {
                    reply.label = TRONA_INVALID_OPERATION;
                }
                // reply to netsrv to complete the callback IPC — do NOT skip reply
            } else {
                unsafe {
                    match msg.label {
                        VFS_OPEN => {
                            fileops::handle_open(&raw const msg, &raw mut reply, badge);
                        }
                        VFS_READ => {
                            let fd = msg.regs[0] as i32;
                            let cli = client::get_client(badge);
                            if !cli.is_null()
                                && fd >= 0
                                && fd < (*cli).fds_cap as i32
                                && (*(*cli).fds.add(fd as usize)).active != 0
                            {
                                match (*(*cli).fds.add(fd as usize)).fd_type {
                                    FD_TYPE_INET_SOCKET => {
                                        skip_reply = inet::handle_inet_read(
                                            &raw const msg,
                                            (*cli).fds.add(fd as usize),
                                            &raw mut reply,
                                            badge,
                                        );
                                    }
                                    FD_TYPE_SOCKET => {
                                        skip_reply = socket::handle_socket_read(
                                            (*cli).fds.add(fd as usize),
                                            &raw mut reply,
                                            badge,
                                        );
                                    }
                                    FD_TYPE_PIPE => {
                                        skip_reply = pipe::handle_pipe_read(
                                            &raw const msg,
                                            (*cli).fds.add(fd as usize),
                                            &raw mut reply,
                                            badge,
                                        );
                                    }
                                    FD_TYPE_DEVICE => {
                                        if (*(*cli).fds.add(fd as usize)).dev_type == DEV_PTY_SLAVE {
                                            skip_reply = misc::handle_pty_dev_read(
                                                &raw const msg,
                                                (*cli).fds.add(fd as usize),
                                                &raw mut reply,
                                                badge,
                                            );
                                        } else {
                                            fileops::handle_read(&raw const msg, &raw mut reply, badge);
                                        }
                                    }
                                    FD_TYPE_MOUNT => {
                                        let fde = &mut *(*cli).fds.add(fd as usize);
                                        let mount_idx = fde.dev_type as usize;
                                        let remote_ino = fde.sock_id as u64;
                                        let count = msg.regs[1];
                                        if *(&raw const VFS_SHM_ACTIVE) {
                                            mount::mount_read_shm(
                                                mount_idx,
                                                remote_ino,
                                                fde.offset,
                                                count,
                                                0,
                                                &raw mut reply,
                                            );
                                            if reply.label == TRONA_OK {
                                                let bytes_read = reply.regs[0];
                                                let copy_len = bytes_read.min(152);
                                                reply.length = 1 + (copy_len + 7) / 8;
                                                let src = VFS_SALTYFS_SHM_VADDR as *const u8;
                                                let dst = &raw mut reply.regs[1] as *mut u8;
                                                for j in 0..copy_len as usize {
                                                    *dst.add(j) = *src.add(j);
                                                }
                                            }
                                        } else {
                                            let capped = count.min(152);
                                            mount::mount_read_inline(
                                                mount_idx,
                                                remote_ino,
                                                fde.offset,
                                                capped,
                                                &raw mut reply,
                                            );
                                        }
                                        if reply.label == TRONA_OK {
                                            let bytes_read = reply.regs[0];
                                            fde.offset += bytes_read;
                                        }
                                    }
                                    _ => {
                                        fileops::handle_read(&raw const msg, &raw mut reply, badge);
                                    }
                                }
                            } else {
                                fileops::handle_read(&raw const msg, &raw mut reply, badge);
                            }
                        },
                        VFS_WRITE => {
                            let fd = msg.regs[0] as i32;
                            let cli = client::get_client(badge);
                            if !cli.is_null()
                                && fd >= 0
                                && fd < (*cli).fds_cap as i32
                                && (*(*cli).fds.add(fd as usize)).active != 0
                            {
                                match (*(*cli).fds.add(fd as usize)).fd_type {
                                    FD_TYPE_INET_SOCKET => {
                                        skip_reply = inet::handle_inet_write(
                                            &raw const msg,
                                            (*cli).fds.add(fd as usize),
                                            &raw mut reply,
                                        );
                                    }
                                    FD_TYPE_SOCKET => {
                                        skip_reply = socket::handle_socket_write(
                                            &raw const msg,
                                            (*cli).fds.add(fd as usize),
                                            &raw mut reply,
                                        );
                                    }
                                    FD_TYPE_PIPE => {
                                        skip_reply = pipe::handle_pipe_write(
                                            &raw const msg,
                                            (*cli).fds.add(fd as usize),
                                            &raw mut reply,
                                            badge,
                                        );
                                    }
                                    FD_TYPE_MOUNT => {
                                        let fde = &mut *(*cli).fds.add(fd as usize);
                                        if !client::flags_allow_write(fde.flags) {
                                            reply.label = TRONA_INVALID_OPERATION;
                                        } else {
                                            let mount_idx = fde.dev_type as usize;
                                            let remote_ino = fde.sock_id as u64;
                                            let count = msg.regs[1];
                                            let mut offset = fde.offset;
                                            if (fde.flags & O_APPEND) != 0 {
                                                if let Some((sz, _, _, _, _)) =
                                                    mount::mount_stat(mount_idx, remote_ino)
                                                {
                                                    offset = sz;
                                                }
                                            }
                                            if count > 136 && *(&raw const VFS_SHM_ACTIVE) {
                                                let max_inline: u64 = 18 * 8;
                                                let shm_limit: u64 = VFS_SALTYFS_SHM_PAGES * 4096;
                                                let safe_count = count.min(max_inline).min(shm_limit);
                                                let src = &msg.regs[2] as *const u64 as *const u8;
                                                let dst = VFS_SALTYFS_SHM_VADDR as *mut u8;
                                                for j in 0..safe_count as usize {
                                                    *dst.add(j) = *src.add(j);
                                                }
                                                mount::mount_write_shm(
                                                    mount_idx,
                                                    remote_ino,
                                                    offset,
                                                    safe_count,
                                                    0,
                                                    &raw mut reply,
                                                );
                                            } else {
                                                let capped = count.min(136);
                                                let src = &msg.regs[2] as *const u64 as *const u8;
                                                mount::mount_write_inline(
                                                    mount_idx,
                                                    remote_ino,
                                                    offset,
                                                    src,
                                                    capped,
                                                    &raw mut reply,
                                                );
                                            }
                                            if reply.label == TRONA_OK {
                                                let written = reply.regs[0];
                                                fde.offset = offset + written;
                                            }
                                        }
                                    }
                                    _ => {
                                        fileops::handle_write(&raw const msg, &raw mut reply, badge);
                                    }
                                }
                            } else {
                                fileops::handle_write(&raw const msg, &raw mut reply, badge);
                            }
                        },
                    VFS_CLOSE => {
                        let fd = msg.regs[0] as i32;
                        let cli = client::get_client(badge);
                        if !cli.is_null()
                            && fd >= 0
                            && fd < (*cli).fds_cap as i32
                            && (*(*cli).fds.add(fd as usize)).active != 0
                        {
                            match (*(*cli).fds.add(fd as usize)).fd_type {
                                FD_TYPE_INET_SOCKET => {
                                    inet::close_inet_socket((*cli).fds.add(fd as usize));
                                }
                                FD_TYPE_SOCKET => {
                                    socket::close_socket((*cli).fds.add(fd as usize));
                                }
                                FD_TYPE_PIPE => {
                                    pipe::close_pipe((*cli).fds.add(fd as usize));
                                }
                                FD_TYPE_EPOLL => {
                                    let ep_idx = (*(*cli).fds.add(fd as usize)).sock_id as usize;
                                    if ep_idx < max_epoll_instances() {
                                        EPOLLS!()[ep_idx].active = 0;
                                    }
                                }
                                _ => {}
                            }
                        }
                        fileops::handle_close(&raw const msg, &raw mut reply, badge);
                    }
                    VFS_STAT => {
                        fileops::handle_stat(&raw const msg, &raw mut reply, badge);
                    }
                    VFS_LSEEK => {
                        fileops::handle_lseek(&raw const msg, &raw mut reply, badge);
                    }
                    VFS_FSTAT => {
                        fileops::handle_fstat(&raw const msg, &raw mut reply, badge);
                    }
                    VFS_ACCESS => {
                        fileops::handle_access(&raw const msg, &raw mut reply, badge);
                    }
                    VFS_UNLINK => {
                        fileops::handle_unlink(&raw const msg, &raw mut reply, badge);
                    }
                    VFS_RENAME => {
                        fileops::handle_rename(&raw const msg, &raw mut reply, badge);
                    }
                    VFS_MKDIR => {
                        fileops::handle_mkdir(&raw const msg, &raw mut reply, badge);
                    }
                    VFS_RMDIR => {
                        fileops::handle_rmdir(&raw const msg, &raw mut reply, badge);
                    }
                    VFS_OPENDIR => {
                        fileops::handle_opendir(&raw const msg, &raw mut reply, badge);
                    }
                    VFS_READDIR => {
                        let fd = msg.regs[0] as i32;
                        let cli = client::get_client(badge);
                        if !cli.is_null()
                            && fd >= 0
                            && fd < (*cli).fds_cap as i32
                            && (*(*cli).fds.add(fd as usize)).active != 0
                            && (*(*cli).fds.add(fd as usize)).fd_type == FD_TYPE_MOUNT
                        {
                            let fde = &mut *(*cli).fds.add(fd as usize);
                            let mount_idx = fde.dev_type as usize;
                            let remote_ino = fde.sock_id as u64;
                            mount::mount_readdir(
                                mount_idx,
                                fde as *mut FdEntry,
                                remote_ino,
                                &raw mut reply,
                            );
                        } else {
                            fileops::handle_readdir(&raw const msg, &raw mut reply, badge);
                        }
                    }
                    VFS_LSTAT => {
                        at_ops::handle_lstat(&raw const msg, &raw mut reply, badge);
                    }
                    VFS_POLL => {
                        skip_reply = poll::handle_poll(&raw const msg, &raw mut reply, badge);
                    }
                    VFS_SHM_OPEN => {
                        skip_reply = misc::handle_shm_open(&raw const msg, &raw mut reply, badge);
                    }
                    VFS_SHM_UNLINK => {
                        skip_reply = misc::handle_shm_unlink(&raw const msg, &raw mut reply);
                    }
                    VFS_FTRUNCATE => {
                        skip_reply = misc::handle_ftruncate(&raw const msg, &raw mut reply, badge);
                    }
                    VFS_SOCKET => {
                        skip_reply = socket::handle_socket(&raw const msg, &raw mut reply, badge);
                    }
                    VFS_BIND => {
                        // Check for AF_INET bind (regs[1] == AF_INET)
                        if msg.regs[1] == trona::consts::AF_INET as u64 {
                            skip_reply =
                                inet::handle_inet_bind(&raw const msg, &raw mut reply, badge);
                        } else {
                            skip_reply = socket::handle_bind(&raw const msg, &raw mut reply, badge);
                        }
                    }
                    VFS_LISTEN => {
                        let fd = msg.regs[0] as i32;
                        let cli = client::get_client(badge);
                        if !cli.is_null()
                            && fd >= 0
                            && fd < (*cli).fds_cap as i32
                            && (*(*cli).fds.add(fd as usize)).active != 0
                            && (*(*cli).fds.add(fd as usize)).fd_type == FD_TYPE_INET_SOCKET
                        {
                            skip_reply =
                                inet::handle_inet_listen(&raw const msg, &raw mut reply, badge);
                        } else {
                            skip_reply =
                                socket::handle_listen(&raw const msg, &raw mut reply, badge);
                        }
                    }
                    VFS_ACCEPT => {
                        let fd = msg.regs[0] as i32;
                        let cli = client::get_client(badge);
                        if !cli.is_null()
                            && fd >= 0
                            && fd < (*cli).fds_cap as i32
                            && (*(*cli).fds.add(fd as usize)).active != 0
                            && (*(*cli).fds.add(fd as usize)).fd_type == FD_TYPE_INET_SOCKET
                        {
                            skip_reply =
                                inet::handle_inet_accept(&raw const msg, &raw mut reply, badge);
                        } else {
                            skip_reply =
                                socket::handle_accept(&raw const msg, &raw mut reply, badge);
                        }
                    }
                    VFS_CONNECT => {
                        let fd = msg.regs[0] as i32;
                        let cli = client::get_client(badge);
                        if !cli.is_null()
                            && fd >= 0
                            && fd < (*cli).fds_cap as i32
                            && (*(*cli).fds.add(fd as usize)).active != 0
                            && (*(*cli).fds.add(fd as usize)).fd_type == FD_TYPE_INET_SOCKET
                        {
                            skip_reply =
                                inet::handle_inet_connect(&raw const msg, &raw mut reply, badge);
                        } else {
                            skip_reply =
                                socket::handle_connect(&raw const msg, &raw mut reply, badge);
                        }
                    }
                    VFS_SENDMSG => {
                        let fd = msg.regs[0] as i32;
                        let cli = client::get_client(badge);
                        if !cli.is_null()
                            && fd >= 0
                            && fd < (*cli).fds_cap as i32
                            && (*(*cli).fds.add(fd as usize)).active != 0
                            && (*(*cli).fds.add(fd as usize)).fd_type == FD_TYPE_INET_SOCKET
                        {
                            // Check if this is a sendto (has dst_ip/port)
                            if msg.regs[3] != 0 || msg.regs[4] != 0 {
                                skip_reply =
                                    inet::handle_inet_sendto(&raw const msg, &raw mut reply, badge);
                            } else {
                                // Regular send on connected inet socket
                                skip_reply = inet::handle_inet_write(
                                    &raw const msg,
                                    (*cli).fds.add(fd as usize),
                                    &raw mut reply,
                                );
                            }
                        } else {
                            skip_reply =
                                socket::handle_sendmsg(&raw const msg, &raw mut reply, badge);
                        }
                    }
                    VFS_RECVMSG => {
                        let fd = msg.regs[0] as i32;
                        let cli = client::get_client(badge);
                        if !cli.is_null()
                            && fd >= 0
                            && fd < (*cli).fds_cap as i32
                            && (*(*cli).fds.add(fd as usize)).active != 0
                            && (*(*cli).fds.add(fd as usize)).fd_type == FD_TYPE_INET_SOCKET
                        {
                            let inet_flags = msg.regs[2] as u32;
                            if (inet_flags & INET_RECV_FLAG_WANT_ADDR) != 0 {
                                skip_reply = inet::handle_inet_recvfrom(
                                    &raw const msg,
                                    &raw mut reply,
                                    badge,
                                );
                            } else {
                                skip_reply = inet::handle_inet_read(
                                    &raw const msg,
                                    (*cli).fds.add(fd as usize),
                                    &raw mut reply,
                                    badge,
                                );
                            }
                        } else {
                            skip_reply =
                                socket::handle_recvmsg(&raw const msg, &raw mut reply, badge);
                        }
                    }
                    VFS_SOCKPAIR => {
                        skip_reply = socket::handle_sockpair(&raw const msg, &raw mut reply, badge);
                    }
                    VFS_SHUTDOWN => {
                        let fd = msg.regs[0] as i32;
                        let cli = client::get_client(badge);
                        if !cli.is_null()
                            && fd >= 0
                            && fd < (*cli).fds_cap as i32
                            && (*(*cli).fds.add(fd as usize)).active != 0
                            && (*(*cli).fds.add(fd as usize)).fd_type == FD_TYPE_INET_SOCKET
                        {
                            skip_reply =
                                inet::handle_inet_shutdown(&raw const msg, &raw mut reply, badge);
                        } else {
                            skip_reply =
                                socket::handle_shutdown(&raw const msg, &raw mut reply, badge);
                        }
                    }
                    VFS_GETSOCKNAME => {
                        skip_reply =
                            inet::handle_inet_getsockname(&raw const msg, &raw mut reply, badge);
                    }
                    VFS_GETPEERNAME => {
                        skip_reply =
                            inet::handle_inet_getpeername(&raw const msg, &raw mut reply, badge);
                    }
                    VFS_SETSOCKOPT => {
                        skip_reply =
                            inet::handle_inet_setsockopt(&raw const msg, &raw mut reply, badge);
                    }
                    VFS_GETSOCKOPT => {
                        skip_reply =
                            inet::handle_inet_getsockopt(&raw const msg, &raw mut reply, badge);
                    }
                    VFS_PIPE => {
                        pipe::handle_pipe(&raw const msg, &raw mut reply, badge);
                    }
                    VFS_DUP => {
                        pipe::handle_dup(&raw const msg, &raw mut reply, badge);
                    }
                    VFS_DUP2 => {
                        pipe::handle_dup2(&raw const msg, &raw mut reply, badge);
                    }
                    VFS_CLONE_FDS => {
                        pipe::handle_clone_fds(&raw const msg, &raw mut reply);
                    }
                    VFS_ISATTY => {
                        misc::handle_isatty(&raw const msg, &raw mut reply, badge);
                    }
                    VFS_IOCTL => {
                        misc::handle_ioctl(&raw const msg, &raw mut reply, badge);
                    }
                    VFS_FCNTL => {
                        misc::handle_fcntl(&raw const msg, &raw mut reply, badge);
                    }
                    VFS_CHDIR => {
                        misc::handle_chdir(&raw const msg, &raw mut reply, badge);
                    }
                    VFS_GETCWD => {
                        misc::handle_getcwd(&raw const msg, &raw mut reply, badge);
                    }
                    VFS_TCGETATTR => {
                        misc::handle_tcgetattr(&raw const msg, &raw mut reply, badge);
                    }
                    VFS_TCSETATTR => {
                        misc::handle_tcsetattr(&raw const msg, &raw mut reply, badge);
                    }
                    VFS_DUP3 => {
                        pipe::handle_dup3(&raw const msg, &raw mut reply, badge);
                    }
                    VFS_MKFIFO => {
                        fileops::handle_mkfifo(&raw const msg, &raw mut reply, badge);
                    }
                    VFS_EPOLL_CREATE => {
                        poll::handle_epoll_create(&raw mut reply, badge);
                    }
                    VFS_EPOLL_CTL => {
                        poll::handle_epoll_ctl(&raw const msg, &raw mut reply, badge);
                    }
                    VFS_EPOLL_WAIT => {
                        skip_reply = poll::handle_epoll_wait(&raw const msg, &raw mut reply, badge);
                    }
                    VFS_MMAP => {
                        misc::handle_mmap(&raw const msg, &raw mut reply, badge);
                    }
                    VFS_MUNMAP => {
                        misc::handle_munmap(&raw const msg, &raw mut reply, badge);
                    }
                    VFS_OPENAT => {
                        at_ops::handle_openat(&raw const msg, &raw mut reply, badge);
                    }
                    VFS_FSTATAT => {
                        at_ops::handle_fstatat(&raw const msg, &raw mut reply, badge);
                    }
                    VFS_UNLINKAT => {
                        at_ops::handle_unlinkat(&raw const msg, &raw mut reply, badge);
                    }
                    VFS_RENAMEAT => {
                        at_ops::handle_renameat(&raw const msg, &raw mut reply, badge);
                    }
                    VFS_MKDIRAT => {
                        at_ops::handle_mkdirat(&raw const msg, &raw mut reply, badge);
                    }
                    VFS_FACCESSAT => {
                        at_ops::handle_faccessat(&raw const msg, &raw mut reply, badge);
                    }
                    VFS_FCHMODAT => {
                        at_ops::handle_fchmodat(&raw const msg, &raw mut reply, badge);
                    }
                    VFS_FCHOWNAT => {
                        at_ops::handle_fchownat(&raw const msg, &raw mut reply, badge);
                    }
                    VFS_LINKAT => {
                        at_ops::handle_linkat(&raw const msg, &raw mut reply, badge);
                    }
                    VFS_SYMLINKAT => {
                        at_ops::handle_symlinkat(&raw const msg, &raw mut reply, badge);
                    }
                    VFS_READLINKAT => {
                        at_ops::handle_readlinkat(&raw const msg, &raw mut reply, badge);
                    }
                    VFS_UTIMENSAT => {
                        at_ops::handle_utimensat(&raw const msg, &raw mut reply, badge);
                    }
                    VFS_FCHMOD => {
                        at_ops::handle_fchmod(&raw const msg, &raw mut reply, badge);
                    }
                    VFS_FCHOWN => {
                        at_ops::handle_fchown(&raw const msg, &raw mut reply, badge);
                    }
                    VFS_CLIENT_EXIT => {
                        client::handle_client_exit(&raw const msg, &raw mut reply);
                        skip_reply = true;
                    }
                    VFS_PREAD => {
                        fileops::handle_pread(&raw const msg, &raw mut reply, badge);
                    }
                    VFS_PWRITE => {
                        fileops::handle_pwrite(&raw const msg, &raw mut reply, badge);
                    }
                    VFS_BULK_SETUP => {
                        bulk::handle_bulk_setup(&raw const msg, &raw mut reply, badge);
                    }
                    VFS_BULK_READ => {
                        bulk::handle_bulk_read(&raw const msg, &raw mut reply, badge);
                    }
                    VFS_BULK_PWRITE => {
                        bulk::handle_bulk_pwrite(&raw const msg, &raw mut reply, badge);
                    }
                    VFS_MMAP_PAGEIN => {
                        misc::handle_mmap_pagein(&raw const msg, &raw mut reply);
                    }
                    VFS_MMAP_WRITEBACK => {
                        misc::handle_mmap_writeback(&raw const msg, &raw mut reply);
                    }
                    _ => {
                        reply.label = TRONA_INVALID_OPERATION;
                    }
                }
            }
        }

        unsafe {
            if CURRENT_RECV_SLOT != 0 {
                let _ = trona::invoke::cnode_delete(CAP_SELF_CSPACE, CURRENT_RECV_SLOT);
                ipc::set_receive_slot_ctx(ipc_ctx(), CAP_SELF_CSPACE, CURRENT_RECV_SLOT, 0);
            }
        }
        }

        unsafe {
            let now_ns = poll::monotonic_now_ns();
            poll::expire_poll_timeouts(now_ns);
            misc::expire_pty_read_timeouts(now_ns);
        }
        let timeout_ns = unsafe {
            let now_ns = poll::monotonic_now_ns();
            let poll_timeout_ns = poll::next_poll_timeout_ns(now_ns);
            let pty_timeout_ns = misc::next_pty_read_timeout_ns(now_ns);
            match (poll_timeout_ns, pty_timeout_ns) {
                (0, other) => other,
                (other, 0) => other,
                (lhs, rhs) => core::cmp::min(lhs, rhs),
            }
        };

        let err = if skip_reply {
            if timeout_ns == 0 {
                unsafe {
                    ipc::recv_any_ctx(
                        ipc_ctx(),
                        recv_endpoints.as_ptr(),
                        recv_endpoints.len(),
                        &raw mut msg,
                        &raw mut badge,
                        &raw mut recv_source,
                    )
                }
            } else {
                unsafe {
                    ipc::recv_any_timed_ctx(
                        ipc_ctx(),
                        recv_endpoints.as_ptr(),
                        recv_endpoints.len(),
                        timeout_ns,
                        &raw mut msg,
                        &raw mut badge,
                        &raw mut recv_source,
                    )
                }
            }
        } else {
            if timeout_ns == 0 {
                unsafe {
                    ipc::reply_recv_any_ctx(
                        ipc_ctx(),
                        recv_endpoints.as_ptr(),
                        recv_endpoints.len(),
                        &raw const reply,
                        &raw mut msg,
                        &raw mut badge,
                        &raw mut recv_source,
                    )
                }
            } else {
                unsafe {
                    ipc::reply_recv_any_timed_ctx(
                        ipc_ctx(),
                        recv_endpoints.as_ptr(),
                        recv_endpoints.len(),
                        timeout_ns,
                        &raw const reply,
                        &raw mut msg,
                        &raw mut badge,
                        &raw mut recv_source,
                    )
                }
            }
        };
        if err == TRONA_CANCELLED as i32 || err == TRONA_TIMED_OUT as i32 {
            unsafe {
                let now_ns = poll::monotonic_now_ns();
                poll::expire_poll_timeouts(now_ns);
                misc::expire_pty_read_timeouts(now_ns);
            }
            have_message = false;
            continue;
        }
        if err != 0 {
            trona::uerror!(|_lb| {
                _lb.str(b"[VFS] reply_recv failed err=");
                _lb.hex(err as u64);
                _lb.str(b"\n");
            });
            break;
        }
        have_message = true;
    }

    idle();
}

fn idle() -> ! {
    loop {
        trona::syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
    }
}
