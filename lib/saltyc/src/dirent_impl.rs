//! Directory operations
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Implements `opendir`/`readdir`/`closedir` using a static pool of 16 `DIR`
//! entries. Each `DIR` wraps a POSIX file descriptor obtained from
//! `posix_open` with `O_DIRECTORY`. Directory entries are read one at a time
//! via `posix_getdents`.

use crate::errno;

/// Directory entry returned by `readdir()`.
#[repr(C)]
pub struct Dirent {
    /// Inode number.
    pub d_ino: u64,
    /// Offset to the next directory entry (opaque).
    pub d_off: i64,
    /// Length of this record in bytes.
    pub d_reclen: u16,
    /// File type: `DT_REG` (8), `DT_DIR` (4), `DT_LNK` (10), `DT_UNKNOWN` (0).
    pub d_type: u8,
    /// ABI padding/alignment field (matches FreeBSD dirent layout).
    pub d_pad0: u8,
    /// Length of string in d_name.
    pub d_namlen: u16,
    /// ABI padding/alignment field (matches FreeBSD dirent layout).
    pub d_pad1: u16,
    /// Null-terminated filename (max 255 characters + NUL).
    pub d_name: [u8; 256],
}

impl Dirent {
    const fn zeroed() -> Self {
        Dirent {
            d_ino: 0,
            d_off: 0,
            d_reclen: 0,
            d_type: 0,
            d_pad0: 0,
            d_namlen: 0,
            d_pad1: 0,
            d_name: [0; 256],
        }
    }
}

pub struct DIR {
    fd: i32,
    entry: Dirent,
    has_entry: bool,
}

impl DIR {
    const fn zeroed() -> Self {
        DIR {
            fd: -1,
            entry: Dirent::zeroed(),
            has_entry: false,
        }
    }
}

const DIR_POOL_SIZE: usize = 16;

static mut DIR_POOL: [DIR; DIR_POOL_SIZE] = {
    const ZERO: DIR = DIR::zeroed();
    [ZERO; DIR_POOL_SIZE]
};
static mut DIR_USED: [bool; DIR_POOL_SIZE] = [false; DIR_POOL_SIZE];

unsafe fn alloc_dir() -> *mut DIR {
    unsafe {
        for i in 0..DIR_POOL_SIZE {
            if !(*(&raw const DIR_USED))[i] {
                (*(&raw mut DIR_USED))[i] = true;
                let dir = &raw mut (*(&raw mut DIR_POOL))[i];
                (*dir).fd = -1;
                (*dir).has_entry = false;
                return dir;
            }
        }
        core::ptr::null_mut()
    }
}

unsafe fn free_dir(dir: *mut DIR) {
    unsafe {
        let pool_base = &raw mut DIR_POOL as *mut DIR;
        let offset = (dir as usize).wrapping_sub(pool_base as usize);
        let elem_size = core::mem::size_of::<DIR>();
        if elem_size > 0 {
            let idx = offset / elem_size;
            if idx < DIR_POOL_SIZE {
                (*(&raw mut DIR_USED))[idx] = false;
                (*dir).fd = -1;
            }
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn opendir(path: *const u8) -> *mut DIR {
    if path.is_null() {
        errno::set_errno(errno::EINVAL);
        return core::ptr::null_mut();
    }

    unsafe {
        let fd = salty::posix::posix_opendir(path);
        if fd < 0 {
            errno::set_errno(-fd);
            return core::ptr::null_mut();
        }

        let dir = alloc_dir();
        if dir.is_null() {
            salty::posix::posix_closedir(fd);
            errno::set_errno(errno::ENOMEM);
            return core::ptr::null_mut();
        }

        (*dir).fd = fd;
        dir
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn readdir(dir: *mut DIR) -> *mut Dirent {
    if dir.is_null() {
        errno::set_errno(errno::EBADF);
        return core::ptr::null_mut();
    }

    unsafe {
        let mut salty_entry = salty::types::SaltyDirent::zeroed();
        let ret = salty::posix::posix_readdir((*dir).fd, &raw mut salty_entry);
        if ret == 0 {
            // No more entries
            return core::ptr::null_mut();
        }

        // Copy fields from SaltyDirent into our Dirent
        (*dir).entry.d_ino = salty_entry.d_ino;
        (*dir).entry.d_off = 0;
        (*dir).entry.d_reclen = core::mem::size_of::<Dirent>() as u16;
        (*dir).entry.d_type = salty_entry.d_type;
        (*dir).entry.d_pad0 = 0;
        (*dir).entry.d_pad1 = 0;

        // Copy name, capping at the smaller of SaltyDirent.d_name (62 bytes)
        // and our d_name (256 bytes)
        let name_len = salty_entry.d_namlen as usize;
        let copy_len = if name_len < 62 { name_len } else { 61 };
        (*dir).entry.d_namlen = copy_len as u16;
        for i in 0..copy_len {
            (*dir).entry.d_name[i] = salty_entry.d_name[i];
        }
        (*dir).entry.d_name[copy_len] = 0;
        (*dir).has_entry = true;

        &raw mut (*dir).entry
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn closedir(dir: *mut DIR) -> i32 {
    if dir.is_null() {
        errno::set_errno(errno::EBADF);
        return -1;
    }

    unsafe {
        let fd = (*dir).fd;
        salty::posix::posix_closedir(fd);
        free_dir(dir);
        0
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dirfd(dir: *mut DIR) -> i32 {
    if dir.is_null() {
        errno::set_errno(errno::EBADF);
        return -1;
    }
    unsafe { (*dir).fd }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rewinddir(_dir: *mut DIR) {
    // Stub: no-op
}
