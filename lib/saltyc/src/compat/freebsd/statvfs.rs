//! statvfs/fstatvfs stubs — ENOSYS
//! SPDX-License-Identifier: GPL-2.0-only

use crate::errno;

#[repr(C)]
pub struct Statvfs {
    pub f_bsize: u64,
    pub f_frsize: u64,
    pub f_blocks: u64,
    pub f_bfree: u64,
    pub f_bavail: u64,
    pub f_files: u64,
    pub f_ffree: u64,
    pub f_favail: u64,
    pub f_fsid: u64,
    pub f_flag: u64,
    pub f_namemax: u64,
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn statvfs(_path: *const u8, _buf: *mut Statvfs) -> i32 {
    errno::set_errno(errno::ENOSYS);
    -1
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fstatvfs(_fd: i32, _buf: *mut Statvfs) -> i32 {
    errno::set_errno(errno::ENOSYS);
    -1
}
