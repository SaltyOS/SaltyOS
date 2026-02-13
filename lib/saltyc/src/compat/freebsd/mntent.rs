//! mntent stubs — empty mount table
//! SPDX-License-Identifier: GPL-2.0-only

#[unsafe(no_mangle)]
pub unsafe extern "C" fn setmntent(_filename: *const u8, _typ: *const u8) -> *mut u8 {
    // Return non-null sentinel (no real file)
    1usize as *mut u8
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getmntent(_stream: *mut u8) -> *mut u8 {
    // Empty mount table — no entries
    core::ptr::null_mut()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn endmntent(_stream: *mut u8) -> i32 {
    1 // success
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn hasmntopt(_mnt: *const u8, _opt: *const u8) -> *mut u8 {
    core::ptr::null_mut()
}
