//! Password database stubs
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Provides a single hardcoded user entry (root, uid=0, gid=0) and a single
//! group entry (root, gid=0). `getpwnam`, `getpwuid`, `getgrnam`, `getgrgid`
//! all return pointers to static data. The `getpw*_r` reentrant variants
//! copy data into caller-provided buffers.

#[repr(C)]
pub struct Passwd {
    pub pw_name: *const u8,
    pub pw_passwd: *const u8,
    pub pw_uid: u32,
    pub pw_gid: u32,
    pub pw_gecos: *const u8,
    pub pw_dir: *const u8,
    pub pw_shell: *const u8,
}

#[repr(C)]
pub struct Group {
    pub gr_name: *const u8,
    pub gr_passwd: *const u8,
    pub gr_gid: u32,
    pub gr_mem: *const *const u8,
}

static ROOT_NAME: [u8; 5] = *b"root\0";
static ROOT_PASSWD: [u8; 2] = *b"x\0";
static ROOT_DIR: [u8; 2] = *b"/\0";
static ROOT_SHELL: [u8; 8] = *b"/bin/sh\0";
static ROOT_GECOS: [u8; 5] = *b"root\0";
static EMPTY_STR: [u8; 1] = *b"\0";

static mut ROOT_PASSWD_ENTRY: Passwd = Passwd {
    pw_name: core::ptr::null(),
    pw_passwd: core::ptr::null(),
    pw_uid: 0,
    pw_gid: 0,
    pw_gecos: core::ptr::null(),
    pw_dir: core::ptr::null(),
    pw_shell: core::ptr::null(),
};

static mut PASSWD_ITER: i32 = 0;

static GROUP_NAME: [u8; 5] = *b"root\0";
static mut MEMBERS: [*const u8; 1] = [core::ptr::null()];

static mut ROOT_GROUP_ENTRY: Group = Group {
    gr_name: core::ptr::null(),
    gr_passwd: core::ptr::null(),
    gr_gid: 0,
    gr_mem: core::ptr::null(),
};

static mut GROUP_ITER: i32 = 0;

/// Initialize the root passwd entry fields with pointers to static data.
unsafe fn init_root_passwd() {
    unsafe {
        let p = &raw mut ROOT_PASSWD_ENTRY;
        (*p).pw_name = ROOT_NAME.as_ptr();
        (*p).pw_passwd = ROOT_PASSWD.as_ptr();
        (*p).pw_uid = 0;
        (*p).pw_gid = 0;
        (*p).pw_gecos = ROOT_GECOS.as_ptr();
        (*p).pw_dir = ROOT_DIR.as_ptr();
        (*p).pw_shell = ROOT_SHELL.as_ptr();
    }
}

/// Initialize the root group entry fields with pointers to static data.
unsafe fn init_root_group() {
    unsafe {
        let g = &raw mut ROOT_GROUP_ENTRY;
        let m = &raw mut MEMBERS;
        (*m)[0] = core::ptr::null();
        (*g).gr_name = GROUP_NAME.as_ptr();
        (*g).gr_passwd = EMPTY_STR.as_ptr();
        (*g).gr_gid = 0;
        (*g).gr_mem = (*m).as_ptr();
    }
}

/// Compare a C string against a byte slice (excluding the null terminator
/// in the slice). Returns true if they match.
unsafe fn streq(cstr: *const u8, expected: &[u8]) -> bool {
    unsafe {
        // expected includes trailing \0 from the static arrays
        let mut i = 0;
        loop {
            let c = *cstr.add(i);
            if i >= expected.len() {
                // expected ended but cstr hasn't — only match if cstr also ends
                return c == 0;
            }
            let e = expected[i];
            if e == 0 {
                // expected's null terminator — cstr must also be null here
                return c == 0;
            }
            if c != e {
                return false;
            }
            i += 1;
        }
    }
}

// ---------------------------------------------------------------------------
// Passwd functions
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getpwnam(name: *const u8) -> *mut Passwd {
    if name.is_null() {
        return core::ptr::null_mut();
    }
    unsafe {
        init_root_passwd();
        if streq(name, &ROOT_NAME) {
            &raw mut ROOT_PASSWD_ENTRY
        } else {
            core::ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getpwuid(uid: u32) -> *mut Passwd {
    unsafe {
        init_root_passwd();
        if uid == 0 {
            &raw mut ROOT_PASSWD_ENTRY
        } else {
            core::ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getpwent() -> *mut Passwd {
    unsafe {
        let iter = *(&raw const PASSWD_ITER);
        if iter == 0 {
            init_root_passwd();
            *(&raw mut PASSWD_ITER) = 1;
            &raw mut ROOT_PASSWD_ENTRY
        } else {
            core::ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn setpwent() {
    unsafe {
        *(&raw mut PASSWD_ITER) = 0;
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn endpwent() {
    unsafe {
        *(&raw mut PASSWD_ITER) = 0;
    }
}

// ---------------------------------------------------------------------------
// Group functions
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getgrnam(name: *const u8) -> *mut Group {
    if name.is_null() {
        return core::ptr::null_mut();
    }
    unsafe {
        init_root_group();
        if streq(name, &GROUP_NAME) {
            &raw mut ROOT_GROUP_ENTRY
        } else {
            core::ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getgrgid(gid: u32) -> *mut Group {
    unsafe {
        init_root_group();
        if gid == 0 {
            &raw mut ROOT_GROUP_ENTRY
        } else {
            core::ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getgrent() -> *mut Group {
    unsafe {
        let iter = *(&raw const GROUP_ITER);
        if iter == 0 {
            init_root_group();
            *(&raw mut GROUP_ITER) = 1;
            &raw mut ROOT_GROUP_ENTRY
        } else {
            core::ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn setgrent() {
    unsafe {
        *(&raw mut GROUP_ITER) = 0;
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn endgrent() {
    unsafe {
        *(&raw mut GROUP_ITER) = 0;
    }
}
