//! Capsicum compatibility stubs
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! SaltyOS uses capability-based security at the kernel level, not Capsicum.
//! These stubs satisfy FreeBSD ports that reference capsicum symbols.
//! __cap_rights_is_set returns true (all rights "granted" since capsicum
//! is not enforced). __cap_rights_set is a no-op.

#[repr(C)]
pub struct CapRights {
    cr_rights: [u64; 2],
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __cap_rights_init(
    _version: i32,
    rights: *mut CapRights,
    mut _args: ...,
) -> *mut CapRights {
    if !rights.is_null() {
        unsafe {
            (*rights).cr_rights[0] = 0;
            (*rights).cr_rights[1] = 0;
        }
    }
    rights
}

/// Capsicum rights check. Always returns true — capsicum is not enforced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __cap_rights_is_set(
    _rights: *const u8,
    _n: i32,
    _args: ...,
) -> bool {
    true
}

/// Capsicum rights manipulation. No-op — returns input unchanged.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __cap_rights_set(
    _rights: *mut u8,
    _n: i32,
    _args: ...,
) -> *mut u8 {
    _rights
}
