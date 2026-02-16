//! FreeBSD stdio compatibility aliases
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! FreeBSD's `<stdio.h>` defines `stdout`/`stdin`/`stderr` as macros
//! expanding to `__stdoutp`/`__stdinp`/`__stderrp`. These static
//! pointers must exist as exported symbols for ported FreeBSD utilities.

use crate::stdio::FILE;

#[unsafe(no_mangle)]
pub static mut __stdinp: *mut FILE = core::ptr::null_mut();
#[unsafe(no_mangle)]
pub static mut __stdoutp: *mut FILE = core::ptr::null_mut();
#[unsafe(no_mangle)]
pub static mut __stderrp: *mut FILE = core::ptr::null_mut();

/// FreeBSD's libc threading indicator. Set to 1 (threaded) to match
/// FreeBSD libc behavior — some ported code checks this to decide
/// whether to use stdio locking.
#[unsafe(no_mangle)]
pub static mut __isthreaded: i32 = 1;
