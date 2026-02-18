//! FreeBSD stdio internals
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! __swbuf and __srget are called by FreeBSD's putc()/getc() macros
//! when the stdio buffer is full/empty.

/// FreeBSD putc() macro calls __swbuf when the buffer is full.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __swbuf(c: i32, f: *mut crate::stdio::FILE) -> i32 {
    unsafe { crate::stdio::fputc(c, f) }
}

unsafe extern "C" {
    safe fn fgetc(stream: *mut u8) -> i32;
}

/// FreeBSD getc() macro calls __srget when the read buffer is empty.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __srget(stream: *mut u8) -> i32 {
    fgetc(stream)
}
