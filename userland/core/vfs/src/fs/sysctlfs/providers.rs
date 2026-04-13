// SPDX-License-Identifier: GPL-2.0-only
//! Built-in sysctl value providers.
//!
//! Each provider is a pair of read/write callbacks registered as a leaf on
//! the appropriate MIB subtree. Write callbacks are only provided for
//! read-write leaves (e.g. kern.hostname).

use super::tree::*;

// =========================================================================
// kern.ostype
// =========================================================================

unsafe fn read_ostype(buf: *mut u8, buf_len: usize) -> usize {
    copy_static(b"SaltyOS\n", buf, buf_len)
}

// =========================================================================
// kern.osrelease
// =========================================================================

unsafe fn read_osrelease(buf: *mut u8, buf_len: usize) -> usize {
    copy_static(b"0.1.0\n", buf, buf_len)
}

// =========================================================================
// kern.hostname
// =========================================================================

/// Mutable hostname buffer. Defaults to "saltyos", writable via sysctl.
static mut HOSTNAME: [u8; 256] = [0; 256];
static mut HOSTNAME_LEN: usize = 0;

unsafe fn read_hostname(buf: *mut u8, buf_len: usize) -> usize {
    unsafe {
        let len = *(&raw const HOSTNAME_LEN);
        let n = if len < buf_len { len } else { buf_len };
        core::ptr::copy_nonoverlapping((&raw const HOSTNAME) as *const u8, buf, n);
        n
    }
}

unsafe fn write_hostname(src: *const u8, len: usize) -> i32 {
    unsafe {
        // Strip trailing newline if present (echo "foo" > /sys/kern/hostname).
        let mut n = len;
        if n > 0 && *src.add(n - 1) == b'\n' {
            n -= 1;
        }
        if n > 255 {
            n = 255;
        }
        core::ptr::copy_nonoverlapping(src, (&raw mut HOSTNAME) as *mut u8, n);
        *(&raw mut HOSTNAME).cast::<u8>().add(n) = 0;
        *(&raw mut HOSTNAME_LEN) = n;
        0
    }
}

// =========================================================================
// kern.version
// =========================================================================

unsafe fn read_version(buf: *mut u8, buf_len: usize) -> usize {
    copy_static(b"SaltyOS 0.1.0\n", buf, buf_len)
}

// =========================================================================
// kern.maxproc
// =========================================================================

unsafe fn read_maxproc(buf: *mut u8, buf_len: usize) -> usize {
    write_u32_to_buf(256, buf, buf_len)
}

// =========================================================================
// hw.ncpu
// =========================================================================

unsafe fn read_hw_ncpu(buf: *mut u8, buf_len: usize) -> usize {
    // Default to 1; actual CPU count requires kernel query not yet wired.
    write_u32_to_buf(1, buf, buf_len)
}

// =========================================================================
// hw.pagesize
// =========================================================================

unsafe fn read_hw_pagesize(buf: *mut u8, buf_len: usize) -> usize {
    write_u32_to_buf(4096, buf, buf_len)
}

// =========================================================================
// hw.physmem
// =========================================================================

unsafe fn read_hw_physmem(buf: *mut u8, buf_len: usize) -> usize {
    // Default placeholder; actual physmem requires bootinfo parsing not yet wired.
    write_u64_to_buf(128 * 1024 * 1024, buf, buf_len)
}

// =========================================================================
// security.securelevel
// =========================================================================

static mut SECURELEVEL: i32 = -1;

unsafe fn read_securelevel(buf: *mut u8, buf_len: usize) -> usize {
    unsafe { write_i32_to_buf(SECURELEVEL, buf, buf_len) }
}

unsafe fn write_securelevel(src: *const u8, len: usize) -> i32 {
    unsafe {
        if len < 1 {
            return -1;
        }
        let val = parse_i32_from_buf(src, len);
        // FreeBSD semantics: securelevel can only increase (except from -1).
        if val < SECURELEVEL && SECURELEVEL >= 0 {
            return -1;
        }
        SECURELEVEL = val;
        0
    }
}

// =========================================================================
// Formatting helpers
// =========================================================================

fn copy_static(val: &[u8], buf: *mut u8, buf_len: usize) -> usize {
    let n = if val.len() < buf_len { val.len() } else { buf_len };
    unsafe { core::ptr::copy_nonoverlapping(val.as_ptr(), buf, n) };
    n
}

fn write_u32_to_buf(val: u32, buf: *mut u8, buf_len: usize) -> usize {
    let mut tmp = [0u8; 16];
    let len = fmt_u32(val, &mut tmp);
    if len < tmp.len() {
        tmp[len] = b'\n';
    }
    let total = len + 1;
    let n = if total < buf_len { total } else { buf_len };
    unsafe { core::ptr::copy_nonoverlapping(tmp.as_ptr(), buf, n) };
    n
}

fn write_u64_to_buf(val: u64, buf: *mut u8, buf_len: usize) -> usize {
    let mut tmp = [0u8; 24];
    let len = fmt_u64(val, &mut tmp);
    if len < tmp.len() {
        tmp[len] = b'\n';
    }
    let total = len + 1;
    let n = if total < buf_len { total } else { buf_len };
    unsafe { core::ptr::copy_nonoverlapping(tmp.as_ptr(), buf, n) };
    n
}

fn write_i32_to_buf(val: i32, buf: *mut u8, buf_len: usize) -> usize {
    let mut tmp = [0u8; 16];
    let pos;
    if val < 0 {
        tmp[0] = b'-';
        let abs = (val as i64).wrapping_neg() as u32;
        pos = 1 + fmt_u32(abs, &mut tmp[1..]);
    } else {
        pos = fmt_u32(val as u32, &mut tmp);
    }
    if pos < tmp.len() {
        tmp[pos] = b'\n';
    }
    let total = pos + 1;
    let n = if total < buf_len { total } else { buf_len };
    unsafe { core::ptr::copy_nonoverlapping(tmp.as_ptr(), buf, n) };
    n
}

fn fmt_u32(mut v: u32, buf: &mut [u8]) -> usize {
    if v == 0 {
        if !buf.is_empty() {
            buf[0] = b'0';
        }
        return 1;
    }
    let mut tmp = [0u8; 10];
    let mut len = 0usize;
    while v > 0 && len < 10 {
        tmp[len] = b'0' + (v % 10) as u8;
        v /= 10;
        len += 1;
    }
    for i in 0..len {
        if i < buf.len() {
            buf[i] = tmp[len - 1 - i];
        }
    }
    len
}

fn fmt_u64(mut v: u64, buf: &mut [u8]) -> usize {
    if v == 0 {
        if !buf.is_empty() {
            buf[0] = b'0';
        }
        return 1;
    }
    let mut tmp = [0u8; 20];
    let mut len = 0usize;
    while v > 0 && len < tmp.len() {
        tmp[len] = b'0' + (v % 10) as u8;
        v /= 10;
        len += 1;
    }
    for i in 0..len {
        if i < buf.len() {
            buf[i] = tmp[len - 1 - i];
        }
    }
    len
}

unsafe fn parse_i32_from_buf(src: *const u8, len: usize) -> i32 {
    unsafe {
        let mut pos = 0usize;
        let neg = if pos < len && *src == b'-' {
            pos += 1;
            true
        } else {
            false
        };
        // Skip leading whitespace / trailing newline.
        let mut end = len;
        while end > pos {
            let b = *src.add(end - 1);
            if b == b'\n' || b == b' ' || b == b'\t' {
                end -= 1;
            } else {
                break;
            }
        }
        let mut val: i32 = 0;
        while pos < end {
            let b = *src.add(pos);
            if b < b'0' || b > b'9' {
                break;
            }
            val = val.wrapping_mul(10).wrapping_add((b - b'0') as i32);
            pos += 1;
        }
        if neg { val.wrapping_neg() } else { val }
    }
}

// =========================================================================
// Registration
// =========================================================================

/// Register all built-in sysctl providers on the MIB tree.
///
/// # Safety
///
/// Must be called after `init_tree()` during VFS bootstrap (single-threaded).
pub(crate) unsafe fn init_providers() {
    unsafe {
        // kern.*
        if let Some(kern) = lookup_node_mut(b"kern") {
            kern.add_leaf(b"ostype", CTLTYPE_STRING, CTLFLAG_RD, Some(read_ostype), None);
            kern.add_leaf(b"osrelease", CTLTYPE_STRING, CTLFLAG_RD, Some(read_osrelease), None);
            kern.add_leaf(b"hostname", CTLTYPE_STRING, CTLFLAG_RW, Some(read_hostname), Some(write_hostname));
            kern.add_leaf(b"version", CTLTYPE_STRING, CTLFLAG_RD, Some(read_version), None);
            kern.add_leaf(b"maxproc", CTLTYPE_INT, CTLFLAG_RD, Some(read_maxproc), None);
        }

        // hw.*
        if let Some(hw) = lookup_node_mut(b"hw") {
            hw.add_leaf(b"ncpu", CTLTYPE_INT, CTLFLAG_RD, Some(read_hw_ncpu), None);
            hw.add_leaf(b"pagesize", CTLTYPE_INT, CTLFLAG_RD, Some(read_hw_pagesize), None);
            hw.add_leaf(b"physmem", CTLTYPE_U64, CTLFLAG_RD, Some(read_hw_physmem), None);
        }

        // security.*
        if let Some(sec) = lookup_node_mut(b"security") {
            sec.add_leaf(b"securelevel", CTLTYPE_INT, CTLFLAG_RW, Some(read_securelevel), Some(write_securelevel));
        }

        // Initialize hostname default.
        let default = b"saltyos";
        HOSTNAME[..default.len()].copy_from_slice(default);
        HOSTNAME_LEN = default.len();
    }
}
