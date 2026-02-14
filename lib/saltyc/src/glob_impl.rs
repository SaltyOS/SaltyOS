//! glob() and fnmatch() implementation
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! `fnmatch` supports `*`, `?`, `[...]` character classes, `FNM_PATHNAME`,
//! `FNM_PERIOD`, `FNM_NOESCAPE`, and `FNM_CASEFOLD` flags. `glob` expands
//! pathname patterns by scanning directories via `opendir`/`readdir` and
//! testing each entry with `fnmatch`. Results are collected into a heap-
//! allocated `Glob` structure with optional sorting (`GLOB_NOSORT`).

use crate::dirent_impl::{closedir, opendir, readdir};

// fnmatch/glob constants — some may only be referenced by C callers
#[allow(dead_code)] const FNM_PATHNAME: i32 = 1;
#[allow(dead_code)] const FNM_NOESCAPE: i32 = 2;
#[allow(dead_code)] const FNM_PERIOD: i32 = 4;
#[allow(dead_code)] const FNM_CASEFOLD: i32 = 16;
#[allow(dead_code)] const FNM_NOMATCH: i32 = 1;

#[allow(dead_code)] const GLOB_ERR: i32 = 1;
#[allow(dead_code)] const GLOB_MARK: i32 = 2;
#[allow(dead_code)] const GLOB_NOSORT: i32 = 4;
#[allow(dead_code)] const GLOB_NOCHECK: i32 = 8;
#[allow(dead_code)] const GLOB_DOOFFS: i32 = 16;
#[allow(dead_code)] const GLOB_APPEND: i32 = 32;
#[allow(dead_code)] const GLOB_NOESCAPE: i32 = 64;

#[allow(dead_code)] const GLOB_NOSPACE: i32 = 1;
#[allow(dead_code)] const GLOB_ABORTED: i32 = 2;
#[allow(dead_code)] const GLOB_NOMATCH: i32 = 3;

#[repr(C)]
pub struct GlobT {
    pub gl_pathc: usize,
    pub gl_pathv: *mut *mut u8,
    pub gl_offs: usize,
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fnmatch(
    pattern: *const u8,
    string: *const u8,
    flags: i32,
) -> i32 {
    if pattern.is_null() || string.is_null() {
        return FNM_NOMATCH;
    }
    unsafe {
        if fnmatch_impl(pattern, 0, string, 0, flags, true) {
            0
        } else {
            FNM_NOMATCH
        }
    }
}

unsafe fn fnmatch_impl(
    pat: *const u8,
    mut pi: usize,
    str: *const u8,
    mut si: usize,
    flags: i32,
    mut at_start: bool,
) -> bool {
    unsafe {
        loop {
            let pc = *pat.add(pi);
            let sc = *str.add(si);

            if pc == 0 {
                return sc == 0;
            }

            match pc {
                b'?' => {
                    if sc == 0 {
                        return false;
                    }
                    if (flags & FNM_PATHNAME) != 0 && sc == b'/' {
                        return false;
                    }
                    if (flags & FNM_PERIOD) != 0 && sc == b'.' && at_start {
                        return false;
                    }
                    pi += 1;
                    si += 1;
                    at_start = false;
                }
                b'*' => {
                    // Skip consecutive stars
                    while *pat.add(pi) == b'*' {
                        pi += 1;
                    }
                    if *pat.add(pi) == 0 {
                        // Trailing * matches everything (unless FNM_PATHNAME)
                        if (flags & FNM_PATHNAME) != 0 {
                            // Must not match '/'
                            let mut k = si;
                            while *str.add(k) != 0 {
                                if *str.add(k) == b'/' {
                                    return false;
                                }
                                k += 1;
                            }
                        }
                        if (flags & FNM_PERIOD) != 0 && sc == b'.' && at_start {
                            return false;
                        }
                        return true;
                    }
                    if (flags & FNM_PERIOD) != 0 && sc == b'.' && at_start {
                        return false;
                    }
                    // Try matching * against 0..n characters
                    let mut k = si;
                    while *str.add(k) != 0 {
                        if (flags & FNM_PATHNAME) != 0 && *str.add(k) == b'/' {
                            break;
                        }
                        if fnmatch_impl(pat, pi, str, k, flags, false) {
                            return true;
                        }
                        k += 1;
                    }
                    // Try matching * against the rest (empty rest)
                    return fnmatch_impl(pat, pi, str, k, flags, false);
                }
                b'[' => {
                    if sc == 0 {
                        return false;
                    }
                    if (flags & FNM_PATHNAME) != 0 && sc == b'/' {
                        return false;
                    }
                    if (flags & FNM_PERIOD) != 0 && sc == b'.' && at_start {
                        return false;
                    }
                    pi += 1;
                    let negate = *pat.add(pi) == b'!' || *pat.add(pi) == b'^';
                    if negate {
                        pi += 1;
                    }

                    let mut matched = false;
                    let mut first = true;
                    loop {
                        let c = *pat.add(pi);
                        if c == 0 {
                            return false; // unclosed bracket
                        }
                        if c == b']' && !first {
                            break;
                        }
                        first = false;

                        // Check for range: a-z
                        if *pat.add(pi + 1) == b'-' && *pat.add(pi + 2) != b']' && *pat.add(pi + 2) != 0 {
                            let lo = c;
                            let hi = *pat.add(pi + 2);
                            let test_c = if (flags & FNM_CASEFOLD) != 0 {
                                to_lower(sc)
                            } else {
                                sc
                            };
                            let lo_c = if (flags & FNM_CASEFOLD) != 0 { to_lower(lo) } else { lo };
                            let hi_c = if (flags & FNM_CASEFOLD) != 0 { to_lower(hi) } else { hi };
                            if test_c >= lo_c && test_c <= hi_c {
                                matched = true;
                            }
                            pi += 3;
                        } else {
                            let test_c = if (flags & FNM_CASEFOLD) != 0 {
                                to_lower(sc)
                            } else {
                                sc
                            };
                            let pat_c = if (flags & FNM_CASEFOLD) != 0 {
                                to_lower(c)
                            } else {
                                c
                            };
                            if test_c == pat_c {
                                matched = true;
                            }
                            pi += 1;
                        }
                    }
                    pi += 1; // skip ']'

                    if negate {
                        matched = !matched;
                    }
                    if !matched {
                        return false;
                    }
                    si += 1;
                    at_start = false;
                }
                b'\\' => {
                    if (flags & FNM_NOESCAPE) == 0 {
                        pi += 1;
                        let pc2 = *pat.add(pi);
                        if pc2 == 0 {
                            return false;
                        }
                        if sc != pc2 {
                            return false;
                        }
                        pi += 1;
                        si += 1;
                    } else {
                        // Treat backslash literally
                        if sc != pc {
                            return false;
                        }
                        pi += 1;
                        si += 1;
                    }
                    at_start = false;
                }
                _ => {
                    if (flags & FNM_CASEFOLD) != 0 {
                        if to_lower(pc) != to_lower(sc) {
                            return false;
                        }
                    } else if pc != sc {
                        return false;
                    }
                    pi += 1;
                    si += 1;
                    at_start = false;
                }
            }
        }
    }
}

fn to_lower(c: u8) -> u8 {
    if c >= b'A' && c <= b'Z' {
        c + 32
    } else {
        c
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn glob(
    pattern: *const u8,
    flags: i32,
    _errfunc: *const u8, // actually fn pointer, but we ignore it
    pglob: *mut GlobT,
) -> i32 {
    if pattern.is_null() || pglob.is_null() {
        return GLOB_ABORTED;
    }

    unsafe {
        if (flags & GLOB_APPEND) == 0 {
            (*pglob).gl_pathc = 0;
            (*pglob).gl_pathv = core::ptr::null_mut();
            (*pglob).gl_offs = 0;
        }

        // Split pattern into directory and file parts
        let pat_len = crate::string::strlen(pattern);
        let mut last_slash: isize = -1;
        for i in 0..pat_len {
            if *pattern.add(i) == b'/' {
                last_slash = i as isize;
            }
        }

        let mut dir_buf = [0u8; 1024];
        let file_pat: *const u8;

        if last_slash >= 0 {
            let dir_len = last_slash as usize + 1;
            let copy_len = if dir_len < 1023 { dir_len } else { 1023 };
            core::ptr::copy_nonoverlapping(pattern, dir_buf.as_mut_ptr(), copy_len);
            dir_buf[copy_len] = 0;
            file_pat = pattern.add(last_slash as usize + 1);
        } else {
            dir_buf[0] = b'.';
            dir_buf[1] = 0;
            file_pat = pattern;
        }

        // Check if the file pattern has any glob chars
        let mut has_glob = false;
        let mut k = 0;
        while *file_pat.add(k) != 0 {
            let c = *file_pat.add(k);
            if c == b'*' || c == b'?' || c == b'[' {
                has_glob = true;
                break;
            }
            k += 1;
        }

        if !has_glob {
            // No glob characters -- check if the file exists directly
            let mut full_path = [0u8; 2048];
            let mut pos = 0;
            if last_slash >= 0 {
                let dir_len = crate::string::strlen(dir_buf.as_ptr());
                for i in 0..dir_len {
                    if pos < 2047 {
                        full_path[pos] = dir_buf[i];
                        pos += 1;
                    }
                }
            }
            let mut j = 0;
            while *file_pat.add(j) != 0 && pos < 2047 {
                full_path[pos] = *file_pat.add(j);
                pos += 1;
                j += 1;
            }
            full_path[pos] = 0;

            let mut salty_st = salty::types::SaltyStat::zeroed();
            let ret = salty::posix::posix_stat(full_path.as_ptr(), &raw mut salty_st);
            if ret >= 0 {
                if !add_glob_result(pglob, full_path.as_ptr(), pos, flags) {
                    return GLOB_NOSPACE;
                }
                return 0;
            }
            if (flags & GLOB_NOCHECK) != 0 {
                // Add the pattern itself as a result
                if !add_glob_result(pglob, pattern, pat_len, flags) {
                    return GLOB_NOSPACE;
                }
                return 0;
            }
            return GLOB_NOMATCH;
        }

        let dir = opendir(dir_buf.as_ptr());
        if dir.is_null() {
            if (flags & GLOB_NOCHECK) != 0 {
                if !add_glob_result(pglob, pattern, pat_len, flags) {
                    return GLOB_NOSPACE;
                }
                return 0;
            }
            return if (flags & GLOB_ERR) != 0 {
                GLOB_ABORTED
            } else {
                GLOB_NOMATCH
            };
        }

        let initial_count = (*pglob).gl_pathc;

        loop {
            let entry = readdir(dir);
            if entry.is_null() {
                break;
            }

            let name = (*entry).d_name.as_ptr();

            // Skip "." and ".." unless pattern starts with '.'
            if *name == b'.' && *file_pat != b'.' {
                continue;
            }

            if fnmatch(file_pat, name, FNM_PERIOD) == 0 {
                // Build full path
                let mut full_path = [0u8; 2048];
                let mut pos = 0;

                if last_slash >= 0 {
                    let dir_len = crate::string::strlen(dir_buf.as_ptr());
                    for i in 0..dir_len {
                        if pos < 2047 {
                            full_path[pos] = dir_buf[i];
                            pos += 1;
                        }
                    }
                }

                let mut j = 0;
                while *name.add(j) != 0 && pos < 2047 {
                    full_path[pos] = *name.add(j);
                    pos += 1;
                    j += 1;
                }

                // GLOB_MARK: append '/' for directories
                if (flags & GLOB_MARK) != 0 && (*entry).d_type == 4 {
                    if pos < 2047 {
                        full_path[pos] = b'/';
                        pos += 1;
                    }
                }

                full_path[pos] = 0;

                if !add_glob_result(pglob, full_path.as_ptr(), pos, flags) {
                    closedir(dir);
                    return GLOB_NOSPACE;
                }
            }
        }

        closedir(dir);

        if (*pglob).gl_pathc == initial_count {
            if (flags & GLOB_NOCHECK) != 0 {
                if !add_glob_result(pglob, pattern, pat_len, flags) {
                    return GLOB_NOSPACE;
                }
                return 0;
            }
            return GLOB_NOMATCH;
        }

        // Sort results unless GLOB_NOSORT
        if (flags & GLOB_NOSORT) == 0 && (*pglob).gl_pathc > initial_count + 1 {
            // Simple insertion sort
            let pathv = (*pglob).gl_pathv;
            let start = initial_count;
            let end = (*pglob).gl_pathc;
            for i in (start + 1)..end {
                let key = *pathv.add(i);
                let mut j = i;
                while j > start && crate::string::strcmp(*pathv.add(j - 1), key) > 0 {
                    *pathv.add(j) = *pathv.add(j - 1);
                    j -= 1;
                }
                *pathv.add(j) = key;
            }
        }

        0
    }
}

unsafe fn add_glob_result(pglob: *mut GlobT, path: *const u8, len: usize, _flags: i32) -> bool {
    unsafe {
        let new_count = (*pglob).gl_pathc + 1;
        // Reallocate pathv: need (new_count + 1) pointers (NULL terminated)
        let new_size = (new_count + 1) * core::mem::size_of::<*mut u8>();
        let new_pathv = if (*pglob).gl_pathv.is_null() {
            crate::malloc::malloc(new_size) as *mut *mut u8
        } else {
            crate::malloc::realloc(
                (*pglob).gl_pathv as *mut u8,
                new_size,
            ) as *mut *mut u8
        };

        if new_pathv.is_null() {
            return false;
        }

        // Allocate copy of path string
        let s = crate::malloc::malloc(len + 1);
        if s.is_null() {
            return false;
        }
        core::ptr::copy_nonoverlapping(path, s, len);
        *s.add(len) = 0;

        *new_pathv.add((*pglob).gl_pathc) = s;
        *new_pathv.add(new_count) = core::ptr::null_mut(); // NULL terminate
        (*pglob).gl_pathv = new_pathv;
        (*pglob).gl_pathc = new_count;
        true
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn globfree(pglob: *mut GlobT) {
    if pglob.is_null() {
        return;
    }
    unsafe {
        if !(*pglob).gl_pathv.is_null() {
            for i in 0..(*pglob).gl_pathc {
                let p = *(*pglob).gl_pathv.add(i);
                if !p.is_null() {
                    crate::malloc::free(p);
                }
            }
            crate::malloc::free((*pglob).gl_pathv as *mut u8);
        }
        (*pglob).gl_pathc = 0;
        (*pglob).gl_pathv = core::ptr::null_mut();
    }
}
