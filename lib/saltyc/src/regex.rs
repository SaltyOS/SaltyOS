//! POSIX regex — basic NFA matcher
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Supports both Basic Regular Expressions (BRE, default) and Extended Regular
//! Expressions (ERE, via `REG_EXTENDED`). Implemented as a backtracking NFA
//! matcher operating directly on the pattern string (no compiled DFA).
//!
//! Supported syntax:
//! - `.` (any char), `^` / `$` (anchors), `[...]` / `[^...]` (char classes)
//! - `*` (zero or more), `+` / `?` (ERE only), `|` (ERE alternation)
//! - `\\(` / `\\)` (BRE groups), `(` / `)` (ERE groups)
//! - `\\` escapes, character ranges in classes (`a-z`)
//! - `REG_ICASE` for case-insensitive matching
//! - `REG_NEWLINE` to prevent `.` and `[^...]` from matching newlines

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const REG_EXTENDED: i32 = 1;
pub const REG_ICASE: i32 = 2;
pub const REG_NOSUB: i32 = 4;
pub const REG_NEWLINE: i32 = 8;

pub const REG_NOMATCH: i32 = 1;
pub const REG_BADPAT: i32 = 2;
pub const REG_ECOLLATE: i32 = 3;
pub const REG_ECTYPE: i32 = 4;
pub const REG_EESCAPE: i32 = 5;
pub const REG_ESUBREG: i32 = 6;
pub const REG_EBRACK: i32 = 7;
pub const REG_EPAREN: i32 = 8;
pub const REG_EBRACE: i32 = 9;
pub const REG_BADBR: i32 = 10;
pub const REG_ERANGE: i32 = 11;
pub const REG_ESPACE: i32 = 12;
pub const REG_BADRPT: i32 = 13;

pub const REG_NOTBOL: i32 = 1;
pub const REG_NOTEOL: i32 = 2;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[repr(C)]
pub struct Regex {
    compiled: *mut u8,
    pattern_len: usize,
    cflags: i32,
    re_nsub: usize,
}

#[repr(C)]
pub struct Regmatch {
    pub rm_so: i32,
    pub rm_eo: i32,
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn to_lower(c: u8) -> u8 {
    if c >= b'A' && c <= b'Z' {
        c + 32
    } else {
        c
    }
}

fn char_eq(a: u8, b: u8, icase: bool) -> bool {
    if icase {
        to_lower(a) == to_lower(b)
    } else {
        a == b
    }
}

/// Returns (matched, new_pos) where new_pos is the position after the ']'.
/// `tpos` is the current text position to check; returns whether the character
/// at text[tpos] is in the character class.
unsafe fn match_char_class(
    pattern: *const u8,
    plen: usize,
    start: usize, // position right after '['
    ch: u8,
    icase: bool,
) -> (bool, usize) {
    unsafe {
        let mut pos = start;
        let mut negate = false;
        let mut matched = false;

        if pos < plen && *pattern.add(pos) == b'^' {
            negate = true;
            pos += 1;
        }

        // Allow ']' as first character in class
        if pos < plen && *pattern.add(pos) == b']' {
            if char_eq(ch, b']', icase) {
                matched = true;
            }
            pos += 1;
        }

        while pos < plen && *pattern.add(pos) != b']' {
            let c = *pattern.add(pos);

            // Check for range: a-z
            if pos + 2 < plen && *pattern.add(pos + 1) == b'-' && *pattern.add(pos + 2) != b']' {
                let lo = if icase { to_lower(c) } else { c };
                let hi = if icase {
                    to_lower(*pattern.add(pos + 2))
                } else {
                    *pattern.add(pos + 2)
                };
                let test = if icase { to_lower(ch) } else { ch };
                if test >= lo && test <= hi {
                    matched = true;
                }
                pos += 3;
            } else {
                if char_eq(ch, c, icase) {
                    matched = true;
                }
                pos += 1;
            }
        }

        // Skip closing ']'
        if pos < plen && *pattern.add(pos) == b']' {
            pos += 1;
        }

        if negate {
            matched = !matched;
        }

        (matched, pos)
    }
}

/// Skip past a character class in the pattern, returning position after ']'.
unsafe fn skip_char_class(pattern: *const u8, plen: usize, start: usize) -> usize {
    unsafe {
        let mut pos = start;
        // Skip negation
        if pos < plen && *pattern.add(pos) == b'^' {
            pos += 1;
        }
        // Allow ']' as first char
        if pos < plen && *pattern.add(pos) == b']' {
            pos += 1;
        }
        while pos < plen && *pattern.add(pos) != b']' {
            pos += 1;
        }
        if pos < plen {
            pos += 1;
        }
        pos
    }
}

/// Find the end of the current "atom" in the pattern (one matchable unit),
/// returning the position after it. This is used to identify what a quantifier
/// applies to.
unsafe fn atom_end(pattern: *const u8, plen: usize, ppos: usize) -> usize {
    unsafe {
        if ppos >= plen {
            return ppos;
        }
        let c = *pattern.add(ppos);
        if c == b'\\' {
            if ppos + 1 < plen {
                ppos + 2
            } else {
                ppos + 1
            }
        } else if c == b'[' {
            skip_char_class(pattern, plen, ppos + 1)
        } else {
            ppos + 1
        }
    }
}

/// Try to match a single atom at pattern[ppos..] against text[tpos].
/// Returns (matched: bool, pattern_end: usize, text_advance: usize).
unsafe fn match_one(
    pattern: *const u8,
    plen: usize,
    ppos: usize,
    text: *const u8,
    tlen: usize,
    tpos: usize,
    cflags: i32,
) -> (bool, usize, usize) {
    unsafe {
        if tpos >= tlen {
            return (false, ppos, 0);
        }
        let icase = (cflags & REG_ICASE) != 0;
        let ch = *text.add(tpos);
        let c = *pattern.add(ppos);

        if c == b'.' {
            // Match any character (except newline if REG_NEWLINE)
            if (cflags & REG_NEWLINE) != 0 && ch == b'\n' {
                return (false, ppos + 1, 1);
            }
            return (true, ppos + 1, 1);
        }

        if c == b'\\' {
            if ppos + 1 < plen {
                let escaped = *pattern.add(ppos + 1);
                return (char_eq(ch, escaped, icase), ppos + 2, 1);
            }
            return (false, ppos + 1, 0);
        }

        if c == b'[' {
            let (matched, end) = match_char_class(pattern, plen, ppos + 1, ch, icase);
            return (matched, end, 1);
        }

        (char_eq(ch, c, icase), ppos + 1, 1)
    }
}

/// Find the matching ')' for a '(' at pattern[start-1], handling nesting.
/// Returns position after the ')'.
unsafe fn find_closing_paren(pattern: *const u8, plen: usize, start: usize) -> usize {
    unsafe {
        let mut depth = 1u32;
        let mut pos = start;
        while pos < plen && depth > 0 {
            let c = *pattern.add(pos);
            if c == b'\\' {
                pos += 2;
                continue;
            }
            if c == b'(' {
                depth += 1;
            } else if c == b')' {
                depth -= 1;
            }
            pos += 1;
        }
        pos
    }
}

/// Core recursive matching engine.
/// Returns the end position in text if matched, or -1 if no match.
unsafe fn match_pattern(
    pattern: *const u8,
    plen: usize,
    ppos: usize,
    text: *const u8,
    tlen: usize,
    tpos: usize,
    cflags: i32,
    eflags: i32,
    nmatch: usize,
    pmatch: *mut Regmatch,
    text_start: usize,
) -> i32 {
    unsafe {
        let mut pp = ppos;
        let mut tp = tpos;
        let extended = (cflags & REG_EXTENDED) != 0;

        loop {
            if pp >= plen {
                return tp as i32;
            }

            let c = *pattern.add(pp);

            // Handle alternation '|' (ERE only)
            if extended && c == b'|' {
                // Current branch matched up to here; try rest
                // Return current position as success
                return tp as i32;
            }

            // Handle '$' anchor
            if c == b'$' && (pp + 1 >= plen || (extended && *pattern.add(pp + 1) == b'|')
                || (extended && *pattern.add(pp + 1) == b')'))
            {
                if (eflags & REG_NOTEOL) != 0 {
                    return -1;
                }
                if tp == tlen || ((cflags & REG_NEWLINE) != 0 && *text.add(tp) == b'\n') {
                    pp += 1;
                    continue;
                }
                return -1;
            }

            // Handle '^' anchor (only meaningful at start or after '|')
            if c == b'^' {
                if (eflags & REG_NOTBOL) != 0 && tp == text_start {
                    return -1;
                }
                if tp == text_start
                    || ((cflags & REG_NEWLINE) != 0 && tp > 0 && *text.add(tp - 1) == b'\n')
                {
                    pp += 1;
                    continue;
                }
                return -1;
            }

            // Handle grouping '(' ... ')' (ERE only)
            if extended && c == b'(' {
                let group_start = pp + 1;
                let group_end = find_closing_paren(pattern, plen, group_start);
                // group_end points after ')'
                let inner_len = if group_end >= 2 {
                    group_end - 1 - group_start
                } else {
                    0
                };

                // Check for quantifier after the group
                let after_group = group_end;
                let has_quantifier = after_group < plen
                    && (*pattern.add(after_group) == b'*'
                        || *pattern.add(after_group) == b'+'
                        || *pattern.add(after_group) == b'?');

                if has_quantifier {
                    let quant = *pattern.add(after_group);
                    let rest_start = after_group + 1;

                    if quant == b'?' {
                        // Try with group first
                        let res = match_group_then_rest(
                            pattern,
                            plen,
                            group_start,
                            inner_len,
                            rest_start,
                            text,
                            tlen,
                            tp,
                            cflags,
                            eflags,
                            nmatch,
                            pmatch,
                            text_start,
                        );
                        if res >= 0 {
                            return res;
                        }
                        // Try without group
                        return match_pattern(
                            pattern, plen, rest_start, text, tlen, tp, cflags, eflags,
                            nmatch, pmatch, text_start,
                        );
                    }

                    if quant == b'+' {
                        // Must match at least once
                        let res = match_group_then_rest(
                            pattern,
                            plen,
                            group_start,
                            inner_len,
                            pp, // retry from same group
                            text,
                            tlen,
                            tp,
                            cflags,
                            eflags,
                            nmatch,
                            pmatch,
                            text_start,
                        );
                        if res < 0 {
                            return -1;
                        }
                        // Now act like '*'
                        return match_group_star(
                            pattern,
                            plen,
                            group_start,
                            inner_len,
                            rest_start,
                            text,
                            tlen,
                            res as usize,
                            cflags,
                            eflags,
                            nmatch,
                            pmatch,
                            text_start,
                        );
                    }

                    // quant == b'*'
                    return match_group_star(
                        pattern,
                        plen,
                        group_start,
                        inner_len,
                        rest_start,
                        text,
                        tlen,
                        tp,
                        cflags,
                        eflags,
                        nmatch,
                        pmatch,
                        text_start,
                    );
                }

                // No quantifier: try alternation inside group
                let res = match_alternation(
                    pattern,
                    plen,
                    group_start,
                    group_end - 1, // up to but not including ')'
                    text,
                    tlen,
                    tp,
                    cflags,
                    eflags,
                    nmatch,
                    pmatch,
                    text_start,
                );
                if res < 0 {
                    return -1;
                }
                tp = res as usize;
                pp = group_end;
                continue;
            }

            // Handle closing paren (should not appear in top-level, but handle gracefully)
            if extended && c == b')' {
                return tp as i32;
            }

            // Determine the atom end for quantifier checking
            let ae = atom_end(pattern, plen, pp);

            // Check for quantifier after atom
            if ae < plen {
                let next = *pattern.add(ae);

                if next == b'*' {
                    // Greedy: match as many as possible, then backtrack
                    let rest_start = ae + 1;
                    let mut positions: [usize; 1024] = [0; 1024];
                    let mut count: usize = 1;
                    positions[0] = tp;

                    let mut cur = tp;
                    loop {
                        let (matched, _, adv) = match_one(pattern, plen, pp, text, tlen, cur, cflags);
                        if !matched || adv == 0 {
                            break;
                        }
                        cur += adv;
                        if count < 1024 {
                            positions[count] = cur;
                            count += 1;
                        }
                    }

                    // Try from longest match to shortest
                    let mut i = count;
                    while i > 0 {
                        i -= 1;
                        let res = match_pattern(
                            pattern, plen, rest_start, text, tlen, positions[i],
                            cflags, eflags, nmatch, pmatch, text_start,
                        );
                        if res >= 0 {
                            return res;
                        }
                    }
                    return -1;
                }

                if extended && next == b'+' {
                    // One or more: must match one, then treat like '*'
                    let (matched, _, adv) = match_one(pattern, plen, pp, text, tlen, tp, cflags);
                    if !matched {
                        return -1;
                    }
                    tp += adv;

                    let rest_start = ae + 1;
                    let mut positions: [usize; 1024] = [0; 1024];
                    let mut count: usize = 1;
                    positions[0] = tp;

                    let mut cur = tp;
                    loop {
                        let (m, _, a) = match_one(pattern, plen, pp, text, tlen, cur, cflags);
                        if !m || a == 0 {
                            break;
                        }
                        cur += a;
                        if count < 1024 {
                            positions[count] = cur;
                            count += 1;
                        }
                    }

                    let mut i = count;
                    while i > 0 {
                        i -= 1;
                        let res = match_pattern(
                            pattern, plen, rest_start, text, tlen, positions[i],
                            cflags, eflags, nmatch, pmatch, text_start,
                        );
                        if res >= 0 {
                            return res;
                        }
                    }
                    return -1;
                }

                if extended && next == b'?' {
                    // Zero or one
                    let rest_start = ae + 1;

                    // Try with match first (greedy)
                    let (matched, _, adv) = match_one(pattern, plen, pp, text, tlen, tp, cflags);
                    if matched {
                        let res = match_pattern(
                            pattern, plen, rest_start, text, tlen, tp + adv,
                            cflags, eflags, nmatch, pmatch, text_start,
                        );
                        if res >= 0 {
                            return res;
                        }
                    }
                    // Try without
                    return match_pattern(
                        pattern, plen, rest_start, text, tlen, tp,
                        cflags, eflags, nmatch, pmatch, text_start,
                    );
                }
            }

            // Regular atom match
            let (matched, new_pp, adv) = match_one(pattern, plen, pp, text, tlen, tp, cflags);
            if !matched {
                return -1;
            }
            pp = new_pp;
            tp += adv;
        }
    }
}

/// Match alternation: try each '|'-separated branch within pattern[start..end].
unsafe fn match_alternation(
    pattern: *const u8,
    plen: usize,
    start: usize,
    end: usize,
    text: *const u8,
    tlen: usize,
    tpos: usize,
    cflags: i32,
    eflags: i32,
    nmatch: usize,
    pmatch: *mut Regmatch,
    text_start: usize,
) -> i32 {
    unsafe {
        let mut branch_start = start;
        loop {
            // Find the end of this branch (next unescaped '|' at the same depth)
            let mut pos = branch_start;
            let mut depth = 0u32;
            while pos < end {
                let ch = *pattern.add(pos);
                if ch == b'\\' {
                    pos += 2;
                    continue;
                }
                if ch == b'(' {
                    depth += 1;
                } else if ch == b')' {
                    if depth > 0 {
                        depth -= 1;
                    }
                } else if ch == b'|' && depth == 0 {
                    break;
                }
                pos += 1;
            }

            let branch_end = pos;

            // Try matching this branch
            let res = match_pattern(
                pattern, plen, branch_start, text, tlen, tpos, cflags, eflags,
                nmatch, pmatch, text_start,
            );
            if res >= 0 {
                return res;
            }

            if branch_end >= end {
                break;
            }
            branch_start = branch_end + 1; // skip '|'
        }
        -1
    }
}

/// Match a group then continue with rest, for group+quantifier.
unsafe fn match_group_then_rest(
    pattern: *const u8,
    plen: usize,
    group_start: usize,
    inner_len: usize,
    rest_start: usize,
    text: *const u8,
    tlen: usize,
    tpos: usize,
    cflags: i32,
    eflags: i32,
    nmatch: usize,
    pmatch: *mut Regmatch,
    text_start: usize,
) -> i32 {
    unsafe {
        let group_end = group_start + inner_len;
        let res = match_alternation(
            pattern, plen, group_start, group_end, text, tlen, tpos, cflags, eflags,
            nmatch, pmatch, text_start,
        );
        if res < 0 {
            return -1;
        }
        match_pattern(
            pattern, plen, rest_start, text, tlen, res as usize, cflags, eflags,
            nmatch, pmatch, text_start,
        )
    }
}

/// Match group* (zero or more group repetitions), then rest.
unsafe fn match_group_star(
    pattern: *const u8,
    plen: usize,
    group_start: usize,
    inner_len: usize,
    rest_start: usize,
    text: *const u8,
    tlen: usize,
    tpos: usize,
    cflags: i32,
    eflags: i32,
    nmatch: usize,
    pmatch: *mut Regmatch,
    text_start: usize,
) -> i32 {
    unsafe {
        // Collect all possible endpoints from repeated group matches
        let mut endpoints: [usize; 256] = [0; 256];
        let mut ep_count: usize = 1;
        endpoints[0] = tpos;

        let mut cur = tpos;
        loop {
            let group_end = group_start + inner_len;
            let res = match_alternation(
                pattern, plen, group_start, group_end, text, tlen, cur, cflags, eflags,
                nmatch, pmatch, text_start,
            );
            if res < 0 || res as usize == cur {
                break;
            }
            cur = res as usize;
            if ep_count < 256 {
                endpoints[ep_count] = cur;
                ep_count += 1;
            }
        }

        // Try from longest to shortest (greedy)
        let mut i = ep_count;
        while i > 0 {
            i -= 1;
            let res = match_pattern(
                pattern, plen, rest_start, text, tlen, endpoints[i], cflags, eflags,
                nmatch, pmatch, text_start,
            );
            if res >= 0 {
                return res;
            }
        }
        -1
    }
}

/// Count unescaped '(' in pattern for re_nsub.
unsafe fn count_subexpressions(pattern: *const u8, len: usize) -> usize {
    unsafe {
        let mut count = 0usize;
        let mut i = 0usize;
        while i < len {
            if *pattern.add(i) == b'\\' {
                i += 2;
                continue;
            }
            if *pattern.add(i) == b'(' {
                count += 1;
            }
            i += 1;
        }
        count
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
/// Compile a regular expression pattern for use with `regexec`.
///
/// Copies the pattern string into a heap-allocated buffer and counts
/// subexpressions (capturing groups) for ERE mode. No bytecode or DFA
/// is generated — matching is done by interpreting the pattern directly.
///
/// `cflags` is a bitwise OR of: `REG_EXTENDED` (ERE syntax), `REG_ICASE`
/// (case-insensitive), `REG_NOSUB` (no subexpression reporting),
/// `REG_NEWLINE` (newline-sensitive matching).
///
/// Returns 0 on success, or `REG_BADPAT` / `REG_ESPACE` on error.
pub unsafe extern "C" fn regcomp(preg: *mut Regex, pattern: *const u8, cflags: i32) -> i32 {
    unsafe {
        if preg.is_null() || pattern.is_null() {
            return REG_BADPAT;
        }

        let len = crate::string::strlen(pattern);

        let buf = crate::malloc::malloc(len + 1);
        if buf.is_null() {
            return REG_ESPACE;
        }

        core::ptr::copy_nonoverlapping(pattern, buf, len);
        *buf.add(len) = 0;

        let nsub = if (cflags & REG_EXTENDED) != 0 {
            count_subexpressions(pattern, len)
        } else {
            0
        };

        (*preg).compiled = buf;
        (*preg).pattern_len = len;
        (*preg).cflags = cflags;
        (*preg).re_nsub = nsub;

        0
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn regexec(
    preg: *const Regex,
    string: *const u8,
    nmatch: usize,
    pmatch: *mut Regmatch,
    eflags: i32,
) -> i32 {
    unsafe {
        if preg.is_null() || string.is_null() {
            return REG_NOMATCH;
        }

        let pattern = (*preg).compiled;
        let plen = (*preg).pattern_len;
        let cflags = (*preg).cflags;

        if pattern.is_null() || plen == 0 {
            // Empty pattern matches everything
            if !pmatch.is_null() && nmatch > 0 {
                (*pmatch).rm_so = 0;
                (*pmatch).rm_eo = 0;
            }
            return 0;
        }

        let tlen = crate::string::strlen(string);

        // Check if pattern starts with '^' (anchored)
        let anchored = *pattern == b'^';

        let extended = (cflags & REG_EXTENDED) != 0;

        let max_start = if anchored { 0 } else { tlen };

        let mut start = 0usize;
        while start <= max_start {
            let result = if extended {
                match_alternation(
                    pattern, plen, 0, plen, string, tlen, start, cflags, eflags,
                    nmatch, pmatch, start,
                )
            } else {
                match_pattern(
                    pattern, plen, 0, string, tlen, start, cflags, eflags,
                    nmatch, pmatch, start,
                )
            };

            if result >= 0 {
                if !pmatch.is_null() && nmatch > 0 {
                    (*pmatch.add(0)).rm_so = start as i32;
                    (*pmatch.add(0)).rm_eo = result;
                }
                // Zero out remaining submatch entries
                let mut i = 1usize;
                while i < nmatch {
                    if !pmatch.is_null() {
                        (*pmatch.add(i)).rm_so = -1;
                        (*pmatch.add(i)).rm_eo = -1;
                    }
                    i += 1;
                }
                return 0;
            }

            start += 1;
        }

        REG_NOMATCH
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn regfree(preg: *mut Regex) {
    unsafe {
        if preg.is_null() {
            return;
        }
        if !(*preg).compiled.is_null() {
            crate::malloc::free((*preg).compiled);
            (*preg).compiled = core::ptr::null_mut();
        }
        (*preg).pattern_len = 0;
        (*preg).re_nsub = 0;
    }
}

static ERROR_STRINGS: [&[u8]; 14] = [
    b"Success\0",
    b"No match\0",
    b"Invalid regular expression\0",
    b"Invalid collation character\0",
    b"Invalid character class name\0",
    b"Trailing backslash\0",
    b"Invalid back reference\0",
    b"Unmatched [ or [^\0",
    b"Unmatched ( or \\(\0",
    b"Unmatched \\{\0",
    b"Invalid content of \\{\\}\0",
    b"Invalid range end\0",
    b"Out of memory\0",
    b"Invalid preceding regular expression\0",
];

#[unsafe(no_mangle)]
pub unsafe extern "C" fn regerror(
    errcode: i32,
    _preg: *const Regex,
    errbuf: *mut u8,
    errbuf_size: usize,
) -> usize {
    unsafe {
        let msg = if errcode >= 0 && (errcode as usize) < ERROR_STRINGS.len() {
            ERROR_STRINGS[errcode as usize]
        } else {
            b"Unknown error\0"
        };

        let msg_len = crate::string::strlen(msg.as_ptr());

        if !errbuf.is_null() && errbuf_size > 0 {
            let copy = if msg_len < errbuf_size {
                msg_len
            } else {
                errbuf_size - 1
            };
            core::ptr::copy_nonoverlapping(msg.as_ptr(), errbuf, copy);
            *errbuf.add(copy) = 0;
        }

        msg_len + 1
    }
}
