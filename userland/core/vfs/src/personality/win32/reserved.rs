// SPDX-License-Identifier: GPL-2.0-only
//! Win32 reserved device name interception.
//!
//! Certain filenames are reserved by Win32 and always refer to devices
//! regardless of directory context or extension. For example, `CON`,
//! `CON.txt`, `CONIN$`, `CONOUT$`, `COM1`, and `NUL.tar.gz` all resolve
//! to the corresponding device.
//!
//! The comparison is:
//! 1. Strip any extension (everything after the first `.`).
//! 2. ASCII case-insensitive match against the reserved name list.
//!
//! When a reserved name is detected, `namei_win32` redirects the lookup
//! to the devfs vnode for the corresponding device.

use super::casefold::ascii_fold_eq;

/// Recognized Win32 reserved device names.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReservedDev {
    /// Console input/output (keyboard + screen).
    Con = 0,
    /// Null device (discard writes, read returns EOF).
    Nul = 1,
    /// Auxiliary device (typically COM1).
    Aux = 2,
    /// Printer device (typically LPT1).
    Prn = 3,
    /// Serial port 1-9.
    Com1 = 4,
    Com2 = 5,
    Com3 = 6,
    Com4 = 7,
    Com5 = 8,
    Com6 = 9,
    Com7 = 10,
    Com8 = 11,
    Com9 = 12,
    /// Parallel port 1-9.
    Lpt1 = 13,
    Lpt2 = 14,
    Lpt3 = 15,
    Lpt4 = 16,
    Lpt5 = 17,
    Lpt6 = 18,
    Lpt7 = 19,
    Lpt8 = 20,
    Lpt9 = 21,
}

/// Check whether a path component (after dot/space trimming) is a Win32
/// reserved device name.
///
/// The check strips any file extension before comparing. For example,
/// `CON.txt` matches `CON`, and `nul.tar.gz` matches `NUL`.
///
/// Returns `Some(dev)` if the component is reserved, `None` otherwise.
pub(crate) fn intercept(component: &[u8]) -> Option<ReservedDev> {
    // Strip extension: take everything before the first '.'.
    let base = match component.iter().position(|&b| b == b'.') {
        Some(pos) => &component[..pos],
        None => component,
    };

    if base.is_empty() {
        return None;
    }

    // `CONIN$` and `CONOUT$` are the canonical Win32 standard console
    // device names. They intentionally route through the same devfs console
    // node as `CON`; access mode decides input vs. output behavior.
    if base.len() == 6 && ascii_fold_eq(base, b"CONIN$") {
        return Some(ReservedDev::Con);
    }
    if base.len() == 7 && ascii_fold_eq(base, b"CONOUT$") {
        return Some(ReservedDev::Con);
    }

    // Match 3-character names (most common).
    if base.len() == 3 {
        if ascii_fold_eq(base, b"CON") {
            return Some(ReservedDev::Con);
        }
        if ascii_fold_eq(base, b"NUL") {
            return Some(ReservedDev::Nul);
        }
        if ascii_fold_eq(base, b"AUX") {
            return Some(ReservedDev::Aux);
        }
        if ascii_fold_eq(base, b"PRN") {
            return Some(ReservedDev::Prn);
        }
    }

    // Match 4-character names: COMn, LPTn (n = 1-9).
    if base.len() == 4 {
        let digit = base[3];
        if digit >= b'1' && digit <= b'9' {
            let prefix = &base[..3];
            if ascii_fold_eq(prefix, b"COM") {
                let idx = (digit - b'1') as u8;
                return Some(match idx {
                    0 => ReservedDev::Com1,
                    1 => ReservedDev::Com2,
                    2 => ReservedDev::Com3,
                    3 => ReservedDev::Com4,
                    4 => ReservedDev::Com5,
                    5 => ReservedDev::Com6,
                    6 => ReservedDev::Com7,
                    7 => ReservedDev::Com8,
                    8 => ReservedDev::Com9,
                    _ => return None,
                });
            }
            if ascii_fold_eq(prefix, b"LPT") {
                let idx = (digit - b'1') as u8;
                return Some(match idx {
                    0 => ReservedDev::Lpt1,
                    1 => ReservedDev::Lpt2,
                    2 => ReservedDev::Lpt3,
                    3 => ReservedDev::Lpt4,
                    4 => ReservedDev::Lpt5,
                    5 => ReservedDev::Lpt6,
                    6 => ReservedDev::Lpt7,
                    7 => ReservedDev::Lpt8,
                    8 => ReservedDev::Lpt9,
                    _ => return None,
                });
            }
        }
    }

    None
}

/// Map a `ReservedDev` to the devfs device name used for lookup in `/dev`.
///
/// Returns the device name as a static byte slice that can be passed to
/// `VopVector::lookup` on the devfs root vnode.
pub(crate) fn devfs_name(dev: ReservedDev) -> &'static [u8] {
    match dev {
        ReservedDev::Con => b"console",
        ReservedDev::Nul => b"null",
        // AUX historically maps to COM1.
        ReservedDev::Aux => b"console",
        // PRN historically maps to LPT1 — we map to null since we have
        // no printer device. A future devfs registration can override.
        ReservedDev::Prn => b"null",
        // COM1 maps to console (serial port).
        ReservedDev::Com1 => b"console",
        // COM2-9 and LPT1-9 have no backing devices — map to null.
        ReservedDev::Com2
        | ReservedDev::Com3
        | ReservedDev::Com4
        | ReservedDev::Com5
        | ReservedDev::Com6
        | ReservedDev::Com7
        | ReservedDev::Com8
        | ReservedDev::Com9 => b"null",
        ReservedDev::Lpt1
        | ReservedDev::Lpt2
        | ReservedDev::Lpt3
        | ReservedDev::Lpt4
        | ReservedDev::Lpt5
        | ReservedDev::Lpt6
        | ReservedDev::Lpt7
        | ReservedDev::Lpt8
        | ReservedDev::Lpt9 => b"null",
    }
}
