// SPDX-License-Identifier: GPL-2.0-only
//! Win32 reserved device-name interception.

use super::casefold::ascii_fold_eq;

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReservedDev {
    Con = 0,
    Nul = 1,
    Aux = 2,
    Prn = 3,
    Com1 = 4,
    Com2 = 5,
    Com3 = 6,
    Com4 = 7,
    Com5 = 8,
    Com6 = 9,
    Com7 = 10,
    Com8 = 11,
    Com9 = 12,
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

pub(crate) fn intercept(component: &[u8]) -> Option<ReservedDev> {
    let base = match component.iter().position(|&b| b == b'.') {
        Some(pos) => &component[..pos],
        None => component,
    };

    if base.is_empty() {
        return None;
    }

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

    if base.len() == 4 {
        let digit = base[3];
        if digit >= b'1' && digit <= b'9' {
            let prefix = &base[..3];
            if ascii_fold_eq(prefix, b"COM") {
                return Some(match digit - b'1' {
                    0 => ReservedDev::Com1,
                    1 => ReservedDev::Com2,
                    2 => ReservedDev::Com3,
                    3 => ReservedDev::Com4,
                    4 => ReservedDev::Com5,
                    5 => ReservedDev::Com6,
                    6 => ReservedDev::Com7,
                    7 => ReservedDev::Com8,
                    _ => ReservedDev::Com9,
                });
            }
            if ascii_fold_eq(prefix, b"LPT") {
                return Some(match digit - b'1' {
                    0 => ReservedDev::Lpt1,
                    1 => ReservedDev::Lpt2,
                    2 => ReservedDev::Lpt3,
                    3 => ReservedDev::Lpt4,
                    4 => ReservedDev::Lpt5,
                    5 => ReservedDev::Lpt6,
                    6 => ReservedDev::Lpt7,
                    7 => ReservedDev::Lpt8,
                    _ => ReservedDev::Lpt9,
                });
            }
        }
    }

    None
}

pub(crate) fn devfs_path(dev: ReservedDev) -> &'static [u8] {
    match dev {
        ReservedDev::Con | ReservedDev::Aux | ReservedDev::Com1 => b"/dev/console",
        ReservedDev::Nul => b"/dev/null",
        ReservedDev::Prn
        | ReservedDev::Com2
        | ReservedDev::Com3
        | ReservedDev::Com4
        | ReservedDev::Com5
        | ReservedDev::Com6
        | ReservedDev::Com7
        | ReservedDev::Com8
        | ReservedDev::Com9
        | ReservedDev::Lpt1
        | ReservedDev::Lpt2
        | ReservedDev::Lpt3
        | ReservedDev::Lpt4
        | ReservedDev::Lpt5
        | ReservedDev::Lpt6
        | ReservedDev::Lpt7
        | ReservedDev::Lpt8
        | ReservedDev::Lpt9 => b"/dev/null",
    }
}
