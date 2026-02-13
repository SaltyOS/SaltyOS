//! FreeBSD compatibility layer
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Functions here exist to support ported FreeBSD utilities.
//! They are NOT part of the core POSIX libc.

pub mod rune;
pub mod capsicum;
pub mod bsd_io;
pub mod bsd_flags;
pub mod bsd_misc;
pub mod bsd_sort;
pub mod mntent;
pub mod statvfs;
