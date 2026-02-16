//! FreeBSD compatibility layer
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Functions here exist to support ported FreeBSD utilities (ls, cat, etc.).
//! They are NOT part of the core POSIX libc.
//!
//! Three-tier implementation strategy:
//! - **Real**: Functions with meaningful behavior (rune locale tables, strmode,
//!   mergesort/heapsort, strverscmp, strtonum)
//! - **Stub**: Functions that return safe defaults (capsicum always grants,
//!   pledge/unveil are no-ops, getlogin returns "root")
//! - **ENOSYS**: Functions that cannot be meaningfully stubbed (kqueue, chflags,
//!   statvfs, mknod)

pub mod rune;
pub mod capsicum;
pub mod bsd_io;
pub mod bsd_flags;
pub mod bsd_misc;
pub mod bsd_sort;
pub mod bsd_err;
pub mod bsd_stdio;
pub mod mntent;
pub mod statvfs;
