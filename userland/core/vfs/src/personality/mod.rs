// SPDX-License-Identifier: GPL-2.0-only
//! Per-personality layers.
//!
//! Each personality (POSIX, Win32, ...) provides:
//! - `namei` — path resolution with personality-specific grammar.
//! - `policy` — open/deny arbitration mapping for that subsystem.
//!
//! Personality code uses the common helpers from `vfs_core::namei_common`
//! and the `VopVector` dispatch table from `vfs_core::vop` — it never
//! talks directly to filesystem backends.

pub(crate) mod posix;
pub(crate) mod win32;
