// SPDX-License-Identifier: GPL-2.0-only
//
//! `core::*` — personality-neutral VFS core. Vnodes, mounts,
//! identity, error type, file operations vtable, vop / vfs op
//! tables, owner / worker contexts. Personality layers
//! (`personality::posix` / `personality::win32`) project these
//! into their own surface.

pub(crate) mod byte_range_lock;
pub(crate) mod cred;
pub(crate) mod error;
pub(crate) mod file;
pub(crate) mod identity;
pub(crate) mod mount;
pub(crate) mod mount_ctl;
pub(crate) mod namei_async;
pub(crate) mod namei_common;
pub(crate) mod outcome;
pub(crate) mod pipe;
pub(crate) mod shm;
pub(crate) mod socket;
pub(crate) mod vnode;
pub(crate) mod vop;
pub(crate) mod vop_context;
