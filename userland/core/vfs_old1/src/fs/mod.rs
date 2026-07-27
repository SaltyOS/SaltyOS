// SPDX-License-Identifier: GPL-2.0-only
//! Filesystem backends ported onto the rebuilt synchronous VFS core.
//!
//! The new VFS starts with one owner-controlled namespace model and then
//! hangs concrete filesystem instances under it. Each backend owns only
//! its mount-private state and vnode defaults; namespace orchestration
//! remains in the generic core.

pub(crate) mod devfs;
pub(crate) mod pipefs;
pub(crate) mod procfs;
pub(crate) mod saltyfs;
pub(crate) mod sysctlfs;
pub(crate) mod tmpfs;
