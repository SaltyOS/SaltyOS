// SPDX-License-Identifier: GPL-2.0-only
//! Filesystem backends.
//!
//! Each sub-module provides a `VfsOps` + `VopVector` pair and a
//! `register()` function called during VFS bootstrap Stage 2.

pub(crate) mod devfs;
pub(crate) mod pipefs;
pub(crate) mod procfs;
pub(crate) mod ramfs;
pub(crate) mod saltyfs_client;
pub(crate) mod sysctlfs;
pub(crate) mod tmpfs;
