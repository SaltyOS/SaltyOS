// SPDX-License-Identifier: GPL-2.0-only
//! VFS core — personality-neutral abstractions.
//!
//! This module hosts the foundational VFS types that every filesystem
//! backend and every personality layer (POSIX, Win32, ...) interoperate
//! through. Nothing in here knows about POSIX syscalls, Win32 API shapes,
//! or any specific filesystem — just the common contract.
//!
//! ## Submodules
//!
//! - [`error`] — `VfsError` enum and TRONA_* mapping.
//! - [`cred`] — `VfsCred` personality-neutral credential descriptor.
//! - [`file`] — `VAttr`, `VStatfs`, personality tags.
//! - [`vnode`] — `Vnode` struct, `VnodeHandle` type alias.
//! - [`arbitration`] — Cross-personality open/deny share-mode enforcement.
//! - [`vop`] — `VopVector` (`VopMetaOps` + `VopDataOps`) and defaults.
//! - [`vop_context`] — `VopContext`, `VopDataContext`, arena callbacks.
//! - [`mount`] — `Mount` struct, flag constants, `MountHandle`.
//! - [`mount_ctl`] — Arena-based mount allocation, trampoline infrastructure.
//! - [`mount_ns`] — `MountNamespace`, `MountNsHandle`.
//! - [`vfs`] — `VfsOps`, `FsType` registry.
//! - [`namei_common`] — `NameiCtx`, `NameiArgs`, `NameiResult`, shared
//!   handle-based path-walk helpers.
//! - [`casefold`] — Case-insensitive lookup fallback via readdir scan.

pub(crate) mod arbitration;
pub(crate) mod casefold;
pub(crate) mod cred;
pub(crate) mod error;
pub(crate) mod file;
pub(crate) mod mount;
pub(crate) mod mount_ctl;
pub(crate) mod mount_ns;
pub(crate) mod namei_common;
pub(crate) mod vfs;
pub(crate) mod vnode;
pub(crate) mod vop;
pub(crate) mod vop_context;
