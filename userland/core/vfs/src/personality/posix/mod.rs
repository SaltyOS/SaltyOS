// SPDX-License-Identifier: GPL-2.0-only
//! POSIX personality — path resolution, open policy, and syscall handlers.

pub(crate) mod consts;
pub(crate) mod dispatch;
pub(crate) mod fd_ops;
pub(crate) mod namei;
pub(crate) mod policy;
pub(crate) mod types;

pub(crate) mod at_ops;
pub(crate) mod inet;
pub(crate) mod misc;
pub(crate) mod poll;
pub(crate) mod procfs;
pub(crate) mod socket;
pub(crate) mod tty;
