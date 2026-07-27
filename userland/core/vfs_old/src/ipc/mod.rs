// SPDX-License-Identifier: GPL-2.0-only
//! VFS IPC module — dispatch, event loop, and timer management.

pub(crate) mod loop_;
pub(crate) mod mount_ipc;
pub(crate) mod timer_wheel;
