// SPDX-License-Identifier: GPL-2.0-only
//! Synchronous file-operation surface.

pub(crate) mod attr;
pub(crate) mod backing;
pub(crate) mod bulk;
pub(crate) mod device;
pub(crate) mod dir;
pub(crate) mod fd;
pub(crate) mod inet_wait;
pub(crate) mod misc;
pub(crate) mod mutate;
pub(crate) mod open;
pub(crate) mod pipe;
pub(crate) mod poll;
pub(crate) mod regular;
pub(crate) mod rw;
pub(crate) mod shm;
pub(crate) mod socket;
pub(crate) mod socket_wait;
pub(crate) mod stat;
pub(crate) mod tty_wait;
