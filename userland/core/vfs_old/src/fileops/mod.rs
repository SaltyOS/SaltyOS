// SPDX-License-Identifier: GPL-2.0-only
//! File operations — split into focused submodules.

pub(crate) mod attr;
pub(crate) mod bulk;
pub(crate) mod dir;
pub(crate) mod mutate;
pub(crate) mod open;
pub(crate) mod pio;
pub(crate) mod pipe;
pub(crate) mod rw;
pub(crate) mod stat;

// Re-export all public items so callers can still use `fileops::handle_open` etc.
pub(crate) use dir::*;
pub(crate) use mutate::*;
pub(crate) use open::*;
pub(crate) use pio::*;
pub(crate) use rw::*;
pub(crate) use stat::*;
