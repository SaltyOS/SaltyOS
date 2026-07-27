// SPDX-License-Identifier: GPL-2.0-only
//! Personality-specific request routing.
//!
//! The namespace core keeps vnode, mount, and open-file objects neutral.
//! Personality modules own the ABI surface and policy that sit on top of
//! those shared primitives.

pub(crate) mod posix;
pub(crate) mod win32;
