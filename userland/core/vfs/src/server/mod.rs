// SPDX-License-Identifier: GPL-2.0-only
//
//! `server::*` — vfs-server-side primitives that are not part of the
//! arena / owner core. Contains memory helpers (`map_anon` / `unmap`),
//! object-table types, and constants that personality-neutral posix
//! depend on.

pub(crate) mod alloc;
pub(crate) mod consts;
pub(crate) mod mem;
pub(crate) mod open_object;
pub(crate) mod types;
