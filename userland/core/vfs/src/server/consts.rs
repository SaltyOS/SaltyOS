// SPDX-License-Identifier: GPL-2.0-only
//
//! Server-side constants and configuration values shared across
//! the saltyfs / posix / personality layers.

/// Initial pool capacities for growable arenas. The arenas grow
/// past these without a fixed cap; the values are sized to the
/// common boot-time working set.
pub(crate) const INITIAL_DIRENTS: usize = 32;
pub(crate) const INITIAL_WRITABLE: usize = 32;
pub(crate) const INITIAL_VDATA: usize = 128;
pub(crate) const INITIAL_SYMLINKS: usize = 32;
pub(crate) const WRITABLE_SIZE: usize = 8192;
pub(crate) const INVALID_WRITABLE_SLOT: u32 = u32::MAX;

/// Anonymous-pipe / FIFO ring-buffer capacity in bytes.
/// Sized to hold `PIPE_BUF` bytes of POSIX-atomic write plus a
/// small reader margin.
pub(crate) const PIPE_BUF_SIZE: usize = 4096;

/// Per-side UNIX socket ring buffer capacity in bytes. Sized to
/// hold a small burst of small datagrams or a few stream packets
/// before the writer has to back off.
pub(crate) const SOCK_BUF_SIZE: usize = 4096;

/// Personality-neutral semantic limits (not pool sizes — these
/// constrain the wire surface, not the arena capacity).
pub(crate) const MAX_PATH_LEN: usize = 128;
pub(crate) const MAX_NAME_LEN: usize = 255;
