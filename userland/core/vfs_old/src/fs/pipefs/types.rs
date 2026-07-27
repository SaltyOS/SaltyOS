// SPDX-License-Identifier: GPL-2.0-only
//! pipefs types — named pipe slot pool for the Win32 `\\.\pipe\` namespace.

use crate::arena::Handle;
use crate::personality::posix::types::PipeState as BackingPipeState;

/// Maximum number of named pipes that can exist simultaneously.
pub(crate) const MAX_NAMED_PIPES: usize = 64;

/// Maximum length of a named pipe name (bytes, not including any prefix).
pub(crate) const MAX_PIPE_NAME_LEN: usize = 128;

/// Lifecycle state of a named pipe instance.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum PipeState {
    /// Slot is free.
    Created = 0,
    /// Server has called CreateNamedPipe; waiting for a client to connect.
    Listening = 1,
    /// A client has connected; data can flow in both directions.
    Connected = 2,
    /// Pipe instance has been closed and is pending cleanup.
    Closed = 3,
}

/// One slot in the pipefs named-pipe pool.
///
/// Each slot corresponds to a single named pipe instance. The actual data
/// buffer is backed by the shared pipe arena and linked directly by handle.
#[repr(C)]
pub(crate) struct NamedPipeSlot {
    /// Pipe name (ASCII, no prefix). Only `name_len` bytes are valid.
    pub(crate) name: [u8; MAX_PIPE_NAME_LEN],
    /// Length of the valid portion of `name`.
    pub(crate) name_len: u8,
    /// Current lifecycle state.
    pub(crate) state: PipeState,
    /// Badge of the server (CreateNamedPipe caller).
    pub(crate) server_badge: u64,
    /// Badge of the connected client (set on ConnectNamedPipe).
    pub(crate) client_badge: u64,
    /// Backing pipe instance.
    pub(crate) pipe: Handle<BackingPipeState>,
    /// Vnode id assigned to this slot within the pipefs mount.
    /// Matches `Vnode.id` for the corresponding vnode.
    pub(crate) vnode_id: u64,
}

impl NamedPipeSlot {
    pub(crate) const fn zeroed() -> Self {
        NamedPipeSlot {
            name: [0; MAX_PIPE_NAME_LEN],
            name_len: 0,
            state: PipeState::Created,
            server_badge: 0,
            client_badge: 0,
            pipe: Handle::<BackingPipeState>::INVALID,
            vnode_id: 0,
        }
    }
}
