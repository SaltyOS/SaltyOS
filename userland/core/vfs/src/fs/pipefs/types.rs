// SPDX-License-Identifier: GPL-2.0-only
//
//! pipefs types — named-pipe slot pool for the Win32 `\\.\pipe\`
//! namespace.

use crate::arena::handle::Handle;
use crate::core::pipe::PipeState;

/// Maximum number of named pipes that can exist simultaneously.
pub(crate) const MAX_NAMED_PIPES: usize = 64;

/// Maximum length of a named pipe name (bytes, no prefix).
pub(crate) const MAX_PIPE_NAME_LEN: usize = 128;

/// Lifecycle state of a named pipe instance.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum NamedPipeState {
    /// Slot is free.
    Created = 0,
    /// Server has called CreateNamedPipe; waiting for a client.
    Listening = 1,
    /// A client has connected; data flows in both directions.
    Connected = 2,
    /// Pipe instance has been closed and is pending cleanup.
    Closed = 3,
}

/// One slot in the pipefs named-pipe pool.
#[repr(C)]
pub(crate) struct NamedPipeSlot {
    pub(crate) name: [u8; MAX_PIPE_NAME_LEN],
    pub(crate) name_len: u8,
    pub(crate) state: NamedPipeState,
    pub(crate) server_badge: u64,
    pub(crate) client_badge: u64,
    pub(crate) pipe: Handle<PipeState>,
    pub(crate) vnode_id: u64,
}

impl NamedPipeSlot {
    pub(crate) const fn zeroed() -> Self {
        NamedPipeSlot {
            name: [0; MAX_PIPE_NAME_LEN],
            name_len: 0,
            state: NamedPipeState::Created,
            server_badge: 0,
            client_badge: 0,
            pipe: Handle::<PipeState>::INVALID,
            vnode_id: 0,
        }
    }
}
