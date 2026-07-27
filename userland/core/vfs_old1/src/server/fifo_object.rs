// SPDX-License-Identifier: GPL-2.0-only
//! Named FIFO backing state.
//!
//! Structural FIFO vnodes live in the namespace tree, but actual read/write
//! traffic flows through a pipe backing object. This side table keeps the
//! association without turning the owner core back into a callback-based
//! async registry.

use crate::arena::Handle;
use crate::server::pipe_object::PipeHandle;
use crate::vfs_core::vnode::VnodeHandle;

pub(crate) type FifoHandle = Handle<FifoState>;

#[repr(C)]
pub(crate) struct FifoState {
    pub(crate) vnode: VnodeHandle,
    pub(crate) pipe: PipeHandle,
    pub(crate) unlinked: u8,
    _pad0: [u8; 7],
}

impl FifoState {
    pub(crate) const fn zeroed() -> Self {
        FifoState {
            vnode: VnodeHandle::INVALID,
            pipe: PipeHandle::INVALID,
            unlinked: 0,
            _pad0: [0; 7],
        }
    }
}
