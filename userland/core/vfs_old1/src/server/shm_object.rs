// SPDX-License-Identifier: GPL-2.0-only
//! POSIX shared-memory backing descriptors.

use crate::arena::Handle;
use crate::vfs_core::vnode::VnodeHandle;

pub(crate) type ShmHandle = Handle<ShmState>;

#[repr(C)]
pub(crate) struct ShmState {
    pub(crate) active: u8,
    pub(crate) unlinked: u8,
    _pad0: [u8; 6],
    pub(crate) id: u64,
    pub(crate) vnode: VnodeHandle,
    pub(crate) open_refs: u32,
    pub(crate) num_pages: u32,
}

impl ShmState {
    pub(crate) const fn zeroed() -> Self {
        ShmState {
            active: 0,
            unlinked: 0,
            _pad0: [0; 6],
            id: 0,
            vnode: VnodeHandle::INVALID,
            open_refs: 0,
            num_pages: 0,
        }
    }
}
