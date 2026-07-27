// SPDX-License-Identifier: GPL-2.0-only
//! Stable structural identity for mounts and vnodes.

use trona_protocol::posix::BackendNodeId;

/// Monotonic identifier for one mounted filesystem instance.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub(crate) struct FsInstanceId(pub u64);

impl FsInstanceId {
    pub(crate) const INVALID: FsInstanceId = FsInstanceId(0);

    #[inline]
    pub(crate) const fn new(value: u64) -> Self {
        FsInstanceId(value)
    }
}

/// Stable identity of a vnode within a mounted filesystem instance.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(crate) struct VnodeKey {
    pub(crate) fs_instance_id: FsInstanceId,
    pub(crate) backend_id: BackendNodeId,
}

impl VnodeKey {
    pub(crate) const INVALID: VnodeKey = VnodeKey {
        fs_instance_id: FsInstanceId::INVALID,
        backend_id: BackendNodeId::INVALID,
    };
}
