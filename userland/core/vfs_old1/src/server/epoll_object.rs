// SPDX-License-Identifier: GPL-2.0-only
//! Immediate-only epoll interest storage.

use crate::arena::Handle;
use crate::server::types::MAX_CLIENT_OBJECTS;

pub(crate) type EpollHandle = Handle<EpollState>;
pub(crate) const EPOLL_MAX_INTERESTS: usize = MAX_CLIENT_OBJECTS;

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct EpollInterest {
    pub(crate) active: u8,
    _pad0: [u8; 3],
    pub(crate) fd: i32,
    _pad1: [u8; 4],
    pub(crate) events: u32,
    _pad2: [u8; 4],
    pub(crate) data: u64,
}

impl EpollInterest {
    pub(crate) const fn zeroed() -> Self {
        EpollInterest {
            active: 0,
            _pad0: [0; 3],
            fd: -1,
            _pad1: [0; 4],
            events: 0,
            _pad2: [0; 4],
            data: 0,
        }
    }
}

#[repr(C)]
pub(crate) struct EpollState {
    pub(crate) active: u8,
    _pad0: [u8; 7],
    pub(crate) entries: [EpollInterest; EPOLL_MAX_INTERESTS],
}

impl EpollState {
    pub(crate) const fn zeroed() -> Self {
        EpollState {
            active: 0,
            _pad0: [0; 7],
            entries: [const { EpollInterest::zeroed() }; EPOLL_MAX_INTERESTS],
        }
    }
}
