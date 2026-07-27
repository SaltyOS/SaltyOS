// SPDX-License-Identifier: GPL-2.0-only
//! Anonymous pipe backing storage.

use crate::arena::Handle;

pub(crate) const PIPE_BUF_SIZE: usize = 4096;
pub(crate) type PipeHandle = Handle<PipeState>;

#[repr(C)]
pub(crate) struct PipeState {
    pub(crate) active: u8,
    _pad0: [u8; 3],
    pub(crate) read_refs: u32,
    pub(crate) write_refs: u32,
    pub(crate) head: u16,
    pub(crate) tail: u16,
    _pad1: [u8; 4],
    pub(crate) data: [u8; PIPE_BUF_SIZE],
}

impl PipeState {
    pub(crate) const fn zeroed() -> Self {
        PipeState {
            active: 0,
            _pad0: [0; 3],
            read_refs: 0,
            write_refs: 0,
            head: 0,
            tail: 0,
            _pad1: [0; 4],
            data: [0; PIPE_BUF_SIZE],
        }
    }
}
