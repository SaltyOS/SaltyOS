// SPDX-License-Identifier: GPL-2.0-only
//! SHM, pipe, and local socket object helpers owned by `VfsState`.

use crate::server::open_file::OpenFileHandle;
use crate::server::pipe_object::{PIPE_BUF_SIZE, PipeHandle};
use crate::server::shm_object::{ShmHandle, ShmState};
use crate::server::unix_socket_object::{
    UNIX_DGRAM_MAX_PAYLOAD, UNIX_DGRAM_QUEUE_CAP, UNIX_SOCKET_ADDR_MAX, UNIX_SOCKET_BUF_SIZE,
    UnixSocketHandle, UnixSocketState,
};
use crate::vfs_core::identity::FsInstanceId;
use crate::vfs_core::vnode::VnodeHandle;

use super::VfsState;

impl VfsState {
    pub(crate) fn alloc_shm_state(&mut self, vnode: VnodeHandle) -> Option<ShmHandle> {
        let handle = self.shms.alloc()?;
        let shm = self.shms.get_mut(handle)?;
        *shm = ShmState::zeroed();
        shm.active = 1;
        shm.vnode = vnode;
        shm.id = 0x5348_4D00_0000_0000u64 | ((handle.slot() as u64) << 32) | handle.epoch() as u64;
        Some(handle)
    }

    pub(crate) fn shm_by_vnode(&self, vnode: VnodeHandle) -> Option<ShmHandle> {
        let mut found = ShmHandle::INVALID;
        self.shms.for_each_active(|handle, shm| {
            if shm.vnode == vnode {
                found = handle;
                return false;
            }
            true
        });
        if found.is_valid() { Some(found) } else { None }
    }

    pub(crate) fn shm_state(&self, handle: ShmHandle) -> Option<&ShmState> {
        self.shms.get(handle)
    }

    pub(crate) fn shm_state_mut(&mut self, handle: ShmHandle) -> Option<&mut ShmState> {
        self.shms.get_mut(handle)
    }

    pub(crate) fn vnode_by_fs_instance_and_inode_id(
        &self,
        fs_instance_id: FsInstanceId,
        ino: u64,
    ) -> Option<VnodeHandle> {
        let mut found = VnodeHandle::INVALID;
        self.vnodes.for_each_active(|vh, vnode| {
            if vnode.fs_instance_id == fs_instance_id && vnode.id == ino {
                found = vh;
                return false;
            }
            true
        });
        if found.is_valid() { Some(found) } else { None }
    }

    pub(crate) fn pipe_refcounts(&self, pipe: PipeHandle) -> Option<(u32, u32)> {
        let pipe = self.pipes.get(pipe)?;
        Some((pipe.read_refs, pipe.write_refs))
    }

    pub(crate) fn pipe_buffer_len(&self, pipe: PipeHandle) -> Option<u16> {
        let pipe = self.pipes.get(pipe)?;
        Some(if pipe.head >= pipe.tail {
            pipe.head - pipe.tail
        } else {
            PIPE_BUF_SIZE as u16 - pipe.tail + pipe.head
        })
    }

    pub(crate) fn pipe_buffer_free(&self, pipe: PipeHandle) -> Option<u16> {
        Some((PIPE_BUF_SIZE as u16 - 1) - self.pipe_buffer_len(pipe)?)
    }

    pub(crate) fn unix_socket_state(&self, socket: UnixSocketHandle) -> Option<&UnixSocketState> {
        self.unix_sockets.get(socket)
    }

    pub(crate) fn unix_socket_state_mut(
        &mut self,
        socket: UnixSocketHandle,
    ) -> Option<&mut UnixSocketState> {
        self.unix_sockets.get_mut(socket)
    }

    pub(crate) fn unix_socket_buffer_len(&self, socket: UnixSocketHandle) -> Option<u16> {
        let socket = self.unix_sockets.get(socket)?;
        Some(if socket.head >= socket.tail {
            socket.head - socket.tail
        } else {
            UNIX_SOCKET_BUF_SIZE as u16 - socket.tail + socket.head
        })
    }

    pub(crate) fn unix_socket_buffer_free(&self, socket: UnixSocketHandle) -> Option<u16> {
        Some((UNIX_SOCKET_BUF_SIZE as u16 - 1) - self.unix_socket_buffer_len(socket)?)
    }

    pub(crate) fn unix_socket_dgram_count(&self, socket: UnixSocketHandle) -> Option<u8> {
        Some(self.unix_sockets.get(socket)?.pending_dgram_count)
    }

    pub(crate) fn unix_socket_dgram_has_space(&self, socket: UnixSocketHandle) -> Option<bool> {
        Some(self.unix_sockets.get(socket)?.pending_dgram_count < UNIX_DGRAM_QUEUE_CAP as u8)
    }

    pub(crate) fn unix_socket_dgram_enqueue(
        &mut self,
        socket: UnixSocketHandle,
        src_vnode: VnodeHandle,
        src_path: &[u8],
        src_path_len: usize,
        src_abstract_name: &[u8],
        src_abstract_len: usize,
        rights: &[OpenFileHandle],
        src: *const u8,
        len: usize,
    ) -> Option<bool> {
        let actual = core::cmp::min(len, UNIX_DGRAM_MAX_PAYLOAD);
        let actual_path = core::cmp::min(
            core::cmp::min(src_path_len, src_path.len()),
            UNIX_SOCKET_ADDR_MAX,
        );
        let actual_name = core::cmp::min(
            core::cmp::min(src_abstract_len, src_abstract_name.len()),
            UNIX_SOCKET_ADDR_MAX,
        );
        let sock = self.unix_sockets.get_mut(socket)?;
        if sock.pending_dgram_count >= UNIX_DGRAM_QUEUE_CAP as u8 {
            return Some(false);
        }
        let slot = sock.pending_dgram_tail as usize;
        sock.pending_dgram_tail = (slot + 1).wrapping_rem(UNIX_DGRAM_QUEUE_CAP) as u8;
        sock.pending_dgram_count = sock.pending_dgram_count.saturating_add(1);
        sock.pending_dgram_len[slot] = actual as u16;
        sock.pending_dgram_src_vnode[slot] = src_vnode;
        sock.pending_dgram_src_path_len[slot] = actual_path as u8;
        sock.pending_dgram_src_abstract_len[slot] = actual_name as u8;
        sock.pending_dgram_right_count[slot] = rights.len() as u8;
        if actual_path != 0 {
            sock.pending_dgram_src_path[slot][..actual_path]
                .copy_from_slice(&src_path[..actual_path]);
        }
        if actual_name != 0 {
            sock.pending_dgram_src_abstract_name[slot][..actual_name]
                .copy_from_slice(&src_abstract_name[..actual_name]);
        }
        if actual != 0 {
            for idx in 0..actual {
                sock.pending_dgram_data[slot][idx] = unsafe { *src.add(idx) };
            }
        }
        for (idx, handle) in rights.iter().copied().enumerate() {
            sock.pending_dgram_rights[slot][idx] = handle;
        }
        Some(true)
    }

    pub(crate) fn unix_socket_write(
        &mut self,
        socket: UnixSocketHandle,
        src: *const u8,
        len: usize,
    ) -> Option<usize> {
        let socket_state = self.unix_sockets.get_mut(socket)?;
        let free = if socket_state.head >= socket_state.tail {
            (UNIX_SOCKET_BUF_SIZE as u16 - 1) - (socket_state.head - socket_state.tail)
        } else {
            socket_state.tail - socket_state.head - 1
        } as usize;
        let actual = core::cmp::min(len, free);
        for idx in 0..actual {
            socket_state.data[socket_state.head as usize] = unsafe { *src.add(idx) };
            socket_state.head = (socket_state.head + 1) % UNIX_SOCKET_BUF_SIZE as u16;
        }
        Some(actual)
    }

    pub(crate) fn unix_socket_read(
        &mut self,
        socket: UnixSocketHandle,
        dst: *mut u8,
        len: usize,
    ) -> Option<usize> {
        let socket_state = self.unix_sockets.get_mut(socket)?;
        let avail = if socket_state.head >= socket_state.tail {
            socket_state.head - socket_state.tail
        } else {
            UNIX_SOCKET_BUF_SIZE as u16 - socket_state.tail + socket_state.head
        } as usize;
        let actual = core::cmp::min(len, avail);
        for idx in 0..actual {
            unsafe {
                *dst.add(idx) = socket_state.data[socket_state.tail as usize];
            }
            socket_state.tail = (socket_state.tail + 1) % UNIX_SOCKET_BUF_SIZE as u16;
        }
        Some(actual)
    }

    pub(crate) fn unix_socket_peek(
        &self,
        socket: UnixSocketHandle,
        dst: *mut u8,
        len: usize,
    ) -> Option<usize> {
        let socket_state = self.unix_sockets.get(socket)?;
        let avail = if socket_state.head >= socket_state.tail {
            socket_state.head - socket_state.tail
        } else {
            UNIX_SOCKET_BUF_SIZE as u16 - socket_state.tail + socket_state.head
        } as usize;
        let actual = core::cmp::min(len, avail);
        let mut tail = socket_state.tail;
        for idx in 0..actual {
            unsafe {
                *dst.add(idx) = socket_state.data[tail as usize];
            }
            tail = (tail + 1) % UNIX_SOCKET_BUF_SIZE as u16;
        }
        Some(actual)
    }

    pub(crate) fn pipe_write(
        &mut self,
        pipe: PipeHandle,
        src: *const u8,
        len: usize,
    ) -> Option<usize> {
        let pipe_state = self.pipes.get_mut(pipe)?;
        let free = if pipe_state.head >= pipe_state.tail {
            (PIPE_BUF_SIZE as u16 - 1) - (pipe_state.head - pipe_state.tail)
        } else {
            pipe_state.tail - pipe_state.head - 1
        } as usize;
        let actual = core::cmp::min(len, free);
        for idx in 0..actual {
            pipe_state.data[pipe_state.head as usize] = unsafe { *src.add(idx) };
            pipe_state.head = (pipe_state.head + 1) % PIPE_BUF_SIZE as u16;
        }
        Some(actual)
    }

    pub(crate) fn pipe_read(
        &mut self,
        pipe: PipeHandle,
        dst: *mut u8,
        len: usize,
    ) -> Option<usize> {
        let pipe_state = self.pipes.get_mut(pipe)?;
        let avail = if pipe_state.head >= pipe_state.tail {
            pipe_state.head - pipe_state.tail
        } else {
            PIPE_BUF_SIZE as u16 - pipe_state.tail + pipe_state.head
        } as usize;
        let actual = core::cmp::min(len, avail);
        for idx in 0..actual {
            unsafe {
                *dst.add(idx) = pipe_state.data[pipe_state.tail as usize];
            }
            pipe_state.tail = (pipe_state.tail + 1) % PIPE_BUF_SIZE as u16;
        }
        Some(actual)
    }
}
