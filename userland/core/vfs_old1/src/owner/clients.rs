// SPDX-License-Identifier: GPL-2.0-only
//! Client state and shared open-file lifecycle helpers.

use trona_kernel::core_types::*;
use trona_posix::consts::*;
use trona_protocol::posix::server::*;
use trona_protocol::posix::*;

use crate::server::epoll_object::{EpollHandle, EpollState};
use crate::server::fifo_object::{FifoHandle, FifoState};
use crate::server::open_file::{OpenFile, OpenFileHandle};
use crate::server::pipe_object::{PipeHandle, PipeState};
use crate::server::shm_object::ShmHandle;
use crate::server::types::{
    ClientHandle, ClientState, MAX_CLIENT_OBJECTS, OBJ_DEVICE, OBJ_PIPE, OpenSlot, PERS_POSIX,
    PERS_WIN32,
};
use crate::server::unix_socket_object::{
    UNIX_DGRAM_QUEUE_CAP, UNIX_SOCKET_ACCEPT_CAP, UNIX_SOCKET_MAX_RIGHTS, UnixSocketHandle,
    UnixSocketState,
};
use crate::vfs_core::namei::PathAnchor;
use crate::vfs_core::vnode::VnodeHandle;

use super::VfsState;

impl VfsState {
    pub(crate) fn seed_win32_client_state(&mut self, client: ClientHandle) {
        let root_anchor = self
            .root_vnode()
            .and_then(|vh| self.anchor_for_vnode(vh))
            .unwrap_or(PathAnchor::INVALID);
        let _ = self.win32_cwd.ensure_seeded(client, root_anchor);
    }

    pub(crate) fn win32_current_drive(&self, client: ClientHandle) -> usize {
        self.win32_cwd
            .get(client)
            .map(|entry| core::cmp::min(entry.current_drive as usize, 25))
            .unwrap_or(2)
    }

    pub(crate) fn win32_drive_base_vnode(
        &self,
        client: ClientHandle,
        drive_index: usize,
        absolute: bool,
    ) -> Option<VnodeHandle> {
        if drive_index >= 26 {
            return None;
        }
        if !absolute {
            if let Some(anchor) = self.win32_cwd.drive_cwd_anchor(client, drive_index) {
                if let Some(vh) = self.resolve_anchor_vnode(anchor) {
                    return Some(vh);
                }
            }
        }
        unsafe { crate::personality::win32::drives::resolve_drive_root(self, drive_index) }
            .or_else(|| self.root_vnode())
    }

    pub(crate) fn update_win32_client_cwd(&mut self, client: ClientHandle, vnode: VnodeHandle) {
        let Some(client_state) = self.clients.get(client) else {
            return;
        };
        if client_state.personality != PERS_WIN32 {
            return;
        }
        let Some(anchor) = self.anchor_for_vnode(vnode) else {
            return;
        };
        let drive = self.win32_current_drive(client);
        let _ = self.win32_cwd.set_drive_cwd(client, drive, anchor);
    }

    pub(crate) fn update_win32_client_cwd_for_drive(
        &mut self,
        client: ClientHandle,
        drive_index: usize,
        vnode: VnodeHandle,
    ) {
        let Some(client_state) = self.clients.get(client) else {
            return;
        };
        if client_state.personality != PERS_WIN32 || drive_index >= 26 {
            return;
        }
        let Some(anchor) = self.anchor_for_vnode(vnode) else {
            return;
        };
        let _ = self.win32_cwd.set_drive_cwd(client, drive_index, anchor);
    }

    pub(crate) fn clone_win32_client_state(&mut self, src: ClientHandle, dst: ClientHandle) {
        let root_anchor = self
            .root_vnode()
            .and_then(|vh| self.anchor_for_vnode(vh))
            .unwrap_or(PathAnchor::INVALID);
        let _ = self.win32_cwd.clone_from(src, dst, root_anchor);
    }

    pub(crate) fn ensure_client(&mut self, badge: u64, personality: u8) -> Option<ClientHandle> {
        let target_personality = if personality == PERS_WIN32 {
            PERS_WIN32
        } else {
            PERS_POSIX
        };
        if let Some(handle) = self.lookup_client(badge) {
            let old_personality = self
                .clients
                .get(handle)
                .map(|client| client.personality)
                .unwrap_or(PERS_POSIX);
            if let Some(client) = self.clients.get_mut(handle) {
                client.personality = target_personality;
            }
            if old_personality == PERS_WIN32 && target_personality != PERS_WIN32 {
                self.win32_cwd.deregister(handle);
            } else if target_personality == PERS_WIN32 {
                self.seed_win32_client_state(handle);
            }
            return Some(handle);
        }

        let handle = self.clients.alloc()?;
        let root_vh = self.root_vnode()?;
        let root_anchor = self.anchor_for_vnode(root_vh)?;
        let client = self.clients.get_mut(handle)?;
        *client = ClientState::zeroed();
        client.badge = badge;
        client.personality = target_personality;
        client.mount_ns = self.global_ns;
        client.cwd_anchor = root_anchor;
        if target_personality == PERS_WIN32 {
            self.seed_win32_client_state(handle);
        }
        Some(handle)
    }

    pub(crate) fn remove_client(&mut self, badge: u64) -> bool {
        let Some(handle) = self.lookup_client(badge) else {
            return false;
        };
        self.win32_cwd.deregister(handle);
        for fd in 0..MAX_CLIENT_OBJECTS {
            let _ = self.release_client_slot(handle, fd);
        }
        self.clients.release(handle)
    }

    fn normalize_status_flags(flags: u32) -> u32 {
        (flags & O_ACCMODE) | (flags & (O_APPEND | O_NONBLOCK))
    }

    pub(crate) fn client_slot(&self, cli_handle: ClientHandle, fd: usize) -> Option<&OpenSlot> {
        if fd >= MAX_CLIENT_OBJECTS {
            return None;
        }
        let client = self.clients.get(cli_handle)?;
        let slot = &client.slots[fd];
        if slot.active == 0 {
            return None;
        }
        Some(slot)
    }

    pub(crate) fn client_slot_mut(
        &mut self,
        cli_handle: ClientHandle,
        fd: usize,
    ) -> Option<&mut OpenSlot> {
        if fd >= MAX_CLIENT_OBJECTS {
            return None;
        }
        let client = self.clients.get_mut(cli_handle)?;
        if client.slots[fd].active == 0 {
            return None;
        }
        Some(&mut client.slots[fd])
    }

    pub(crate) fn client_open_file_handle(
        &self,
        cli_handle: ClientHandle,
        fd: usize,
    ) -> Option<OpenFileHandle> {
        self.client_slot(cli_handle, fd).map(|slot| slot.open_file)
    }

    pub(crate) fn client_open_file(
        &self,
        cli_handle: ClientHandle,
        fd: usize,
    ) -> Option<&OpenFile> {
        let handle = self.client_open_file_handle(cli_handle, fd)?;
        self.open_files.get(handle)
    }

    pub(crate) fn client_open_file_mut(
        &mut self,
        cli_handle: ClientHandle,
        fd: usize,
    ) -> Option<&mut OpenFile> {
        let handle = self.client_open_file_handle(cli_handle, fd)?;
        self.open_files.get_mut(handle)
    }

    fn alloc_open_file(
        &mut self,
        vnode: VnodeHandle,
        kind: u8,
        flags: u32,
    ) -> Option<OpenFileHandle> {
        let handle = self.open_files.alloc()?;
        let of = self.open_files.get_mut(handle)?;
        *of = OpenFile::zeroed();
        of.vnode = vnode;
        of.kind = kind;
        of.status_flags = Self::normalize_status_flags(flags);
        of.refcount = 0;
        if let Some(vn) = self.vnodes.get_mut(vnode) {
            vn.open_count = vn.open_count.saturating_add(1);
        }
        Some(handle)
    }

    pub(crate) fn alloc_pipe(&mut self) -> Option<PipeHandle> {
        let handle = self.pipes.alloc()?;
        let pipe = self.pipes.get_mut(handle)?;
        *pipe = PipeState::zeroed();
        pipe.active = 1;
        Some(handle)
    }

    fn alloc_pipe_open_file(
        &mut self,
        vnode: VnodeHandle,
        pipe: PipeHandle,
        flags: u32,
    ) -> Option<OpenFileHandle> {
        let handle = self.open_files.alloc()?;
        let of = self.open_files.get_mut(handle)?;
        *of = OpenFile::zeroed();
        of.vnode = vnode;
        of.pipe = pipe;
        of.kind = OBJ_PIPE;
        of.status_flags = Self::normalize_status_flags(flags);
        of.refcount = 0;
        if vnode.is_valid() {
            if let Some(vn) = self.vnodes.get_mut(vnode) {
                vn.open_count = vn.open_count.saturating_add(1);
            }
        }
        let access = of.status_flags & O_ACCMODE;
        let pipe_state = self.pipes.get_mut(pipe)?;
        if access != O_WRONLY {
            pipe_state.read_refs = pipe_state.read_refs.saturating_add(1);
        }
        if access != O_RDONLY {
            pipe_state.write_refs = pipe_state.write_refs.saturating_add(1);
        }
        Some(handle)
    }

    fn alloc_shm_open_file(
        &mut self,
        vnode: VnodeHandle,
        shm: ShmHandle,
        flags: u32,
    ) -> Option<OpenFileHandle> {
        let handle = self.open_files.alloc()?;
        let of = self.open_files.get_mut(handle)?;
        *of = OpenFile::zeroed();
        of.vnode = vnode;
        of.shm = shm;
        of.kind = crate::server::types::OBJ_SHM;
        of.status_flags = Self::normalize_status_flags(flags);
        of.refcount = 0;
        if let Some(vn) = self.vnodes.get_mut(vnode) {
            vn.open_count = vn.open_count.saturating_add(1);
        }
        let shm_state = self.shms.get_mut(shm)?;
        shm_state.open_refs = shm_state.open_refs.saturating_add(1);
        Some(handle)
    }

    fn alloc_epoll_open_file(&mut self, epoll: EpollHandle) -> Option<OpenFileHandle> {
        let handle = self.open_files.alloc()?;
        let of = self.open_files.get_mut(handle)?;
        *of = OpenFile::zeroed();
        of.epoll = epoll;
        of.kind = crate::server::types::OBJ_EPOLL;
        of.refcount = 0;
        Some(handle)
    }

    fn alloc_socket_open_file(&mut self, conn_id: u32, flags: u32) -> Option<OpenFileHandle> {
        let handle = self.open_files.alloc()?;
        let of = self.open_files.get_mut(handle)?;
        *of = OpenFile::zeroed();
        of.kind = crate::server::types::OBJ_SOCKET;
        of.status_flags = Self::normalize_status_flags(flags);
        of.socket_conn_id = conn_id;
        of.refcount = 0;
        Some(handle)
    }

    pub(crate) fn alloc_unix_socket(&mut self) -> Option<UnixSocketHandle> {
        let handle = self.unix_sockets.alloc()?;
        let socket = self.unix_sockets.get_mut(handle)?;
        *socket = UnixSocketState::zeroed();
        socket.active = 1;
        Some(handle)
    }

    fn alloc_unix_socket_open_file(
        &mut self,
        socket: UnixSocketHandle,
        flags: u32,
    ) -> Option<OpenFileHandle> {
        let handle = self.open_files.alloc()?;
        let of = self.open_files.get_mut(handle)?;
        *of = OpenFile::zeroed();
        of.kind = crate::server::types::OBJ_SOCKET;
        of.status_flags = Self::normalize_status_flags(flags);
        of.unix_socket = socket;
        of.refcount = 0;
        let socket_state = self.unix_sockets.get_mut(socket)?;
        socket_state.refcount = socket_state.refcount.saturating_add(1);
        Some(handle)
    }

    pub(crate) fn alloc_device_open_file(
        &mut self,
        vnode: VnodeHandle,
        dev_type: u8,
        pty_id: u32,
        generation: u32,
        flags: u32,
    ) -> Option<OpenFileHandle> {
        let handle = self.open_files.alloc()?;
        let of = self.open_files.get_mut(handle)?;
        *of = OpenFile::zeroed();
        of.vnode = vnode;
        of.kind = OBJ_DEVICE;
        of.status_flags = Self::normalize_status_flags(flags);
        of.device_dev_type = dev_type;
        of.device_pty_id = pty_id;
        of.device_generation = generation;
        of.refcount = 0;
        if let Some(vn) = self.vnodes.get_mut(vnode) {
            vn.open_count = vn.open_count.saturating_add(1);
        }
        Some(handle)
    }

    fn retain_open_file(&mut self, handle: OpenFileHandle) -> bool {
        let Some(of) = self.open_files.get_mut(handle) else {
            return false;
        };
        of.refcount = of.refcount.saturating_add(1);
        true
    }

    pub(crate) fn retain_open_file_handle(&mut self, handle: OpenFileHandle) -> bool {
        self.retain_open_file(handle)
    }

    pub(crate) fn release_shared_open_file(&mut self, handle: OpenFileHandle) {
        self.release_open_file(handle);
    }

    fn release_unix_socket_rights(&mut self, socket: UnixSocketHandle) {
        let pending = {
            let Some(sock) = self.unix_sockets.get_mut(socket) else {
                return;
            };
            let mut handles = [OpenFileHandle::INVALID; UNIX_SOCKET_MAX_RIGHTS];
            let count = sock.pending_right_count as usize;
            for (idx, slot) in handles.iter_mut().enumerate().take(count) {
                *slot = sock.pending_rights[idx];
                sock.pending_rights[idx] = OpenFileHandle::INVALID;
            }
            sock.pending_right_count = 0;
            handles
        };
        for handle in pending {
            if handle.is_valid() {
                self.release_open_file(handle);
            }
        }
    }

    fn release_unix_socket_dgram_queue(&mut self, socket: UnixSocketHandle) {
        let pending = {
            let Some(sock) = self.unix_sockets.get_mut(socket) else {
                return;
            };
            let mut src_vnodes = [VnodeHandle::INVALID; UNIX_DGRAM_QUEUE_CAP];
            let mut rights =
                [[OpenFileHandle::INVALID; UNIX_SOCKET_MAX_RIGHTS]; UNIX_DGRAM_QUEUE_CAP];
            let mut right_counts = [0usize; UNIX_DGRAM_QUEUE_CAP];
            let count = sock.pending_dgram_count as usize;
            for idx in 0..count {
                let queue_idx = (sock.pending_dgram_head as usize + idx) % UNIX_DGRAM_QUEUE_CAP;
                src_vnodes[idx] = sock.pending_dgram_src_vnode[queue_idx];
                sock.pending_dgram_src_vnode[queue_idx] = VnodeHandle::INVALID;
                sock.pending_dgram_src_path_len[queue_idx] = 0;
                sock.pending_dgram_src_abstract_len[queue_idx] = 0;
                let right_count = sock.pending_dgram_right_count[queue_idx] as usize;
                right_counts[idx] = right_count;
                sock.pending_dgram_right_count[queue_idx] = 0;
                sock.pending_dgram_len[queue_idx] = 0;
                for right_idx in 0..right_count {
                    rights[idx][right_idx] = sock.pending_dgram_rights[queue_idx][right_idx];
                    sock.pending_dgram_rights[queue_idx][right_idx] = OpenFileHandle::INVALID;
                }
            }
            sock.pending_dgram_head = 0;
            sock.pending_dgram_tail = 0;
            sock.pending_dgram_count = 0;
            (src_vnodes, rights, right_counts)
        };
        let (src_vnodes, rights, right_counts) = pending;
        for idx in 0..UNIX_DGRAM_QUEUE_CAP {
            if src_vnodes[idx].is_valid() {
                self.release_socket_name_vnode(src_vnodes[idx]);
            }
            for right_idx in 0..right_counts[idx] {
                let handle = rights[idx][right_idx];
                if handle.is_valid() {
                    self.release_open_file(handle);
                }
            }
        }
    }

    pub(crate) fn retain_socket_name_vnode(&mut self, vnode: VnodeHandle) -> bool {
        let Some(vn) = self.vnodes.get_mut(vnode) else {
            return false;
        };
        vn.open_count = vn.open_count.saturating_add(1);
        true
    }

    pub(crate) fn release_socket_name_vnode(&mut self, vnode: VnodeHandle) {
        if let Some(vn) = self.vnodes.get_mut(vnode) {
            vn.open_count = vn.open_count.saturating_sub(1);
        }
        self.reclaim_bootstrap_vnode(vnode);
    }

    fn release_unix_socket_accept_queue(&mut self, socket: UnixSocketHandle) {
        let pending = {
            let Some(sock) = self.unix_sockets.get_mut(socket) else {
                return;
            };
            let mut handles = [UnixSocketHandle::INVALID; UNIX_SOCKET_ACCEPT_CAP];
            let count = sock.pending_accept_count as usize;
            for (idx, slot) in handles.iter_mut().enumerate().take(count) {
                let queue_idx = (sock.pending_accept_head as usize + idx) % UNIX_SOCKET_ACCEPT_CAP;
                *slot = sock.pending_accept[queue_idx];
                sock.pending_accept[queue_idx] = UnixSocketHandle::INVALID;
            }
            sock.pending_accept_head = 0;
            sock.pending_accept_tail = 0;
            sock.pending_accept_count = 0;
            handles
        };
        for accepted in pending {
            if !accepted.is_valid() {
                continue;
            }
            let (peer, bound_vnode, peer_name_vnode) = self
                .unix_sockets
                .get(accepted)
                .map(|sock| (sock.peer, sock.bound_vnode, sock.peer_name_vnode))
                .unwrap_or((
                    UnixSocketHandle::INVALID,
                    VnodeHandle::INVALID,
                    VnodeHandle::INVALID,
                ));
            self.release_unix_socket_rights(accepted);
            if bound_vnode.is_valid() {
                self.release_socket_name_vnode(bound_vnode);
            }
            if peer_name_vnode.is_valid() && peer_name_vnode != bound_vnode {
                self.release_socket_name_vnode(peer_name_vnode);
            }
            if peer.is_valid() {
                if let Some(peer_sock) = self.unix_sockets.get_mut(peer) {
                    peer_sock.peer_closed = 1;
                }
            }
            let _ = self.unix_sockets.release(accepted);
        }
    }

    fn release_open_file(&mut self, handle: OpenFileHandle) {
        let (
            vnode,
            pipe,
            shm,
            epoll,
            unix_socket,
            socket_conn_id,
            dev_type,
            dev_pty_id,
            kind,
            flags,
            should_release,
        ) = match self.open_files.get_mut(handle) {
            Some(of) => {
                of.refcount = of.refcount.saturating_sub(1);
                (
                    of.vnode,
                    of.pipe,
                    of.shm,
                    of.epoll,
                    of.unix_socket,
                    of.socket_conn_id,
                    of.device_dev_type,
                    of.device_pty_id,
                    of.kind,
                    of.status_flags,
                    of.refcount == 0,
                )
            }
            None => return,
        };
        if !should_release {
            return;
        }
        if kind == OBJ_PIPE {
            if let Some(pipe_state) = self.pipes.get_mut(pipe) {
                let access = flags & O_ACCMODE;
                if access != O_WRONLY {
                    pipe_state.read_refs = pipe_state.read_refs.saturating_sub(1);
                }
                if access != O_RDONLY {
                    pipe_state.write_refs = pipe_state.write_refs.saturating_sub(1);
                }
                if pipe_state.read_refs == 0 && pipe_state.write_refs == 0 {
                    let _ = self.pipes.release(pipe);
                }
            }
            if vnode.is_valid() {
                if let Some(vn) = self.vnodes.get_mut(vnode) {
                    vn.open_count = vn.open_count.saturating_sub(1);
                }
                self.release_fifo_state_if_unused(vnode);
            }
        } else if kind == crate::server::types::OBJ_SHM {
            if let Some(shm_state) = self.shms.get_mut(shm) {
                shm_state.open_refs = shm_state.open_refs.saturating_sub(1);
                if let Some(vn) = self.vnodes.get_mut(vnode) {
                    vn.open_count = vn.open_count.saturating_sub(1);
                }
                let should_reclaim = shm_state.open_refs == 0 && shm_state.unlinked != 0;
                if should_reclaim {
                    let shm_id = shm_state.id;
                    shm_state.active = 0;
                    let _ = self.shms.release(shm);
                    let mut mm_msg = TronaMsg::zeroed();
                    let mut mm_reply = TronaMsg::zeroed();
                    mm_msg.label = MM_SHM_DESTROY;
                    mm_msg.length = 1;
                    mm_msg.regs[0] = shm_id;
                    let _ = unsafe {
                        trona_kernel::ipc::call_ctx(
                            crate::ipc_ctx(),
                            trona_runtime::client::caps::mmsrv_ep(),
                            &raw const mm_msg,
                            &raw mut mm_reply,
                        )
                    };
                    self.reclaim_bootstrap_vnode(vnode);
                }
            }
        } else if kind == crate::server::types::OBJ_EPOLL {
            let _ = self.epolls.release(epoll);
        } else if kind == crate::server::types::OBJ_SOCKET {
            if unix_socket.is_valid() {
                let (peer, bound_vnode, peer_name_vnode) = self
                    .unix_sockets
                    .get(unix_socket)
                    .map(|sock| (sock.peer, sock.bound_vnode, sock.peer_name_vnode))
                    .unwrap_or((
                        UnixSocketHandle::INVALID,
                        VnodeHandle::INVALID,
                        VnodeHandle::INVALID,
                    ));
                let should_destroy = match self.unix_sockets.get_mut(unix_socket) {
                    Some(sock) => {
                        sock.refcount = sock.refcount.saturating_sub(1);
                        sock.refcount == 0
                    }
                    None => false,
                };
                if should_destroy {
                    self.release_unix_socket_rights(unix_socket);
                    self.release_unix_socket_dgram_queue(unix_socket);
                    self.release_unix_socket_accept_queue(unix_socket);
                    if bound_vnode.is_valid() {
                        self.release_socket_name_vnode(bound_vnode);
                    }
                    if peer_name_vnode.is_valid() && peer_name_vnode != bound_vnode {
                        self.release_socket_name_vnode(peer_name_vnode);
                    }
                    if peer.is_valid() {
                        if let Some(peer_sock) = self.unix_sockets.get_mut(peer) {
                            if peer_sock.socket_type as i32 == SOCK_STREAM
                                || peer_sock.socket_type as i32 == super::SOCK_SEQPACKET
                            {
                                peer_sock.peer_closed = 1;
                            } else if peer_sock.peer == unix_socket {
                                peer_sock.peer = UnixSocketHandle::INVALID;
                                peer_sock.peer_name_vnode = VnodeHandle::INVALID;
                                peer_sock.peer_name_path_len = 0;
                                peer_sock.peer_name_abstract_len = 0;
                            }
                        }
                    }
                    // Cancel any deferred waiters that named this
                    // socket directly. Peer-side waiters parked on
                    // *us* will now see `peer_closed = 1` and be
                    // unblocked by the drive sweep below with EOF /
                    // EPIPE-equivalent reply labels.
                    unsafe {
                        crate::fileops::socket_wait::cancel_unix_socket_waiters_for_handle(
                            self,
                            unix_socket,
                        );
                        crate::fileops::socket_wait::drive_unix_socket_waiters(self);
                    }
                    let _ = self.unix_sockets.release(unix_socket);
                }
            } else if socket_conn_id != 0 && crate::netsrv_ep() != 0 {
                // Cancel parked inet waiters BEFORE telling netsrv to
                // close the conn. Otherwise a NET_COMPLETE may already
                // be inflight and would land on a stale waiter.
                unsafe {
                    crate::fileops::inet_wait::cancel_inet_waiters_for_conn(self, socket_conn_id);
                }
                let mut net_msg = TronaMsg::zeroed();
                let mut net_reply = TronaMsg::zeroed();
                net_msg.label = NET_CLOSE;
                net_msg.length = 1;
                net_msg.regs[0] = socket_conn_id as u64;
                let _ = unsafe {
                    trona_kernel::ipc::call_ctx(
                        crate::ipc_ctx(),
                        crate::netsrv_ep(),
                        &raw const net_msg,
                        &raw mut net_reply,
                    )
                };
            }
        } else if kind == OBJ_DEVICE {
            if (dev_type == DEV_PTMX || dev_type == DEV_PTY_SLAVE) && crate::posix_ttysrv_ep() != 0
            {
                let mut tty_msg = TronaMsg::zeroed();
                let mut tty_reply = TronaMsg::zeroed();
                tty_msg.label = POSIX_TTYSRV_PTY_CLOSE;
                tty_msg.length = 2;
                tty_msg.regs[0] = dev_pty_id as u64;
                tty_msg.regs[1] = if dev_type == DEV_PTMX { 1 } else { 0 };
                let _ = unsafe {
                    trona_kernel::ipc::call_ctx(
                        crate::ipc_ctx(),
                        crate::posix_ttysrv_ep(),
                        &raw const tty_msg,
                        &raw mut tty_reply,
                    )
                };
            }
            if let Some(vn) = self.vnodes.get_mut(vnode) {
                vn.open_count = vn.open_count.saturating_sub(1);
            }
            self.reclaim_bootstrap_vnode(vnode);
        } else {
            if let Some(vn) = self.vnodes.get_mut(vnode) {
                vn.open_count = vn.open_count.saturating_sub(1);
            }
            self.reclaim_bootstrap_vnode(vnode);
        }
        let _ = self.open_files.release(handle);
    }

    pub(crate) fn install_client_slot_shared(
        &mut self,
        cli_handle: ClientHandle,
        fd: usize,
        open_file: OpenFileHandle,
        fd_flags: u32,
    ) -> bool {
        if fd >= MAX_CLIENT_OBJECTS || !self.retain_open_file(open_file) {
            return false;
        }
        let old = match self.clients.get(cli_handle) {
            Some(client) => {
                if client.slots[fd].active != 0 {
                    client.slots[fd].open_file
                } else {
                    OpenFileHandle::INVALID
                }
            }
            None => {
                self.release_open_file(open_file);
                return false;
            }
        };
        if old.is_valid() {
            self.release_open_file(old);
        }
        let Some(client) = self.clients.get_mut(cli_handle) else {
            self.release_open_file(open_file);
            return false;
        };
        let slot = &mut client.slots[fd];
        *slot = OpenSlot::empty();
        slot.active = 1;
        slot.fd_flags = fd_flags & (FD_CLOEXEC as u32);
        slot.open_file = open_file;
        true
    }

    pub(crate) fn alloc_shared_fd_for_client(
        &mut self,
        cli_handle: ClientHandle,
        open_file: OpenFileHandle,
        fd_flags: u32,
    ) -> Option<usize> {
        let fd = {
            let client = self.clients.get(cli_handle)?;
            let mut found = None;
            for fd in 0..MAX_CLIENT_OBJECTS {
                if client.slots[fd].active == 0 {
                    found = Some(fd);
                    break;
                }
            }
            found?
        };
        if !self.install_client_slot_shared(cli_handle, fd, open_file, fd_flags) {
            return None;
        }
        Some(fd)
    }

    pub(crate) fn alloc_client_slot(
        &mut self,
        cli_handle: ClientHandle,
        vnode: VnodeHandle,
        kind: u8,
        flags: u32,
    ) -> Option<usize> {
        let fd = self.first_free_fd(cli_handle)?;
        let open_file = self.alloc_open_file(vnode, kind, flags)?;
        let client = self.clients.get_mut(cli_handle)?;
        let slot = &mut client.slots[fd];
        *slot = OpenSlot::empty();
        slot.active = 1;
        slot.fd_flags = if (flags & O_CLOEXEC) != 0 {
            FD_CLOEXEC as u32
        } else {
            0
        };
        slot.open_file = open_file;
        if let Some(of) = self.open_files.get_mut(open_file) {
            of.refcount = 1;
        }
        Some(fd)
    }

    pub(crate) fn alloc_pipe_client_slot(
        &mut self,
        cli_handle: ClientHandle,
        vnode: VnodeHandle,
        pipe: PipeHandle,
        flags: u32,
    ) -> Option<usize> {
        let fd = self.first_free_fd(cli_handle)?;
        let open_file = self.alloc_pipe_open_file(vnode, pipe, flags)?;
        let client = self.clients.get_mut(cli_handle)?;
        let slot = &mut client.slots[fd];
        *slot = OpenSlot::empty();
        slot.active = 1;
        slot.fd_flags = if (flags & O_CLOEXEC) != 0 {
            FD_CLOEXEC as u32
        } else {
            0
        };
        slot.open_file = open_file;
        if let Some(of) = self.open_files.get_mut(open_file) {
            of.refcount = 1;
        }
        Some(fd)
    }

    fn fifo_state_handle_for_vnode(&self, vnode: VnodeHandle) -> Option<FifoHandle> {
        let mut found = FifoHandle::INVALID;
        self.fifos.for_each_active(|handle, fifo| {
            if fifo.vnode == vnode {
                found = handle;
                return false;
            }
            true
        });
        if found.is_valid() { Some(found) } else { None }
    }

    pub(crate) fn ensure_fifo_state_for_vnode(&mut self, vnode: VnodeHandle) -> Option<FifoHandle> {
        if let Some(handle) = self.fifo_state_handle_for_vnode(vnode) {
            return Some(handle);
        }
        let handle = self.fifos.alloc()?;
        let fifo = self.fifos.get_mut(handle)?;
        *fifo = FifoState::zeroed();
        fifo.vnode = vnode;
        Some(handle)
    }

    pub(crate) fn ensure_fifo_pipe_for_vnode(&mut self, vnode: VnodeHandle) -> Option<PipeHandle> {
        let fifo_h = self.ensure_fifo_state_for_vnode(vnode)?;
        let pipe = self.fifos.get(fifo_h)?.pipe;
        if pipe.is_valid() {
            return Some(pipe);
        }
        let pipe = self.alloc_pipe()?;
        let fifo = self.fifos.get_mut(fifo_h)?;
        fifo.pipe = pipe;
        Some(pipe)
    }

    pub(crate) fn mark_fifo_unlinked(&mut self, vnode: VnodeHandle) {
        let Some(handle) = self.fifo_state_handle_for_vnode(vnode) else {
            return;
        };
        if let Some(fifo) = self.fifos.get_mut(handle) {
            fifo.unlinked = 1;
        }
    }

    pub(crate) fn release_fifo_state_if_unused(&mut self, vnode: VnodeHandle) {
        let Some(handle) = self.fifo_state_handle_for_vnode(vnode) else {
            return;
        };
        let (pipe, unlinked) = match self.fifos.get(handle) {
            Some(fifo) => (fifo.pipe, fifo.unlinked != 0),
            None => return,
        };
        let can_drop = match self.vnodes.get(vnode) {
            Some(vn) => vn.open_count == 0 && (vn.nlink == 0 || unlinked),
            None => true,
        };
        if !can_drop {
            return;
        }
        if pipe.is_valid() {
            let _ = self.pipes.release(pipe);
        }
        let _ = self.fifos.release(handle);
    }

    pub(crate) fn alloc_epoll_client_slot(&mut self, cli_handle: ClientHandle) -> Option<usize> {
        let fd = self.first_free_fd(cli_handle)?;
        let epoll = self.epolls.alloc()?;
        let epoll_state = self.epolls.get_mut(epoll)?;
        *epoll_state = EpollState::zeroed();
        epoll_state.active = 1;
        let open_file = match self.alloc_epoll_open_file(epoll) {
            Some(handle) => handle,
            None => {
                let _ = self.epolls.release(epoll);
                return None;
            }
        };
        let client = self.clients.get_mut(cli_handle)?;
        let slot = &mut client.slots[fd];
        *slot = OpenSlot::empty();
        slot.active = 1;
        slot.open_file = open_file;
        if let Some(of) = self.open_files.get_mut(open_file) {
            of.refcount = 1;
        }
        Some(fd)
    }

    pub(crate) fn alloc_shm_client_slot(
        &mut self,
        cli_handle: ClientHandle,
        vnode: VnodeHandle,
        shm: ShmHandle,
        flags: u32,
    ) -> Option<usize> {
        let fd = self.first_free_fd(cli_handle)?;
        let open_file = self.alloc_shm_open_file(vnode, shm, flags)?;
        let client = self.clients.get_mut(cli_handle)?;
        let slot = &mut client.slots[fd];
        *slot = OpenSlot::empty();
        slot.active = 1;
        slot.fd_flags = if (flags & O_CLOEXEC) != 0 {
            FD_CLOEXEC as u32
        } else {
            0
        };
        slot.open_file = open_file;
        if let Some(of) = self.open_files.get_mut(open_file) {
            of.refcount = 1;
        }
        Some(fd)
    }

    pub(crate) fn alloc_socket_client_slot(
        &mut self,
        cli_handle: ClientHandle,
        conn_id: u32,
        flags: u32,
    ) -> Option<usize> {
        let fd = self.first_free_fd(cli_handle)?;
        let open_file = self.alloc_socket_open_file(conn_id, flags)?;
        let client = self.clients.get_mut(cli_handle)?;
        let slot = &mut client.slots[fd];
        *slot = OpenSlot::empty();
        slot.active = 1;
        slot.fd_flags = if (flags & O_CLOEXEC) != 0 {
            FD_CLOEXEC as u32
        } else {
            0
        };
        slot.open_file = open_file;
        if let Some(of) = self.open_files.get_mut(open_file) {
            of.refcount = 1;
        }
        Some(fd)
    }

    pub(crate) fn alloc_unix_socket_client_slot(
        &mut self,
        cli_handle: ClientHandle,
        socket: UnixSocketHandle,
        flags: u32,
    ) -> Option<usize> {
        let fd = self.first_free_fd(cli_handle)?;
        let open_file = self.alloc_unix_socket_open_file(socket, flags)?;
        let client = self.clients.get_mut(cli_handle)?;
        let slot = &mut client.slots[fd];
        *slot = OpenSlot::empty();
        slot.active = 1;
        slot.fd_flags = if (flags & O_CLOEXEC) != 0 {
            FD_CLOEXEC as u32
        } else {
            0
        };
        slot.open_file = open_file;
        if let Some(of) = self.open_files.get_mut(open_file) {
            of.refcount = 1;
        }
        Some(fd)
    }

    pub(crate) fn alloc_device_client_slot(
        &mut self,
        cli_handle: ClientHandle,
        vnode: VnodeHandle,
        dev_type: u8,
        pty_id: u32,
        generation: u32,
        flags: u32,
    ) -> Option<usize> {
        let fd = self.first_free_fd(cli_handle)?;
        let open_file = self.alloc_device_open_file(vnode, dev_type, pty_id, generation, flags)?;
        let client = self.clients.get_mut(cli_handle)?;
        let slot = &mut client.slots[fd];
        *slot = OpenSlot::empty();
        slot.active = 1;
        slot.fd_flags = if (flags & O_CLOEXEC) != 0 {
            FD_CLOEXEC as u32
        } else {
            0
        };
        slot.open_file = open_file;
        if let Some(of) = self.open_files.get_mut(open_file) {
            of.refcount = 1;
        }
        Some(fd)
    }

    pub(crate) fn release_client_slot(&mut self, cli_handle: ClientHandle, fd: usize) -> bool {
        let Some(client) = self.clients.get_mut(cli_handle) else {
            return false;
        };
        if fd >= MAX_CLIENT_OBJECTS || client.slots[fd].active == 0 {
            return false;
        }
        let open_file = client.slots[fd].open_file;
        client.slots[fd] = OpenSlot::empty();
        self.release_open_file(open_file);
        true
    }

    pub(crate) fn client_directory_slot(
        &self,
        cli_handle: ClientHandle,
        fd: usize,
    ) -> Option<(VnodeHandle, u8, u64)> {
        let of = self.client_open_file(cli_handle, fd)?;
        Some((of.vnode, of.dir_cursor_state, of.dir_cursor))
    }

    fn first_free_fd(&self, cli_handle: ClientHandle) -> Option<usize> {
        let client = self.clients.get(cli_handle)?;
        let mut found = None;
        for fd in 0..MAX_CLIENT_OBJECTS {
            if client.slots[fd].active == 0 {
                found = Some(fd);
                break;
            }
        }
        found
    }
}
