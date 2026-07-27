// SPDX-License-Identifier: GPL-2.0-only
//! Centralised teardown of a shared `OpenObject` backing.
//!
//! Fires exactly once per `OpenObject`, when its `refcount` drops to
//! zero in `VfsState::close_open_object`. Every per-backing side effect
//! — VOP_CLOSE, arbitration release, pipe/socket refcount + waiter
//! wake, PTY_CLOSE IPC, NET_CLOSE IPC, epoll arena release, SHM unmap
//! — lives here.
//!
//! `release_backing` is the **only** place backing teardown runs; the
//! previous generation of per-kind `pre_close_*` hooks has been deleted
//! entirely because every teardown observed so far is `OpenObject`-
//! scoped. If future additions introduce genuinely descriptor-local
//! state (per-fd epoll interest, per-fd poll waiter, audit tag, …) that
//! cannot be shared across dups, it belongs in the `close_open_object`
//! descriptor-local seam — see `owner/mod.rs::descriptor_local_close_hook`
//! for the stub and extension rules.
//!
//! The dispatcher matches on `ObjectBacking` and routes each variant to
//! its arm. Callers must pass the backing value *snapshot* (the live
//! arena entry may be released by the caller immediately after) and a
//! `ReleaseAux` bundle carrying the fields each arm reads.

use trona_kernel::core_types::*;
use trona_kernel::ipc;
use trona_posix::consts::{DEV_PTMX, DEV_PTY_SLAVE};
use trona_protocol::posix::mmsrv::MM_SHM_UNMAP;
use trona_protocol::posix::posix::POSIX_TTYSRV_PTY_CLOSE;
use trona_protocol::posix::server::NET_CLOSE;
use uapi::*;

use crate::ipc_ctx;
use crate::owner::VfsState;
use crate::owner::op::{OpCore, OwnerPostOp};
use crate::personality::posix::misc::maybe_reclaim_unlinked_shm;
use crate::personality::posix::socket::state::release_socket;
use crate::server::consts::{OBJ_RIGHT_READ, netsrv_ep, posix_ttysrv_ep};
use crate::server::types::{DeviceInfo, ObjectBacking, ObjectKind};
use crate::vfs_core::arbitration::release_open;
use crate::vfs_core::vnode::VnodeHandle;

/// Auxiliary fields `release_backing` needs that are not recoverable
/// from the `ObjectBacking` alone. Snapshotted from the `OpenObject`
/// and its owner right before release; the arena entry is already
/// logically released by the time the dispatcher runs.
pub(crate) struct ReleaseAux {
    /// Client badge at the time of release. `0` when the client is
    /// already gone (exit sweep) — SHM unmap skips unbadged releases.
    pub(crate) badge: u64,
    /// Open flags (passed to VOP close).
    pub(crate) flags: u32,
    /// Arbitration: access modes the open was holding.
    pub(crate) held_access: u8,
    /// Arbitration: deny modes the open was holding.
    pub(crate) held_deny: u8,
    /// Pipe end selector — `OBJ_RIGHT_READ` bit decides read vs write
    /// end when tearing down a `Pipe` backing.
    pub(crate) rights: u8,
    /// Current SHM mapping offset (0 means "not mapped" so unmap is
    /// skipped). Also reused as the VOP_CLOSE offset argument.
    pub(crate) offset: u64,
    /// Inode id, used by the SHM arm to identify the mapping to mmsrv
    /// and by `maybe_reclaim_unlinked_shm` for lookup.
    pub(crate) inode: u32,
}

/// Tear down a just-released `OpenObject`'s backing.
///
/// Safety: `backing` must be the snapshot taken immediately before the
/// arena entry referenced by the caller was released. The caller is
/// responsible for clearing `slots[idx]` and releasing the arena entry;
/// this function only handles per-kind teardown.
pub(crate) unsafe fn release_backing(
    state: &mut VfsState,
    backing: ObjectBacking,
    aux: ReleaseAux,
) {
    unsafe {
        match backing {
            ObjectBacking::None | ObjectBacking::Reserved => {}
            ObjectBacking::Vnode {
                vnode,
                inode: _,
                kind,
                device,
            } => {
                release_vnode_backing(state, vnode, kind, device, &aux);
            }
            ObjectBacking::Pipe {
                pipe,
                vnode: _,
                inode: _,
            } => {
                release_pipe_backing(state, pipe, aux.rights);
            }
            ObjectBacking::UnixSocket { socket } => {
                release_unix_socket_backing(state, socket);
            }
            ObjectBacking::InetSocket { sock_id } => {
                release_inet_socket_backing(sock_id);
            }
            ObjectBacking::Epoll { epoll } => {
                let _ = state.epolls.release(epoll);
            }
        }
    }
}

// -------------------------------------------------------------------------
// Vnode backing (File / Directory / Device / Shm)
// -------------------------------------------------------------------------

unsafe fn release_vnode_backing(
    state: &mut VfsState,
    vh: VnodeHandle,
    kind: ObjectKind,
    device: Option<DeviceInfo>,
    aux: &ReleaseAux,
) {
    unsafe {
        // SHM-mapped vnode: tell mmsrv to unmap *before* the generic
        // vnode teardown below — mmsrv references the inode id which
        // stays valid only while the vnode is alive. Fire-and-forget:
        // close(2) returns to the client without waiting for mmsrv's
        // ack. mmsrv still processes the request in its normal
        // `reply_recv` loop; the reply is dropped by the kernel
        // because no reply cap was transferred.
        if kind == ObjectKind::Shm && aux.offset != 0 && vh.is_valid() && aux.badge != 0 {
            let mut mm_msg = TronaMsg::zeroed();
            mm_msg.label = MM_SHM_UNMAP;
            mm_msg.length = 3;
            mm_msg.regs[0] = aux.inode as u64;
            mm_msg.regs[1] = aux.badge;
            mm_msg.regs[2] = aux.offset;
            ipc::send_ctx(
                ipc_ctx(),
                trona_runtime::client::caps::mmsrv_ep(),
                &raw const mm_msg,
            );
        }

        // PTY device: notify ttysrv about this side closing. Fires
        // exactly once per OpenObject (refcount==0), so each
        // `posix_ttysrv` per-side counter decrements by exactly 1 per
        // last-reference close. Fire-and-forget per the async
        // teardown contract.
        if kind == ObjectKind::Device {
            if let Some(dev) = device {
                if dev.dev_type == DEV_PTY_SLAVE || dev.dev_type == DEV_PTMX {
                    let mut treq = TronaMsg::zeroed();
                    treq.label = POSIX_TTYSRV_PTY_CLOSE;
                    treq.length = 2;
                    treq.regs[0] = dev.pty_id as u64;
                    treq.regs[1] = if dev.dev_type == DEV_PTMX { 1 } else { 0 };
                    ipc::send_ctx(ipc_ctx(), posix_ttysrv_ep(), &raw const treq);
                }
            }
        }

        // Generic VOP_CLOSE + arbitration release + reclaim — skip for
        // pure handles that never had a vnode backing.
        if !vh.is_valid() {
            return;
        }

        if let Some(mut ctx) = crate::vfs_core::vop_context::OwnerVopCtx::from_state(state, vh) {
            let ops = (*ctx.vnode).ops;
            if !ops.is_null() {
                let _ = ((*ops).meta.close)(&mut ctx, aux.flags);
            }
        }

        let shm_handle_on_close = if kind == ObjectKind::Shm {
            shm_handle_for_vnode(state, vh)
        } else {
            crate::arena::Handle::<crate::ipc_objects::ShmData>::INVALID
        };

        if let Some(vnode) = state.vnodes.get_mut(vh) {
            release_open(vnode, aux.held_access, aux.held_deny);

            if vnode.should_reclaim() {
                if vnode.flight_count == 0 {
                    if let Some(mut ctx) =
                        crate::vfs_core::vop_context::OwnerVopCtx::from_state(state, vh)
                    {
                        let ops = (*ctx.vnode).ops;
                        if !ops.is_null() {
                            let _ = ((*ops).meta.inactive)(&mut ctx);
                        }
                    }
                    state.vnodes.release(vh);
                } else {
                    state.vnodes.retire(vh);
                }
            }
        }

        if shm_handle_on_close.is_valid() {
            let _ = maybe_reclaim_unlinked_shm(state, shm_handle_on_close, vh, None);
        }
    }
}

unsafe fn shm_handle_for_vnode(
    state: &VfsState,
    vh: VnodeHandle,
) -> crate::arena::Handle<crate::ipc_objects::ShmData> {
    unsafe {
        let invalid = crate::arena::Handle::<crate::ipc_objects::ShmData>::INVALID;
        let Some(vn) = state.vnodes.get(vh) else {
            return invalid;
        };
        let vd = vn.data as *const crate::fs::tmpfs::TmpfsVnodeData;
        if vd.is_null() {
            return invalid;
        }
        (*vd).shm_handle
    }
}

// -------------------------------------------------------------------------
// Pipe backing
// -------------------------------------------------------------------------

unsafe fn release_pipe_backing(
    state: &mut VfsState,
    pipe_handle: crate::arena::Handle<crate::ipc_objects::PipeState>,
    rights: u8,
) {
    unsafe {
        if !pipe_handle.is_valid() {
            return;
        }
        let pipe = crate::fileops::pipe::find_pipe(state, pipe_handle);
        if pipe.is_null() {
            return;
        }

        let is_read_end = (rights & OBJ_RIGHT_READ) != 0;
        if is_read_end {
            (*pipe).read_refcount = (*pipe).read_refcount.saturating_sub(1);
            if (*pipe).read_refcount == 0 {
                // State mutated above — now wake opposing waiters.
                while let Some(w) = crate::fileops::pipe::pipe_pop_write_waiter(pipe) {
                    let mut wake = TronaMsg::zeroed();
                    wake.label = TRONA_INVALID_OPERATION;
                    state.complete_op(w.op, OwnerPostOp::None, &raw const wake);
                }
                crate::fileops::pipe::wake_poll_waiters_pipe(state, pipe_handle, false, 0x008);
            }
        } else {
            (*pipe).write_refcount = (*pipe).write_refcount.saturating_sub(1);
            if (*pipe).write_refcount == 0 {
                while let Some(w) = crate::fileops::pipe::pipe_pop_recv_waiter(pipe) {
                    let mut wake = TronaMsg::zeroed();
                    wake.label = TRONA_OK;
                    wake.length = 1;
                    wake.regs[0] = 0;
                    state.complete_op(w.op, OwnerPostOp::None, &raw const wake);
                }
                crate::fileops::pipe::wake_poll_waiters_pipe(state, pipe_handle, true, 0x010);
            }
        }

        if (*pipe).read_refcount == 0 && (*pipe).write_refcount == 0 {
            crate::fileops::pipe::release_pipe(state, pipe_handle);
        }
    }
}

// -------------------------------------------------------------------------
// UNIX domain socket backing
// -------------------------------------------------------------------------

unsafe fn release_unix_socket_backing(
    state: &mut VfsState,
    socket_handle: crate::arena::Handle<crate::ipc_objects::SocketState>,
) {
    unsafe {
        if !socket_handle.is_valid() {
            return;
        }
        let sock = crate::personality::posix::socket::state::find_socket(state, socket_handle);
        if sock.is_null() {
            return;
        }

        (*sock).refcount = (*sock).refcount.saturating_sub(1);
        if (*sock).refcount > 0 {
            return;
        }

        // State transitions first, then wake peers and blocked callers.
        (*sock).state = crate::personality::posix::consts::SOCK_CLOSED;

        if (*sock).peer_socket.is_valid() {
            let peer =
                crate::personality::posix::socket::state::find_socket(state, (*sock).peer_socket);
            if !peer.is_null() {
                (*peer).peer_closed = 1;
                if (*peer).recv_op.reply_slot != 0 {
                    let mut wake = TronaMsg::zeroed();
                    wake.label = TRONA_OK;
                    wake.length = 1;
                    wake.regs[0] = 0;
                    state.complete_op((*peer).recv_op, OwnerPostOp::None, &raw const wake);
                    (*peer).recv_op = OpCore::INVALID;
                    (*peer).recv_badge = 0;
                }
            }
        }

        if (*sock).accept_op.reply_slot != 0 {
            let mut wake = TronaMsg::zeroed();
            wake.label = TRONA_INVALID_OPERATION;
            state.complete_op((*sock).accept_op, OwnerPostOp::None, &raw const wake);
            (*sock).accept_op = OpCore::INVALID;
            (*sock).accept_badge = 0;
        }

        for i in 0..(*sock).pending_cap as usize {
            let slot = (*sock).pending.add(i);
            if (*slot).active != 0 && (*slot).op.reply_slot != 0 {
                let mut wake = TronaMsg::zeroed();
                wake.label = TRONA_INVALID_OPERATION;
                state.complete_op((*slot).op, OwnerPostOp::None, &raw const wake);
                (*slot).active = 0;
                (*slot).op = OpCore::INVALID;
            }
        }
        (*sock).pending_count = 0;

        release_socket(state, socket_handle);
    }
}

// -------------------------------------------------------------------------
// Internet socket backing
// -------------------------------------------------------------------------

unsafe fn release_inet_socket_backing(sock_id: u32) {
    unsafe {
        let mut req = TronaMsg::zeroed();
        req.label = NET_CLOSE;
        req.regs[0] = sock_id as u64;
        req.length = 1;
        // Fire-and-forget: close(2) returns to the client immediately.
        // netsrv drops the connection asynchronously; its reply is
        // discarded because no reply cap was transferred.
        ipc::send_ctx(ipc_ctx(), netsrv_ep(), &raw const req);
    }
}
