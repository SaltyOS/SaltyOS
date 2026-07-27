// SPDX-License-Identifier: GPL-2.0-only
//! Owner-level request routing.
//!
//! The owner keeps only service-global requests here: backend helpers,
//! client lifecycle, and structural mount control. Personality-specific
//! ABI surfaces live below this layer.

use trona_kernel::core_types::*;
use trona_posix::consts::*;
use trona_protocol::posix::posix::POSIX_TTYSRV_PTY_LOOKUP;
use trona_protocol::posix::process_client::*;
use trona_protocol::posix::server::{NET_COMPLETE, POSIX_TTYSRV_PTY_OPEN_SLAVE};
use trona_protocol::posix::vfs::*;
use uapi::*;

use crate::arena::Handle;
use crate::owner::VfsState;
use crate::owner::backend_rpc::{
    self, BACKEND_OP_TTYSRV_GET_GENERATION, BACKEND_OP_TTYSRV_OPEN_SLAVE, BackendOpCtx,
    PendingBackendJob,
};
use crate::owner::pending_ops::{self, PO_KIND_TTY_STDIO, PendingOpId};
use crate::server::types::{ClientHandle, ClientState, MAX_CLIENT_OBJECTS, OpenSlot, PERS_POSIX};

#[inline]
pub(crate) fn pack_client_handle(h: ClientHandle) -> u64 {
    ((h.epoch() as u64) << 32) | (h.slot() as u64)
}

#[inline]
pub(crate) fn unpack_client_handle(v: u64) -> ClientHandle {
    Handle::<ClientState>::new(v as u32, (v >> 32) as u32)
}

fn tty_stdio_path(path: &mut [u8; 32], tty_dev: u64) -> Option<(&[u8], u8, u32, u32)> {
    if tty_dev == TTY_DEV_CONSOLE {
        let src = b"/dev/console";
        path[..src.len()].copy_from_slice(src);
        return Some((&path[..src.len()], DEV_CONSOLE, 0, 0));
    }
    if tty_dev < TTY_DEV_PTS_BASE {
        return None;
    }

    let pty_id = (tty_dev - TTY_DEV_PTS_BASE).try_into().ok()?;
    let prefix = b"/dev/pts/";
    path[..prefix.len()].copy_from_slice(prefix);
    let mut len = prefix.len();
    let mut digits = [0u8; 10];
    let mut digits_len = 0usize;
    let mut value = pty_id;
    loop {
        digits[digits_len] = b'0' + (value % 10) as u8;
        digits_len += 1;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    for idx in 0..digits_len {
        path[len + idx] = digits[digits_len - 1 - idx];
    }
    len += digits_len;
    Some((&path[..len], DEV_PTY_SLAVE, pty_id, 0))
}

fn install_provisioned_stdio_slot(
    state: &mut VfsState,
    cli_handle: crate::server::types::ClientHandle,
    fd: usize,
    vnode: crate::vfs_core::vnode::VnodeHandle,
    dev_type: u8,
    pty_id: u32,
    generation: u32,
) -> bool {
    if fd >= MAX_CLIENT_OBJECTS {
        return false;
    }
    if state.client_slot(cli_handle, fd).is_some() {
        return false;
    }
    let Some(open_file) = state.alloc_device_open_file(vnode, dev_type, pty_id, generation, O_RDWR)
    else {
        return false;
    };
    let Some(client) = state.clients.get_mut(cli_handle) else {
        return false;
    };
    let slot = &mut client.slots[fd];
    *slot = OpenSlot::empty();
    slot.active = 1;
    slot.fd_flags = 0;
    slot.open_file = open_file;
    if let Some(of) = state.open_files.get_mut(open_file) {
        of.refcount = 1;
    }
    true
}

fn rollback_provisioned_stdio_slots(
    state: &mut VfsState,
    cli_handle: crate::server::types::ClientHandle,
    upto_fd: usize,
) {
    for fd in 0..=upto_fd.min(2) {
        let _ = state.release_client_slot(cli_handle, fd);
    }
}

unsafe fn handle_provision_tty_stdio_to(
    state: &mut VfsState,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let target_badge = (*msg).regs[0];
        let tty_dev = (*msg).regs[1];
        if target_badge == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }

        let Some(cli_handle) = (if let Some(handle) = state.lookup_client(target_badge) {
            Some(handle)
        } else {
            state.ensure_client(target_badge, PERS_POSIX)
        }) else {
            (*reply).label = TRONA_OUT_OF_MEMORY;
            (*reply).length = 0;
            return;
        };

        let slots_busy = state
            .clients
            .get(cli_handle)
            .map(|client| {
                (0..=2).any(|fd| fd >= MAX_CLIENT_OBJECTS || client.slots[fd].active != 0)
            })
            .unwrap_or(true);
        if slots_busy {
            (*reply).label = TRONA_INVALID_OPERATION;
            (*reply).length = 0;
            return;
        }

        let mut path_buf = [0u8; 32];
        let Some((path_slice, dev_type, pty_id, mut generation)) =
            tty_stdio_path(&mut path_buf, tty_dev)
        else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        };

        // PTY: needs ttysrv RPC chain. Defer the entire provisioning
        // to the worker so the owner stays unblocked.
        if dev_type == DEV_PTY_SLAVE {
            let Some(reply_slot) = crate::fileops::tty_wait::save_current_caller(reply) else {
                return;
            };
            let Some(op_id) =
                pending_ops::alloc(PO_KIND_TTY_STDIO, target_badge, cli_handle, reply_slot)
            else {
                crate::fileops::tty_wait::release_reply_slot(reply_slot);
                (*reply).label = TRONA_OUT_OF_MEMORY;
                (*reply).length = 0;
                return;
            };
            if !enqueue_provision_lookup(cli_handle, target_badge, tty_dev, pty_id, op_id) {
                let recovered = pending_ops::take_reply_slot(op_id);
                pending_ops::free(op_id);
                crate::fileops::tty_wait::release_reply_slot(recovered);
                (*reply).label = TRONA_INVALID_OPERATION;
                (*reply).length = 0;
                return;
            }
            (*reply).label = crate::fileops::tty_wait::REPLY_DEFERRED_LABEL;
            (*reply).length = 0;
            return;
        }

        // Console / non-PTY: no backend RPC needed. Run inline.
        let vnode = match crate::vfs_core::vops::into_value_or_label(
            state.lookup_path_dynamic_absolute(path_slice, false),
        ) {
            Ok(Some(vh)) => vh,
            _ => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                (*reply).length = 0;
                return;
            }
        };
        let _ = generation;
        for fd in 0usize..=2 {
            if !install_provisioned_stdio_slot(
                state, cli_handle, fd, vnode, dev_type, pty_id, generation,
            ) {
                rollback_provisioned_stdio_slots(state, cli_handle, fd.saturating_sub(1));
                (*reply).label = TRONA_OUT_OF_MEMORY;
                (*reply).length = 0;
                return;
            }
        }
        (*reply).label = TRONA_OK;
        (*reply).length = 0;
    }
}

/// Stage 0 of provision_tty_stdio_to: ttysrv `PTY_LOOKUP` to fetch the
/// live generation. Worker performs the call; completion advances to
/// stage 1 via `BACKEND_OP_TTYSRV_GET_GENERATION` handler.
fn enqueue_provision_lookup(
    cli_handle: ClientHandle,
    target_badge: u64,
    tty_dev: u64,
    pty_id: u32,
    op_id: PendingOpId,
) -> bool {
    let mut req = TronaMsg::zeroed();
    req.label = POSIX_TTYSRV_PTY_LOOKUP;
    req.length = 1;
    req.regs[0] = pty_id as u64;
    let mut ctx = BackendOpCtx::zeroed();
    ctx.badge = target_badge;
    ctx.client_handle_raw = pack_client_handle(cli_handle);
    ctx.stage = 0;
    ctx.data[0] = tty_dev;
    ctx.data[1] = pty_id as u64;
    let job = PendingBackendJob {
        target_ep: crate::posix_ttysrv_ep(),
        op_kind: BACKEND_OP_TTYSRV_GET_GENERATION,
        payload_out_bytes: 0,
        op_id: op_id.raw(),
        request: req,
        ctx,
    };
    if !backend_rpc::try_enqueue_job(job) {
        return false;
    }
    true
}

/// Enqueue an `OPEN_SLAVE` job for one of the three stdio fds.
/// `current_fd` (0..=2) lives in `ctx.stage`; vnode/dev_type/generation
/// are packed in `ctx.data[2..5]` so the completion handler can install
/// the slot when the worker reply arrives.
pub(crate) fn enqueue_provision_open_slave(
    cli_handle: ClientHandle,
    target_badge: u64,
    tty_dev: u64,
    pty_id: u32,
    vnode_slot: u32,
    vnode_epoch: u32,
    dev_type: u8,
    generation: u32,
    current_fd: u8,
    op_id: PendingOpId,
) -> bool {
    let mut req = TronaMsg::zeroed();
    req.label = POSIX_TTYSRV_PTY_OPEN_SLAVE;
    req.length = 2;
    req.regs[0] = pty_id as u64;
    req.regs[1] = generation as u64;
    let mut ctx = BackendOpCtx::zeroed();
    ctx.badge = target_badge;
    ctx.client_handle_raw = pack_client_handle(cli_handle);
    ctx.stage = current_fd as u32 + 1;
    ctx.data[0] = tty_dev;
    ctx.data[1] = pty_id as u64;
    ctx.data[2] = ((vnode_epoch as u64) << 32) | (vnode_slot as u64);
    ctx.data[3] = generation as u64;
    ctx.data[4] = dev_type as u64;
    let job = PendingBackendJob {
        target_ep: crate::posix_ttysrv_ep(),
        op_kind: BACKEND_OP_TTYSRV_OPEN_SLAVE,
        payload_out_bytes: 0,
        op_id: op_id.raw(),
        request: req,
        ctx,
    };
    if !backend_rpc::try_enqueue_job(job) {
        return false;
    }
    true
}

/// Owner-side completion handler for provision_tty_stdio_to chain.
/// Called from `loop_::complete_backend_op` when an op_kind in the
/// tty range arrives. Returns true if it consumed the completion.
pub(crate) unsafe fn complete_provision_tty_stdio_to(
    state: &mut VfsState,
    completion: &backend_rpc::PendingBackendCompletion,
) -> bool {
    unsafe {
        let op_id = PendingOpId::from_raw(completion.op_id);
        let Some(op) = pending_ops::get(op_id) else {
            return false;
        };
        if op.kind != PO_KIND_TTY_STDIO {
            return false;
        }
        match completion.op_kind {
            BACKEND_OP_TTYSRV_GET_GENERATION => {
                handle_provision_lookup_completion(state, completion);
                true
            }
            BACKEND_OP_TTYSRV_OPEN_SLAVE => {
                handle_provision_open_slave_completion(state, completion);
                true
            }
            _ => false,
        }
    }
}

unsafe fn handle_provision_lookup_completion(
    state: &mut VfsState,
    completion: &backend_rpc::PendingBackendCompletion,
) {
    unsafe {
        let op_id = PendingOpId::from_raw(completion.op_id);
        let cli_handle = unpack_client_handle(completion.ctx.client_handle_raw);
        let target_badge = completion.ctx.badge;
        let tty_dev = completion.ctx.data[0];
        let pty_id = completion.ctx.data[1] as u32;

        if completion.backend_err != 0 || completion.backend_reply.label != TRONA_OK {
            fail_provision_op(op_id, TRONA_INVALID_OPERATION);
            return;
        }
        let generation = completion.backend_reply.regs[0] as u32;

        // sync vnode lookup using owner state.
        let mut path_buf = [0u8; 32];
        let Some((path_slice, dev_type, _, _)) = tty_stdio_path(&mut path_buf, tty_dev) else {
            fail_provision_op(op_id, TRONA_INVALID_ARGUMENT);
            return;
        };
        let vnode = match crate::vfs_core::vops::into_value_or_label(
            state.lookup_path_dynamic_absolute(path_slice, false),
        ) {
            Ok(Some(vh)) => vh,
            _ => {
                fail_provision_op(op_id, TRONA_INVALID_ARGUMENT);
                return;
            }
        };

        // Stage 1: enqueue OPEN_SLAVE for fd 0 — chain reuses the same
        // op_id, carrying reply-slot ownership forward. The previous
        // stage left the op in COMPLETING; requeue back to QUEUED so
        // the worker's mark_running compare_exchange can succeed.
        if !pending_ops::requeue(op_id) {
            // Cancelled between stages — drain_cancelled tears down.
            return;
        }
        if !enqueue_provision_open_slave(
            cli_handle,
            target_badge,
            tty_dev,
            pty_id,
            vnode.slot(),
            vnode.epoch(),
            dev_type,
            generation,
            0,
            op_id,
        ) {
            // queue full mid-chain — abort with INVALID_OPERATION.
            fail_provision_op(op_id, TRONA_INVALID_OPERATION);
        }
    }
}

unsafe fn handle_provision_open_slave_completion(
    state: &mut VfsState,
    completion: &backend_rpc::PendingBackendCompletion,
) {
    unsafe {
        let op_id = PendingOpId::from_raw(completion.op_id);
        let cli_handle = unpack_client_handle(completion.ctx.client_handle_raw);
        let target_badge = completion.ctx.badge;
        let tty_dev = completion.ctx.data[0];
        let pty_id = completion.ctx.data[1] as u32;
        let vnode_slot = completion.ctx.data[2] as u32;
        let vnode_epoch = (completion.ctx.data[2] >> 32) as u32;
        let generation = completion.ctx.data[3] as u32;
        let dev_type = completion.ctx.data[4] as u8;
        let current_fd = (completion.ctx.stage as usize).saturating_sub(1);

        let vnode = Handle::<crate::vfs_core::vnode::Vnode>::new(vnode_slot, vnode_epoch);

        let open_ok = completion.backend_err == 0 && completion.backend_reply.label == TRONA_OK;
        if !open_ok {
            rollback_provisioned_stdio_slots(state, cli_handle, current_fd.saturating_sub(1));
            fail_provision_op(op_id, TRONA_INVALID_OPERATION);
            return;
        }
        if !install_provisioned_stdio_slot(
            state, cli_handle, current_fd, vnode, dev_type, pty_id, generation,
        ) {
            rollback_provisioned_stdio_slots(state, cli_handle, current_fd.saturating_sub(1));
            fail_provision_op(op_id, TRONA_OUT_OF_MEMORY);
            return;
        }

        if current_fd >= 2 {
            // Final stage: all three fds installed. Reply OK and free
            // the chain's pending-op slot.
            let reply_slot = pending_ops::take_reply_slot(op_id);
            pending_ops::free(op_id);
            if reply_slot != 0 {
                let mut reply = TronaMsg::zeroed();
                reply.label = TRONA_OK;
                crate::fileops::tty_wait::send_saved_reply(reply_slot, &raw const reply);
            }
            return;
        }

        // Enqueue next fd's OPEN_SLAVE — same op_id continues the
        // chain. Requeue COMPLETING -> QUEUED before the worker
        // re-picks this op_id for mark_running.
        let next_fd = current_fd + 1;
        if !pending_ops::requeue(op_id) {
            // Cancelled between stages — drop the partially-installed
            // stdio slots; drain_cancelled releases the reply slot.
            rollback_provisioned_stdio_slots(state, cli_handle, current_fd);
            return;
        }
        if !enqueue_provision_open_slave(
            cli_handle,
            target_badge,
            tty_dev,
            pty_id,
            vnode_slot,
            vnode_epoch,
            dev_type,
            generation,
            next_fd as u8,
            op_id,
        ) {
            rollback_provisioned_stdio_slots(state, cli_handle, current_fd);
            fail_provision_op(op_id, TRONA_INVALID_OPERATION);
        }
    }
}

unsafe fn send_provision_failure(reply_slot: u64, err_label: u64) {
    unsafe {
        let mut reply = TronaMsg::zeroed();
        reply.label = err_label;
        crate::fileops::tty_wait::send_saved_reply(reply_slot, &raw const reply);
    }
}

unsafe fn fail_provision_op(op_id: PendingOpId, err_label: u64) {
    unsafe {
        let reply_slot = pending_ops::take_reply_slot(op_id);
        pending_ops::free(op_id);
        if reply_slot != 0 {
            send_provision_failure(reply_slot, err_label);
        }
    }
}

/// `source` index of the dedicated netsrv callback endpoint inside
/// `endpoint_buf` in `run_owner_loop`. Index 1 is the callback EP when
/// it has been allocated; index 0 is always `service_ep`.
const SOURCE_NETSRV_CALLBACK_EP: u32 = 1;

/// Dispatch one VFS request.
pub(crate) fn dispatch_request(
    state: &mut VfsState,
    msg: *const TronaMsg,
    badge: u64,
    source: u32,
    reply: *mut TronaMsg,
) {
    unsafe {
        // NET_COMPLETE callbacks from netsrv are isolated by source EP,
        // label, and badge. A buggy or malicious client cannot
        // impersonate netsrv via the service EP, and netsrv cannot
        // reach VFS internals via the wrong label.
        let is_callback_source =
            source == SOURCE_NETSRV_CALLBACK_EP && state.netsrv_callback_ep != 0;
        if (*msg).label == NET_COMPLETE {
            if !is_callback_source || badge != crate::fileops::inet_wait::NETSRV_CALLBACK_BADGE {
                (*reply).label = TRONA_INVALID_OPERATION;
                (*reply).length = 0;
                return;
            }
            crate::fileops::inet_wait::handle_netsrv_completion(state, msg, reply);
            return;
        }
        if is_callback_source {
            // Anything else arriving on the callback EP is unexpected.
            (*reply).label = TRONA_INVALID_OPERATION;
            (*reply).length = 0;
            return;
        }

        match (*msg).label {
            VFS_BACKEND_RESOLVE_BACKING => {
                crate::fileops::backing::handle_resolve_backing_owned(state, msg, reply);
            }
            VFS_BACKEND_RESOLVE_PATH_BACKING => {
                crate::fileops::backing::handle_resolve_path_backing_owned(
                    state, badge, msg, reply,
                );
            }
            VFS_BACKEND_PAGER_READ => {
                crate::fileops::backing::handle_pager_read_owned(state, msg, reply);
            }
            VFS_BACKEND_PAGER_WRITE => {
                crate::fileops::backing::handle_pager_write_owned(state, msg, reply);
            }
            VFS_CLIENT_REGISTER => {
                let target_badge = (*msg).regs[0];
                let personality = (*msg).regs[1] as u8;
                (*reply).label = if state.ensure_client(target_badge, personality).is_some() {
                    TRONA_OK
                } else {
                    TRONA_OUT_OF_MEMORY
                };
                (*reply).length = 0;
            }
            VFS_CLIENT_EXIT => {
                let target_badge = (*msg).regs[0];
                crate::owner::cancel::vfs_cancel_for_badge(
                    state,
                    target_badge,
                    pending_ops::CANCEL_DROP,
                );
                let _ = state.remove_client(target_badge);
                (*reply).label = TRONA_OK;
                (*reply).length = 0;
            }
            PROC_CLIENT_CREATE => {
                let target_badge = (*msg).regs[0];
                let personality = (*msg).regs[2] as u8;
                if state.ensure_client(target_badge, personality).is_some() {
                    (*reply).label = TRONA_OK;
                    (*reply).length = 1;
                    (*reply).regs[0] = target_badge;
                } else {
                    (*reply).label = TRONA_OUT_OF_MEMORY;
                    (*reply).length = 0;
                }
            }
            PROC_CLIENT_CLONE => {
                crate::fileops::fd::handle_clone_fds_owned(state, msg, reply);
                if (*reply).label == TRONA_OK {
                    (*reply).length = 1;
                    (*reply).regs[0] = (*msg).regs[1];
                }
            }
            PROC_CLIENT_EXEC => {
                crate::fileops::fd::handle_client_exec_owned(state, msg, reply);
                if (*reply).label == TRONA_OK {
                    (*reply).length = 1;
                    (*reply).regs[0] = (*msg).regs[0];
                }
            }
            PROC_CLIENT_DROP => {
                let target_badge = (*msg).regs[0];
                crate::owner::cancel::vfs_cancel_for_badge(
                    state,
                    target_badge,
                    pending_ops::CANCEL_DROP,
                );
                let _ = state.remove_client(target_badge);
                (*reply).label = TRONA_OK;
                (*reply).length = 0;
            }
            VFS_PROVISION_TTY_STDIO_TO => handle_provision_tty_stdio_to(state, msg, reply),
            VFS_MOUNT => crate::ipc::mount_ipc::handle_vfs_mount(state, badge, msg, reply),
            VFS_UMOUNT => crate::ipc::mount_ipc::handle_vfs_umount(state, badge, msg, reply),
            VFS_PIVOT_ROOT => crate::ipc::mount_ipc::handle_vfs_pivot_root(state, msg, reply),
            VFS_REMOUNT => crate::ipc::mount_ipc::handle_vfs_remount(state, badge, msg, reply),
            VFS_STATFS => crate::ipc::statfs_ipc::handle_vfs_statfs(state, badge, msg, reply),
            VFS_FSTATFS => crate::ipc::statfs_ipc::handle_vfs_fstatfs(state, badge, msg, reply),
            VFS_MOUNT_LIST => crate::ipc::mountlist_ipc::handle_vfs_mount_list(state, msg, reply),
            VFS_BACKEND_RELEASE_TMPFS => {
                let kind = (*msg).regs[0];
                let fs_id = (*msg).regs[1];
                let ino = (*msg).regs[2];
                if kind != trona_runtime::core::server_consts::server::MMAP_BACKING_TMPFS {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    (*reply).length = 0;
                } else {
                    // Edge-triggered: a missing match is harmless
                    // (the vnode raced through full reclaim before
                    // the notification arrived) so collapse to OK.
                    let _ = crate::fs::tmpfs::release_export_ref(state, fs_id, ino);
                    (*reply).label = TRONA_OK;
                    (*reply).length = 0;
                }
            }
            VFS_BACKEND_ACQUIRE_TMPFS => {
                let kind = (*msg).regs[0];
                let fs_id = (*msg).regs[1];
                let ino = (*msg).regs[2];
                let delta = if (*msg).regs[3] == 0 {
                    1
                } else {
                    (*msg).regs[3]
                };
                if kind != trona_runtime::core::server_consts::server::MMAP_BACKING_TMPFS {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    (*reply).length = 0;
                } else {
                    let _ = crate::fs::tmpfs::acquire_export_ref(state, fs_id, ino, delta);
                    (*reply).label = TRONA_OK;
                    (*reply).length = 0;
                }
            }
            _ => {
                if crate::personality::posix::dispatch::dispatch_request(state, badge, msg, reply) {
                    return;
                }
                if crate::personality::win32::dispatch::dispatch_request(state, badge, msg, reply) {
                    return;
                }
                (*reply).label = TRONA_NOT_SUPPORTED;
                (*reply).length = 0;
            }
        }
    }
}
