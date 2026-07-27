// SPDX-License-Identifier: GPL-2.0-only
//! VFS IPC dispatch — owner-loop entry point.
//!
//! Replaces `ipc/dispatch.rs`. Every handler receives `&mut VfsState`
//! instead of reaching into global statics. Client lookup uses
//! `BadgeMap` instead of O(n) pool scan.

use trona_kernel::core_types::*;
use trona_posix::consts::{DEV_CONSOLE, DEV_PTY_SLAVE, O_RDWR, TTY_DEV_CONSOLE, TTY_DEV_PTS_BASE};
use trona_protocol::posix::mmsrv::*;
use trona_protocol::posix::posix::{POSIX_TTYSRV_PTY_LOOKUP, POSIX_TTYSRV_PTY_OPEN_SLAVE};
use trona_protocol::posix::vfs::*;
use uapi::*;

use crate::arena::Handle;
use crate::owner::VfsState;
use crate::owner::op::{OpCore, OpKind, OwnerPostOp};
use crate::server::consts::*;
use crate::server::types::*;
use crate::vfs_core::error::VfsError;
use crate::vfs_core::file::PERS_WIN32;
use crate::vfs_core::mount_ctl;
use crate::vfs_core::namei_common::{NameiArgs, NameiResult};
use crate::vfs_core::outcome::{Parked, Ready};
use crate::vfs_core::vnode::{Vnode, VnodeHandle};
use crate::vfs_core::vop_context::{OwnerVopCtx, WorkerIoCtx};
use crate::{ipc_ctx, personality};

// =========================================================================
// Client resolution
// =========================================================================

/// Resolve badge to ClientHandle, auto-registering new clients.
fn resolve_client(state: &mut VfsState, badge: u64) -> Option<ClientHandle> {
    if let Some((slot, epoch)) = state.badge_map.lookup(badge) {
        let h = ClientHandle::new(slot, epoch);
        if state.clients.is_alive(h) {
            return Some(h);
        }
    }
    // Auto-register new client.
    let h = state.alloc_client_slot(b"resolve_client")?;
    let cli = state.clients.get_mut(h)?;
    *cli = ClientState::zeroed();
    cli.badge = badge;
    cli.personality = 0; // PERS_POSIX default
    cli.cwd_ref = crate::vfs_core::cached_ref::CachedRef::<
        crate::vfs_core::identity::VnodeKey,
        VnodeHandle,
    >::INVALID;
    cli.mount_ns = state.global_ns;
    cli.cwd[0] = b'/';
    if state.badge_map.insert(badge, h.slot(), h.epoch()).is_err() {
        trona_runtime::uwarn!(|_lb| {
            _lb.str(b"[VFS] badge-map insert failed ctx=resolve_client badge=");
            _lb.hex(badge);
            _lb.str(b" len=");
            _lb.dec(state.badge_map.len() as u64);
            _lb.str(b" cap=");
            _lb.dec(state.badge_map.capacity() as u64);
            _lb.str(b"\n");
        });
        let _ = state.clients.release(h);
        state.clients.sweep();
        return None;
    }
    Some(h)
}

fn lookup_client(state: &VfsState, badge: u64) -> Option<ClientHandle> {
    let (slot, epoch) = state.badge_map.lookup(badge)?;
    let h = ClientHandle::new(slot, epoch);
    if state.clients.is_alive(h) {
        Some(h)
    } else {
        None
    }
}

/// Get client personality without allocating.
fn client_personality(state: &VfsState, badge: u64) -> u8 {
    if let Some((slot, epoch)) = state.badge_map.lookup(badge) {
        let h = ClientHandle::new(slot, epoch);
        if let Some(cli) = state.clients.get(h) {
            return cli.personality;
        }
    }
    0 // PERS_POSIX default
}

// =========================================================================
// FD resolution helpers
// =========================================================================

/// Resolve an fd from a client's slot table to the referenced
/// `OpenObject` (immutable). Returns `None` if the slot is free, the
/// `OpenObject` has been reclaimed, or `fd` is out of range.
pub(crate) fn resolve_fd<'a>(
    state: &'a VfsState,
    cli_handle: ClientHandle,
    fd: i32,
) -> Option<&'a crate::server::open_object::OpenObject> {
    if fd < 0 || fd as usize >= MAX_CLIENT_OBJECTS {
        return None;
    }
    state.open_object_at(cli_handle, fd as usize)
}

/// Mutable variant of [`resolve_fd`]. Returns a `&mut OpenObject`.
/// Callers that need to update `offset` / `dir_cursor` do so directly
/// through the returned reference; both fields live exclusively on the
/// `OpenObject` and are therefore authoritative.
pub(crate) fn resolve_fd_mut<'a>(
    state: &'a mut VfsState,
    cli_handle: ClientHandle,
    fd: i32,
) -> Option<&'a mut crate::server::open_object::OpenObject> {
    if fd < 0 || fd as usize >= MAX_CLIENT_OBJECTS {
        return None;
    }
    state.open_object_at_mut(cli_handle, fd as usize)
}

/// Resolve fd to its VnodeHandle. Returns INVALID if the fd is not
/// vnode-backed (pipes, sockets, epoll).
pub(crate) fn fd_vnode_handle(state: &VfsState, cli_handle: ClientHandle, fd: i32) -> VnodeHandle {
    match resolve_fd(state, cli_handle, fd) {
        Some(slot) => slot.vnode_handle(),
        None => VnodeHandle::INVALID,
    }
}

/// Build an `OwnerVopCtx` for a vnode handle.
pub(crate) unsafe fn build_ctx<'a>(
    state: &'a mut VfsState,
    vh: VnodeHandle,
) -> Option<crate::vfs_core::vop_context::OwnerVopCtx<'a>> {
    unsafe { crate::vfs_core::vop_context::OwnerVopCtx::from_state(state, vh) }
}

/// Build a `NameiCtx` from `&mut VfsState` for path-walk helpers. The
/// returned ctx borrows `state` for its lifetime.
pub(crate) fn build_namei_ctx<'a>(
    state: &'a mut VfsState,
) -> crate::vfs_core::namei_common::NameiCtx<'a> {
    crate::vfs_core::namei_common::NameiCtx { state }
}

/// Resolve a path according to the caller personality. DataOps-side
/// `ctx.state` is armed for the duration of the walk so
/// backend DataOps dispatched from the walk can reach owner state.
pub(crate) unsafe fn resolve_namei(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    args: &NameiArgs,
) -> Result<NameiResult, VfsError> {
    unsafe {
        let personality = state
            .clients
            .get(cli_handle)
            .map(|cli| cli.personality)
            .unwrap_or(0);
        let result = {
            let mut namei_ctx = build_namei_ctx(state);
            if personality == PERS_WIN32 {
                personality::win32::namei::namei_win32(&mut namei_ctx, args)
            } else {
                personality::posix::namei::namei_posix(&mut namei_ctx, args)
            }
        };
        result
    }
}

/// Build a WorkerIoCtx from a vnode handle. No trampolines needed.
///
/// The vnode's cached `mount` handle is consulted first; if the cache
/// is stale (arena slot recycled) the authoritative `mount_fs_id` is
/// used to recover a live `MountHandle` via
/// `VfsState::resolve_vnode_mount`.
pub(crate) fn build_data_ctx(state: &mut VfsState, vh: VnodeHandle) -> Option<WorkerIoCtx> {
    let state_ptr = state as *mut VfsState;
    let vnode = state.vnodes.get(vh)?;
    let ops = vnode.ops;
    let mount_handle = state.resolve_vnode_mount(vh)?;
    let mount = state.mounts.get(mount_handle)?;
    Some(
        WorkerIoCtx::new(
            vh,
            mount_handle,
            vnode.data,
            mount.data,
            vnode.vtype,
            vnode.id,
            mount.fs_instance_id,
        )
        .with_ops(ops)
        .with_state(state_ptr),
    )
}

// =========================================================================
// Credential helpers
// =========================================================================

/// Build a VfsCred from a client's cached credentials.
pub(crate) fn client_cred(
    state: &VfsState,
    cli_handle: ClientHandle,
) -> crate::vfs_core::cred::VfsCred {
    let mut cred = crate::vfs_core::cred::VfsCred::zeroed();
    if let Some(cli) = state.clients.get(cli_handle) {
        cred.pid = (cli.badge & 0xFFFF) as u32;
        cred.uid = cli.cred_uid;
        cred.euid = cli.cred_uid;
        cred.gid = cli.cred_gid;
        cred.egid = cli.cred_gid;
        cred.ngroups = cli.cred_ngroups;
        let n = cred.ngroups as usize;
        for i in 0..n {
            cred.groups[i] = cli.cred_groups[i];
        }
    }
    cred
}

/// Get the root vnode handle for a client (namespace root or global root).
pub(crate) fn root_vnode_for(state: &VfsState, cli_handle: ClientHandle) -> VnodeHandle {
    if let Some(cli) = state.clients.get(cli_handle) {
        if cli.mount_ns.is_valid() {
            if let Some(ns) = state.mount_ns.get(cli.mount_ns) {
                if ns.root_mount.is_valid() {
                    if let Some(mp) = state.mounts.get(ns.root_mount) {
                        return mp.root_vnode;
                    }
                }
            }
        }
    }
    // Fall back to global root.
    if let Some(mp) = state.mounts.get(state.root_mount) {
        mp.root_vnode
    } else {
        VnodeHandle::INVALID
    }
}

/// Get the cwd vnode handle for a client. Falls back to root if unset.
///
/// Consults the cached `cwd_vnode` handle first and, if it has become
/// stale (arena slot recycled), falls back to the authoritative
/// `cwd_key` via the resolve cache. Returns the client's root when
/// neither path yields a live handle.
pub(crate) fn cwd_vnode_for(state: &VfsState, cli_handle: ClientHandle) -> VnodeHandle {
    if let Some(cli) = state.clients.get(cli_handle) {
        if let Some(vh) = cli.cwd_ref.resolve_ro(state) {
            return vh;
        }
    }
    root_vnode_for(state, cli_handle)
}

// =========================================================================
// Main dispatch
// =========================================================================

/// Dispatch a single VFS IPC message.
///
/// Returns `true` if the reply should be skipped (deferred reply via saved
/// caller cap), `false` if the caller should send `reply` back.
pub(crate) unsafe fn vfs_dispatch_owned(
    state: &mut VfsState,
    msg: *const TronaMsg,
    badge: u64,
    recv_source: u64,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        state.dispatch_count += 1;

        match classify_event(msg, badge, recv_source) {
            VfsEvent::PtyNotification { badge } => {
                personality::posix::tty::handle_pty_notification(state, badge);
                true
            }
            VfsEvent::NetsrvCallback => {
                personality::posix::inet::handle_netsrv_callback(state, msg, reply);
                false
            }
            VfsEvent::PagerRequest { write } => {
                if write {
                    crate::backend::handle_pager_write(state, msg, reply);
                } else {
                    crate::backend::handle_pager_read(state, msg, reply);
                }
                false
            }
            VfsEvent::BackendCompletion => {
                // Async saltyfs RPC completion — resume the parked
                // fileops continuation. The dispatcher unwinds the
                // reply itself (if any) to the client's saved reply
                // slot and returns; we have no synchronous reply to
                // emit on the callback EP.
                crate::owner::pending::dispatch_pending_reply(state, &*msg);
                true
            }
            VfsEvent::WorkerCompletionKick => true,
            VfsEvent::UnknownCallback => {
                (*reply).label = TRONA_INVALID_OPERATION;
                false
            }
            VfsEvent::TimerFired { now_ns } => {
                // The classifier does not produce `TimerFired` from
                // IPC ingress today — the owner loop calls
                // `dispatch_timer_fired` directly from its timer-wheel
                // integration (see [`run_owner_loop`]) so this arm is
                // unreachable from the recv path. The variant exists so
                // new ingress sources that deliver timer expiries as
                // IPC messages (future kernel-pushed timer events)
                // land in a single named classification instead of an
                // inline branch.
                let _ = now_ns;
                true
            }
            VfsEvent::ClientRequest => {
                // Fall through to the client-request dispatch below.
                vfs_dispatch_client_request(state, msg, badge, reply)
            }
        }
    }
}

/// Ingress-source classification. Every message that lands in the owner
/// loop is classified into exactly one variant before dispatch; new
/// sources extend this enum rather than adding an inline branch to
/// `vfs_dispatch_owned`. Rust's exhaustive match guarantees the
/// classifier stays complete.
#[derive(Clone, Copy)]
pub(crate) enum VfsEvent {
    /// PTY bound-notification (data-ready wake-up).
    PtyNotification { badge: u64 },
    /// netsrv async completion callback.
    NetsrvCallback,
    /// Owner-loop kick sent by a local VFS worker when a completion
    /// ring transitions from empty to non-empty.
    WorkerCompletionKick,
    /// mmsrv pager request on the backend callback EP.
    PagerRequest { write: bool },
    /// Backend async RPC completion (SaltyFS etc.) carrying a
    /// `CorrelationHeader` with `kind = COMPLETION`.
    BackendCompletion,
    /// Callback-EP message whose label does not match any known
    /// classification. Rejected with `TRONA_INVALID_OPERATION`.
    UnknownCallback,
    /// Timer-wheel expiry observed by the owner loop. Routes into
    /// `ipc::timer_wheel::process_expired_timers`. The owner loop
    /// polls this at the top of each iteration so every expiry
    /// funnels through the same classification surface instead of
    /// an inline branch.
    TimerFired { now_ns: u64 },
    /// Regular client request arriving on the VFS service EP.
    ClientRequest,
}

/// Entry point the owner loop calls when the timer wheel reports an
/// expiry. The event flows through the same classification surface as
/// IPC ingress so adding new timer-driven work extends the
/// [`VfsEvent`] enum, not an inline branch. Delegates into
/// `ipc::timer_wheel::process_expired_timers` which is the
/// authoritative timer consumer.
pub(crate) unsafe fn dispatch_timer_fired(state: &mut VfsState, now_ns: u64) {
    // The classification is cosmetic (the variant is not currently
    // carried by an IPC message), but the call routes through the
    // same surface so future kernel-pushed timer events fold in with
    // zero branching changes. `process_expired_timers` reads the
    // current clock itself; `now_ns` is stamped onto the
    // `TimerFired` event for telemetry / future hand-off into a
    // ring-based timer queue.
    let _event = VfsEvent::TimerFired { now_ns };
    unsafe {
        crate::ipc::timer_wheel::process_expired_timers(state);
    }
}

/// Classify an ingress message into a [`VfsEvent`]. Pure function over
/// the message + badge + recv-source triple; no state mutation.
#[inline]
unsafe fn classify_event(msg: *const TronaMsg, badge: u64, recv_source: u64) -> VfsEvent {
    unsafe {
        if recv_source == IPC_RECV_SOURCE_NOTIFICATION {
            return VfsEvent::PtyNotification { badge };
        }
        if recv_source == 1 {
            if (*msg).label == VFS_OWNER_WORKER_KICK {
                return VfsEvent::WorkerCompletionKick;
            }
            if badge == NETSRV_CALLBACK_BADGE {
                return VfsEvent::NetsrvCallback;
            }
            if (*msg).label == MM_PAGER_REQUEST {
                return VfsEvent::PagerRequest { write: false };
            }
            if (*msg).label == MM_PAGER_WRITE_REQUEST {
                return VfsEvent::PagerRequest { write: true };
            }
            if crate::owner::pending::decode_fs_completion_header(&*msg).is_some() {
                return VfsEvent::BackendCompletion;
            }
            return VfsEvent::UnknownCallback;
        }
        VfsEvent::ClientRequest
    }
}

/// Client-request path — the original inline-dispatch body of
/// `vfs_dispatch_owned` minus the classification prelude. Split out so
/// the caller can drive it from the `VfsEvent::ClientRequest` arm.
unsafe fn vfs_dispatch_client_request(
    state: &mut VfsState,
    msg: *const TronaMsg,
    badge: u64,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        // Backend service requests sent through the regular VFS service EP.
        if (*msg).label == VFS_BACKEND_PAGER_READ {
            crate::backend::handle_pager_read(state, msg, reply);
            return false;
        }
        if (*msg).label == VFS_BACKEND_PAGER_WRITE {
            crate::backend::handle_pager_write(state, msg, reply);
            return false;
        }
        if (*msg).label == VFS_BACKEND_RESOLVE_BACKING {
            let target_badge = (*msg).regs[1];
            let Some(target_client) = lookup_client(state, target_badge) else {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return false;
            };
            let _ = crate::backend::ensure_mmsrv_pager_callback_registered(state);
            crate::backend::handle_resolve_backing(state, target_client, msg, reply);
            return false;
        }
        if (*msg).label == VFS_BACKEND_RESOLVE_PATH_BACKING {
            let _ = crate::backend::ensure_mmsrv_pager_callback_registered(state);
            let cli_handle = match resolve_client(state, badge) {
                Some(h) => h,
                None => {
                    (*reply).label = TRONA_OUT_OF_MEMORY;
                    return false;
                }
            };
            crate::backend::handle_resolve_path_backing(state, cli_handle, msg, reply);
            return false;
        }

        if (*msg).label == VFS_CLIENT_REGISTER {
            dispatch_client_register(state, msg, reply, badge);
            return false;
        }
        if (*msg).label == VFS_CLIENT_EXIT {
            dispatch_client_exit(state, msg, reply, badge);
            return true;
        }
        if (*msg).label == VFS_CLIENT_EXEC {
            dispatch_client_exec(state, msg, reply, badge);
            return true;
        }
        if (*msg).label == VFS_DUP_OBJECT_SLOTS_TO {
            dispatch_dup_object_slots_to(state, msg, reply, badge);
            return false;
        }
        if (*msg).label == VFS_PROVISION_TTY_STDIO_TO {
            dispatch_provision_tty_stdio_to(state, msg, reply, badge);
            return false;
        }
        if (*msg).label == VFS_POSIX_CLONE_FDS {
            personality::posix::fd_ops::handle_clone_fds(
                state,
                crate::server::types::ClientHandle::INVALID,
                msg,
                reply,
            );
            return false;
        }

        if badge == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        // Resolve client.
        let cli_handle = match resolve_client(state, badge) {
            Some(h) => h,
            None => {
                (*reply).label = TRONA_OUT_OF_MEMORY;
                return false;
            }
        };

        let mut skip_reply = false;

        match (*msg).label {
            VFS_READ => {
                let fd = (*msg).regs[0] as i32;
                let pers = client_personality(state, badge);
                skip_reply = if pers == PERS_WIN32 {
                    personality::win32::dispatch::dispatch_read(state, cli_handle, fd, msg, reply)
                } else {
                    personality::posix::dispatch::dispatch_read(state, cli_handle, fd, msg, reply)
                };
            }
            VFS_WRITE => {
                let fd = (*msg).regs[0] as i32;
                let pers = client_personality(state, badge);
                skip_reply = if pers == PERS_WIN32 {
                    personality::win32::dispatch::dispatch_write(state, cli_handle, fd, msg, reply)
                } else {
                    personality::posix::dispatch::dispatch_write(state, cli_handle, fd, msg, reply)
                };
            }
            VFS_CLOSE => {
                crate::fileops::mutate::handle_close_owned(state, cli_handle, msg, reply, badge);
            }
            VFS_LSEEK => {
                crate::fileops::mutate::handle_lseek_owned(state, cli_handle, msg, reply);
            }
            VFS_PREAD => {
                skip_reply = crate::fileops::pio::handle_pread_owned(state, cli_handle, msg, reply);
            }
            VFS_PWRITE => {
                skip_reply =
                    crate::fileops::pio::handle_pwrite_owned(state, cli_handle, msg, reply);
            }
            VFS_BULK_SETUP => {
                crate::fileops::bulk::handle_bulk_setup_owned(state, cli_handle, msg, reply);
            }
            VFS_BULK_READ => {
                skip_reply =
                    crate::fileops::bulk::handle_bulk_read_owned(state, cli_handle, msg, reply);
            }
            VFS_BULK_PWRITE => {
                skip_reply =
                    crate::fileops::bulk::handle_bulk_pwrite_owned(state, cli_handle, msg, reply);
            }
            VFS_FSYNC => {
                skip_reply = dispatch_fsync(state, msg, reply, cli_handle);
            }
            VFS_GETXATTR => {
                skip_reply = dispatch_getxattr(state, msg, reply, cli_handle);
            }
            VFS_SETXATTR => {
                skip_reply = dispatch_setxattr(state, msg, reply, cli_handle);
            }
            VFS_REMOVEXATTR => {
                skip_reply = dispatch_removexattr(state, msg, reply, cli_handle);
            }
            VFS_LISTXATTR => {
                skip_reply = dispatch_listxattr(state, msg, reply, cli_handle);
            }
            VFS_SYSCTL => {
                dispatch_sysctl(msg, reply);
            }
            VFS_MOUNT => {
                skip_reply = crate::ipc::mount_ipc::handle_vfs_mount(state, msg, reply, badge);
            }
            VFS_UMOUNT => {
                crate::ipc::mount_ipc::handle_vfs_umount(state, msg, reply, badge);
            }
            VFS_PIVOT_ROOT => {
                crate::ipc::mount_ipc::handle_vfs_pivot_root(state, msg, reply, badge);
            }
            VFS_DUMP_PENDING => {
                (*reply).label = TRONA_OK;
            }
            _ => {
                let pers = client_personality(state, badge);
                let handled = if pers == PERS_WIN32 {
                    personality::win32::dispatch::dispatch(state, cli_handle, msg, reply)
                } else {
                    personality::posix::dispatch::dispatch(state, cli_handle, msg, reply)
                };
                if let Some(sr) = handled {
                    skip_reply = sr;
                } else {
                    (*reply).label = TRONA_INVALID_OPERATION;
                }
            }
        }

        skip_reply
    }
}

// =========================================================================
// Client registration (VfsState-based)
// =========================================================================

unsafe fn dispatch_client_register(
    state: &mut VfsState,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
    _badge: u64,
) {
    unsafe {
        let target_badge = (*msg).regs[0];
        let pers = (*msg).regs[1] as u8;
        if pers > 1 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let existing = lookup_client(state, target_badge).is_some();

        let cli_handle = match resolve_client(state, target_badge) {
            Some(h) => h,
            None => {
                (*reply).label = TRONA_OUT_OF_MEMORY;
                return;
            }
        };

        // Win32 CWD sidecar (per-client current drive + per-drive
        // CWD) lives outside `ClientState` — update the sidecar
        // separately so `server::types::ClientState` stays
        // personality-neutral.
        let mut win32_register_needed = false;
        if let Some(cli) = state.clients.get_mut(cli_handle) {
            if existing {
                // Exec-time re-registration must preserve inherited fd/cwd/ns
                // state; only the client personality changes.
                cli.personality = pers;
            } else {
                let badge = cli.badge;
                *cli = ClientState::zeroed();
                cli.badge = badge;
                cli.personality = pers;
                cli.mount_ns = state.global_ns;
                cli.cwd[0] = b'/';
            }
            if pers == PERS_WIN32 {
                win32_register_needed = true;
            }
        }
        if win32_register_needed {
            // Register (or reset) the Win32 per-client sidecar entry.
            // C: as the default current drive matches the legacy
            // `ClientState::win32_current_drive = 2` seed.
            let _ = state.win32_cwd.register(cli_handle);
            if let Some(entry) = state.win32_cwd.get_mut(cli_handle) {
                entry.current_drive = 2;
                entry.drive_cwd = [crate::vfs_core::identity::VnodeKey::INVALID; 26];
            }
        } else {
            // Non-Win32 personality re-registration: drop any stale
            // sidecar state so drive-letter paths from a prior Win32
            // exec don't surface for a now-POSIX client.
            state.win32_cwd.deregister(cli_handle);
        }
        (*reply).label = TRONA_OK;
    }
}

// =========================================================================
// Cross-client slot dup (neutral — personality-agnostic)
// =========================================================================

/// Handle `VFS_DUP_OBJECT_SLOTS_TO`. For each bit set in the 128-wide
/// bitmap, clone the caller's slot into the target client's slot at
/// the same index via the standard `slot_share` refcount path. Nothing
/// else is copied — `cwd`, `mount_ns`, credentials, and personality
/// remain whatever the target client was registered with (or the
/// defaults from `resolve_client` if the target is being auto-created
/// by this call).
///
/// Source is always the caller. A client may only dup slots it already
/// owns, so no `source_badge` field; any trusted-spawner variant ("dup
/// someone else's slots to a third client") would need a separate op
/// with its own authorization model and is out of scope here.
unsafe fn dispatch_dup_object_slots_to(
    state: &mut VfsState,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
    badge: u64,
) {
    unsafe {
        let target_badge = (*msg).regs[0];
        let bitmap_lo = (*msg).regs[1];
        let bitmap_hi = (*msg).regs[2];
        // `dst_offset` is subtracted from the source bit index to get the
        // target slot index. Default (0) preserves same-index semantics;
        // non-zero lets procmgr keep multiple stdio triples in its own
        // fd table (e.g. `/dev/console` at 0..=2 and `/dev/pts/0` at
        // 3..=5) and still land them in the child's 0/1/2.
        let dst_offset = (*msg).regs[3] as usize;

        if badge == 0 || target_badge == 0 || badge == target_badge {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let src_handle = match lookup_client(state, badge) {
            Some(h) => h,
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
        };

        let tgt_handle = match resolve_client(state, target_badge) {
            Some(h) => h,
            None => {
                (*reply).label = TRONA_OUT_OF_MEMORY;
                return;
            }
        };

        let tgt_badge_for_share = state
            .clients
            .get(tgt_handle)
            .map(|c| c.badge)
            .unwrap_or(target_badge);

        let mut word_idx = 0usize;
        for mut word in [bitmap_lo, bitmap_hi] {
            while word != 0 {
                let bit = word.trailing_zeros() as usize;
                let src_slot_idx = word_idx * 64 + bit;
                word &= !(1u64 << bit);
                if src_slot_idx >= MAX_CLIENT_OBJECTS {
                    continue;
                }
                // `dst_offset > src_slot_idx` would underflow the target
                // index; drop those bits silently so callers can pass a
                // bitmap slightly wider than the offset without caring.
                let Some(dst_slot_idx) = src_slot_idx.checked_sub(dst_offset) else {
                    continue;
                };
                if dst_slot_idx >= MAX_CLIENT_OBJECTS {
                    continue;
                }
                let (src_open_object, src_cloexec) = {
                    let cli = match state.clients.get(src_handle) {
                        Some(c) => c,
                        None => {
                            (*reply).label = TRONA_INVALID_ARGUMENT;
                            return;
                        }
                    };
                    let slot = cli.slots[src_slot_idx];
                    if slot.is_free() {
                        continue;
                    }
                    (slot.open_object, slot.cloexec)
                };
                let _ = state.slot_share(
                    tgt_handle,
                    dst_slot_idx,
                    src_open_object,
                    src_cloexec,
                    tgt_badge_for_share,
                );
            }
            word_idx += 1;
        }

        (*reply).label = TRONA_OK;
    }
}

unsafe fn close_provisioned_stdio_slot(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    fd: i32,
    badge: u64,
) {
    if fd < 0 || fd as usize >= MAX_CLIENT_OBJECTS {
        return;
    }
    let _ = state.close_open_object(cli_handle, fd as usize, badge);
}

fn tty_stdio_device(tty_dev: u64) -> Option<DeviceInfo> {
    if tty_dev == TTY_DEV_CONSOLE {
        return Some(DeviceInfo {
            dev_type: DEV_CONSOLE,
            pty_id: 0,
        });
    }
    if tty_dev < TTY_DEV_PTS_BASE {
        return None;
    }
    let pty_id = tty_dev - TTY_DEV_PTS_BASE;
    if pty_id > u32::MAX as u64 {
        return None;
    }
    Some(DeviceInfo {
        dev_type: DEV_PTY_SLAVE,
        pty_id: pty_id as u32,
    })
}

fn install_tty_stdio_slot(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    idx: usize,
    device: DeviceInfo,
) -> bool {
    let mut value = crate::server::open_object::OpenObject::zeroed();
    value.rights = OBJ_RIGHT_READ | OBJ_RIGHT_WRITE;
    value.flags = crate::server::client::object_open_flags(O_RDWR as u32);
    value.set_device(VnodeHandle::INVALID, 0, device.dev_type, device.pty_id);
    state.slot_install(cli_handle, idx, value, 0).is_some()
}

unsafe fn prepare_tty_stdio_device(device: DeviceInfo) -> bool {
    unsafe {
        if device.dev_type != DEV_PTY_SLAVE {
            return true;
        }

        let mut lookup_req = TronaMsg::zeroed();
        let mut lookup_reply = TronaMsg::zeroed();
        lookup_req.label = POSIX_TTYSRV_PTY_LOOKUP;
        lookup_req.length = 1;
        lookup_req.regs[0] = device.pty_id as u64;
        let err = trona_kernel::ipc::call_ctx(
            crate::ipc_ctx(),
            posix_ttysrv_ep(),
            &raw const lookup_req,
            &raw mut lookup_reply,
        );
        if err != 0 || lookup_reply.label != TRONA_OK {
            return false;
        }

        let mut open_req = TronaMsg::zeroed();
        let mut open_reply = TronaMsg::zeroed();
        open_req.label = POSIX_TTYSRV_PTY_OPEN_SLAVE;
        open_req.length = 2;
        open_req.regs[0] = device.pty_id as u64;
        open_req.regs[1] = lookup_reply.regs[0];
        let err = trona_kernel::ipc::call_ctx(
            crate::ipc_ctx(),
            posix_ttysrv_ep(),
            &raw const open_req,
            &raw mut open_reply,
        );
        err == 0 && open_reply.label == TRONA_OK
    }
}

unsafe fn dispatch_provision_tty_stdio_to(
    state: &mut VfsState,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
    _badge: u64,
) {
    unsafe {
        let target_badge = (*msg).regs[0];
        let tty_dev = (*msg).regs[1];
        if target_badge == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let tgt_handle = match resolve_client(state, target_badge) {
            Some(h) => h,
            None => {
                (*reply).label = TRONA_OUT_OF_MEMORY;
                return;
            }
        };

        let target_slots_busy = state
            .clients
            .get(tgt_handle)
            .map(|cli| {
                !(cli.slots[0].is_free() && cli.slots[1].is_free() && cli.slots[2].is_free())
            })
            .unwrap_or(true);
        if target_slots_busy {
            (*reply).label = TRONA_INVALID_OPERATION;
            return;
        }

        let Some(device) = tty_stdio_device(tty_dev) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        };
        if !prepare_tty_stdio_device(device) {
            (*reply).label = TRONA_INVALID_OPERATION;
            return;
        }
        if !install_tty_stdio_slot(state, tgt_handle, 0, device) {
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return;
        }
        if !prepare_tty_stdio_device(device) {
            close_provisioned_stdio_slot(state, tgt_handle, 0, target_badge);
            (*reply).label = TRONA_INVALID_OPERATION;
            return;
        }
        if !install_tty_stdio_slot(state, tgt_handle, 1, device) {
            close_provisioned_stdio_slot(state, tgt_handle, 0, target_badge);
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return;
        }
        if !prepare_tty_stdio_device(device) {
            close_provisioned_stdio_slot(state, tgt_handle, 1, target_badge);
            close_provisioned_stdio_slot(state, tgt_handle, 0, target_badge);
            (*reply).label = TRONA_INVALID_OPERATION;
            return;
        }
        if !install_tty_stdio_slot(state, tgt_handle, 2, device) {
            close_provisioned_stdio_slot(state, tgt_handle, 1, target_badge);
            close_provisioned_stdio_slot(state, tgt_handle, 0, target_badge);
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return;
        }

        (*reply).label = TRONA_OK;
        (*reply).length = 0;
    }
}

// =========================================================================
// Client exit (VfsState-based)
// =========================================================================

unsafe fn dispatch_client_exit(
    state: &mut VfsState,
    msg: *const TronaMsg,
    _reply: *mut TronaMsg,
    _badge: u64,
) {
    unsafe {
        let dead_badge = (*msg).regs[0];
        if let Some((slot, epoch)) = state.badge_map.lookup(dead_badge) {
            let h = ClientHandle::new(slot, epoch);
            let pers = state.clients.get(h).map(|cli| cli.personality).unwrap_or(0);
            let mount_ns = state
                .clients
                .get(h)
                .map(|cli| cli.mount_ns)
                .unwrap_or(crate::vfs_core::mount_ns::MountNsHandle::INVALID);

            // Centralised close sweep — each cleanup_client_objects
            // walks live slots and runs `close_open_object` per index.
            // The dead client's badge is threaded through so the SHM
            // arm of `release_backing` can still call `MM_SHM_UNMAP`
            // while the mapping is resolvable.
            if pers == PERS_WIN32 {
                personality::win32::dispatch::cleanup_client_objects(state, h, dead_badge);
            } else {
                personality::posix::dispatch::cleanup_client_objects(state, h, dead_badge);
            }

            clear_poll_waiters_for_badge(state, dead_badge);
            clear_pipe_waiters_for_badge(state, dead_badge);
            clear_socket_waiters_for_badge(state, dead_badge);
            crate::personality::posix::inet::callback::clear_pending_badge(state, dead_badge);
            crate::personality::posix::tty::pty::clear_pty_pending_badge(state, dead_badge);
            cancel_pending_ops_for_badge(state, dead_badge);
            state.release_reply_slots_for_badge(dead_badge);

            // Drop the cwd pin so the vnode can be reclaimed when no
            // other client references it.
            let cwd_vh = state
                .clients
                .get(h)
                .map(|c| c.cwd_ref.handle_hint())
                .unwrap_or(VnodeHandle::INVALID);
            if cwd_vh.is_valid() {
                if let Some(vn) = state.vnodes.get_mut(cwd_vh) {
                    vn.unpin();
                }
            }

            if mount_ns.is_valid() {
                let mut should_release = false;
                if let Some(ns) = state.mount_ns.get_mut(mount_ns) {
                    ns.refcount = ns.refcount.saturating_sub(1);
                    should_release = ns.refcount == 0 && mount_ns != state.global_ns;
                }
                if should_release {
                    let _ = state.mount_ns.release(mount_ns);
                }
            }

            // Drop any personality-sidecar state scoped to the
            // departing client. Currently: Win32 drive-CWD table.
            // Non-Win32 clients are not registered there; the call
            // is a no-op for them.
            state.win32_cwd.deregister(h);

            state.badge_map.remove(dead_badge);
            let _ = state.clients.release(h);
        }
    }
}

unsafe fn clear_poll_waiters_for_badge(state: &mut VfsState, dead_badge: u64) {
    unsafe {
        loop {
            let mut target =
                crate::arena::Handle::<crate::personality::posix::types::PollWaiter>::INVALID;
            state.poll_waiters.for_each_active(|handle, waiter| {
                if waiter.active != 0 && waiter.badge == dead_badge {
                    target = handle;
                    return false;
                }
                true
            });
            if !target.is_valid() {
                break;
            }
            let reply_slot = match state.poll_waiters.get(target) {
                Some(waiter) if waiter.active != 0 => waiter.op.reply_slot,
                _ => 0,
            };
            if reply_slot != 0 {
                crate::server::client::send_client_exit_error(state, reply_slot);
            }
            if let Some(waiter) = state.poll_waiters.get_mut(target) {
                waiter.active = 0;
                waiter.op.reply_slot = 0;
                waiter.deadline_ns = 0;
            }
            let _ = state.poll_waiters.release(target);
        }
    }
}

unsafe fn clear_pipe_waiters_for_badge(state: &mut VfsState, dead_badge: u64) {
    unsafe {
        // Collect evicted reply slots under the arena iteration, then
        // fire client-exit replies after the iteration releases its
        // borrow on `state.pipes` so we can reach `state` as `&mut`.
        const EVICT_CAP: usize = 128;
        let mut evicted: [OpCore; EVICT_CAP] = [OpCore::INVALID; EVICT_CAP];
        let mut evicted_count = 0usize;
        state.pipes.for_each_active(|handle, _| {
            let pipe = state.pipes.raw_ptr(handle).unwrap_or(core::ptr::null_mut());
            if pipe.is_null() {
                return true;
            }

            let recv_count = (*pipe).recv_waiter_count as usize;
            let mut keep = 0usize;
            for idx in 0..recv_count {
                let waiter = *(*pipe).recv_waiters.add(idx);
                if waiter.badge == dead_badge {
                    if waiter.op.reply_slot != 0 && evicted_count < EVICT_CAP {
                        evicted[evicted_count] = waiter.op;
                        evicted_count += 1;
                    }
                    continue;
                }
                if keep != idx {
                    *(*pipe).recv_waiters.add(keep) = waiter;
                }
                keep += 1;
            }
            while keep < recv_count {
                *(*pipe).recv_waiters.add(keep) =
                    crate::personality::posix::types::PipeReadWaiter::zeroed();
                keep += 1;
            }
            (*pipe).recv_waiter_count = keep as u8;

            let write_count = (*pipe).write_waiter_count as usize;
            let mut keep = 0usize;
            for idx in 0..write_count {
                let waiter = *(*pipe).write_waiters.add(idx);
                if waiter.badge == dead_badge {
                    if waiter.op.reply_slot != 0 && evicted_count < EVICT_CAP {
                        evicted[evicted_count] = waiter.op;
                        evicted_count += 1;
                    }
                    continue;
                }
                if keep != idx {
                    *(*pipe).write_waiters.add(keep) = waiter;
                }
                keep += 1;
            }
            while keep < write_count {
                *(*pipe).write_waiters.add(keep) =
                    crate::personality::posix::types::PipeWriteWaiter::zeroed();
                keep += 1;
            }
            (*pipe).write_waiter_count = keep as u8;
            true
        });
        let mut wake = TronaMsg::zeroed();
        wake.label = TRONA_INVALID_OPERATION;
        for i in 0..evicted_count {
            state.complete_op(evicted[i], OwnerPostOp::None, &raw const wake);
        }
    }
}

unsafe fn clear_socket_waiters_for_badge(state: &mut VfsState, dead_badge: u64) {
    unsafe {
        const EVICT_CAP: usize = 128;
        let mut evicted: [OpCore; EVICT_CAP] = [OpCore::INVALID; EVICT_CAP];
        let mut evicted_count = 0usize;
        state.sockets.for_each_active(|handle, _| {
            let sock = state
                .sockets
                .raw_ptr(handle)
                .unwrap_or(core::ptr::null_mut());
            if sock.is_null() {
                return true;
            }

            if (*sock).accept_badge == dead_badge {
                if (*sock).accept_op.reply_slot != 0 && evicted_count < EVICT_CAP {
                    evicted[evicted_count] = (*sock).accept_op;
                    evicted_count += 1;
                }
                (*sock).accept_op = OpCore::INVALID;
                (*sock).accept_badge = 0;
            }
            if (*sock).recv_badge == dead_badge {
                if (*sock).recv_op.reply_slot != 0 && evicted_count < EVICT_CAP {
                    evicted[evicted_count] = (*sock).recv_op;
                    evicted_count += 1;
                }
                (*sock).recv_op = OpCore::INVALID;
                (*sock).recv_badge = 0;
            }

            let pending_count = (*sock).pending_count as usize;
            let mut keep = 0usize;
            for idx in 0..pending_count {
                let pend = *(*sock).pending.add(idx);
                if pend.active != 0 && pend.client_badge == dead_badge {
                    if pend.op.reply_slot != 0 && evicted_count < EVICT_CAP {
                        evicted[evicted_count] = pend.op;
                        evicted_count += 1;
                    }
                    continue;
                }
                if keep != idx {
                    *(*sock).pending.add(keep) = pend;
                }
                keep += 1;
            }
            while keep < pending_count {
                *(*sock).pending.add(keep) =
                    crate::personality::posix::types::PendingConn::zeroed();
                keep += 1;
            }
            (*sock).pending_count = keep as u8;
            true
        });
        let mut wake = TronaMsg::zeroed();
        wake.label = TRONA_INVALID_OPERATION;
        for i in 0..evicted_count {
            state.complete_op(evicted[i], OwnerPostOp::None, &raw const wake);
        }
    }
}

unsafe fn cancel_pending_ops_for_badge(state: &mut VfsState, dead_badge: u64) {
    unsafe {
        loop {
            let mut target = crate::owner::pending::PendingOpHandle::INVALID;
            state.pending_ops.for_each_active(|handle, op| {
                if op.client_badge == dead_badge {
                    target = handle;
                    return false;
                }
                true
            });
            if !target.is_valid() {
                break;
            }
            state.cancel_pending_op(target);
        }
    }
}

unsafe fn dispatch_client_exec(
    state: &mut VfsState,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
    _badge: u64,
) {
    unsafe {
        let exec_badge = (*msg).regs[0];

        // POSIX exec semantics: slots flagged `FD_CLOEXEC` are closed
        // across the exec transition; every other slot survives so the
        // new image inherits them. We scan the full slot table here
        // because procmgr's exec path has no way to know which slots
        // hold which flag — the information lives inside the VFS's own
        // per-slot metadata. Close happens through the normal
        // `close_open_object` path so backing release / arena refcount
        // run unchanged.
        if let Some(cli_h) = state
            .badge_map
            .lookup(exec_badge)
            .and_then(|(slot, epoch)| {
                let h = crate::server::types::ClientHandle::new(slot, epoch);
                if state.clients.is_alive(h) {
                    Some(h)
                } else {
                    None
                }
            })
        {
            let mut cloexec_slots = [false; crate::server::types::MAX_CLIENT_OBJECTS];
            if let Some(cli) = state.clients.get(cli_h) {
                for i in 0..crate::server::types::MAX_CLIENT_OBJECTS {
                    if !cli.slots[i].is_free() && cli.slots[i].cloexec != 0 {
                        cloexec_slots[i] = true;
                    }
                }
            }
            for (i, &should_close) in cloexec_slots.iter().enumerate() {
                if should_close {
                    let _ = state.close_open_object(cli_h, i, exec_badge);
                }
            }
        }

        crate::personality::posix::tty::pty::clear_pty_pending_badge(state, exec_badge);
        (*reply).label = TRONA_OK;
        (*reply).length = 0;
    }
}

// =========================================================================
// Xattr dispatch (fd-based, using VfsState)
// =========================================================================

const XATTR_INLINE_MAX: usize = 30 * 8;

unsafe fn extract_inline(msg: *const TronaMsg, reg_start: usize, dst: *mut u8, len: usize) -> bool {
    let avail = (32 - reg_start) * 8;
    if len > avail {
        return false;
    }
    unsafe {
        let src = &(*msg).regs[reg_start] as *const u64 as *const u8;
        core::ptr::copy_nonoverlapping(src, dst, len);
    }
    true
}

unsafe fn pack_inline(reply: *mut TronaMsg, reg_start: usize, src: *const u8, len: usize) {
    unsafe {
        let dst = &raw mut (*reply).regs[reg_start] as *mut u8;
        core::ptr::copy_nonoverlapping(src, dst, len);
    }
}

/// Resolve fd to VnodeHandle and build a WorkerIoCtx.
fn fd_to_data_ctx(state: &mut VfsState, cli_handle: ClientHandle, fd: i32) -> Option<WorkerIoCtx> {
    let vh = resolve_fd(state, cli_handle, fd)?.vnode_handle();
    if !vh.is_valid() {
        return None;
    }
    build_data_ctx(state, vh)
}

/// Dispatch `VFS_FSYNC`. Returns `true` when the reply is deferred
/// via the worker dispatch path (owner's drain will send it later
/// from `worker_drain_completions`), `false` when the reply is
/// synchronous in `*reply`.
unsafe fn dispatch_fsync(
    state: &mut VfsState,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
    cli_handle: ClientHandle,
) -> bool {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        match fd_to_data_ctx(state, cli_handle, fd) {
            Some(data_ctx) => {
                if data_ctx.ops.is_null() {
                    (*reply).label = TRONA_OK;
                    return false;
                }

                // Route through the worker pool when a worker is live.
                // Fsync is the canary path that exercises end-to-end
                // `WorkerIoCtx → run_item_on_worker → DataResult →
                // worker_drain_completions → send_saved_reply` routing.
                if crate::owner::worker::worker_running() {
                    let op = match state.begin_worker_op_for_client(cli_handle, OpKind::Fsync) {
                        Ok(op) => op,
                        Err(err) => {
                            (*reply).label = err.to_trona();
                            return false;
                        }
                    };
                    // Snapshot the ops pointer before `data_ctx` moves
                    // into the worker item — the inline-fallback arm
                    // below may need it.
                    let ops_snapshot = data_ctx.ops;
                    let worker_ctx = data_ctx.into_worker_ctx();
                    let item = crate::owner::worker::WorkItem::Fsync {
                        op,
                        data_ctx: worker_ctx,
                    };
                    if let Some(rejected) = crate::owner::worker::try_submit(item) {
                        // Ring full — fall back to inline dispatch so
                        // the client unblocks. Recover the ctx from
                        // the rejected item, release the saved slot
                        // since we will reply synchronously.
                        let ctx = match rejected {
                            crate::owner::worker::WorkItem::Fsync { op, data_ctx } => {
                                state.cancel_worker_op(op);
                                data_ctx
                            }
                            _ => {
                                (*reply).label = TRONA_INVALID_OPERATION;
                                return false;
                            }
                        };
                        match ((*ops_snapshot).data.fsync)(&ctx) {
                            Ok(Ready(())) => (*reply).label = TRONA_OK,
                            Ok(Parked(_)) => (*reply).label = TRONA_BUSY,
                            Err(e) => (*reply).label = e.to_trona(),
                        }
                        return false;
                    }
                    // Worker accepted the item; its completion drive
                    // will emit the reply.
                    return true;
                }

                // No worker running — dispatch inline.
                let ops = data_ctx.ops;
                match ((*ops).data.fsync)(&data_ctx) {
                    Ok(Ready(())) => (*reply).label = TRONA_OK,
                    Ok(Parked(_)) => (*reply).label = TRONA_BUSY,
                    Err(e) => (*reply).label = e.to_trona(),
                }
                false
            }
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                false
            }
        }
    }
}

unsafe fn dispatch_getxattr(
    state: &mut VfsState,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
    cli_handle: ClientHandle,
) -> bool {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let data_ctx = match fd_to_data_ctx(state, cli_handle, fd) {
            Some(ctx) => ctx,
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return false;
            }
        };
        let name_len = (*msg).regs[1] as usize;
        if name_len == 0 || name_len > XATTR_INLINE_MAX {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }
        let mut name_buf = [0u8; XATTR_INLINE_MAX];
        if !extract_inline(msg, 2, name_buf.as_mut_ptr(), name_len) {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        let (vkey, ops, fs_id) = match state.vnodes.get(data_ctx.vnode_handle) {
            Some(v) => {
                if v.ops.is_null() {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    return false;
                }
                (v.vnode_key(), v.ops, v.fs_instance_id)
            }
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return false;
            }
        };

        let val_cap = 31 * 8;
        let mut val_buf = [0u8; 31 * 8];
        match ((*ops).data.getxattr)(
            &data_ctx,
            name_buf.as_ptr(),
            name_len as u8,
            val_buf.as_mut_ptr(),
            val_cap,
        ) {
            Ok(Ready(val_len)) => {
                (*reply).label = TRONA_OK;
                (*reply).regs[0] = val_len as u64;
                if val_len > 0 {
                    pack_inline(reply, 1, val_buf.as_ptr(), val_len);
                }
                (*reply).length = 1 + ((val_len as u64) + 7) / 8;
                false
            }
            Ok(Parked(handle)) => {
                if let Err(err) = state.arm_pending_fs_reply_for_client(
                    handle,
                    cli_handle,
                    crate::owner::resume::Resume::Fs(
                        crate::owner::resume::fs::FsResume::FillXattrGetReply {
                            client: cli_handle,
                            vkey,
                            fs_id,
                        },
                    ),
                ) {
                    (*reply).label = err.to_trona();
                    return false;
                }
                true
            }
            Err(crate::vfs_core::error::VfsError::WouldBlock) => {
                // Backend SHM held by another live xattr / readdir op.
                // Park on the session's waiter ring via
                // [`DeferArgs::XattrGet`]; drain path promotes us when
                // the prior owner's completion releases the SHM.
                let badge = state.clients.get(cli_handle).map(|c| c.badge).unwrap_or(0);
                let op = match state.begin_op_for_client(cli_handle, OpKind::DeferredBackend) {
                    Ok(op) => op,
                    Err(err) => {
                        (*reply).label = err.to_trona();
                        return false;
                    }
                };
                let mut name_payload = [0u8; crate::owner::pending::WALK_NAME_MAX];
                for i in 0..name_len {
                    name_payload[i] = name_buf[i];
                }
                let parked = state.session_defer_push(
                    fs_id,
                    crate::owner::DeferArgs::XattrGet {
                        vnode_data: data_ctx.data,
                        mount_data: data_ctx.mount_data,
                        client: cli_handle,
                        vkey,
                        name: name_payload,
                        name_len: name_len as u8,
                    },
                    badge,
                    op,
                );
                if parked {
                    true
                } else {
                    state.cancel_op(op);
                    (*reply).label = TRONA_BUSY;
                    false
                }
            }
            Err(e) => {
                (*reply).label = e.to_trona();
                false
            }
        }
    }
}

unsafe fn dispatch_setxattr(
    state: &mut VfsState,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
    cli_handle: ClientHandle,
) -> bool {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let data_ctx = match fd_to_data_ctx(state, cli_handle, fd) {
            Some(ctx) => ctx,
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return false;
            }
        };
        let name_len = (*msg).regs[1] as usize;
        let value_len = (*msg).regs[2] as usize;
        let flags = (*msg).regs[3] as u32;
        let total = name_len + value_len;
        if name_len == 0 || total > (28 * 8) {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }
        let mut buf = [0u8; 28 * 8];
        if !extract_inline(msg, 4, buf.as_mut_ptr(), total) {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        let (vkey, ops) = match state.vnodes.get(data_ctx.vnode_handle) {
            Some(v) => {
                if v.ops.is_null() {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    return false;
                }
                (v.vnode_key(), v.ops)
            }
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return false;
            }
        };

        let fs_id = match state.vnodes.get(data_ctx.vnode_handle) {
            Some(v) => v.fs_instance_id,
            None => crate::vfs_core::identity::FsInstanceId::INVALID,
        };

        match ((*ops).data.setxattr)(
            &data_ctx,
            buf.as_ptr(),
            name_len as u8,
            buf.as_ptr().add(name_len),
            value_len,
            flags,
        ) {
            Ok(Ready(())) => {
                (*reply).label = TRONA_OK;
                false
            }
            Ok(Parked(handle)) => stamp_ack_mutation_parked(state, cli_handle, vkey, handle, reply),
            Err(crate::vfs_core::error::VfsError::WouldBlock) => {
                let badge = state.clients.get(cli_handle).map(|c| c.badge).unwrap_or(0);
                let op = match state.begin_op_for_client(cli_handle, OpKind::DeferredBackend) {
                    Ok(op) => op,
                    Err(err) => {
                        (*reply).label = err.to_trona();
                        return false;
                    }
                };
                let mut name_payload = [0u8; crate::owner::pending::WALK_NAME_MAX];
                let mut value_payload = [0u8; crate::owner::pending::WALK_NAME_MAX];
                for i in 0..name_len {
                    name_payload[i] = buf[i];
                }
                for i in 0..value_len {
                    value_payload[i] = buf[name_len + i];
                }
                let parked = state.session_defer_push(
                    fs_id,
                    crate::owner::DeferArgs::XattrSet {
                        vnode_data: data_ctx.data,
                        mount_data: data_ctx.mount_data,
                        client: cli_handle,
                        vkey,
                        name: name_payload,
                        value: value_payload,
                        name_len: name_len as u8,
                        value_len: value_len as u16,
                        flags,
                    },
                    badge,
                    op,
                );
                if parked {
                    true
                } else {
                    state.cancel_op(op);
                    (*reply).label = TRONA_BUSY;
                    false
                }
            }
            Err(e) => {
                (*reply).label = e.to_trona();
                false
            }
        }
    }
}

/// Common Parked finaliser for simple-mutation fd-dispatched ops
/// (`setxattr`, `removexattr`). Allocates a reply slot, saves the
/// caller, stamps `FsResume::AckMutation`, and returns `true` when
/// the reply is deferred successfully.
unsafe fn stamp_ack_mutation_parked(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    vkey: crate::vfs_core::identity::VnodeKey,
    handle: crate::owner::pending::PendingOpHandle,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        if let Err(err) = state.arm_pending_fs_reply_for_client(
            handle,
            cli_handle,
            crate::owner::resume::Resume::Fs(crate::owner::resume::fs::FsResume::AckMutation {
                client: cli_handle,
                vkey,
            }),
        ) {
            (*reply).label = err.to_trona();
            return false;
        }
        true
    }
}

unsafe fn dispatch_listxattr(
    state: &mut VfsState,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
    cli_handle: ClientHandle,
) -> bool {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let data_ctx = match fd_to_data_ctx(state, cli_handle, fd) {
            Some(ctx) => ctx,
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return false;
            }
        };

        let (vkey, ops, fs_id) = match state.vnodes.get(data_ctx.vnode_handle) {
            Some(v) => {
                if v.ops.is_null() {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    return false;
                }
                (v.vnode_key(), v.ops, v.fs_instance_id)
            }
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return false;
            }
        };

        let requested = (*msg).regs[1] as usize;
        let buf_cap = 31 * 8;
        let effective = if requested == 0 {
            0
        } else {
            buf_cap.min(requested)
        };
        let mut buf = [0u8; 31 * 8];

        match ((*ops).data.listxattr)(
            &data_ctx,
            if effective == 0 {
                core::ptr::null_mut()
            } else {
                buf.as_mut_ptr()
            },
            effective,
        ) {
            Ok(Ready(actual_len)) => {
                (*reply).label = TRONA_OK;
                (*reply).regs[0] = actual_len as u64;
                if actual_len > 0 && effective > 0 {
                    let copy_len = actual_len.min(effective);
                    pack_inline(reply, 1, buf.as_ptr(), copy_len);
                }
                (*reply).length = 1 + ((actual_len.min(effective) as u64) + 7) / 8;
                false
            }
            Ok(Parked(handle)) => {
                if let Err(err) = state.arm_pending_fs_reply_for_client(
                    handle,
                    cli_handle,
                    crate::owner::resume::Resume::Fs(
                        crate::owner::resume::fs::FsResume::FillListXattrReply {
                            client: cli_handle,
                            vkey,
                            fs_id,
                        },
                    ),
                ) {
                    (*reply).label = err.to_trona();
                    return false;
                }
                true
            }
            Err(crate::vfs_core::error::VfsError::WouldBlock) => {
                let badge = state.clients.get(cli_handle).map(|c| c.badge).unwrap_or(0);
                let op = match state.begin_op_for_client(cli_handle, OpKind::DeferredBackend) {
                    Ok(op) => op,
                    Err(err) => {
                        (*reply).label = err.to_trona();
                        return false;
                    }
                };
                let parked = state.session_defer_push(
                    fs_id,
                    crate::owner::DeferArgs::XattrList {
                        vnode_data: data_ctx.data,
                        mount_data: data_ctx.mount_data,
                        client: cli_handle,
                        vkey,
                    },
                    badge,
                    op,
                );
                if parked {
                    true
                } else {
                    state.cancel_op(op);
                    (*reply).label = TRONA_BUSY;
                    false
                }
            }
            Err(e) => {
                (*reply).label = e.to_trona();
                false
            }
        }
    }
}

unsafe fn dispatch_removexattr(
    state: &mut VfsState,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
    cli_handle: ClientHandle,
) -> bool {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let data_ctx = match fd_to_data_ctx(state, cli_handle, fd) {
            Some(ctx) => ctx,
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return false;
            }
        };
        let name_len = (*msg).regs[1] as usize;
        if name_len == 0 || name_len > XATTR_INLINE_MAX {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }
        let mut name_buf = [0u8; XATTR_INLINE_MAX];
        if !extract_inline(msg, 2, name_buf.as_mut_ptr(), name_len) {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }
        let (vkey, ops) = match state.vnodes.get(data_ctx.vnode_handle) {
            Some(v) => {
                if v.ops.is_null() {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    return false;
                }
                (v.vnode_key(), v.ops)
            }
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return false;
            }
        };

        match ((*ops).data.removexattr)(&data_ctx, name_buf.as_ptr(), name_len as u8) {
            Ok(Ready(())) => {
                (*reply).label = TRONA_OK;
                false
            }
            Ok(Parked(handle)) => stamp_ack_mutation_parked(state, cli_handle, vkey, handle, reply),
            Err(e) => {
                (*reply).label = e.to_trona();
                false
            }
        }
    }
}

// =========================================================================
// Sysctl dispatch — unchanged logic, no VfsState dependency
// =========================================================================

const SYSCTL_OP_GET: u64 = 0;
const SYSCTL_OP_SET: u64 = 1;

unsafe fn dispatch_sysctl(msg: *const TronaMsg, reply: *mut TronaMsg) {
    // Sysctl logic is self-contained (MIB tree walk, no VFS state).
    // Kept identical to the old implementation.
    unsafe {
        use crate::fs::sysctlfs::tree;
        let op = (*msg).regs[0];
        match op {
            SYSCTL_OP_GET => {
                let path_len = (*msg).regs[1] as usize;
                if path_len == 0 || path_len > 30 * 8 {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    return;
                }
                let path_ptr = &(*msg).regs[2] as *const u64 as *const u8;
                let root = &raw const tree::MIB_ROOT;
                let mut current = &*root;
                let mut pos = 0usize;
                let mut leaf: Option<&tree::SysctlLeaf> = None;
                while pos < path_len {
                    let comp_start = pos;
                    while pos < path_len && *path_ptr.add(pos) != b'.' {
                        pos += 1;
                    }
                    let comp =
                        core::slice::from_raw_parts(path_ptr.add(comp_start), pos - comp_start);
                    if pos < path_len {
                        pos += 1;
                    }
                    let is_last = pos >= path_len;
                    if is_last {
                        if let Some(l) = current.find_leaf(comp) {
                            leaf = Some(l);
                            break;
                        }
                    }
                    match current.find_child_node(comp) {
                        Some(child) => current = child,
                        None => {
                            (*reply).label = TRONA_NOT_FOUND;
                            return;
                        }
                    }
                }
                match leaf {
                    Some(l) => {
                        if let Some(read_fn) = l.read_fn {
                            let mut buf = [0u8; 31 * 8];
                            let val_len = read_fn(buf.as_mut_ptr(), 31 * 8);
                            (*reply).label = TRONA_OK;
                            (*reply).regs[0] = val_len as u64;
                            if val_len > 0 {
                                let dst = &raw mut (*reply).regs[1] as *mut u8;
                                core::ptr::copy_nonoverlapping(buf.as_ptr(), dst, val_len);
                            }
                            (*reply).length = 1 + ((val_len as u64) + 7) / 8;
                        } else {
                            (*reply).label = TRONA_NOT_SUPPORTED;
                        }
                    }
                    None => {
                        (*reply).label = TRONA_NOT_FOUND;
                    }
                }
            }
            SYSCTL_OP_SET => {
                let packed = (*msg).regs[1];
                let path_len = (packed >> 32) as usize;
                let value_len = (packed & 0xFFFF_FFFF) as usize;
                let total = path_len + value_len;
                if path_len == 0 || total > 30 * 8 {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    return;
                }
                let data_ptr = &(*msg).regs[2] as *const u64 as *const u8;
                let root = &raw const tree::MIB_ROOT;
                let mut current = &*root;
                let mut pos = 0usize;
                let mut leaf: Option<&tree::SysctlLeaf> = None;
                while pos < path_len {
                    let comp_start = pos;
                    while pos < path_len && *data_ptr.add(pos) != b'.' {
                        pos += 1;
                    }
                    let comp =
                        core::slice::from_raw_parts(data_ptr.add(comp_start), pos - comp_start);
                    if pos < path_len {
                        pos += 1;
                    }
                    let is_last = pos >= path_len;
                    if is_last {
                        if let Some(l) = current.find_leaf(comp) {
                            leaf = Some(l);
                            break;
                        }
                    }
                    match current.find_child_node(comp) {
                        Some(child) => current = child,
                        None => {
                            (*reply).label = TRONA_NOT_FOUND;
                            return;
                        }
                    }
                }
                match leaf {
                    Some(l) => {
                        if (l.flags & tree::CTLFLAG_WR) == 0 {
                            (*reply).label = TRONA_INSUFFICIENT_RIGHTS;
                            return;
                        }
                        if let Some(write_fn) = l.write_fn {
                            let value_ptr = data_ptr.add(path_len);
                            let rc = write_fn(value_ptr, value_len);
                            (*reply).label = if rc == 0 {
                                TRONA_OK
                            } else {
                                TRONA_INVALID_ARGUMENT
                            };
                        } else {
                            (*reply).label = TRONA_NOT_SUPPORTED;
                        }
                    }
                    None => {
                        (*reply).label = TRONA_NOT_FOUND;
                    }
                }
            }
            _ => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
            }
        }
    }
}
