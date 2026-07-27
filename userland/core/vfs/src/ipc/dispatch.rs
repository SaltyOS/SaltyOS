// SPDX-License-Identifier: GPL-2.0-only
//
//! `VfsDispatcher` — owner-reactor `EqDispatcher` impl.
//!
//! The reactor delivers four cookie kinds (frontend / backend /
//! pager / timer); the dispatcher decodes the cookie, validates
//! generation, and routes to the matching handler module. The
//! reactor itself owns no `VfsState` reference — it stores a raw
//! pointer plus the per-iteration `IpcContext` and re-borrows on
//! every dispatch.
//!
//! Reply lifecycle (frontend path):
//! 1. Reactor's `mp_read_ctx` returns a request from the static
//!    frontend MessagePipe receive endpoint.
//! 2. Dispatcher wraps that endpoint in a `ReplyLease`-shaped
//!    single-consume guard. The name is historical; the stored cap is
//!    the MessagePipe endpoint to reply on with `reply-marked MP_WRITE`.
//! 3. The frontend handler either consumes the lease with a
//!    synchronous reply or parks it on a `PendingOp` for an async
//!    completion router.
//!
//! Single-consume invariant: every inbound frontend request gets
//! exactly one terminal — either `reply_send` (success / error
//! reply) or `reply_drop` (cancel / handler did not park).

use trona_kernel::core_types::{Cap, IpcContext, TronaMsg};
use trona_server::event_loop::EqDispatcher;
use trona_server::{MpReplyTarget, ReplyLease};

use crate::ipc::cookie::{
    KIND_BACKEND_SESSION, KIND_FRONTEND, KIND_FRONTEND_CLIENT, KIND_INIT_REPLY,
    KIND_MMSRV_WRITEBACK, KIND_MMSRV_WRITEBACK_DONE, KIND_PAGER, KIND_TIMER, decode_cookie,
    encode_cookie,
};
use crate::owner::VfsState;
use crate::server::types::ClientHandle;

/// Holds raw pointers back into the owner's stack frame. Both
/// pointers stay valid for the dispatcher's lifetime since the
/// run loop keeps the corresponding storage alive across
/// iterations.
pub(crate) struct VfsDispatcher {
    state: *mut VfsState,
}

impl VfsDispatcher {
    pub(crate) fn new(state: *mut VfsState, _ctx: *mut IpcContext) -> Self {
        Self { state }
    }

    fn state_mut(&mut self) -> &mut VfsState {
        unsafe { &mut *self.state }
    }

    fn state_ref(&self) -> &VfsState {
        unsafe { &*self.state }
    }
}

impl EqDispatcher for VfsDispatcher {
    fn resolve_mp_recv(&self, cookie: u64) -> Option<Cap> {
        let (kind, slot, epoch) = decode_cookie(cookie);
        let st = self.state_ref();
        match kind {
            KIND_FRONTEND => {
                // Frontend cookie is the static service-EP receive
                // — single, never recycled, generation field is
                // unused. Skip the epoch check. This master endpoint
                // accepts only VFS_BIND_CLIENT_SELF; all normal VFS
                // RPCs flow through per-client request MPs.
                if st.service_ep_recv != 0 {
                    Some(st.service_ep_recv)
                } else {
                    None
                }
            }
            KIND_FRONTEND_CLIENT => {
                let handle = ClientHandle::new(slot, epoch);
                let client = st.clients.get(handle)?;
                let recv_addr = client.request_mp_recv_addr();
                if client.is_active() && recv_addr != 0 {
                    Some(recv_addr)
                } else {
                    None
                }
            }
            KIND_BACKEND_SESSION => {
                // Per-mount-instance backend session callback. The
                // session arena slot may be recycled across
                // remount cycles; the cookie's `epoch` (lower 32 bit
                // of `BackendSessionSlot.live_gen` at arm time)
                // must match the slot's current `live_gen` or the
                // record is from a torn-down incarnation.
                let s = st.backend_sessions.handle_from_slot(slot)?;
                let entry = st.backend_sessions.get(s)?;
                if entry.is_empty() {
                    return None;
                }
                if entry.live_gen != epoch {
                    return None;
                }
                Some(entry.callback_recv.as_raw())
            }
            KIND_INIT_REPLY => {
                // init reply channel — replies arrive on the recv side
                // of the `init_ep` connection VFS also sends queries on.
                if st.init_ep_cap != 0 {
                    Some(st.init_ep_cap)
                } else {
                    None
                }
            }
            KIND_MMSRV_WRITEBACK => st
                .mmsrv_writeback_mp
                .as_ref()
                .and_then(|mp| mp.recv())
                .map(|recv| recv.addr())
                .filter(|addr| *addr != 0),
            KIND_MMSRV_WRITEBACK_DONE => None,
            KIND_PAGER => {
                // Pager events arrive as `EVENT_TYPE_PAGER_REQUEST`,
                // not `EVENT_TYPE_STATE` — the kernel pushes the
                // record straight into the EQ without a Watch +
                // MP_READ round-trip. Returning `None` here drops
                // any stray STATE record carrying this cookie kind
                // (defence against legacy senders); the real
                // handling lives in `handle_pager_request`.
                let _ = (slot, epoch);
                None
            }
            KIND_TIMER => None,
            _ => None,
        }
    }

    fn dispatch_state(
        &mut self,
        cookie: u64,
        msg: &TronaMsg,
        meta: trona_server::event_loop::MpReadMeta,
    ) -> i32 {
        let badge = meta.badge;
        let (kind, slot, epoch) = decode_cookie(cookie);
        let state = self.state_mut();
        match kind {
            KIND_FRONTEND => unsafe { dispatch_frontend_master_record(state, badge, msg) },
            KIND_FRONTEND_CLIENT => unsafe {
                dispatch_frontend_client_record(state, slot, epoch, msg)
            },
            KIND_BACKEND_SESSION => unsafe { dispatch_backend(state, slot, msg) },
            KIND_INIT_REPLY => {
                // init reply, demuxed by the kernel `mp_txid` (init
                // echoes it and sets `MP_FLAG_REPLY`). Require both so a
                // stray non-reply record on this channel is dropped, not
                // mis-dispatched as a request.
                if meta.flags & (uapi::KERNITE_MP_FLAG_REPLY as u64) != 0 && meta.txid != 0 {
                    crate::owner::init_rpc::init_reply_complete(state, meta.txid, msg);
                }
                0
            }
            KIND_MMSRV_WRITEBACK => {
                let _ = badge;
                unsafe { crate::owner::pager_rpc::handle_mmsrv_writeback_request(state, msg) };
                0
            }
            KIND_MMSRV_WRITEBACK_DONE => {
                crate::owner::pager_rpc::handle_mmsrv_writeback_done_writable(state);
                0
            }
            // KIND_PAGER cannot reach `dispatch_state` — pager events
            // are `EVENT_TYPE_PAGER_REQUEST`, dispatched through
            // `handle_pager_request` instead.
            KIND_PAGER | KIND_TIMER => 0,
            _ => 0,
        }
    }

    fn handle_mp_read_error(
        &mut self,
        _cookie: u64,
        err: i32,
        _state_set: u64,
        _status: u32,
    ) -> i32 {
        err
    }

    fn prepare_mp_read(&mut self, cookie: u64) -> bool {
        let (kind, slot, epoch) = decode_cookie(cookie);
        match kind {
            KIND_FRONTEND | KIND_FRONTEND_CLIENT | KIND_BACKEND_SESSION | KIND_INIT_REPLY
            | KIND_MMSRV_WRITEBACK => {
                if kind == KIND_FRONTEND_CLIENT && !self.frontend_client_ready(slot, epoch) {
                    return false;
                }
                if kind == KIND_BACKEND_SESSION && !self.backend_session_ready(slot) {
                    return false;
                }
                let scratch = self.state_ref().recv_scratch_slot;
                if scratch == 0 {
                    return false;
                }
                let window = trona_server::recv_slot::FixedRecvWindow::new(
                    scratch,
                    1,
                    trona_runtime::core::slot_alloc::slot_invoke_depth_cb,
                );
                unsafe {
                    window.arm(
                        trona_posix::tls::current_ipc_ctx(),
                        uapi::KERNITE_CAP_SELF_CSPACE as u64,
                    );
                }
                true
            }
            KIND_MMSRV_WRITEBACK_DONE | KIND_PAGER | KIND_TIMER => false,
            _ => false,
        }
    }

    fn rearm_state_source(&mut self, cookie: u64) -> i32 {
        let (kind, slot, epoch) = decode_cookie(cookie);
        let state = self.state_mut();
        match kind {
            KIND_FRONTEND => {
                rearm_watch(
                    state.frontend_watch_cap.as_raw(),
                    state.service_ep_recv,
                    state.owner_eq.as_raw(),
                    state.frontend_cookie,
                );
            }
            KIND_FRONTEND_CLIENT => {
                rearm_frontend_client_watch(state, slot, epoch);
            }
            KIND_BACKEND_SESSION => {
                rearm_backend_watch(state, slot);
            }
            KIND_INIT_REPLY => {
                // One-shot + level Watch: re-arm so the next init reply
                // re-fires `STATE_READABLE` on `init_ep`'s recv side.
                rearm_watch(
                    state.init_watch_cap.as_raw(),
                    state.init_ep_cap,
                    state.owner_eq.as_raw(),
                    state.init_cookie,
                );
            }
            KIND_MMSRV_WRITEBACK => {
                rearm_mmsrv_writeback_watch(state);
            }
            KIND_MMSRV_WRITEBACK_DONE | KIND_PAGER | KIND_TIMER => {}
            _ => {}
        }
        0
    }

    fn handle_overflow(&mut self, dropped: u64) {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[VFS] owner EQ overflow dropped=");
            _lb.hex(dropped);
            _lb.str(b"\n");
        });
    }

    fn handle_timer(&mut self, cookie: u64) {
        crate::owner::timer::handle_owner_timer(self.state_mut(), cookie);
    }

    fn handle_pager_request(&mut self, record: &uapi::kernite_event_record) -> i32 {
        // The kernel published a file-backed page-fault event onto
        // `state.owner_eq` because a client-process MO bound to
        // `state.pager_cap` faulted on an absent page. The handler
        // resolves the kernel-supplied `mo_id` (carried in
        // `record.object_id`) back to its vnode binding, fires a
        // backend READ, and replies via `PAGER_SUPPLY_COPY` /
        // `PAGER_FAIL` once the backend round-trip lands.
        //
        // Cookie sanity-check first — if the record did not come
        // from our own `PAGER_BIND_EQ` invocation, drop. The kernel
        // would only emit one if a stale pager binding is still in
        // flight; the conservative response is to ignore.
        let st = self.state_ref();
        if record.cookie != st.pager_cookie {
            return 0;
        }
        let state = self.state_mut();
        unsafe { crate::owner::pager_rpc::handle_pager_request_event(state, record) }
    }
}

impl VfsDispatcher {
    fn frontend_client_ready(&self, slot: u32, epoch: u32) -> bool {
        let handle = ClientHandle::new(slot, epoch);
        self.state_ref()
            .clients
            .get(handle)
            .map(|c| c.is_active() && c.request_mp_recv_addr() != 0)
            .unwrap_or(false)
    }

    fn backend_session_ready(&self, slot: u32) -> bool {
        let Some(handle) = self.state_ref().backend_sessions.handle_from_slot(slot) else {
            return false;
        };
        let Some(entry) = self.state_ref().backend_sessions.get(handle) else {
            return false;
        };
        !entry.is_empty()
    }
}

fn rearm_watch(watch_cap: u64, watched_cap: u64, eq_cap: u64, cookie: u64) {
    if watch_cap == 0 || watched_cap == 0 || eq_cap == 0 {
        return;
    }
    let _ = trona_kernel::invoke::watch_register(
        trona_runtime::core::slot_alloc::resolved_cap_ref(watch_cap),
        trona_runtime::core::slot_alloc::resolved_cap_ref(watched_cap),
        trona_runtime::core::slot_alloc::resolved_cap_ref(eq_cap),
        uapi::KERNITE_STATE_READABLE as u64,
        cookie,
    );
}

fn rearm_backend_watch(state: &VfsState, slot: u32) {
    let Some(handle) = state.backend_sessions.handle_from_slot(slot) else {
        return;
    };
    let Some(entry) = state.backend_sessions.get(handle) else {
        return;
    };
    if entry.is_empty() {
        return;
    }
    rearm_watch(
        entry.callback_watch.as_raw(),
        entry.callback_recv.as_raw(),
        state.owner_eq.as_raw(),
        entry.callback_cookie,
    );
}

fn rearm_frontend_client_watch(state: &VfsState, slot: u32, epoch: u32) {
    let handle = ClientHandle::new(slot, epoch);
    let Some(client) = state.clients.get(handle) else {
        return;
    };
    let recv_addr = client.request_mp_recv_addr();
    if !client.is_active() || recv_addr == 0 {
        return;
    }
    rearm_watch(
        client.watch_cap_addr(),
        recv_addr,
        state.owner_eq.as_raw(),
        client.watch_cookie,
    );
}

fn rearm_mmsrv_writeback_watch(state: &VfsState) {
    let recv_addr = state
        .mmsrv_writeback_mp
        .as_ref()
        .and_then(|mp| mp.recv())
        .map(|recv| recv.addr())
        .unwrap_or(0);
    let watch_addr = state
        .mmsrv_writeback_watch_cap
        .as_ref()
        .and_then(|watch| watch.as_raw())
        .unwrap_or(0);
    rearm_watch(
        watch_addr,
        recv_addr,
        state.owner_eq.as_raw(),
        state.mmsrv_writeback_cookie,
    );
}

// =========================================================================
// Frontend dispatch — every inbound client RPC.
// =========================================================================

fn current_reply_target(reply_mp: u64) -> MpReplyTarget {
    unsafe {
        let ctx = trona_posix::tls::current_ipc_ctx();
        if ctx.is_null() || (*ctx).ipc_buffer.is_null() {
            MpReplyTarget::none()
        } else {
            MpReplyTarget::from_ipc_buffer((*ctx).ipc_buffer as *const _, reply_mp)
        }
    }
}

unsafe fn dispatch_frontend_master_record(state: &mut VfsState, badge: u64, msg: &TronaMsg) -> i32 {
    // Supervisor admin tier: init invokes a per-client (or per-server ROOT)
    // control cap — a badged send to this master EP. The control-cap badge
    // (tag 0xC) both authorizes the verb and names the target client; a
    // normal client's badge (its own client_id, never the 0xC tag) can never
    // reach this branch, and the lazy bind below never sees a control badge.
    if trona_protocol::control::tag_matches(badge) {
        return unsafe { dispatch_admin(state, badge, msg) };
    }
    // The master service EP accepts exactly one label: VFS_BIND_CLIENT_SELF,
    // the second step of a client's lazy `vfs_ep()` resolution. Every normal
    // VFS RPC flows through the per-client request MP (KIND_FRONTEND_CLIENT),
    // never here. Intercept the bind before the personality dispatcher, which
    // only routes the 0x500-0x57F / 0x5C0-0x5DF ranges and would reject 0x5E0
    // as NotSup — leaving the client unable to resolve vfs_ep at all.
    if msg.label == trona_protocol::vfs::public::VFS_BIND_CLIENT_SELF {
        return unsafe { handle_bind_client_self(state, badge) };
    }
    unsafe { dispatch_frontend_record(state, badge, msg) }
}

/// `VFS_BIND_CLIENT_SELF` — establish (or re-confirm) a client's per-request
/// MessagePipe and hand back its send side.
///
/// A client reaches the badged master service EP once, during lazy
/// `vfs_ep()` resolution. On first bind vfs allocates the client's request
/// MessagePipe, arms an owner-EQ Watch over the receive side
/// (`KIND_FRONTEND_CLIENT` cookie carrying the `ClientState` handle), and
/// stores both sides. The reply carries a *transient copy* of the retained
/// send side: the MP transfer moves the staged cap, so vfs keeps the source
/// to satisfy any later re-bind (e.g. a post-fork re-resolve) without
/// allocating a second pipe. The reply label is `KERNITE_OK` — the lazy
/// resolver keys on exactly that.
unsafe fn handle_bind_client_self(state: &mut VfsState, badge: u64) -> i32 {
    let reply_mp = state.service_ep_recv;
    if reply_mp == 0 {
        return uapi::KERNITE_ERR_INVALID_OPERATION as i32;
    }
    let reply_lease = ReplyLease::saved_target(current_reply_target(reply_mp), badge);

    let client_id = (badge & 0xFFFF_FFFF) as u32;
    // Bind-adoption: if init pre-created a control client for this client_id
    // (the spawn / fork path), adopt that entry — already carrying its control
    // epoch and any cloned FD table — instead of allocating a fresh one;
    // otherwise lazily ensure a first-bind client.
    let (handle, adopted) =
        match crate::owner::clients::adopt_precreated_by_client_id(state, badge, client_id) {
            Some(h) => (h, true),
            None => match crate::owner::clients::ensure_client(state, badge, client_id) {
                Some(h) => (h, false),
                None => {
                    crate::personality::wire::send_error_reply(
                        reply_lease,
                        crate::core::error::VfsError::Io,
                    );
                    return 0;
                }
            },
        };

    let needs_mp = state
        .clients
        .get(handle)
        .map(|c| c.request_mp_recv_addr() == 0)
        .unwrap_or(true);
    if needs_mp && !bind_alloc_request_mp(state, handle) {
        if adopted {
            // The control client was pre-created by init; a transient MP-alloc
            // failure must NOT tear it down (that would bump the epoch and
            // invalidate init's control cap). Un-adopt instead — drop the badge
            // stamp + map entry so the entry stays pre-created and a later
            // re-bind re-adopts it.
            state.badge_map.remove(badge);
            if let Some(c) = state.clients.get_mut(handle) {
                c.client_badge = 0;
            }
        } else {
            // Roll back the freshly-ensured lazy ClientState (its MP/watch
            // never got allocated) so it doesn't linger active-but-unusable.
            crate::owner::clients::remove_client(state, handle);
        }
        crate::personality::wire::send_error_reply(
            reply_lease,
            crate::core::error::VfsError::NoMem,
        );
        return 0;
    }

    let send_src = match state.clients.get(handle) {
        Some(c) if c.request_mp_send_addr() != 0 => c.request_mp_send_addr(),
        _ => {
            crate::personality::wire::send_error_reply(
                reply_lease,
                crate::core::error::VfsError::Io,
            );
            return 0;
        }
    };
    let Some(cap) = trona_runtime::core::slot_alloc::dup_for_transfer(
        trona_runtime::core::slot_alloc::resolved_cap_ref(send_src),
    ) else {
        crate::personality::wire::send_error_reply(
            reply_lease,
            crate::core::error::VfsError::NoMem,
        );
        return 0;
    };

    let mut out = TronaMsg::zeroed();
    out.label = uapi::KERNITE_OK as u64;
    out.length = 0;
    // `cap` is a disposable copy of the retained request-MP send cap; the
    // reply moves it out and the TransferCap drop reclaims the temp slot.
    crate::owner::op::reply_send_with_cap(reply_lease, &out, cap);
    0
}

/// Allocate a client's request MessagePipe and arm its owner-EQ Watch.
/// Stores the `OwnedMpPair` and `OwnedRecordedCap` (Watch) into the
/// `ClientState`. On any failure all partial allocations are dropped
/// automatically and `false` is returned.
fn bind_alloc_request_mp(state: &mut VfsState, handle: ClientHandle) -> bool {
    let mut mp = match trona_runtime::core::slot_alloc::alloc_mp_pair_owned() {
        Ok(p) => p,
        Err(_) => return false,
    };
    let watch = match trona_runtime::core::slot_alloc::alloc_object_owned(
        uapi::KERNITE_OBJ_WATCH as u64,
        0,
    ) {
        Ok(w) => w,
        Err(_) => {
            // `mp` drops here, releasing both side caps + rsrcsrv record.
            let _ = mp.release_in_place();
            return false;
        }
    };
    let cookie = encode_cookie(KIND_FRONTEND_CLIENT, handle.slot(), handle.epoch());
    let recv_addr = mp.recv().map(|r| r.addr()).unwrap_or(0);
    let watch_addr = watch.borrow().map(|r| r.addr()).unwrap_or(0);
    let err = trona_kernel::invoke::watch_register(
        trona_runtime::core::slot_alloc::resolved_cap_ref(watch_addr),
        trona_runtime::core::slot_alloc::resolved_cap_ref(recv_addr),
        state.owner_eq.borrow(),
        uapi::KERNITE_STATE_READABLE as u64,
        cookie,
    );
    if err != 0 {
        let _ = trona_kernel::invoke::watch_cancel(
            trona_runtime::core::slot_alloc::resolved_cap_ref(watch_addr),
        );
        let _ = watch.release();
        let _ = mp.release_in_place();
        return false;
    }
    let Some(client) = state.clients.get_mut(handle) else {
        let _ = trona_kernel::invoke::watch_cancel(
            trona_runtime::core::slot_alloc::resolved_cap_ref(watch_addr),
        );
        let _ = watch.release();
        let _ = mp.release_in_place();
        return false;
    };
    client.request_mp = Some(mp);
    client.watch = Some(watch);
    client.watch_cookie = cookie;
    client.cookie_slot = handle.slot();
    true
}

/// Supervisor admin dispatch: every label invoked on a control cap (the ROOT
/// cap for register, a per-client cap otherwise). The badge both authorizes
/// and identifies; only init holds control caps, so reaching here proves init.
///
/// # Safety
/// Single-threaded owner reactor; the reply machinery reads the current IPC
/// buffer via TLS.
unsafe fn dispatch_admin(state: &mut VfsState, badge: u64, msg: &TronaMsg) -> i32 {
    use trona_protocol::vfs::public::{
        VFS_ADMIN_CLONE_FDS, VFS_ADMIN_CLONE_SET_PARTNER, VFS_ADMIN_EXEC_SWEEP,
        VFS_ADMIN_REGISTER_CLIENT, VFS_DEREGISTER_CLIENT,
    };
    match msg.label {
        VFS_ADMIN_REGISTER_CLIENT => handle_admin_register_client(state, badge, msg),
        VFS_ADMIN_CLONE_SET_PARTNER => handle_admin_clone_set_partner(state, badge, msg),
        VFS_ADMIN_CLONE_FDS => handle_admin_clone_fds(state, badge, msg),
        VFS_ADMIN_EXEC_SWEEP => handle_admin_exec_sweep(state, badge),
        VFS_DEREGISTER_CLIENT => {
            // Fire-and-forget (MP_WRITE): no reply. The control-cap badge both
            // authorizes the teardown and names the client.
            if let Some(handle) = crate::owner::clients::resolve_control(state, badge) {
                crate::owner::clients::remove_client(state, handle);
            }
            0
        }
        _ => 0,
    }
}

/// `VFS_ADMIN_REGISTER_CLIENT` (ROOT cap) — pre-create the child's control
/// client, stamp its PID in the credential snapshot, mint its per-client
/// control cap, and return it in `caps[0]`.
fn handle_admin_register_client(state: &mut VfsState, badge: u64, msg: &TronaMsg) -> i32 {
    let reply_lease = ReplyLease::saved_target(current_reply_target(state.service_ep_recv), badge);
    if !trona_protocol::control::is_root(badge) {
        crate::personality::wire::send_error_reply(
            reply_lease,
            crate::core::error::VfsError::Inval,
        );
        return 0;
    }
    if msg.length < 2 || msg.regs[1] == 0 {
        crate::personality::wire::send_error_reply(
            reply_lease,
            crate::core::error::VfsError::Inval,
        );
        return 0;
    }
    let client_id = msg.regs[0] as u32;
    let pid = msg.regs[1] as u32;
    let Some(handle) = crate::owner::clients::create_control_client(state, client_id, pid) else {
        crate::personality::wire::send_error_reply(
            reply_lease,
            crate::core::error::VfsError::NoMem,
        );
        return 0;
    };
    // The control-cap badge encodes the slot in 16 bits; reject the
    // (astronomically unlikely) slot overflow rather than truncate it.
    if handle.slot() > trona_protocol::control::SLOT_MAX {
        crate::owner::clients::remove_client(state, handle);
        crate::personality::wire::send_error_reply(
            reply_lease,
            crate::core::error::VfsError::NoMem,
        );
        return 0;
    }
    let epoch = state
        .clients
        .get(handle)
        .map(|c| c.control_epoch)
        .unwrap_or(0);
    let control_badge = trona_protocol::control::encode(handle.slot() as u16, epoch);
    let Some(cap) = mint_control_cap(control_badge) else {
        crate::owner::clients::remove_client(state, handle);
        crate::personality::wire::send_error_reply(
            reply_lease,
            crate::core::error::VfsError::NoMem,
        );
        return 0;
    };
    let mut out = TronaMsg::zeroed();
    out.label = uapi::KERNITE_OK as u64;
    out.length = 0;
    if !crate::owner::op::reply_send_with_cap(reply_lease, &out, cap) {
        // The control cap never reached init (no reply target or a failed
        // transfer), so init holds nothing to drive this client with. Roll the
        // pre-created client back so VFS keeps no orphan it cannot release.
        crate::owner::clients::remove_client(state, handle);
    }
    0
}

/// `VFS_ADMIN_CLONE_SET_PARTNER` (child's control cap) — record the child as
/// the pending clone partner so the parent's operate step can pin it.
fn handle_admin_clone_set_partner(state: &mut VfsState, badge: u64, msg: &TronaMsg) -> i32 {
    let reply_lease = ReplyLease::saved_target(current_reply_target(state.service_ep_recv), badge);
    let Some(child) = crate::owner::clients::resolve_control(state, badge) else {
        crate::personality::wire::send_error_reply(
            reply_lease,
            crate::core::error::VfsError::Inval,
        );
        return 0;
    };
    crate::owner::clients::set_admin_partner(state, child, msg.regs[0]);
    crate::personality::wire::send_ok_reply(reply_lease, &[]);
    0
}

/// `VFS_ADMIN_CLONE_FDS` (parent's control cap) — clone the parent's FD table
/// into the child pinned by the matching `SET_PARTNER`. Fails the fork on
/// error so the caller does not commit a child with a truncated FD table.
fn handle_admin_clone_fds(state: &mut VfsState, badge: u64, msg: &TronaMsg) -> i32 {
    let reply_lease = ReplyLease::saved_target(current_reply_target(state.service_ep_recv), badge);
    let Some(parent) = crate::owner::clients::resolve_control(state, badge) else {
        crate::personality::wire::send_error_reply(
            reply_lease,
            crate::core::error::VfsError::Inval,
        );
        return 0;
    };
    let Some(child) = crate::owner::clients::consume_admin_partner(state, msg.regs[0]) else {
        crate::personality::wire::send_error_reply(
            reply_lease,
            crate::core::error::VfsError::Inval,
        );
        return 0;
    };
    match crate::personality::posix::fork_clone::clone_client_for_fork(state, parent, child) {
        Ok(_) => crate::personality::wire::send_ok_reply(reply_lease, &[]),
        Err(e) => crate::personality::wire::send_error_reply(reply_lease, e),
    }
    0
}

/// `VFS_ADMIN_EXEC_SWEEP` (client's control cap) — drop the client's
/// FD_CLOEXEC descriptors after the exec point of no return. Best-effort: it
/// only frees state, so the reply is OK once the client resolves.
fn handle_admin_exec_sweep(state: &mut VfsState, badge: u64) -> i32 {
    let reply_lease = ReplyLease::saved_target(current_reply_target(state.service_ep_recv), badge);
    let Some(client) = crate::owner::clients::resolve_control(state, badge) else {
        crate::personality::wire::send_error_reply(
            reply_lease,
            crate::core::error::VfsError::Inval,
        );
        return 0;
    };
    crate::ops::close::cloexec_sweep(state, client);
    crate::personality::wire::send_ok_reply(reply_lease, &[]);
    0
}

/// Mint a per-client control cap — a badged copy of vfs's own master-EP send
/// (`service_client_ep`, GRANT-bearing) — into a transient slot, wrapped as a
/// move-on-transfer cap for the reply. The kernel strips GRANT, leaving an
/// invocable `READ|WRITE|TRANSFER` leaf the reply moves into init's window.
fn mint_control_cap(badge: u64) -> Option<trona_runtime::core::slot_alloc::TransferCap> {
    let src = trona_runtime::client::caps::service_client_ep();
    if src.is_null() {
        return None;
    }
    let temp = trona_runtime::core::slot_alloc::alloc_slot()?;
    let self_cspace = trona_kernel::core_types::CapRef::flat(uapi::KERNITE_CAP_SELF_CSPACE as u64);
    let err = trona_kernel::invoke::cnode_mint_ref(
        self_cspace,
        src.cap_ref(),
        self_cspace,
        trona_runtime::core::slot_alloc::resolved_cap_ref(temp.addr()),
        badge,
    );
    if err != 0 {
        // temp (OwnedSlot) drops here, freeing the empty slot.
        return None;
    }
    // SAFETY: temp holds the freshly-minted cap and is solely owned here; hand
    // its slot to the reply transfer, which moves the cap into init's window
    // and reclaims the slot afterwards.
    Some(unsafe {
        trona_runtime::core::slot_alloc::move_for_transfer(
            trona_runtime::core::slot_alloc::resolved_cap_ref(temp.into_raw()),
        )
    })
}

unsafe fn dispatch_frontend_client_record(
    state: &mut VfsState,
    slot: u32,
    epoch: u32,
    msg: &TronaMsg,
) -> i32 {
    let handle = ClientHandle::new(slot, epoch);
    let (reply_mp, badge) = match state.clients.get(handle) {
        Some(client) if client.is_active() && client.request_mp_recv_addr() != 0 => {
            (client.request_mp_recv_addr(), client.client_badge)
        }
        _ => return uapi::KERNITE_ERR_INVALID_OPERATION as i32,
    };
    let reply_lease = ReplyLease::saved_target(current_reply_target(reply_mp), badge);
    unsafe {
        dispatch_frontend(state, badge, msg, reply_lease);
    }
    0
}

/// Drain one inbound frontend request into the public-protocol
/// dispatcher. The frontend service endpoint itself is the reply
/// target for `reply-marked MP_WRITE`, so no per-call reply object is moved or
/// retained.
unsafe fn dispatch_frontend_record(state: &mut VfsState, badge: u64, msg: &TronaMsg) -> i32 {
    let reply_mp = state.service_ep_recv;
    if reply_mp == 0 {
        return uapi::KERNITE_ERR_INVALID_OPERATION as i32;
    }
    let reply_lease = ReplyLease::saved_target(current_reply_target(reply_mp), badge);
    unsafe {
        dispatch_frontend(state, badge, msg, reply_lease);
    }
    0
}

/// Frontend label dispatch — owner reactor's per-RPC fan-out.
///
/// Resolves `badge` to a client slot, stamps the client's
/// personality on first contact, and routes the request to the
/// matching personality dispatcher.
unsafe fn dispatch_frontend(
    state: &mut VfsState,
    badge: u64,
    msg: &TronaMsg,
    reply_lease: ReplyLease,
) {
    let client_id = (badge & 0xFFFF_FFFF) as u32;
    let client = match crate::owner::clients::ensure_client(state, badge, client_id) {
        Some(c) => c,
        None => {
            crate::personality::wire::send_error_reply(
                reply_lease,
                crate::core::error::VfsError::Io,
            );
            return;
        }
    };

    let label = msg.label;
    if let Some(cli) = state.clients.get(client) {
        if cli.personality == crate::personality::Personality::DEFAULT
            && (0x540..=0x57F).contains(&label)
        {
            if let Some(cli_mut) = state.clients.get_mut(client) {
                cli_mut.personality = crate::personality::Personality::Win32;
            }
            crate::personality::win32::lifecycle::seed_client_state(state, client);
        }
    }

    let personality = state
        .clients
        .get(client)
        .map(|c| c.personality)
        .unwrap_or(crate::personality::Personality::DEFAULT);

    if (0x500..=0x53F).contains(&label) || (0x5C0..=0x5DF).contains(&label) {
        if personality != crate::personality::Personality::Posix {
            crate::personality::wire::send_error_reply(
                reply_lease,
                crate::core::error::VfsError::NotSup,
            );
            return;
        }
        unsafe { crate::personality::posix::dispatch::dispatch(state, client, msg, reply_lease) };
        return;
    }

    if (0x540..=0x57F).contains(&label) {
        if personality != crate::personality::Personality::Win32 {
            crate::personality::wire::send_error_reply(
                reply_lease,
                crate::core::error::VfsError::NotSup,
            );
            return;
        }
        unsafe { crate::personality::win32::dispatch::dispatch(state, client, msg, reply_lease) };
        return;
    }

    crate::personality::wire::send_error_reply(reply_lease, crate::core::error::VfsError::NotSup);
}

// =========================================================================
// Backend dispatch — drained reply or async event from a per-mount-
// instance backend session.
// =========================================================================

/// Route an inbound backend record (BACKEND_* reply) to the
/// originating PendingOp's completion handler.
///
/// Wire flow:
/// 1. Look up the live session at `slot` (cookie's slot field).
///    Empty / stale slots drop the record silently.
/// 2. Decode the 4-word `CorrelationHeader` (`regs[28..=31]`).
///    Wrong class / kind / out-of-bounds length drops the
///    record silently — the wire is shared with backend-initiated
///    callbacks (future) and only completion records advance the
///    pending pipeline.
/// 3. Cross-check `header.session` against the session's current
///    `session_id` to short-circuit replies meant for a torn-down
///    incarnation that happens to have re-allocated the same
///    arena slot.
/// 4. Hand off to `crate::owner::pending::dispatch_pending_reply`
///    with the cookie-side identity tuple. That helper does the
///    PendingOp lookup, the rest of the 5-tuple validation, and
///    the per-session `completion_fn` invocation.
unsafe fn dispatch_backend(state: &mut VfsState, slot: u32, msg: &TronaMsg) -> i32 {
    use crate::ipc::protocol::correlation::{
        CORRELATION_CLASS_DEV, CORRELATION_CLASS_FS, CORRELATION_CLASS_NET,
        CORRELATION_CLASS_PAGER, CORRELATION_CLASS_PTY, CORRELATION_HEADER_REG_COUNT,
        CORRELATION_HEADER_REG_START, CORRELATION_KIND_COMPLETION, CorrelationHeader,
    };
    use crate::owner::pending::{TxId, dispatch_pending_reply};

    let session_handle = match state.backend_sessions.handle_from_slot(slot) {
        Some(h) => h,
        None => return 0,
    };
    let (fs_id, mount_handle_raw, session_id, live_gen) =
        match state.backend_sessions.get(session_handle) {
            Some(entry) if !entry.is_empty() => (
                entry.fs_instance_id,
                entry.mount_handle_raw,
                entry.session_id,
                entry.live_gen,
            ),
            _ => return 0,
        };

    // Correlation header occupies regs[28..=31]. Records shorter
    // than that cannot carry a valid header.
    if (msg.length as usize) < (CORRELATION_HEADER_REG_START + CORRELATION_HEADER_REG_COUNT) {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[VFS] backend record below header length len=");
            _lb.hex(msg.length as u64);
            _lb.str(b" slot=");
            _lb.hex(slot as u64);
            _lb.str(b"\n");
        });
        return 0;
    }
    let words = [
        msg.regs[CORRELATION_HEADER_REG_START],
        msg.regs[CORRELATION_HEADER_REG_START + 1],
        msg.regs[CORRELATION_HEADER_REG_START + 2],
        msg.regs[CORRELATION_HEADER_REG_START + 3],
    ];
    let header = CorrelationHeader::decode_words(words);
    if !matches!(
        header.class,
        CORRELATION_CLASS_FS
            | CORRELATION_CLASS_NET
            | CORRELATION_CLASS_PTY
            | CORRELATION_CLASS_PAGER
            | CORRELATION_CLASS_DEV
    ) {
        // Unknown classes are a backend-side bug. Known non-FS
        // classes still use the same backend-session callback
        // demux; the installed session completion_fn selects the
        // PTY / NET / pager router after the shared 5-tuple check.
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[VFS] backend record wrong class=");
            _lb.hex(header.class as u64);
            _lb.str(b" slot=");
            _lb.hex(slot as u64);
            _lb.str(b"\n");
        });
        return 0;
    }
    if header.kind != CORRELATION_KIND_COMPLETION {
        // Backend-initiated callbacks (e.g. invalidation pushes)
        // would arrive with a non-completion `kind`; until those
        // wire shapes land they are out of scope and we drop the
        // record without disturbing the pending pipeline.
        return 0;
    }
    if header.session != session_id {
        // Reply targets a torn-down incarnation that happens to
        // share this slot. Drop.
        return 0;
    }

    let tx_id = TxId(header.token);
    let _ = dispatch_pending_reply(
        state,
        tx_id,
        fs_id,
        mount_handle_raw,
        session_id,
        live_gen,
        msg,
    );
    0
}
