// SPDX-License-Identifier: GPL-2.0-only
//
//! ldsrv's reactor — the standard `EQ_WAIT → cookie demux → MP_READ →
//! dispatch` loop shared with every other core server
//! ([`trona_server::event_loop::EventLoop`]). Two sources are armed, each a
//! one-shot Watch on `STATE_READABLE` posting into one EventQueue:
//!
//! * the **public** service endpoint — `resolve_library` for any client;
//! * the **private** exec-control MP — `resolve_main` for init only.
//!
//! `RESOLVE_MAIN` is honoured only on the control-MP cookie, so conferring
//! EXECUTE on a caller-supplied backing is gated to the holder of that private
//! cap (init). The EventQueue and both Watches are retyped from the plumbing
//! untyped init carves for ldsrv at spawn; the cookie table's storage is
//! mmsrv-backed (ldsrv boots after mmsrv).

use trona_kernel::core_types::{Cap, CapRef, IpcContext, TronaMsg};
use trona_kernel::invoke;
use trona_kernel::ipc;
use trona_kernel::syscall;
use trona_server::event_loop::{CookieTable, EqDispatcher, EventLoop, MpReadMeta};
use uapi::{KERNITE_OBJ_EVENT_QUEUE, KERNITE_OBJ_WATCH, KERNITE_STATE_READABLE};

use crate::cache::Cache;
use crate::dispatch;
use crate::segment_alloc::LdsrvSegmentAllocator;
use trona_runtime::core::slot_alloc::alloc_slot;
use trona_server::recv_slot::RecvSlotArena;

const SELF_CSPACE: u64 = uapi::KERNITE_CAP_SELF_CSPACE as u64;

/// Per-cookie source in ldsrv's reactor.
#[derive(Clone, Copy)]
pub enum LdsrvTarget {
    /// Public service endpoint — `resolve_library` for any client.
    PublicEp,
    /// Private exec-control MP — `resolve_main` for init only.
    ControlMp,
}

/// Cookie kinds for the two reactor sources.
const KIND_PUBLIC: u8 = 0;
const KIND_CONTROL: u8 = 1;

/// Reactor objects (retyped from the plumbing untyped) plus the cookie table.
/// The per-source Watch caps and cookies are retained for re-arm (Watches are
/// one-shot) and overflow recovery.
pub struct ReactorState {
    cookie_table: CookieTable<LdsrvTarget>,
    seg_alloc: LdsrvSegmentAllocator,
    eq: u64,
    public_ep: u64,
    control_mp: u64,
    w_public: u64,
    w_control: u64,
    public_cookie: u64,
    control_cookie: u64,
}

impl ReactorState {
    pub const fn new() -> Self {
        Self {
            cookie_table: CookieTable::new_empty(),
            seg_alloc: LdsrvSegmentAllocator::new(),
            eq: 0,
            public_ep: 0,
            control_mp: 0,
            w_public: 0,
            w_control: 0,
            public_cookie: 0,
            control_cookie: 0,
        }
    }
}

static mut REACTOR_STATE: ReactorState = ReactorState::new();

/// Retype one object of `obj_type` from `untyped` into a fresh slot, leaking
/// the slot (reactor objects live for the system lifetime). Returns the cap
/// addr, or `0` on slot exhaustion / retype failure.
fn retype_one(untyped: u64, obj_type: u64) -> u64 {
    let Some(slot) = alloc_slot() else {
        return 0;
    };
    let addr = slot.addr();
    if invoke::untyped_retype(CapRef::flat(untyped), obj_type, 0, addr) != 0 {
        // `slot` (OwnedSlot) drops here, returning the empty slot to the pool.
        return 0;
    }
    slot.into_raw()
}

/// Re-arm `watch` over `watched`'s `STATE_READABLE` on `eq` with `cookie`.
fn arm_watch(watch: u64, watched: u64, eq: u64, cookie: u64) -> i32 {
    invoke::watch_register(
        CapRef::flat(watch),
        CapRef::flat(watched),
        CapRef::flat(eq),
        KERNITE_STATE_READABLE,
        cookie,
    )
}

/// Retype a Watch for `mp_recv`, register its cookie, arm it on the EventQueue,
/// and stash the Watch / cookie for later re-arm. `false` (caller idles) on any
/// failure.
fn arm_source(
    rs: &mut ReactorState,
    kind: u8,
    mp_recv: u64,
    untyped: u64,
    target: LdsrvTarget,
) -> bool {
    let watch = retype_one(untyped, KERNITE_OBJ_WATCH as u64);
    if watch == 0 {
        return false;
    }
    let cookie = match unsafe {
        rs.cookie_table
            .arm(&mut rs.seg_alloc, kind, mp_recv, watch, target)
    } {
        Ok(c) => c,
        Err(_) => return false,
    };
    if arm_watch(watch, mp_recv, rs.eq, cookie) != 0 {
        return false;
    }
    match target {
        LdsrvTarget::PublicEp => {
            rs.w_public = watch;
            rs.public_cookie = cookie;
        }
        LdsrvTarget::ControlMp => {
            rs.w_control = watch;
            rs.control_cookie = cookie;
        }
    }
    true
}

/// `EqDispatcher` for ldsrv. Holds raw pointers back to the reactor state and
/// the main module's cache / receive arena / exec-authority slot, all of which
/// outlive the dispatcher (single-threaded server — no lock).
pub struct LdsrvDispatcher {
    rs: *mut ReactorState,
    cache: *mut Cache,
    arena: *mut RecvSlotArena,
    exec_authority_slot: *const u64,
}

impl LdsrvDispatcher {
    fn rs_ref(&self) -> &ReactorState {
        unsafe { &*self.rs }
    }
}

impl EqDispatcher for LdsrvDispatcher {
    fn resolve_mp_recv(&self, cookie: u64) -> Option<Cap> {
        let entry = self.rs_ref().cookie_table.lookup(cookie)?;
        (entry.mp_recv != 0).then_some(entry.mp_recv)
    }

    fn dispatch_state(&mut self, cookie: u64, msg: &TronaMsg, meta: MpReadMeta) -> i32 {
        let (ep, allow_main) = match self.rs_ref().cookie_table.lookup(cookie) {
            Some(e) => (e.mp_recv, matches!(e.target, LdsrvTarget::ControlMp)),
            None => return 0,
        };
        let ctx = trona_runtime::current_ipc_ctx();
        let cache = unsafe { &mut *self.cache };
        let arena = unsafe { &mut *self.arena };
        let exec_authority = unsafe { core::ptr::read_volatile(self.exec_authority_slot) };
        unsafe {
            dispatch::handle_resolve(
                ctx,
                msg,
                meta.txid,
                ep,
                cache,
                arena,
                exec_authority,
                allow_main,
            );
            arena.recycle_for_next_recv(ctx, SELF_CSPACE);
        }
        0
    }

    fn prepare_mp_read(&mut self, cookie: u64) -> bool {
        if self.rs_ref().cookie_table.lookup(cookie).is_none() {
            return false;
        }
        // Drop the prior reply's staged send-cap before the next MP_READ;
        // received caps land in the receive arena slot, not the send `caps[]`.
        unsafe { ipc::clear_send_caps_ctx(trona_runtime::current_ipc_ctx()) };
        true
    }

    fn rearm_state_source(&mut self, cookie: u64) -> i32 {
        let rs = self.rs_ref();
        match rs.cookie_table.lookup(cookie).map(|e| e.target) {
            Some(LdsrvTarget::PublicEp) => {
                arm_watch(rs.w_public, rs.public_ep, rs.eq, rs.public_cookie)
            }
            Some(LdsrvTarget::ControlMp) => {
                arm_watch(rs.w_control, rs.control_mp, rs.eq, rs.control_cookie)
            }
            None => 0,
        }
    }

    fn handle_overflow(&mut self, dropped: u64) {
        // A dropped state edge means a source may be readable without a pending
        // fire; re-arm both Watches so no readable edge is permanently lost.
        let rs = self.rs_ref();
        let _ = arm_watch(rs.w_public, rs.public_ep, rs.eq, rs.public_cookie);
        let _ = arm_watch(rs.w_control, rs.control_mp, rs.eq, rs.control_cookie);
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[LDSRV] EQ overflow dropped=");
            _lb.hex(dropped);
            _lb.str(b"\n");
        });
    }

    fn handle_timer(&mut self, _cookie: u64) {}
}

/// Build the reactor from the plumbing `untyped` and run it forever. Diverges:
/// on a fatal build failure it idles; otherwise it loops on the EventQueue.
pub fn run(
    control_mp: u64,
    untyped: u64,
    cache: *mut Cache,
    arena: *mut RecvSlotArena,
    exec_authority_slot: *const u64,
) -> ! {
    let ctx: *mut IpcContext = trona_runtime::current_ipc_ctx();
    let public_ep = trona_runtime::client::caps::service_recv_ep().addr();
    let rs = unsafe { &mut *(&raw mut REACTOR_STATE) };
    rs.public_ep = public_ep;
    rs.control_mp = control_mp;
    rs.eq = retype_one(untyped, KERNITE_OBJ_EVENT_QUEUE as u64);

    let built = rs.eq != 0
        && arm_source(rs, KIND_PUBLIC, public_ep, untyped, LdsrvTarget::PublicEp)
        && arm_source(
            rs,
            KIND_CONTROL,
            control_mp,
            untyped,
            LdsrvTarget::ControlMp,
        );
    if !built {
        loop {
            let _ = syscall::yield_now();
        }
    }

    let eq = rs.eq;
    let dispatcher = LdsrvDispatcher {
        rs: rs as *mut ReactorState,
        cache,
        arena,
        exec_authority_slot,
    };
    let mut reactor: EventLoop<LdsrvDispatcher> = EventLoop::new(eq, dispatcher);
    loop {
        let r = unsafe { reactor.run_iteration(ctx) };
        if r != 0 {
            let _ = syscall::yield_now();
        }
    }
}
