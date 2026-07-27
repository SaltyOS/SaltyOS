// SPDX-License-Identifier: GPL-2.0-only
//
//! Reactor loop and shared state container.
//!
//! `ServerState` aggregates every mutable structure namesrv owns.
//! The reactor is single-threaded (one TCB), so all access is via
//! `&mut state` — no locks, no atomics on the data side.
//!
//! The reactor lives on top of substrate's
//! [`trona_server::event_loop::EventLoop`]: `EQ_WAIT
//! → cookie demux → MP_READ → dispatch` with a cookie table keyed
//! by `(kind, slot, live_gen)`. namesrv's cookie kinds:
//!
//! - `kind = 0`: master MP `STATE_READABLE` (one entry, slot 0).
//! - `kind = 2`: registered cap `STATE_PEER_CLOSED` (one entry per
//!   registered name, slot reused on tombstone).
//!
//! Park Timer fires arrive as `EVENT_TYPE_TIMER` records and are
//! routed through `EqDispatcher::handle_timer` — no Watch on the
//! Timer's `STATE_TIMED_OUT` flag is needed because the kernel
//! publishes a TIMER record directly when the deadline expires.

use trona_kernel::core_types::{Cap, IpcContext, TronaMsg};
use trona_kernel::syscall;
use trona_server::event_loop::{CookieTable, EqDispatcher, EventLoop};
use uapi::{
    KERNITE_INV_CLOCK_READ, KERNITE_INV_TIMER_CANCEL, KERNITE_INV_TIMER_SET, KERNITE_STATE_READABLE,
};

use crate::dispatch;
use crate::owner::OwnerTable;
use crate::policy::PublisherPolicy;
use crate::registry::NameRegistry;
use crate::segment_alloc::NamesrvSegmentAllocator;
use crate::slots::{StartupSlots, arm_recv_scratch};
use crate::subs::PendingSubs;
use crate::watch::WatchSlab;

/// Cookie-kind constants for namesrv's reactor cookie table.
pub const NAMESRV_KIND_MASTER_MP: u8 = 0;
pub const NAMESRV_KIND_REGISTERED_CAP: u8 = 2;

/// Per-cookie target stored alongside the source MP recv inside
/// the reactor's `CookieTable`.
#[derive(Clone, Copy)]
pub enum NamesrvTarget {
    /// `kind = 0` — master MP. Dispatcher reads one record and
    /// routes by label through `dispatch::dispatch`.
    MasterMp,
    /// `kind = 2` — registered cap PEER_CLOSED. Dispatcher hands
    /// `idx` to `eviction::evict_one`.
    RegisteredCap { idx: u32 },
}

pub struct ServerState {
    pub startup: StartupSlots,
    pub registry: NameRegistry,
    pub owners: OwnerTable,
    pub policy: PublisherPolicy,
    pub watches: WatchSlab,
    pub pending: PendingSubs,
    pub clock_cap: u64,
    /// Cookie → target index used by `NamesrvDispatcher` to route
    /// inbound EQ records. Backed by namesrv's
    /// `SegmentAllocator` which retypes 4 KiB frames out of
    /// `state.startup.boot_untyped`.
    pub cookie_table: CookieTable<NamesrvTarget>,
    /// Frame allocator backing `cookie_table` (and any future
    /// namesrv-internal `SegmentedArray<T>` that needs dynamic
    /// growth). Initialised with `boot_untyped == 0`; rebound
    /// after `boot::read_startup_caps` populates the real cap.
    pub segment_allocator: NamesrvSegmentAllocator,
}

impl ServerState {
    pub const fn new() -> Self {
        Self {
            startup: StartupSlots::zeroed(),
            registry: NameRegistry::new(),
            owners: OwnerTable::new(),
            policy: PublisherPolicy::new(),
            watches: WatchSlab::new(),
            pending: PendingSubs::new(),
            clock_cap: 0,
            cookie_table: CookieTable::new_empty(),
            segment_allocator: NamesrvSegmentAllocator::new(0),
        }
    }
}

/// Read the monotonic clock against the per-process `Clock` cap.
pub(crate) fn now_ns(state: &ServerState) -> u64 {
    if state.clock_cap == 0 {
        return 0;
    }
    let r = syscall::invoke(
        state.clock_cap,
        KERNITE_INV_CLOCK_READ as u64,
        uapi::KERNITE_CLOCK_ID_MONOTONIC as u64,
        0,
        0,
        0,
    );
    if r.error == 0 { r.value } else { 0 }
}

/// Re-arm the park Timer for the earliest pending deadline.
/// Cancels the timer if no timed park remains.
pub(crate) fn rearm_park_timer(state: &ServerState) {
    let _ = syscall::invoke(
        state.startup.park_timer,
        KERNITE_INV_TIMER_CANCEL as u64,
        0,
        0,
        0,
        0,
    );
    if let Some(deadline) = state.pending.earliest_deadline_ns() {
        let _ = syscall::invoke(
            state.startup.park_timer,
            KERNITE_INV_TIMER_SET as u64,
            deadline,
            0, // arg1 = deadline mode (0 = absolute monotonic)
            0,
            0,
        );
    }
}

fn rearm_watch(watch_cap: u64, watched_cap: u64, eq_cap: u64, cookie: u64) {
    if watch_cap == 0 || watched_cap == 0 || eq_cap == 0 {
        return;
    }
    let _ = trona_kernel::invoke::watch_register(
        trona_kernel::core_types::CapRef::flat(watch_cap),
        trona_kernel::core_types::CapRef::flat(watched_cap),
        trona_kernel::core_types::CapRef::flat(eq_cap),
        KERNITE_STATE_READABLE as u64,
        cookie,
    );
}

/// `EqDispatcher` implementation backed by a raw `*mut
/// ServerState`. namesrv's reactor is single-threaded so the raw
/// pointer is sound: only the reactor TCB ever borrows the state,
/// and the borrows do not overlap across iterations.
pub struct NamesrvDispatcher {
    state: *mut ServerState,
}

impl NamesrvDispatcher {
    pub fn new(state: *mut ServerState) -> Self {
        Self { state }
    }

    fn state(&self) -> &ServerState {
        unsafe { &*self.state }
    }

    fn state_mut(&mut self) -> &mut ServerState {
        unsafe { &mut *self.state }
    }
}

impl EqDispatcher for NamesrvDispatcher {
    fn resolve_mp_recv(&self, cookie: u64) -> Option<Cap> {
        let entry = self.state().cookie_table.lookup(cookie)?;
        // mp_recv == 0 marks a close-without-read entry such as
        // the registered-cap `STATE_PEER_CLOSED` watch — the
        // reactor must skip `MP_READ` and route directly to
        // `dispatch_state` so the eviction path runs.
        if entry.mp_recv == 0 {
            None
        } else {
            Some(entry.mp_recv)
        }
    }

    fn dispatch_state(
        &mut self,
        cookie: u64,
        msg: &TronaMsg,
        meta: trona_server::event_loop::MpReadMeta,
    ) -> i32 {
        let badge = meta.badge;
        let target = match self.state().cookie_table.lookup(cookie) {
            Some(e) => e.target,
            None => return 0, // stale cookie — drop
        };
        match target {
            NamesrvTarget::MasterMp => {
                let buf = unsafe { (*trona_posix::tls::current_ipc_ctx()).ipc_buffer };
                let state = self.state_mut();
                dispatch::set_current_reply_target(buf as *const _, state.startup.master_mp);
                let recognised = dispatch::dispatch(buf, msg.label, &msg.regs, badge, state);
                if !recognised {
                    use uapi::KERNITE_ERR_INVALID_OPERATION;
                    dispatch::send_reply(
                        buf,
                        dispatch::reply_mp_slot(buf),
                        KERNITE_ERR_INVALID_OPERATION as u64,
                        &[],
                        0,
                    );
                }
                0
            }
            NamesrvTarget::RegisteredCap { idx } => {
                let state = self.state_mut();
                crate::eviction::evict_one(
                    &mut state.registry,
                    &mut state.owners,
                    &mut state.watches,
                    &mut state.cookie_table,
                    idx as usize,
                );
                0
            }
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
        let target = match self.state().cookie_table.lookup(cookie) {
            Some(e) => e.target,
            None => return false,
        };
        match target {
            NamesrvTarget::MasterMp => {
                arm_recv_scratch(trona_posix::tls::current_ipc_ctx());
                true
            }
            NamesrvTarget::RegisteredCap { .. } => false,
        }
    }

    fn rearm_state_source(&mut self, cookie: u64) -> i32 {
        let target = match self.state().cookie_table.lookup(cookie) {
            Some(e) => e.target,
            None => return 0,
        };
        match target {
            NamesrvTarget::MasterMp => {
                let (watch_cap, mp_recv) = match self.state().cookie_table.lookup(cookie) {
                    Some(e) => (e.watch_cap, e.mp_recv),
                    None => return 0,
                };
                let master_eq = self.state().startup.master_eq;
                rearm_watch(watch_cap, mp_recv, master_eq, cookie);
            }
            NamesrvTarget::RegisteredCap { .. } => {}
        }
        0
    }

    fn handle_overflow(&mut self, dropped: u64) {
        // EQ ring overflow — namesrv's cookies all carry a
        // `live_gen` that `CookieTable::lookup` validates, so a
        // few dropped records cannot wedge the registry. Log so
        // operators can observe sustained pressure.
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[NAMESERV] EQ overflow dropped=");
            _lb.hex(dropped);
            _lb.str(b"\n");
        });
    }

    fn handle_timer(&mut self, _cookie: u64) {
        let state = self.state_mut();
        let now = now_ns(state);
        let buf = unsafe { (*trona_posix::tls::current_ipc_ctx()).ipc_buffer };
        dispatch::fire_timed_outs(buf, now, &mut state.pending);
        rearm_park_timer(state);
    }
}

/// Block on the master EQ until at least one event arrives, then
/// drain it through the reactor. Loops forever — the reactor TCB
/// never returns.
pub fn run_loop(state: &mut ServerState) -> ! {
    let ctx: *mut IpcContext = trona_posix::tls::current_ipc_ctx();
    arm_recv_scratch(ctx);

    let dispatcher = NamesrvDispatcher::new(state as *mut ServerState);
    let mut reactor: EventLoop<NamesrvDispatcher> =
        EventLoop::new(state.startup.master_eq, dispatcher);

    loop {
        let r = unsafe { reactor.run_iteration(ctx) };
        if r != 0 {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[NAMESERV] reactor iteration err=");
                _lb.hex(r as u64);
                _lb.str(b"\n");
            });
            syscall::invoke(
                uapi::KERNITE_CAP_SELF_TCB as u64,
                uapi::KERNITE_INV_TCB_YIELD as u64,
                0,
                0,
                0,
                0,
            );
        }
        arm_recv_scratch(ctx);
    }
}
