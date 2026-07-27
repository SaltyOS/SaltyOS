// SPDX-License-Identifier: GPL-2.0-only
//
//! Owner reactor: a single TCB sitting on `EQ_WAIT(control_eq)` with
//! Watches over every per-client request MP recv side, the master
//! service-EP MP, the worker_completion EQ, the unit_mgr ↔ namesrv
//! subscribe channel, and `control_timer`. One record per wait →
//! dispatch → loop.
//!
//! Built on [`trona_server::event_loop::EventLoop`]
//! (Plan 7 LD-10): the reactor's standard
//! `EQ_WAIT → cookie demux → MP_READ → dispatch_state` loop is
//! shared with every other core server. The dispatcher maps each
//! kernel-published cookie back to its `InitTarget` via
//! `state.cookie_table`; the table's `live_gen` field guarantees a
//! stale fire after teardown drops on dispatch instead of routing
//! to a recycled slot.

use trona_kernel::core_types::{Cap, CapRef, IpcContext, TronaMsg};
use trona_kernel::invoke;
use trona_runtime::core::slot_alloc::OwnedCap;
use trona_server::event_loop::{EqDispatcher, EventLoop};
use uapi::{KERNITE_STATE_READABLE, KERNITE_STATE_TIMED_OUT};

use crate::internal_slots::{
    SLOT_CONTROL_EQ_WATCH_SERVICE_MP, SLOT_CONTROL_EQ_WATCH_TIMER, SLOT_CONTROL_EQ_WATCH_WORKER,
};
use crate::supervisor::dispatch;
use crate::supervisor::proc_table::ProcessState;
use crate::supervisor::state::{InitTarget, SupervisorState};

/// Per-iteration context the reactor passes to dispatch handlers.
/// Currently only carries scratch-frame coordinates; in the future we
/// can attach worker-completion bookkeeping here.
pub struct OwnerCtx {
    pub iteration: u64,
}

impl OwnerCtx {
    pub const fn new() -> Self {
        Self { iteration: 0 }
    }
}

/// `EqDispatcher` impl for init's owner reactor. Holds raw pointers
/// back into `state` and the per-iteration `OwnerCtx`; both stay
/// valid for the dispatcher's lifetime since `run` keeps them on the
/// reactor's stack frame.
pub struct InitDispatcher {
    state: *mut SupervisorState,
    ctx: *mut OwnerCtx,
}

impl InitDispatcher {
    pub fn new(state: *mut SupervisorState, ctx: *mut OwnerCtx) -> Self {
        Self { state, ctx }
    }

    fn state_ref(&self) -> &SupervisorState {
        unsafe { &*self.state }
    }
}

impl EqDispatcher for InitDispatcher {
    fn resolve_mp_recv(&self, cookie: u64) -> Option<Cap> {
        let entry = self.state_ref().cookie_table.lookup(cookie)?;
        if entry.mp_recv == 0 {
            // Bound caps that publish state events without a readable
            // message body (control_timer's STATE_TIMED_OUT, an EQ's
            // STATE_READABLE on the worker_completion fan-in queue)
            // surface here as `mp_recv = 0`. Skip the MP_READ; the
            // dispatcher's handler reads the inner queue itself.
            None
        } else {
            Some(entry.mp_recv)
        }
    }

    fn dispatch_state(
        &mut self,
        cookie: u64,
        _msg: &TronaMsg,
        meta: trona_server::event_loop::MpReadMeta,
    ) -> i32 {
        let target = match self.state_ref().cookie_table.lookup(cookie) {
            Some(e) => e.target,
            None => return 0,
        };
        // The reactor has already drained the inbound MP_READ for
        // sources where `resolve_mp_recv` returned a cap; `_msg`
        // carries the body and `meta.badge` carries the
        // kernel-stamped sender badge.
        let state = unsafe { &mut *self.state };
        let ctx = unsafe { &mut *self.ctx };
        ctx.iteration = ctx.iteration.wrapping_add(1);
        match target {
            InitTarget::MasterServiceMp => {
                dispatch::handle_master_msg(state, ctx, _msg, meta.badge);
            }
            InitTarget::ControlTimer => {
                dispatch::handle_timer(state, ctx, 0);
                rearm_watch(
                    SLOT_CONTROL_EQ_WATCH_TIMER,
                    state
                        .caps
                        .control_timer
                        .as_ref()
                        .map(OwnedCap::borrow)
                        .unwrap_or_default()
                        .addr(),
                    state
                        .caps
                        .control_eq
                        .as_ref()
                        .map(OwnedCap::borrow)
                        .unwrap_or_default()
                        .addr(),
                    KERNITE_STATE_TIMED_OUT,
                    state.caps.control_timer_watch_cookie,
                );
            }
            InitTarget::WorkerCompletion => {
                dispatch::handle_worker_completion(state, ctx, 0);
                rearm_watch(
                    SLOT_CONTROL_EQ_WATCH_WORKER,
                    state
                        .caps
                        .worker_completion_eq
                        .as_ref()
                        .map(OwnedCap::borrow)
                        .unwrap_or_default()
                        .addr(),
                    state
                        .caps
                        .control_eq
                        .as_ref()
                        .map(OwnedCap::borrow)
                        .unwrap_or_default()
                        .addr(),
                    KERNITE_STATE_READABLE,
                    state.caps.worker_completion_watch_cookie,
                );
            }
            InitTarget::NamesrvRegisterEvent => {
                dispatch::handle_namesrv_register_event(state, ctx, _msg);
            }
            InitTarget::Request { client_id } => {
                dispatch::handle_request_msg(state, ctx, client_id, _msg, meta.badge);
            }
        }
        0
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
        let target = match self.state_ref().cookie_table.lookup(cookie) {
            Some(e) => e.target,
            None => return false,
        };
        match target {
            InitTarget::MasterServiceMp
            | InitTarget::NamesrvRegisterEvent
            | InitTarget::Request { .. } => {
                crate::supervisor::recv_window::arm(trona_runtime::current_ipc_ctx());
                true
            }
            InitTarget::ControlTimer | InitTarget::WorkerCompletion => false,
        }
    }

    fn rearm_state_source(&mut self, cookie: u64) -> i32 {
        let target = match self.state_ref().cookie_table.lookup(cookie) {
            Some(e) => e.target,
            None => return 0,
        };
        let state = unsafe { &mut *self.state };
        match target {
            InitTarget::MasterServiceMp => {
                rearm_watch(
                    SLOT_CONTROL_EQ_WATCH_SERVICE_MP,
                    state
                        .caps
                        .master_service_mp_recv
                        .as_ref()
                        .map(OwnedCap::borrow)
                        .unwrap_or_default()
                        .addr(),
                    state
                        .caps
                        .control_eq
                        .as_ref()
                        .map(OwnedCap::borrow)
                        .unwrap_or_default()
                        .addr(),
                    KERNITE_STATE_READABLE,
                    state.caps.master_service_mp_watch_cookie,
                );
            }
            InitTarget::NamesrvRegisterEvent => {
                rearm_watch(
                    state
                        .caps
                        .unit_mgr_namesrv_event_watch
                        .as_ref()
                        .map(OwnedCap::borrow)
                        .unwrap_or_default()
                        .addr(),
                    state
                        .caps
                        .unit_mgr_namesrv_event_mp_recv
                        .as_ref()
                        .map(OwnedCap::borrow)
                        .unwrap_or_default()
                        .addr(),
                    state
                        .caps
                        .control_eq
                        .as_ref()
                        .map(OwnedCap::borrow)
                        .unwrap_or_default()
                        .addr(),
                    KERNITE_STATE_READABLE,
                    state.caps.namesrv_register_event_watch_cookie,
                );
            }
            InitTarget::Request { client_id } => {
                rearm_request_watch(state, client_id);
            }
            InitTarget::ControlTimer | InitTarget::WorkerCompletion => {}
        }
        0
    }

    fn handle_overflow(&mut self, dropped: u64) {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[INIT] control EQ overflow dropped=");
            _lb.hex(dropped);
            _lb.str(b"\n");
        });
    }

    fn handle_timer(&mut self, _cookie: u64) {
        // init does not arm kernel TIMER objects directly today; the
        // single `control_timer` is exposed via STATE_TIMED_OUT on
        // the timer cap and arrives as `EVENT_TYPE_STATE` rather than
        // `EVENT_TYPE_TIMER`. Future itimer / sleep timers can land
        // here under their own cookie kind.
    }
}

fn rearm_watch(watch_cap: u64, watched_cap: u64, eq_cap: u64, mask: u64, cookie: u64) {
    if watch_cap == 0 || watched_cap == 0 || eq_cap == 0 || cookie == 0 {
        return;
    }
    let _ = invoke::watch_register(
        CapRef::flat(watch_cap),
        CapRef::flat(watched_cap),
        CapRef::flat(eq_cap),
        mask,
        cookie,
    );
}

fn rearm_request_watch(state: &mut SupervisorState, client_id: u32) {
    let control_eq = state
        .caps
        .control_eq
        .as_ref()
        .map(OwnedCap::borrow)
        .unwrap_or_default()
        .addr();
    let Some(proc) = state.find_proc_by_client_id_mut(client_id) else {
        return;
    };
    if proc.state != ProcessState::Active {
        return;
    }
    rearm_watch(
        proc.request_watch
            .as_ref()
            .map(OwnedCap::borrow)
            .unwrap_or_default()
            .addr(),
        proc.request_mp_recv
            .as_ref()
            .map(OwnedCap::borrow)
            .unwrap_or_default()
            .addr(),
        control_eq,
        KERNITE_STATE_READABLE,
        proc.request_watch_cookie,
    );
}

/// Run the reactor forever. Returns only on EQ_WAIT failure (which is
/// fatal — owner thread idles).
pub fn run(state: &mut SupervisorState) -> ! {
    let mut ctx = OwnerCtx::new();
    let control_eq = state
        .caps
        .control_eq
        .as_ref()
        .map(OwnedCap::borrow)
        .unwrap_or_default()
        .addr();
    let dispatcher = InitDispatcher::new(state as *mut SupervisorState, &raw mut ctx);
    let mut reactor: EventLoop<InitDispatcher> = EventLoop::new(control_eq, dispatcher);

    let ipc_ctx: *mut IpcContext = trona_runtime::current_ipc_ctx();
    loop {
        crate::supervisor::recv_window::arm(ipc_ctx);
        let r = unsafe { reactor.run_iteration(ipc_ctx) };
        if r != 0 {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[INIT] reactor iteration err=");
                _lb.hex(r as u64);
                log_reactor_error_context(&mut _lb, state, ipc_ctx);
                _lb.str(b"\n");
            });
            trona_kernel::syscall::yield_now();
        }
    }
}

fn log_reactor_error_context(
    lb: &mut trona_runtime::debug::serial::LineBuf,
    state: &SupervisorState,
    ipc_ctx: *mut IpcContext,
) {
    if ipc_ctx.is_null() {
        return;
    }
    let ipc_buf = unsafe { (*ipc_ctx).ipc_buffer };
    if ipc_buf.is_null() {
        return;
    }
    let record = unsafe { trona_kernel::ipc_buffer::read_event_record(ipc_buf as *const _) };
    lb.str(b" event_kind=");
    lb.hex(record.kind as u64);
    lb.str(b" cookie=");
    lb.hex(record.cookie);
    lb.str(b" state=");
    lb.hex(record.state_set);
    if let Some(entry) = state.cookie_table.lookup(record.cookie) {
        lb.str(b" target=");
        match entry.target {
            InitTarget::MasterServiceMp => lb.str(b"master"),
            InitTarget::ControlTimer => lb.str(b"timer"),
            InitTarget::WorkerCompletion => lb.str(b"worker"),
            InitTarget::NamesrvRegisterEvent => lb.str(b"namesrv"),
            InitTarget::Request { client_id } => {
                lb.str(b"request:");
                lb.dec(client_id as u64);
            }
        }
    }
}
