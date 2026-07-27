// SPDX-License-Identifier: GPL-2.0-only
//
//! Reactor loop and shared state container.
//!
//! rsrcsrv runs a single-threaded `EventLoop` over its
//! `service_eq`. The reactor's only armed source today is the
//! master MP recv side — every `RSRC_*` call from a client lands
//! there, the Watch fires `EVENT_TYPE_STATE`, the dispatcher reads
//! the inbound message and routes it to `dispatch::dispatch`.
//!
//! Even with a single source rsrcsrv keeps the same abstraction
//! the other core servers use (Plan 7 LD-10) so future additions
//! (timer-driven quota expiry, multi-pool fan-in) drop in by
//! reserving a new cookie kind without rewriting the reactor.

use trona_kernel::core_types::{Cap, IpcContext, TronaMsg};
use trona_kernel::syscall;
use trona_server::event_loop::{CookieTable, EqDispatcher, EventLoop};
use uapi::{KERNITE_STATE_READABLE, kernite_ipc_buffer};

use crate::dispatch;
use crate::objects::ObjectTable;
use crate::quotas::OwnerTable;
use crate::segment_alloc::RsrcsrvSegmentAllocator;
use crate::untyped::FreeList;

#[derive(Clone, Copy, Debug)]
pub struct StartupSlots {
    pub init_ep: u64,
    pub master_mp_recv: u64,
    pub fault_pipe_send: u64,
    pub namesrv_ep: u64,
    /// EventQueue cap that the reactor blocks on. Init retypes this
    /// from rsrcsrv's plumbing untyped and hands it over via the
    /// startup cap_table under [`ROLE_RSRCSRV_SERVICE_EQ`].
    pub service_eq: u64,
}

impl StartupSlots {
    pub const fn zeroed() -> Self {
        Self {
            init_ep: 0,
            master_mp_recv: 0,
            fault_pipe_send: 0,
            namesrv_ep: 0,
            service_eq: 0,
        }
    }
}

/// Per-cookie target in rsrcsrv's reactor cookie table. Today the
/// only kind is the master-MP recv side; future expansions add
/// variants (e.g., quota-expiry timer) here.
#[derive(Clone, Copy)]
pub enum RsrcsrvTarget {
    /// `kind = RSRCSRV_KIND_MASTER_MP` — every `RSRC_*` call from a
    /// client. Demuxed inside `dispatch::dispatch` by the call's
    /// `record.badge` (lower 32 bits = client_id).
    MasterMp,
}

/// Cookie kinds for rsrcsrv's reactor.
pub const RSRCSRV_KIND_MASTER_MP: u8 = 0;

pub struct ServerState {
    pub startup: StartupSlots,
    pub untyped: FreeList,
    pub objects: ObjectTable,
    pub quotas: OwnerTable,
    /// Watch cap armed on `startup.master_mp_recv`'s `STATE_READABLE`
    /// bit, posting `EVENT_TYPE_STATE` records into
    /// `startup.service_eq`. Re-armed after every fire since Watches
    /// are one-shot.
    pub master_mp_watch_cap: u64,
    /// Encoded cookie returned by `cookie_table.arm` for the master
    /// MP Watch. The dispatcher re-arms with the same value so the
    /// `live_epoch` survives across re-arms.
    pub master_mp_cookie: u64,
    /// Cookie table for the reactor. Backed by `segment_allocator`
    /// (frames retyped from rsrcsrv's untyped pool and mapped at
    /// `selfmem::SELF_STORAGE_BASE+`).
    pub cookie_table: CookieTable<RsrcsrvTarget>,
    /// Self-storage allocator for `cookie_table` and any other
    /// rsrcsrv-internal `SegmentedArray<T>`. mmsrv's `MM_MMAP` is
    /// not yet available at rsrcsrv-spawn time (mmsrv comes after
    /// rsrcsrv in init's boot sequence), so growth retypes pages
    /// directly from `untyped`.
    pub segment_allocator: RsrcsrvSegmentAllocator,
}

impl ServerState {
    pub const fn new() -> Self {
        Self {
            startup: StartupSlots::zeroed(),
            untyped: FreeList::new(),
            objects: ObjectTable::new(),
            quotas: OwnerTable::new(),
            master_mp_watch_cap: 0,
            master_mp_cookie: 0,
            cookie_table: CookieTable::new_empty(),
            segment_allocator: RsrcsrvSegmentAllocator::new(),
        }
    }
}

static mut STATE: ServerState = ServerState::new();

/// Single-threaded server: callers run inside the reactor turn so
/// `&mut STATE` is uncontended. The closure is the only place that
/// acquires the `static mut`; do not stash the reference past return.
pub unsafe fn with_state_mut<R>(mut f: impl FnMut(&mut ServerState) -> R) -> R {
    let s = unsafe { &mut *(&raw mut STATE) };
    f(s)
}

pub fn state_mut() -> &'static mut ServerState {
    unsafe { &mut *(&raw mut STATE) }
}

fn arm_recv_window(ctx: *mut IpcContext) {
    let window = trona_server::recv_slot::FixedRecvWindow::new(
        crate::caps::recv_base_slot(),
        crate::caps::RECV_WINDOW_LEN,
        trona_runtime::core::slot_alloc::slot_invoke_depth_cb,
    );
    unsafe {
        window.arm(ctx, crate::caps::CAP_SELF_CSPACE);
    }
}

fn consume_unknown(buf: *mut kernite_ipc_buffer) {
    if buf.is_null() {
        return;
    }
    let _ = dispatch::send_reply(buf, uapi::KERNITE_ERR_INVALID_OPERATION as u64, &[], 0);
}

/// Re-arm a Watch over `watched_cap` on `eq_cap` with `cookie`.
fn rearm_watch(watch_cap: u64, watched_cap: u64, eq_cap: u64, cookie: u64) {
    if watch_cap == 0 || watched_cap == 0 || eq_cap == 0 {
        return;
    }
    let _ = trona_kernel::invoke::watch_register(
        trona_kernel::core_types::CapRef::flat(watch_cap),
        trona_kernel::core_types::CapRef::flat(watched_cap),
        trona_kernel::core_types::CapRef::flat(eq_cap),
        KERNITE_STATE_READABLE,
        cookie,
    );
}

// -------------------------------------------------------------------
// Reactor dispatcher.
// -------------------------------------------------------------------

/// `EqDispatcher` impl for rsrcsrv. Holds a raw pointer back into
/// `static mut STATE` so dispatch handlers borrow `&mut ServerState`
/// directly. Single-threaded server — no lock.
pub struct RsrcsrvDispatcher {
    state: *mut ServerState,
}

impl RsrcsrvDispatcher {
    pub fn new(state: *mut ServerState) -> Self {
        Self { state }
    }

    fn state_ref(&self) -> &ServerState {
        unsafe { &*self.state }
    }

    fn state_mut(&mut self) -> &mut ServerState {
        unsafe { &mut *self.state }
    }
}

impl EqDispatcher for RsrcsrvDispatcher {
    fn resolve_mp_recv(&self, cookie: u64) -> Option<Cap> {
        let entry = self.state_ref().cookie_table.lookup(cookie)?;
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
        let target = match self.state_ref().cookie_table.lookup(cookie) {
            Some(e) => e.target,
            None => return 0,
        };
        let buf = unsafe { (*trona_posix::tls::current_ipc_ctx()).ipc_buffer };
        match target {
            RsrcsrvTarget::MasterMp => {
                let st = self.state_mut();
                dispatch::set_current_reply_target(buf as *const _, st.startup.master_mp_recv);
                let recognised = dispatch::dispatch(buf, msg.label, &msg.regs, badge, st);
                if !recognised {
                    consume_unknown(buf);
                }
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
        if self.state_ref().cookie_table.lookup(cookie).is_none() {
            return false;
        }
        arm_recv_window(trona_posix::tls::current_ipc_ctx());
        true
    }

    fn rearm_state_source(&mut self, cookie: u64) -> i32 {
        let target = match self.state_ref().cookie_table.lookup(cookie) {
            Some(e) => e.target,
            None => return 0,
        };
        match target {
            RsrcsrvTarget::MasterMp => {
                let st = self.state_mut();
                rearm_watch(
                    st.master_mp_watch_cap,
                    st.startup.master_mp_recv,
                    st.startup.service_eq,
                    st.master_mp_cookie,
                );
            }
        }
        0
    }

    fn handle_overflow(&mut self, dropped: u64) {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[RSRCSRV] EQ overflow dropped=");
            _lb.hex(dropped);
            _lb.str(b"\n");
        });
    }

    fn handle_timer(&mut self, _cookie: u64) {
        // No timers armed yet. Future quota-expiry / lease-deadline
        // sources land here under their own cookie kind.
    }
}

// -------------------------------------------------------------------
// Reactor driver.
// -------------------------------------------------------------------

pub fn run_loop() -> ! {
    let ctx: *mut IpcContext = trona_posix::tls::current_ipc_ctx();
    arm_recv_window(ctx);
    let service_eq = state_mut().startup.service_eq;
    let dispatcher = RsrcsrvDispatcher::new(state_mut() as *mut ServerState);
    let mut reactor: EventLoop<RsrcsrvDispatcher> = EventLoop::new(service_eq, dispatcher);

    loop {
        let r = unsafe { reactor.run_iteration(ctx) };
        if r != 0 {
            // EQ_WAIT or MP_READ failed. Yield briefly (give the
            // scheduler a chance to run a peer) and retry.
            syscall::invoke(
                uapi::KERNITE_CAP_SELF_TCB as u64,
                uapi::KERNITE_INV_TCB_YIELD as u64,
                0,
                0,
                0,
                0,
            );
        }
        // Re-arm the recv window every iteration; the shared helper
        // clears stale scratch caps before the next MP_READ.
        arm_recv_window(ctx);
    }
}
